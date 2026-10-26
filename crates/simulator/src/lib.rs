pub mod ablation;
pub mod controller;
pub mod entity;
pub mod hci;
pub mod telemetry;

use crate::{
    ablation::{AblationConfig, AblationFlags},
    controller::{Controller, ControllerError, ControllerExitReason},
    hci::{
        dump::PcapDumper,
        protocol::{Protocol, ProtocolError, create_protocol},
        transport::{TransportError, create_tranport},
    },
    telemetry::{TelemetryState, write_run_jsonl},
};
use ble::{
    att::AttError,
    gatt::GattProfile,
    hci::{
        ControllerToHostPacket, HciAclDataPkt, HciCommandPkt, HciEventPkt, HostToControllerPacket,
        event::LeMetaEventBody,
        parameter::{AclPacketBoundaryFlag, AddrKind, BroadcastFlag},
    },
    input::{InteractPhase, LocalVersionInformation},
    l2cap::{L2capBframeEncoder, L2capCframeEncoder, L2capInformationPayload},
};
use ble::{input::MetaInput, l2cap::L2capError};
use libafl_bolts::HasLen;
use nix::{
    sys::wait::{WaitPidFlag, WaitStatus, waitpid},
    unistd::{Pid, close, write},
};
use serde::Deserialize;
use std::{cell::RefCell, os::fd::OwnedFd, path::PathBuf};
use std::{
    cell::{Ref, RefMut},
    io,
};
use tokio::{
    signal::unix::{SignalKind, signal},
    time::{Duration, sleep},
};
use tracing::{debug, error, info, trace, warn};

#[derive(Debug, PartialEq)]
enum SimulatorInteractType {
    ByFuzz,
    BySimulator,
}

#[derive(Debug)]
pub enum SimulatorError {
    HciError(ProtocolError),
    L2capError(L2capError),
    AttError(AttError),
    IpcError(std::io::Error),
    ControllerError(ControllerError),
    TargetCrash,
}

impl From<TransportError> for SimulatorError {
    fn from(value: TransportError) -> Self {
        SimulatorError::HciError(ProtocolError::TransportFail(value))
    }
}

impl From<ProtocolError> for SimulatorError {
    fn from(value: ProtocolError) -> Self {
        SimulatorError::HciError(value)
    }
}

impl From<ControllerError> for SimulatorError {
    fn from(value: ControllerError) -> Self {
        SimulatorError::ControllerError(value)
    }
}

impl From<L2capError> for SimulatorError {
    fn from(value: L2capError) -> Self {
        SimulatorError::L2capError(value)
    }
}

impl From<AttError> for SimulatorError {
    fn from(value: AttError) -> Self {
        SimulatorError::AttError(value)
    }
}

/// Inner state for the Simulator.
struct SimulatorInnerState {
    /// fuzz input, simulator may extend the input with default interaction packets
    input: Option<MetaInput>,
    /// track for the current interacting phase, inital value is 0
    cur_phase: usize,
    /// track for the current interacting packet
    cur_packet: usize,
    /// total count of the fuzz generated phases
    cnt_fuzz_gen_phase: usize,
    /// total count of the fuzz generated packet in current phase
    cnt_fuzz_gen_packet: usize,
    /// Number of HCI packets sent to target in current fuzz run.
    round_sent_hci_packets: u64,
    /// Number of host->controller HCI packets observed in current fuzz run.
    round_host_hci_packets: u64,
    /// Controller-generated fallback packets recorded in ByFuzz mode for the current phase.
    fallback_phase_packets: Vec<ControllerToHostPacket>,
}

impl Default for SimulatorInnerState {
    fn default() -> Self {
        Self {
            input: None,
            cur_phase: 0,
            cur_packet: 0,
            cnt_fuzz_gen_packet: 0,
            cnt_fuzz_gen_phase: 0,
            round_sent_hci_packets: 0,
            round_host_hci_packets: 0,
            fallback_phase_packets: Vec::new(),
        }
    }
}

impl SimulatorInnerState {
    /// Resets the interact phase and the input, `input` will be cloned to take the ownership.
    pub fn reset_with_input<'a>(&mut self, input: &'a MetaInput) {
        self.input = Some(input.clone());
        self.input.as_mut().unwrap().clear_last_execution_feedback();
        self.input.as_mut().unwrap().normalize_vendor_response_marks();
        self.cur_phase = 0;
        self.cur_packet = 0;
        self.cnt_fuzz_gen_phase = input.phases().len();
        self.cnt_fuzz_gen_packet = if self.cnt_fuzz_gen_phase > 0 { input.phases()[0].len() } else { 0 };
        self.round_sent_hci_packets = 0;
        self.round_host_hci_packets = 0;
        self.fallback_phase_packets.clear();
    }

    /// Gets the reference to the current input.
    pub fn get_input(&self) -> &MetaInput {
        &self.input.as_ref().unwrap()
    }

    /// Gets the mutable reference to the current input.
    pub fn get_input_mut(&mut self) -> &mut MetaInput {
        self.input.as_mut().unwrap()
    }

    /// Increases the cursor of the interacting phase.
    pub fn phase_move_on(&mut self) {
        let next_phase = self.cur_phase + 1;
        self.cur_phase = next_phase;
        self.cur_packet = 0;
        self.cnt_fuzz_gen_packet = if next_phase < self.cnt_fuzz_gen_phase {
            self.get_input().phases()[next_phase].len()
        } else {
            0
        };
        self.fallback_phase_packets.clear();
    }

    /// Decides the interacting method by the phase. if we have remaining fuzz generated inputs,
    /// we should send packets from fuzzer rather than simulator.
    pub fn interact_type(&self) -> SimulatorInteractType {
        if self.cur_phase >= self.cnt_fuzz_gen_phase {
            return SimulatorInteractType::BySimulator;
        }
        if self.cur_packet >= self.cnt_fuzz_gen_packet {
            return SimulatorInteractType::BySimulator;
        }
        return SimulatorInteractType::ByFuzz;
    }

    /// Pushes the simulator generated packet to input.
    pub fn push_packet(&mut self, packet: ControllerToHostPacket) {
        let input = self.input.as_mut().unwrap();
        let phases = input.phases_mut();
        if phases.len() == self.cur_phase {
            phases.push(InteractPhase::new());
        }
        phases[self.cur_phase].push(packet);
        input.normalize_vendor_response_marks();
    }

    /// Gets the packets in current phase from input.
    pub fn get_phase(&mut self) -> &InteractPhase {
        let input = self.input.as_mut().unwrap();
        let phases = input.phases_mut();
        if phases.len() == self.cur_phase {
            phases.push(InteractPhase::new());
        }
        input.normalize_vendor_response_marks();
        &self.input.as_ref().unwrap().phases()[self.cur_phase]
    }

    pub fn add_round_sent_hci_packets(&mut self, n: u64) {
        self.round_sent_hci_packets = self.round_sent_hci_packets.saturating_add(n);
    }

    pub fn push_fallback_phase_packet(&mut self, packet: ControllerToHostPacket) {
        self.fallback_phase_packets.push(packet);
    }

    pub fn take_fallback_phase_packets(&mut self) -> Vec<ControllerToHostPacket> {
        std::mem::take(&mut self.fallback_phase_packets)
    }

    pub fn round_sent_hci_packets(&self) -> u64 {
        self.round_sent_hci_packets
    }

    pub fn note_host_hci_packet(&mut self) {
        self.round_host_hci_packets = self.round_host_hci_packets.saturating_add(1);
    }

    pub fn round_host_hci_packets(&self) -> u64 {
        self.round_host_hci_packets
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct SimulatorConfig {
    pub protocol: String,
    pub transport: String,
    pub timeout: u64,
    pub initial_timeout: u64,
    #[serde(default = "default_public_device_address")]
    pub public_device_address: [u8; 6],
    #[serde(default)]
    pub initial_local_version_information: Option<LocalVersionInformation>,
    #[serde(default)]
    pub keep_alive_on_timeout_until_child_exit: bool,
    #[serde(default = "default_replay_fuzz_phases")]
    pub replay_fuzz_phases: bool,
    #[serde(default)]
    pub freeze_version_mutation: bool,
    #[serde(default)]
    pub freeze_vendor_response_mutation: bool,
    #[serde(default)]
    pub round_timeout: u64,
    #[serde(default)]
    pub max_acl_packets_per_round: u32,
    #[serde(default)]
    pub max_hci_packets_per_round: u32,
    #[serde(default)]
    pub legacy_scan_reports: Vec<LegacyScanReportConfig>,
    #[serde(default = "default_emit_default_legacy_scan_report")]
    pub emit_default_legacy_scan_report: bool,
    #[serde(default)]
    pub emit_extended_adv_probe_on_le_event_mask: bool,
    #[serde(default)]
    pub targeted_bootstrap_vendor_opcodes: Vec<u16>,
    #[serde(default = "default_att_profile_guided_probe_steps")]
    pub max_att_profile_guided_probe_steps: u8,
    #[serde(default)]
    pub att_semantic_probe_order: AttSemanticProbeOrder,
    #[serde(default)]
    pub le_credit: LeCreditConfig,
    #[serde(default)]
    pub supported_states: Vec<u8>,
    #[serde(default)]
    pub peer_gatt_profile_preset: PeerGattProfilePreset,
    #[serde(default)]
    pub ablation: AblationConfig,
}

fn default_att_profile_guided_probe_steps() -> u8 {
    6
}

#[derive(Debug, Clone, Deserialize)]
pub struct LegacyScanReportConfig {
    #[serde(default = "default_legacy_scan_report_event_type")]
    pub event_type: u8,
    #[serde(default = "default_legacy_scan_report_address_type")]
    pub address_type: AddrKind,
    #[serde(default = "default_legacy_scan_report_address")]
    pub address: [u8; 6],
    #[serde(default = "default_legacy_scan_report_data")]
    pub data: Vec<u8>,
    #[serde(default = "default_legacy_scan_report_rssi")]
    pub rssi: i8,
}

fn default_legacy_scan_report_event_type() -> u8 {
    0x00
}

fn default_public_device_address() -> [u8; 6] {
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
}

fn default_legacy_scan_report_address_type() -> AddrKind {
    AddrKind::Public
}

fn default_legacy_scan_report_address() -> [u8; 6] {
    [0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6]
}

fn default_legacy_scan_report_data() -> Vec<u8> {
    vec![
        // Flags
        0x02, 0x01, 0x06, // Complete list of 16-bit service UUIDs:
        // 0x180D (Heart Rate), 0x1825 (OTS), 0x180F (Battery), 0x181D (Weight Scale)
        0x09, 0x03, 0x0D, 0x18, 0x25, 0x18, 0x0F, 0x18, 0x1D, 0x18,
    ]
}

fn default_legacy_scan_report_rssi() -> i8 {
    -59
}

fn default_emit_default_legacy_scan_report() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
pub struct LeCreditConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_le_credit_psm")]
    pub psm: u16,
    #[serde(default = "default_le_credit_mtu")]
    pub mtu: u16,
    #[serde(default = "default_le_credit_mps")]
    pub mps: u16,
    #[serde(default = "default_le_credit_initial_credits")]
    pub initial_credits: u16,
    #[serde(default)]
    pub auto_open_as_client: bool,
    #[serde(default)]
    pub auto_stream_after_open: bool,
    #[serde(default = "default_le_credit_stream_payload_len")]
    pub stream_payload_len: u16,
    #[serde(default = "default_le_credit_stream_packets_per_burst")]
    pub stream_packets_per_burst: u16,
    #[serde(default)]
    pub suppress_att_interact: bool,
    #[serde(default = "default_le_credit_semantic_probe_actions_per_trigger")]
    pub semantic_probe_actions_per_trigger: u8,
    #[serde(default)]
    pub semantic_probe_sequence: Vec<LeCreditSemanticAction>,
}

impl Default for LeCreditConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            psm: default_le_credit_psm(),
            mtu: default_le_credit_mtu(),
            mps: default_le_credit_mps(),
            initial_credits: default_le_credit_initial_credits(),
            auto_open_as_client: false,
            auto_stream_after_open: false,
            stream_payload_len: default_le_credit_stream_payload_len(),
            stream_packets_per_burst: default_le_credit_stream_packets_per_burst(),
            suppress_att_interact: false,
            semantic_probe_actions_per_trigger: default_le_credit_semantic_probe_actions_per_trigger(),
            semantic_probe_sequence: Vec::new(),
        }
    }
}

fn default_le_credit_psm() -> u16 {
    0x0025
}

fn default_le_credit_mtu() -> u16 {
    1024
}

fn default_le_credit_mps() -> u16 {
    247
}

fn default_le_credit_initial_credits() -> u16 {
    32
}

fn default_le_credit_stream_payload_len() -> u16 {
    1000
}

fn default_le_credit_stream_packets_per_burst() -> u16 {
    6
}

fn default_le_credit_semantic_probe_actions_per_trigger() -> u8 {
    1
}

fn default_replay_fuzz_phases() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LeCreditSemanticAction {
    ValidSmallSdu,
    ValidMtuSdu,
    OversizedSdu,
    OversizedFragment,
    CreditRefillSmall,
    CreditRefillBurst,
    CreditOverrun,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PeerGattProfilePreset {
    #[default]
    GenericDefault,
    EspGattsDemo,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AttSemanticProbeOrder {
    #[default]
    ReadFirst,
    WriteFirst,
}

#[derive(Debug, Clone, Default)]
pub struct RuntimeProfileState {
    pub active_connection_handles: Vec<u16>,
    pub host_visible_dynamic_cids: Vec<u16>,
    pub le_credit_psms: Vec<u16>,
    pub last_le_credit_mtu: Option<u16>,
    pub last_le_credit_mps: Option<u16>,
    pub last_initial_credits: Option<u16>,
    pub pairing_started: bool,
    pub pairing_completed: bool,
}

impl RuntimeProfileState {
    fn reset(&mut self) {
        *self = Self::default();
    }

    fn push_unique(values: &mut Vec<u16>, value: u16) {
        if values.contains(&value) {
            return;
        }
        values.push(value);
        values.sort_unstable();
    }

    fn remove_value(values: &mut Vec<u16>, value: u16) {
        values.retain(|candidate| *candidate != value);
    }

    fn note_connection_handle(&mut self, handle: u16) {
        Self::push_unique(&mut self.active_connection_handles, handle);
    }

    fn note_disconnect_handle(&mut self, handle: u16) {
        Self::remove_value(&mut self.active_connection_handles, handle);
    }

    fn note_host_visible_dynamic_cid(&mut self, cid: u16) {
        Self::push_unique(&mut self.host_visible_dynamic_cids, cid);
    }

    fn note_le_credit_psm(&mut self, psm: u16) {
        Self::push_unique(&mut self.le_credit_psms, psm);
    }

    fn note_le_credit_context(&mut self, psm: u16, mtu: u16, mps: u16, initial_credits: u16, host_visible_cid: Option<u16>) {
        self.note_le_credit_psm(psm);
        self.last_le_credit_mtu = Some(mtu);
        self.last_le_credit_mps = Some(mps);
        self.last_initial_credits = Some(initial_credits);
        if let Some(cid) = host_visible_cid {
            self.note_host_visible_dynamic_cid(cid);
        }
    }
}


impl SimulatorConfig {
    pub const fn module_flags(&self) -> AblationFlags {
        self.ablation.resolved_flags()
    }
}

impl Default for SimulatorConfig {
    fn default() -> Self {
        Self {
            protocol: String::new(),
            transport: String::new(),
            timeout: 0,
            initial_timeout: 0,
            public_device_address: default_public_device_address(),
            initial_local_version_information: None,
            keep_alive_on_timeout_until_child_exit: false,
            replay_fuzz_phases: default_replay_fuzz_phases(),
            freeze_version_mutation: false,
            freeze_vendor_response_mutation: false,
            round_timeout: 0,
            max_acl_packets_per_round: 0,
            max_hci_packets_per_round: 0,
            legacy_scan_reports: Vec::new(),
            emit_default_legacy_scan_report: default_emit_default_legacy_scan_report(),
            emit_extended_adv_probe_on_le_event_mask: false,
            targeted_bootstrap_vendor_opcodes: Vec::new(),
            max_att_profile_guided_probe_steps: default_att_profile_guided_probe_steps(),
            att_semantic_probe_order: AttSemanticProbeOrder::default(),
            le_credit: LeCreditConfig::default(),
            supported_states: Vec::new(),
            peer_gatt_profile_preset: PeerGattProfilePreset::default(),
            ablation: AblationConfig::default(),
        }
    }
}

impl Default for LegacyScanReportConfig {
    fn default() -> Self {
        Self {
            event_type: default_legacy_scan_report_event_type(),
            address_type: default_legacy_scan_report_address_type(),
            address: default_legacy_scan_report_address(),
            data: default_legacy_scan_report_data(),
            rssi: default_legacy_scan_report_rssi(),
        }
    }
}

/// Simulator holds the knownledge and state across all fuzzing loops.
pub struct Simulator {
    /// HCI protocol of the controller
    protocol_arg: String,
    /// HCI transport of the controller
    transport_arg: String,
    /// Timeout between two HCI packets
    timeout: Duration,
    /// Timeout for the first HCI packet
    initial_timeout: Duration,
    /// Maximum total time of one fuzz round (0 means disabled)
    round_timeout: Duration,
    /// If true, a receive timeout does not end this round while child is still running.
    keep_alive_on_timeout_until_child_exit: bool,
    /// HCI protocol instance to send HCI packet
    protocol: RefCell<Option<Box<dyn Protocol>>>,
    /// Inner state
    inner: RefCell<SimulatorInnerState>,
    /// Gatt Profile
    target_gatt_profile: RefCell<GattProfile>,
    /// Runtime-discovered protocol profile carried across one fuzz loop.
    runtime_profile: RefCell<RuntimeProfileState>,
    /// Default legacy scan reports emitted on LE Set Scan Enable.
    legacy_scan_reports: Vec<LegacyScanReportConfig>,
    /// Emit one synthetic Extended Advertising Report after LE Set Event Mask.
    emit_extended_adv_probe_on_le_event_mask: bool,
    /// Limit of profile-guided ATT probes emitted after discovery completes.
    max_att_profile_guided_probe_steps: u8,
    /// Ordering strategy for profile-guided ATT probes.
    att_semantic_probe_order: AttSemanticProbeOrder,
    /// Optional LE Credit specific behavior.
    le_credit: LeCreditConfig,
    /// Optional override for LE supported states response.
    supported_states: Vec<u8>,
    /// Case-specific peer GATT profile preset.
    peer_gatt_profile_preset: PeerGattProfilePreset,
    /// Mutable peer-side GATT profile served by the simulator.
    peer_gatt_profile: RefCell<GattProfile>,
    /// Public device address returned by Read BD_ADDR.
    public_device_address: [u8; 6],
    /// Optional cap of handled ACL packets per fuzz run (0 means unlimited).
    max_acl_packets_per_round: u32,
    /// Optional cap of handled host->controller HCI packets per fuzz run (0 means unlimited).
    max_hci_packets_per_round: u32,
    /// If false, simulator will ignore stored fuzz phases and always use live controller output.
    replay_fuzz_phases: bool,
    /// Ablation configuration and resolved module flags.
    ablation: AblationConfig,
    ablation_flags: AblationFlags,
    /// Optional telemetry output directory for JSONL run logs.
    telemetry_dir: Option<PathBuf>,
    /// Current case name used in telemetry.
    telemetry_case_name: String,
    /// Per-run telemetry state.
    telemetry: RefCell<TelemetryState>,
    /// Packet recorder and dumper
    pcap_dumper: PcapDumper,
}

impl std::fmt::Debug for Simulator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Simulator").finish()
    }
}

impl Simulator {
    #[inline]
    fn is_vendor_response_event_packet(packet: &ControllerToHostPacket) -> bool {
        matches!(
            packet,
            ControllerToHostPacket::Event(HciEventPkt::CommandComplete(_)) | ControllerToHostPacket::Event(HciEventPkt::CommandStatus(_))
        )
    }

    #[inline]
    fn vendor_response_opcode(packet: &ControllerToHostPacket) -> Option<u16> {
        match packet {
            ControllerToHostPacket::Event(HciEventPkt::CommandComplete(evt)) => Some(evt.command_opcode),
            ControllerToHostPacket::Event(HciEventPkt::CommandStatus(evt)) => Some(evt.command_opcode),
            _ => None,
        }
    }

    #[inline]
    fn align_command_response_opcode(packet: &mut ControllerToHostPacket, expected_opcode: Option<u16>) {
        let Some(expected_opcode) = expected_opcode else {
            return;
        };
        match packet {
            ControllerToHostPacket::Event(HciEventPkt::CommandComplete(evt)) => {
                if evt.command_opcode != expected_opcode {
                    trace!(
                        "align stale CommandComplete opcode from 0x{:04x} to 0x{:04x}",
                        evt.command_opcode, expected_opcode
                    );
                    evt.command_opcode = expected_opcode;
                }
            }
            ControllerToHostPacket::Event(HciEventPkt::CommandStatus(evt)) => {
                if evt.command_opcode != expected_opcode {
                    trace!(
                        "align stale CommandStatus opcode from 0x{:04x} to 0x{:04x}",
                        evt.command_opcode, expected_opcode
                    );
                    evt.command_opcode = expected_opcode;
                }
            }
            _ => {}
        }
    }

    #[inline]
    fn is_mutable_packet(&self, packet: &ControllerToHostPacket, vendor_marked: bool) -> bool {
        match packet {
            ControllerToHostPacket::AclData(_) => true,
            ControllerToHostPacket::IsoData(_) => true,
            ControllerToHostPacket::SyncData(_) => true,
            ControllerToHostPacket::Event(HciEventPkt::LeMata(le_meta_event)) => {
                matches!(
                    le_meta_event.body,
                    LeMetaEventBody::AdvertisingReport(_)
                        | LeMetaEventBody::ExtendedAdvertisingReport(_)
                        | LeMetaEventBody::PeriodicAdvertisingReport(_)
                )
            }
            _ => {
                if vendor_marked && Self::is_vendor_response_event_packet(packet) {
                    true
                } else {
                    self.ablation_flags.enable_random_hci_floor && Self::is_vendor_response_event_packet(packet)
                }
            }
        }
    }

    pub fn new(config: &SimulatorConfig, enable_dump: bool) -> Self {
        let protocol_arg = config.protocol.clone();
        let transport_arg = config.transport.clone();
        let timeout = Duration::from_millis(config.timeout);
        let initial_timeout = Duration::from_millis(config.initial_timeout);
        let round_timeout = Duration::from_millis(config.round_timeout);
        let keep_alive_on_timeout_until_child_exit = config.keep_alive_on_timeout_until_child_exit;
        let max_acl_packets_per_round = config.max_acl_packets_per_round;
        let max_hci_packets_per_round = config.max_hci_packets_per_round;
        let replay_fuzz_phases = config.replay_fuzz_phases;
        let legacy_scan_reports = if config.legacy_scan_reports.is_empty() && config.emit_default_legacy_scan_report {
            vec![LegacyScanReportConfig::default()]
        } else {
            config.legacy_scan_reports.clone()
        };
        let emit_extended_adv_probe_on_le_event_mask = config.emit_extended_adv_probe_on_le_event_mask;
        let max_att_profile_guided_probe_steps = config.max_att_profile_guided_probe_steps;
        let att_semantic_probe_order = config.att_semantic_probe_order.clone();
        let le_credit = config.le_credit.clone();
        let supported_states = config.supported_states.clone();
        let peer_gatt_profile_preset = config.peer_gatt_profile_preset.clone();
        let public_device_address = config.public_device_address;
        let ablation = config.ablation.clone();
        let ablation_flags = ablation.resolved_flags();
        let telemetry_dir = ablation.telemetry_dir.as_ref().map(PathBuf::from);
        let telemetry_case_name = ablation.case_name.clone().unwrap_or_else(|| String::from("unknown_case"));

        Self {
            protocol_arg,
            transport_arg,
            timeout,
            initial_timeout,
            round_timeout,
            keep_alive_on_timeout_until_child_exit,
            protocol: RefCell::new(None),
            inner: RefCell::new(SimulatorInnerState::default()),
            target_gatt_profile: RefCell::new(GattProfile::blank()),
            runtime_profile: RefCell::new(RuntimeProfileState::default()),
            legacy_scan_reports,
            emit_extended_adv_probe_on_le_event_mask,
            max_att_profile_guided_probe_steps,
            att_semantic_probe_order,
            le_credit,
            supported_states,
            peer_gatt_profile: RefCell::new(entity::att::build_peer_gatt_profile(&peer_gatt_profile_preset)),
            peer_gatt_profile_preset,
            public_device_address,
            max_acl_packets_per_round,
            max_hci_packets_per_round,
            replay_fuzz_phases,
            ablation,
            ablation_flags,
            telemetry_dir,
            telemetry_case_name,
            telemetry: RefCell::new(TelemetryState::default()),
            pcap_dumper: PcapDumper::new(enable_dump),
        }
    }

    pub fn ablation_config(&self) -> &AblationConfig {
        &self.ablation
    }

    pub const fn ablation_flags(&self) -> AblationFlags {
        self.ablation_flags
    }

    pub fn telemetry_enabled(&self) -> bool {
        self.ablation.record_telemetry && self.telemetry_dir.is_some()
    }

    pub fn pcap_dumper(&self) -> &PcapDumper {
        &self.pcap_dumper
    }

    pub fn target_gatt_profile<'a>(&'a self) -> Ref<'a, GattProfile> {
        self.target_gatt_profile.borrow()
    }

    pub fn target_gatt_profile_mut<'a>(&'a self) -> RefMut<'a, GattProfile> {
        self.target_gatt_profile.borrow_mut()
    }

    pub fn runtime_profile(&self) -> RuntimeProfileState {
        self.runtime_profile.borrow().clone()
    }

    pub fn peer_gatt_profile<'a>(&'a self) -> Ref<'a, GattProfile> {
        self.peer_gatt_profile.borrow()
    }

    pub fn peer_gatt_profile_mut<'a>(&'a self) -> RefMut<'a, GattProfile> {
        self.peer_gatt_profile.borrow_mut()
    }

    pub fn note_connection_handle(&self, handle: u16) {
        self.runtime_profile.borrow_mut().note_connection_handle(handle);
    }

    pub fn note_disconnect_handle(&self, handle: u16) {
        self.runtime_profile.borrow_mut().note_disconnect_handle(handle);
    }

    pub fn note_host_visible_dynamic_cid(&self, cid: u16) {
        self.runtime_profile.borrow_mut().note_host_visible_dynamic_cid(cid);
    }

    pub fn note_le_credit_context(&self, psm: u16, mtu: u16, mps: u16, initial_credits: u16, host_visible_cid: Option<u16>) {
        self.runtime_profile
            .borrow_mut()
            .note_le_credit_context(psm, mtu, mps, initial_credits, host_visible_cid);
    }

    pub fn legacy_scan_reports(&self) -> &[LegacyScanReportConfig] {
        &self.legacy_scan_reports
    }

    pub fn emit_extended_adv_probe_on_le_event_mask(&self) -> bool {
        self.emit_extended_adv_probe_on_le_event_mask
    }

    pub fn public_device_address(&self) -> [u8; 6] {
        self.public_device_address
    }

    pub fn max_att_profile_guided_probe_steps(&self) -> u8 {
        self.max_att_profile_guided_probe_steps
    }

    pub fn att_semantic_probe_order(&self) -> &AttSemanticProbeOrder {
        &self.att_semantic_probe_order
    }

    pub fn le_credit_config(&self) -> &LeCreditConfig {
        &self.le_credit
    }

    pub fn supported_states(&self) -> &[u8] {
        &self.supported_states
    }

    pub fn max_acl_packets_per_round(&self) -> u32 {
        self.max_acl_packets_per_round
    }

    pub fn max_hci_packets_per_round(&self) -> u32 {
        self.max_hci_packets_per_round
    }

    pub fn current_round_host_hci_packets(&self) -> u64 {
        self.inner.borrow().round_host_hci_packets()
    }

    #[inline]
    fn interact_type(&self) -> SimulatorInteractType {
        if self.replay_fuzz_phases {
            self.inner.borrow().interact_type()
        } else {
            SimulatorInteractType::BySimulator
        }
    }

    /// takes the modified input after one fuzz execution.
    pub fn clone_input(&self) -> MetaInput {
        self.inner.borrow().get_input().clone()
    }

    /// Gets local version information from current input without cloning whole input.
    pub fn current_local_version_information(&self) -> LocalVersionInformation {
        self.inner.borrow().get_input().local_version_information().clone()
    }

    /// Returns number of HCI packets sent to target in last fuzz run.
    pub fn last_round_sent_hci_packets(&self) -> u64 {
        self.inner.borrow().round_sent_hci_packets()
    }

    fn count_mutable_units_in_input(&self, input: &MetaInput) -> u64 {
        let mut cnt = 0u64;
        for (phase_idx, phase) in input.phases().iter().enumerate() {
            let marks = input
                .vendor_response_marks()
                .get(phase_idx)
                .cloned()
                .unwrap_or_else(|| vec![false; phase.len()]);
            for (packet_idx, packet) in phase.iter().enumerate() {
                let vendor_marked = marks.get(packet_idx).copied().unwrap_or(false);
                if self.is_mutable_packet(packet, vendor_marked) {
                    cnt = cnt.saturating_add(1);
                }
            }
        }
        cnt
    }

    fn begin_run_telemetry(&self) {
        if !self.telemetry_enabled() {
            return;
        }
        self.telemetry.borrow_mut().begin_run(&self.telemetry_case_name, self.ablation.mode.as_str());
    }

    fn with_run_telemetry<F>(&self, mut f: F)
    where
        F: FnMut(&mut telemetry::RunTelemetry),
    {
        if !self.telemetry_enabled() {
            return;
        }
        if let Some(run) = self.telemetry.borrow_mut().current_run_mut() {
            f(run);
        }
    }

    fn current_run_elapsed_secs(&self) -> f64 {
        if !self.telemetry_enabled() {
            return 0.0;
        }
        self.telemetry
            .borrow()
            .current_run_elapsed_secs()
            .unwrap_or(0.0)
    }

    fn mark_bootstrap_from_target_state(&self) {
        let packet_idx = self.current_round_host_hci_packets();
        let elapsed_secs = self.current_run_elapsed_secs();
        self.with_run_telemetry(|run| {
            run.bootstrap_success = run.entered_scanning || run.entered_advertising || run.entered_connection;
            if run.bootstrap_success {
                run.bootstrap_stabilized = true;
                run.bootstrap_stabilization_latency_packets.get_or_insert(packet_idx);
                run.bootstrap_stabilization_latency_secs.get_or_insert(elapsed_secs);
            }
        });
    }

    pub fn telemetry_mark_scanning(&self) {
        let packet_idx = self.current_round_host_hci_packets();
        let elapsed_secs = self.current_run_elapsed_secs();
        self.with_run_telemetry(|run| run.mark_scanning(packet_idx, elapsed_secs));
        self.mark_bootstrap_from_target_state();
    }

    pub fn telemetry_mark_advertising(&self) {
        let packet_idx = self.current_round_host_hci_packets();
        let elapsed_secs = self.current_run_elapsed_secs();
        self.with_run_telemetry(|run| run.mark_advertising(packet_idx, elapsed_secs));
        self.mark_bootstrap_from_target_state();
    }

    pub fn telemetry_mark_connection(&self) {
        let packet_idx = self.current_round_host_hci_packets();
        let elapsed_secs = self.current_run_elapsed_secs();
        self.with_run_telemetry(|run| run.mark_connection(packet_idx, elapsed_secs));
        self.mark_bootstrap_from_target_state();
    }

    pub fn telemetry_mark_peer_created(&self) {
        self.with_run_telemetry(|run| run.mark_peer_created());
    }

    pub fn telemetry_mark_pairing_started(&self) {
        self.runtime_profile.borrow_mut().pairing_started = true;
        let packet_idx = self.current_round_host_hci_packets();
        let elapsed_secs = self.current_run_elapsed_secs();
        self.with_run_telemetry(|run| run.mark_pairing_started(packet_idx, elapsed_secs));
    }

    pub fn telemetry_mark_pairing_completed(&self) {
        self.runtime_profile.borrow_mut().pairing_completed = true;
        self.with_run_telemetry(|run| run.mark_pairing_completed());
    }

    pub fn telemetry_mark_discovery_started(&self) {
        let packet_idx = self.current_round_host_hci_packets();
        let elapsed_secs = self.current_run_elapsed_secs();
        self.with_run_telemetry(|run| run.mark_discovery_started(packet_idx, elapsed_secs));
    }

    pub fn telemetry_mark_discovery_completed(&self) {
        self.with_run_telemetry(|run| run.mark_discovery_completed());
    }

    pub fn telemetry_mark_semantic_interaction_started(&self) {
        let packet_idx = self.current_round_host_hci_packets();
        let elapsed_secs = self.current_run_elapsed_secs();
        self.with_run_telemetry(|run| run.mark_semantic_interaction_started(packet_idx, elapsed_secs));
    }

    pub fn telemetry_mark_semantic_probe_sent(&self) {
        self.with_run_telemetry(|run| run.mark_semantic_probe_sent());
    }

    pub fn telemetry_mark_semantic_probe_success(&self) {
        self.with_run_telemetry(|run| run.mark_semantic_probe_success());
    }

    pub fn telemetry_note_vendor_hci_seen(&self, opcode: u16) {
        self.with_run_telemetry(|run| run.mark_vendor_hci_seen(opcode));
    }

    pub fn telemetry_note_vendor_hci_specialized_response(&self, opcode: u16) {
        self.with_run_telemetry(|run| run.mark_vendor_hci_specialized_response(opcode));
    }

    pub fn telemetry_note_vendor_hci_generic_ack(&self, opcode: u16) {
        self.with_run_telemetry(|run| run.mark_vendor_hci_generic_ack(opcode));
    }

    fn finalize_run_telemetry_common(&self) {
        if !self.telemetry_enabled() {
            return;
        }
        let final_input = {
            let inner = self.inner.borrow();
            let Some(input) = inner.input.as_ref() else {
                return;
            };
            input.clone()
        };
        let delivered = self.last_round_sent_hci_packets();
        let total_available = self.count_mutable_units_in_input(&final_input);
        let known_handle_count = self.target_gatt_profile().known_handles().len();
        let host_packets = self.current_round_host_hci_packets();
        self.with_run_telemetry(|run| {
            run.known_handle_count_end_of_run = known_handle_count;
            run.mutable_hci_units_delivered = delivered;
            run.total_mutable_units_available = total_available;
            run.host_visible_mutation_delivery_ratio = if total_available == 0 {
                0.0
            } else {
                delivered as f64 / total_available as f64
            };
            run.round_host_hci_packets = host_packets;
            run.bootstrap_success = run.entered_scanning || run.entered_advertising || run.entered_connection;
            if run.bootstrap_success {
                run.bootstrap_stabilized = true;
                let first_target_packet = [
                    run.time_to_first_scanning_packets,
                    run.time_to_first_advertising_packets,
                    run.time_to_first_connection_packets,
                ]
                .into_iter()
                .flatten()
                .min();
                if let Some(first_packet) = first_target_packet {
                    run.bootstrap_stabilization_latency_packets.get_or_insert(first_packet);
                }
                let first_target_secs = [
                    run.time_to_first_scanning_secs,
                    run.time_to_first_advertising_secs,
                    run.time_to_first_connection_secs,
                ]
                .into_iter()
                .flatten()
                .reduce(f64::min);
                if let Some(first_secs) = first_target_secs {
                    run.bootstrap_stabilization_latency_secs.get_or_insert(first_secs);
                }
            }
        });
    }

    pub fn record_run_outcome(&self, crashed: bool, timed_out: bool) -> Result<(), io::Error> {
        if !self.telemetry_enabled() {
            return Ok(());
        }
        self.finalize_run_telemetry_common();
        let Some(dir) = &self.telemetry_dir else {
            return Ok(());
        };
        let run = {
            let mut telemetry = self.telemetry.borrow_mut();
            let Some(run) = telemetry.current_run_mut() else {
                return Ok(());
            };
            run.crashed = crashed;
            run.timed_out = timed_out;
            run.clone()
        };
        write_run_jsonl(dir, &run)
    }

    /// Performs one fuzz execution.
    pub async fn fuzz_once(&self, notifier_fd: Option<OwnedFd>, track_pid: Option<Pid>, input: &MetaInput) -> Result<ControllerExitReason, SimulatorError> {
        self.pre_fuzz_once(input).await?;
        let ret = self.recv_loop_wrapper(notifier_fd, track_pid).await;
        self.post_fuzz_once().await?;
        ret
    }

    /// Actions needs to be done before one fuzz run.
    async fn pre_fuzz_once(&self, input: &MetaInput) -> Result<(), SimulatorError> {
        // recreates the protocol and transport
        trace!("setting up protocol and transport ...");
        if !self.protocol.borrow().is_none() {
            panic!("HCI protocol and transport is not closed");
        }
        *self.protocol.borrow_mut() = Some(create_protocol(&self.protocol_arg, create_tranport(&self.transport_arg).await?).await?);
        self.begin_run_telemetry();

        // resets inner state
        {
            let mut inner = self.inner.borrow_mut();
            inner.reset_with_input(input);
            if !self.ablation_flags.enable_vendor_response_marking {
                inner.get_input_mut().vendor_response_marks_mut().clear();
            }
            if !self.replay_fuzz_phases {
                inner.get_input_mut().phases_mut().clear();
                inner.get_input_mut().vendor_response_marks_mut().clear();
                inner.cnt_fuzz_gen_phase = 0;
                inner.cnt_fuzz_gen_packet = 0;
                inner.cur_phase = 0;
                inner.cur_packet = 0;
            }
        }
        self.target_gatt_profile_mut().reset();
        *self.peer_gatt_profile_mut() = entity::att::build_peer_gatt_profile(&self.peer_gatt_profile_preset);
        self.runtime_profile.borrow_mut().reset();
        Ok(())
    }

    /// Actions needs to be done after one fuzz run.
    async fn post_fuzz_once(&self) -> Result<(), SimulatorError> {
        self.protocol.take().unwrap().finish_phase().await?;
        Ok(())
    }

    /// Wrapper for the receiving loop to make sure the cleanup code is called.
    async fn recv_loop_wrapper(&self, notifier_fd: Option<OwnedFd>, track_pid: Option<Pid>) -> Result<ControllerExitReason, SimulatorError> {
        // creates the virtual controller
        trace!("creating controller ...");
        let mut controller = Controller::new(&self).await;

        // sends signal to the child to notify the controller is running now
        if let Some(notifier_fd) = notifier_fd {
            trace!("sending target run signal ...");
            write(&notifier_fd, &[1]).map_err(|err| SimulatorError::IpcError(err.into()))?;
            close(notifier_fd).map_err(|err| SimulatorError::IpcError(err.into()))?;
        }

        // start the receive loop
        trace!("all done, start receive loop ...");
        let ret = self.recv_loop(&mut controller, track_pid).await;

        let timed_out = matches!(ret, Ok(ControllerExitReason::Ok));
        self.inner.borrow_mut().get_input_mut().apply_execution_feedback_with_policy(
            controller.execution_feedback(timed_out),
            self.ablation_flags.enable_vendor_bootstrap_search,
            self.ablation_flags.enable_vendor_response_marking,
            self.ablation_flags.enable_vendor_bootstrap_freeze,
        );

        ret
    }

    /// Performs loop reading of HCI packet from host, exits when timeout or controller requires.
    /// Should only be called in fuzz run.
    async fn recv_loop<'a>(&self, controller: &mut Controller<'a>, track_pid: Option<Pid>) -> Result<ControllerExitReason, SimulatorError> {
        const ABLATION_BOOTSTRAP_ONLY_PACKET_CAP: u32 = 40;
        const KEEP_ALIVE_IDLE_TIMEOUTS_BEFORE_DETACH: u32 = 3;

        let round_start = tokio::time::Instant::now();
        let mut host_hci_packets: u32 = 0;
        let mut idle_timeout_streak: u32 = 0;
        if let Some(pid) = track_pid {
            debug!("receive loop tracking child pid {}", pid);
        }
        loop {
            if self.round_timeout.as_millis() > 0 && round_start.elapsed() >= self.round_timeout {
                warn!("receive loop round timeout");
                return Ok(ControllerExitReason::Ok);
            }

            let read_timeout = if host_hci_packets == 0 {
                // `initial_timeout` is meant to cover target bootstrap until the first HCI
                // packet arrives. After bootstrap starts, fall back to the normal per-packet
                // timeout so idle states do not pin the whole run until an outer watchdog kills
                // it.
                self.initial_timeout
            } else {
                self.timeout
            };

            let ret = read_with_track(self.protocol.borrow().as_ref().unwrap(), read_timeout, track_pid).await;

            match ret {
                // receive packet
                ReadWithTrackResult::Done(Ok(packet)) => {
                    idle_timeout_streak = 0;
                    host_hci_packets = host_hci_packets.saturating_add(1);
                    self.inner.borrow_mut().note_host_hci_packet();
                    if let Err(err) = self.on_recv_hci_packet(controller, packet).await {
                        if is_simulator_peer_disconnect(&err) {
                            debug!("receive loop ended by transport peer disconnect while handling packet: {:?}", err);
                            return Ok(ControllerExitReason::Ok);
                        }
                        return Err(err);
                    }
                    let max_hci_packets = self.max_hci_packets_per_round();
                    if max_hci_packets > 0 && host_hci_packets >= max_hci_packets {
                        info!("receive loop early-exit on host HCI packet cap: {}/{}", host_hci_packets, max_hci_packets);
                        return Ok(ControllerExitReason::Ok);
                    }
                    if !self.ablation_flags.enable_dynamic_peer_creation {
                        let feedback = controller.execution_feedback(false);
                        if !feedback.entered_connection_state
                            && (feedback.entered_scanning_state || feedback.entered_advertising_state)
                            && host_hci_packets >= ABLATION_BOOTSTRAP_ONLY_PACKET_CAP
                        {
                            info!(
                                "receive loop early-exit on bootstrap-only ablation cap: {}/{}",
                                host_hci_packets, ABLATION_BOOTSTRAP_ONLY_PACKET_CAP
                            );
                            return Ok(ControllerExitReason::Ok);
                        }
                    }
                    if controller.should_early_exit() {
                        info!("controller requested early exit");
                        return Ok(ControllerExitReason::Ok);
                    }
                }
                // failed to read packet
                ReadWithTrackResult::Done(Err(read_err)) => {
                    if is_transport_peer_disconnect(&read_err) {
                        debug!("receive loop ended by transport peer disconnect: {:?}", read_err);
                        return Ok(ControllerExitReason::Ok);
                    }
                    Err(read_err)?;
                }
                // timeout
                ReadWithTrackResult::Timeout => {
                    let mut injected_packets = false;
                    if host_hci_packets > 0 {
                        injected_packets |= controller.try_idle_peer_bootstrap()?;
                        injected_packets |= controller.try_idle_peer_progress()?;
                    }
                    if injected_packets {
                        self.flush_current_phase_packets(controller, None, None).await?;
                        idle_timeout_streak = 0;
                        continue;
                    }
                    if self.keep_alive_on_timeout_until_child_exit && track_pid.is_some() {
                        if host_hci_packets == 0 {
                            debug!("receive loop timeout before first host packet while child is alive, keep waiting");
                            continue;
                        }
                        idle_timeout_streak = idle_timeout_streak.saturating_add(1);
                        if idle_timeout_streak < KEEP_ALIVE_IDLE_TIMEOUTS_BEFORE_DETACH {
                            debug!(
                                "receive loop timeout while child is still alive, continue waiting ({}/{})",
                                idle_timeout_streak, KEEP_ALIVE_IDLE_TIMEOUTS_BEFORE_DETACH
                            );
                            continue;
                        }
                        info!(
                            "receive loop detached after {} consecutive idle timeouts; child stays alive for post-processing/modeling",
                            idle_timeout_streak
                        );
                        return Ok(ControllerExitReason::Ok);
                    }
                    warn!("receive loop timeout");
                    return Ok(ControllerExitReason::Ok);
                }
                // child exit (only used by legacy callsites passing tracked child into read_with_track)
                ReadWithTrackResult::ChildExit(Ok(status)) => {
                    info!("child exit, {:?}", status);
                    return Ok(ControllerExitReason::ChildExit(status));
                }
                // child error (only used by legacy callsites passing tracked child into read_with_track)
                ReadWithTrackResult::ChildExit(Err(child_err)) => {
                    error!("child error, {:?}", child_err);
                    return Err(SimulatorError::IpcError(child_err));
                }
            }
        }
    }

    /// Reads HCI packet from host via the given protocol and transport.
    /// Should only be called in fuzz run.
    async fn on_recv_hci_packet<'a>(&self, controller: &mut Controller<'a>, packet: HostToControllerPacket) -> Result<(), SimulatorError> {
        let expected_command_opcode = match &packet {
            HostToControllerPacket::Command(cmd) => Some(Controller::command_opcode(cmd)),
            _ => None,
        };
        let expected_vendor_opcode = match &packet {
            HostToControllerPacket::Command(HciCommandPkt::Vendor { id, .. }) => Some(*id),
            _ => None,
        };
        let is_vendor_command = expected_vendor_opcode.is_some();
        let (phase_idx, phase_len_before) = {
            let mut inner = self.inner.borrow_mut();
            let phase_idx = inner.cur_phase;
            let phase_len_before = inner.get_phase().len();
            (phase_idx, phase_len_before)
        };

        self.pcap_dumper.host_to_controller(&packet);
        controller.handle_hci_packet(packet).await?;

        if is_vendor_command && self.ablation_flags.enable_vendor_response_marking {
            let mut inner = self.inner.borrow_mut();
            let phase_len_after = inner.get_phase().len();
            inner.get_input_mut().mark_vendor_response_range(phase_idx, phase_len_before, phase_len_after);
        }

        self.flush_current_phase_packets(controller, expected_command_opcode, expected_vendor_opcode)
            .await?;
        Ok(())
    }

    async fn flush_current_phase_packets<'a>(
        &self,
        controller: &mut Controller<'a>,
        expected_command_opcode: Option<u16>,
        expected_vendor_opcode: Option<u16>,
    ) -> Result<(), SimulatorError> {
        let (phase_idx, phase_packets, vendor_marks, fallback_phase_packets) = {
            let mut inner = self.inner.borrow_mut();
            let phase_idx = inner.cur_phase;
            let phase_packets = inner.get_phase().clone();
            let vendor_marks = inner
                .get_input()
                .vendor_response_marks()
                .get(phase_idx)
                .cloned()
                .unwrap_or_else(|| vec![false; phase_packets.len()]);
            let fallback_phase_packets = inner.take_fallback_phase_packets();
            (phase_idx, phase_packets, vendor_marks, fallback_phase_packets)
        };

        let use_fallback_cmd_response = expected_vendor_opcode.is_none()
            && expected_command_opcode.is_some_and(|expected_opcode| {
                fallback_phase_packets.iter().any(|packet| match packet {
                    ControllerToHostPacket::Event(HciEventPkt::CommandComplete(evt)) => evt.command_opcode == expected_opcode,
                    ControllerToHostPacket::Event(HciEventPkt::CommandStatus(evt)) => evt.command_opcode == expected_opcode,
                    _ => false,
                })
            });

        let mut mutable_sent_cnt: u64 = 0;
        for packet in &phase_packets {
            if use_fallback_cmd_response {
                let is_non_vendor_cmd_response = matches!(
                    packet,
                    ControllerToHostPacket::Event(HciEventPkt::CommandComplete(evt))
                        if evt.command_opcode < 0xFC00
                ) || matches!(
                    packet,
                    ControllerToHostPacket::Event(HciEventPkt::CommandStatus(evt))
                        if evt.command_opcode < 0xFC00
                );
                if is_non_vendor_cmd_response {
                    continue;
                }
            }
            if let Some(pkt_opcode) = Self::vendor_response_opcode(packet) {
                // Guard against stale phase replay only for Vendor command responses.
                // Non-vendor command-complete/status events (e.g. Reset 0x0C03) must still be
                // emitted, otherwise host init state machine desynchronizes immediately.
                if (0xFC00..=0xFFFF).contains(&pkt_opcode) && expected_vendor_opcode != Some(pkt_opcode) {
                    continue;
                }
            }
            let mut packet_to_send = packet.clone();
            if expected_vendor_opcode.is_none() {
                Self::align_command_response_opcode(&mut packet_to_send, expected_command_opcode);
            }
            match &packet_to_send {
                ControllerToHostPacket::AclData(_) => controller.enqueue_acl_packet(packet_to_send),
                _ => {
                    self.protocol.borrow().as_ref().unwrap().write(&packet_to_send).await?;
                    self.pcap_dumper.controller_to_host(&packet_to_send);
                }
            }
        }
        for packet in &fallback_phase_packets {
            match packet {
                ControllerToHostPacket::AclData(_) => controller.enqueue_acl_packet(packet.clone()),
                _ => {
                    self.protocol.borrow().as_ref().unwrap().write(packet).await?;
                    self.pcap_dumper.controller_to_host(packet);
                }
            }
        }
        for packet in controller.take_sendable_acl_packets() {
            self.protocol.borrow().as_ref().unwrap().write(&packet).await?;
            self.pcap_dumper.controller_to_host(&packet);
        }
        for (idx, packet) in phase_packets.iter().enumerate() {
            let vendor_marked = vendor_marks.get(idx).copied().unwrap_or(false);
            if self.is_mutable_packet(packet, vendor_marked) {
                mutable_sent_cnt = mutable_sent_cnt.saturating_add(1);
            }
        }
        self.protocol.borrow().as_ref().unwrap().finish_phase().await?;
        let mut inner = self.inner.borrow_mut();
        debug!("phase {} sent packets: total={}, mutable={}", phase_idx, phase_packets.len(), mutable_sent_cnt);
        inner.add_round_sent_hci_packets(mutable_sent_cnt);
        inner.phase_move_on();
        Ok(())
    }

    /// API for controller and peer to send reply packet in this phase.
    pub fn send_hci_packet(&self, packet: ControllerToHostPacket) {
        let interact_type = self.interact_type();
        let packet_dbg = format!("{:?}", packet);
        if SimulatorInteractType::BySimulator == interact_type {
            let cur_phase = self.inner.borrow().cur_phase;
            let cur_packet = self.inner.borrow().cur_packet;
            trace!("enqueue packet by simulator: phase={} packet={} kind={}", cur_phase, cur_packet, packet_dbg);
            self.inner.borrow_mut().push_packet(packet);
        } else {
            let cur_phase = self.inner.borrow().cur_phase;
            let cur_packet = self.inner.borrow().cur_packet;
            let is_non_vendor_cmd_response = matches!(
                &packet,
                ControllerToHostPacket::Event(HciEventPkt::CommandComplete(evt))
                    if evt.command_opcode < 0xFC00
            ) || matches!(
                &packet,
                ControllerToHostPacket::Event(HciEventPkt::CommandStatus(evt))
                    if evt.command_opcode < 0xFC00
            );
            if is_non_vendor_cmd_response {
                trace!(
                    "record fallback packet by simulator in fuzz mode: phase={} packet={} kind={}",
                    cur_phase, cur_packet, packet_dbg
                );
                self.inner.borrow_mut().push_fallback_phase_packet(packet);
            } else {
                trace!(
                    "skip enqueue packet by fuzz input: phase={} packet={} kind={}",
                    cur_phase, cur_packet, packet_dbg
                );
            }
        }
        self.inner.borrow_mut().cur_packet += 1;
    }

    /// API to send the SDU from upper layer to the Host via HCI.
    pub fn send_l2cap_bframe(&self, conn_handle: u16, channel_id: u16, payload: Vec<u8>) -> Result<(), L2capError> {
        let l2cap_pkt = L2capBframeEncoder::encode(channel_id, payload)?;
        let hci_pkt = HciAclDataPkt {
            handle: conn_handle,
            packet_boundary_flag: AclPacketBoundaryFlag::ControllerToHostStart,
            broadcast_flag: BroadcastFlag::PointToPoint,
            data_total_length: l2cap_pkt.len() as u16,
            data: l2cap_pkt,
        };
        let hci_packet = ControllerToHostPacket::AclData(hci_pkt);
        self.send_hci_packet(hci_packet);
        Ok(())
    }

    pub fn send_l2cap_cframe(&self, conn_handle: u16, channel_id: u16, payload: L2capInformationPayload) -> Result<(), L2capError> {
        let l2cap_pkt = L2capCframeEncoder::encode(channel_id, payload)?;
        let hci_pkt = HciAclDataPkt {
            handle: conn_handle,
            packet_boundary_flag: AclPacketBoundaryFlag::ControllerToHostStart,
            broadcast_flag: BroadcastFlag::PointToPoint,
            data_total_length: l2cap_pkt.len() as u16,
            data: l2cap_pkt,
        };
        let hci_packet = ControllerToHostPacket::AclData(hci_pkt);
        self.send_hci_packet(hci_packet);
        Ok(())
    }
}

pub enum ReadWithTrackResult {
    Timeout,
    Done(Result<HostToControllerPacket, ProtocolError>),
    ChildExit(io::Result<WaitStatus>),
}

fn is_transport_peer_disconnect(error: &ProtocolError) -> bool {
    match error {
        ProtocolError::TransportFail(TransportError::ReadFail(io_err)) | ProtocolError::TransportFail(TransportError::WriteFail(io_err)) => {
            matches!(
                io_err.kind(),
                io::ErrorKind::BrokenPipe
                    | io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::NotConnected
                    | io::ErrorKind::NotFound
            )
        }
        _ => false,
    }
}

fn is_simulator_peer_disconnect(error: &SimulatorError) -> bool {
    match error {
        SimulatorError::HciError(protocol_err) => is_transport_peer_disconnect(protocol_err),
        _ => false,
    }
}

async fn wait_pid_exit(pid: Pid) -> io::Result<WaitStatus> {
    let mut sigchld = signal(SignalKind::child())?;

    loop {
        // avoid the race that the child exit before we wait for signals
        match waitpid(pid, Some(WaitPidFlag::WNOHANG))? {
            WaitStatus::StillAlive => {}
            status => return Ok(status),
        }
        sigchld.recv().await;
    }
}

async fn read_with_track<'a>(protocol: &'a Box<dyn Protocol>, timeout: Duration, child: Option<Pid>) -> ReadWithTrackResult {
    match child {
        Some(pid) => tokio::select! {
            status = wait_pid_exit(pid) => {
                ReadWithTrackResult::ChildExit(status)
            }
            _ = sleep(timeout) => {
                ReadWithTrackResult::Timeout
            }
            packet = protocol.read() => {
                ReadWithTrackResult::Done(packet)
            }
        },
        None => tokio::select! {
            _ = sleep(timeout) => {
                ReadWithTrackResult::Timeout
            }
            packet = protocol.read() => {
                ReadWithTrackResult::Done(packet)
            }
        },
    }
}
