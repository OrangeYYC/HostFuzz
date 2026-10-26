use crate::{Simulator, SimulatorError, controller::advertising_manager::AdvertisingSet, entity::mesh::MeshEntity};
use aes::Aes128;
use ble::{
    hci::{command::*, event::*, parameter::*, *},
    helper::{set_bit, set_octet_bit},
    input::ExecutionFeedback,
};
use cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use deku::DekuContainerWrite;
use nix::sys::wait::WaitStatus;
use rand::{Rng, SeedableRng, rngs::StdRng};
use std::collections::VecDeque;
use tracing::{debug, error, info, warn};

pub mod advertising_manager;
use advertising_manager::AdvertisingManager;

pub mod connection_manager;
use connection_manager::ConnectionManager;

pub mod filter_accept_list;
use filter_accept_list::FilterAcceptList;
mod iso;

#[derive(Debug)]
pub enum ControllerExitReason {
    Ok,
    Timeout,
    ChildExit(WaitStatus),
}

#[derive(Debug)]
pub enum ControllerError {
    CreateFail,
    InvalidConnection,
    RequestCrash,
    RequestExit,
}

#[derive(Debug, Default)]
struct HostAclFlowControl {
    enabled: bool,
    acl_packet_length: u16,
    total_acl_packets: u16,
    available_acl_packets: u16,
}

impl HostAclFlowControl {
    fn reset(&mut self) {
        *self = Self::default();
    }

    fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
        if !enabled {
            self.available_acl_packets = self.total_acl_packets;
        } else if self.total_acl_packets > 0 && self.available_acl_packets == 0 {
            self.available_acl_packets = self.total_acl_packets;
        }
    }

    fn update_host_buffer_size(&mut self, packet_length: u16, total_acl_packets: u16) {
        self.acl_packet_length = packet_length;
        self.total_acl_packets = total_acl_packets;
        self.available_acl_packets = total_acl_packets;
    }

    fn can_send_acl(&self) -> bool {
        !self.enabled || self.available_acl_packets > 0
    }

    fn note_acl_sent(&mut self) {
        if self.enabled && self.available_acl_packets > 0 {
            self.available_acl_packets -= 1;
        }
    }

    fn reclaim_completed(&mut self, completed: u16) {
        if !self.enabled {
            return;
        }
        self.available_acl_packets = self.available_acl_packets.saturating_add(completed).min(self.total_acl_packets);
    }
}

#[derive(Debug, Clone, Copy)]
struct PendingCisRequest {
    acl_handle: u16,
    cis_handle: u16,
}

#[derive(Debug, Clone, Copy)]
struct ActiveCisStream {
    acl_handle: u16,
    cis_handle: u16,
    rx_path_ready: bool,
}

#[derive(Debug, Default)]
struct IsoSessionState {
    host_iso_initialized: bool,
    pending_request: Option<PendingCisRequest>,
    active_stream: Option<ActiveCisStream>,
    gated_acl_for_request: Option<u16>,
    gated_acl_idle_rounds: u8,
}

impl IsoSessionState {
    fn reset(&mut self) {
        *self = Self::default();
    }

    fn mark_host_iso_initialized(&mut self) {
        self.host_iso_initialized = true;
    }

    fn can_initiate_request(&self) -> bool {
        self.host_iso_initialized && self.pending_request.is_none() && self.active_stream.is_none()
    }

    fn bind_pending_request(&mut self, acl_handle: u16, cis_handle: u16) {
        self.gated_acl_for_request = None;
        self.gated_acl_idle_rounds = 0;
        self.pending_request = Some(PendingCisRequest { acl_handle, cis_handle });
    }

    fn mark_established(&mut self, pending: PendingCisRequest) {
        self.pending_request = None;
        self.active_stream = Some(ActiveCisStream {
            acl_handle: pending.acl_handle,
            cis_handle: pending.cis_handle,
            rx_path_ready: false,
        });
    }

    fn clear_pending_for_acl(&mut self, acl_handle: u16) {
        if self.pending_request.is_some_and(|req| req.acl_handle == acl_handle) {
            self.pending_request = None;
        }
    }

    fn clear_stream_for_acl(&mut self, acl_handle: u16) {
        if self.active_stream.is_some_and(|stream| stream.acl_handle == acl_handle) {
            self.active_stream = None;
        }
    }

    fn take_gated_request_on_acl_rx(&mut self, acl_handle: u16) -> bool {
        if self.gated_acl_for_request == Some(acl_handle) {
            self.gated_acl_for_request = None;
            self.gated_acl_idle_rounds = 0;
            return true;
        }
        false
    }

    fn take_gated_request_on_idle_fallback(&mut self, idle_limit_rounds: u8) -> Option<u16> {
        let acl_handle = self.gated_acl_for_request?;
        self.gated_acl_idle_rounds = self.gated_acl_idle_rounds.saturating_add(1);
        if self.gated_acl_idle_rounds < idle_limit_rounds {
            return None;
        }
        self.gated_acl_for_request = None;
        self.gated_acl_idle_rounds = 0;
        Some(acl_handle)
    }

    fn clear_gate_for_acl(&mut self, acl_handle: u16) {
        if self.gated_acl_for_request == Some(acl_handle) {
            self.gated_acl_for_request = None;
            self.gated_acl_idle_rounds = 0;
        }
    }
}

#[derive(Debug)]
struct PeriodicAdvSessionState {
    sync_handle: u16,
    sync_established: bool,
    past_received_emitted: bool,
    reports_sent: u16,
    discovery_enabled: bool,
    create_sync_requested: bool,
    past_transfer_enabled: bool,
    advertising_sid: u8,
    advertiser_address_type: AddrKind,
    advertiser_address: BdAddr,
    periodic_interval: u16,
}

impl Default for PeriodicAdvSessionState {
    fn default() -> Self {
        Self {
            sync_handle: 0x0040,
            sync_established: false,
            past_received_emitted: false,
            reports_sent: 0,
            discovery_enabled: false,
            create_sync_requested: false,
            past_transfer_enabled: false,
            advertising_sid: 0x01,
            advertiser_address_type: AddrKind::Public,
            advertiser_address: BdAddr {
                addr: [0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6],
            },
            periodic_interval: 0x00C8,
        }
    }
}

impl PeriodicAdvSessionState {
    fn reset(&mut self) {
        *self = Self::default();
    }
}

/// virtual BLE controller
pub struct Controller<'a> {
    /// Parent simulator
    simulator: &'a Simulator,
    /// RNG of the controller
    rng: StdRng,
    /// Local name of the controller
    local_name: String,
    /// Version information of the controller
    local_version_information: ReadLocalVersionInformationReturn,
    /// Indicats if the controller has been reset
    reset_once: bool,
    /// Filter Accept List of the controller
    filter_accept_list: FilterAcceptList,
    /// Advertising manager
    advertising_manager: AdvertisingManager,
    /// Connection manager
    connection_manager: ConnectionManager<'a>,
    /// Advertising enabled (created using legacy advertising commands)
    legacy_advertising_enabled: bool,
    /// Parameters for legacy advertising
    advertising_parameters: AdvertisingParameters,
    advertising_data: Vec<u8>,
    /// Scanning enabled
    scanning_enabled: bool,
    /// Public device address of the controller
    public_device_address: [u8; 6],
    /// Random adderess of the controller
    random_device_address: Option<[u8; 6]>,
    /// Event mask for events
    event_mask: EventMask,
    /// Event mask for LE Meta Events
    le_event_mask: LeEventMask,
    /// Runtime execution feedback for version mutation strategy
    execution_feedback: ExecutionFeedback,
    /// Number of ACL packets handled in this run
    acl_rx_count: u32,
    /// Host-advertised ACL credits for controller->host traffic.
    host_acl_flow: HostAclFlowControl,
    /// Controller->host ACL packets waiting for host credits.
    pending_acl_packets: VecDeque<ControllerToHostPacket>,
    /// One-shot fallback that synthesizes an inbound connection after prolonged idle.
    idle_peer_bootstrap_done: bool,
    /// Generic CIS/ISO session progression state.
    iso_session: IsoSessionState,
    /// Generic periodic advertising event progression state.
    periodic_adv_session: PeriodicAdvSessionState,
    /// Mesh interaction state used by synthetic scan probing.
    mesh_entity: MeshEntity<'a>,
    /// Disable advertising-command capability bits for extended advertising in
    /// Read Local Supported Commands while still allowing extended events.
    disable_ext_adv_command_support: bool,
}

impl<'a> Controller<'a> {
    fn parse_bool_env(key: &str) -> bool {
        std::env::var(key)
            .ok()
            .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
            .unwrap_or(false)
    }

    pub(crate) fn command_opcode(packet: &HciCommandPkt) -> u16 {
        let bytes = packet.to_bytes().expect("failed to serialize HCI command packet");
        u16::from_le_bytes([bytes[0], bytes[1]])
    }

    // fn send_random_floor_response(&mut self, opcode: u16) {
    //     const STATUS_POOL: [u8; 8] = [0x00, 0x01, 0x05, 0x07, 0x0C, 0x12, 0x1A, 0x3B];

    //     let status = STATUS_POOL[self.rng.gen_range(0..STATUS_POOL.len())];
    //     if self.rng.gen_bool(0.35) {
    //         self.send_hci_event_packet(CommandStatusEvent::cmd_status(opcode, status));
    //         return;
    //     }

    //     let mut ret = vec![status];
    //     let extra_len = self.rng.gen_range(0..=8);
    //     for _ in 0..extra_len {
    //         ret.push(self.rng.gen_range(0..=u8::MAX));
    //     }
    //     self.send_hci_event_packet(CommandCompleteEvent::cmd_ret(opcode, ret));
    // }

    fn zephyr_vs_static_addr(&self) -> [u8; 6] {
        // Zephyr host treats BT_HCI_OP_VS_READ_STATIC_ADDRS entries as random static
        // identities. Returning an all-zero/non-static value can stall host init.
        let mut addr = self.random_device_address.unwrap_or([0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6]);
        if addr.iter().all(|v| *v == 0) {
            addr = [0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6];
        }
        // BT_ADDR_IS_STATIC checks the top two bits of the most significant octet.
        addr[5] = (addr[5] & 0x3F) | 0xC0;
        addr
    }

    pub async fn new(simulator: &'a Simulator) -> Self {
        let disable_ext_adv_command_support = Self::parse_bool_env("VIRTBLE_DISABLE_EXT_ADV_COMMAND_SUPPORT");
        if disable_ext_adv_command_support {
            debug!("disable ext-adv command support by VIRTBLE_DISABLE_EXT_ADV_COMMAND_SUPPORT");
        }
        let local_version_information = {
            let version = simulator.current_local_version_information();
            ReadLocalVersionInformationReturn {
                hci_version: version.hci_version,
                hci_subversion: version.hci_subversion,
                lmp_version: version.lmp_version,
                company_identifier: version.company_identifier,
                lmp_subversion: version.lmp_subversion,
            }
        };
        Self {
            simulator,
            rng: StdRng::seed_from_u64(0xdead_beef),
            reset_once: false,
            local_name: String::from("virtble_controller"),
            local_version_information,
            filter_accept_list: FilterAcceptList::default(),
            advertising_manager: AdvertisingManager::new(),
            connection_manager: ConnectionManager::new(),
            legacy_advertising_enabled: false,
            advertising_parameters: AdvertisingParameters::default(),
            advertising_data: Vec::new(),
            scanning_enabled: false,
            public_device_address: simulator.public_device_address(),
            random_device_address: None,
            event_mask: EventMask::default(),
            le_event_mask: LeEventMask::default(),
            execution_feedback: ExecutionFeedback::default(),
            acl_rx_count: 0,
            host_acl_flow: HostAclFlowControl::default(),
            pending_acl_packets: VecDeque::new(),
            idle_peer_bootstrap_done: false,
            iso_session: IsoSessionState::default(),
            periodic_adv_session: PeriodicAdvSessionState::default(),
            mesh_entity: MeshEntity::new(simulator),
            disable_ext_adv_command_support,
        }
    }

    pub fn execution_feedback(&self, timed_out: bool) -> ExecutionFeedback {
        let mut feedback = self.execution_feedback.clone();
        feedback.timed_out = timed_out;
        feedback
    }

    pub fn should_early_exit(&self) -> bool {
        let max_acl_packets = self.simulator.max_acl_packets_per_round();
        max_acl_packets > 0 && self.acl_rx_count >= max_acl_packets
    }

    /// Fallback bootstrap for server-style targets that become HCI-idle after init.
    /// When no connection exists yet, synthesize one inbound LE connection so ATT/SMP
    /// interaction can start without requiring app-specific shell triggers.
    pub fn try_idle_peer_bootstrap(&mut self) -> Result<bool, ControllerError> {
        if self.idle_peer_bootstrap_done {
            return Ok(false);
        }
        if !self.simulator.ablation_flags().enable_dynamic_peer_creation {
            return Ok(false);
        }
        // Keep bootstrap focused on server-style targets. Scanner-style apps
        // should progress via scan reports instead of synthetic inbound links.
        if self.scanning_enabled {
            return Ok(false);
        }
        if !self.legacy_advertising_enabled && !self.advertising_manager.has_enabled() {
            return Ok(false);
        }
        if !self.connection_manager.is_empty() {
            self.idle_peer_bootstrap_done = true;
            return Ok(false);
        }
        if !self.reset_once {
            return Ok(false);
        }

        let peer_address_type = AddrKind::Public;
        let peer_address = BdAddr {
            addr: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
        };
        let (local_addr, local_addr_type) = self.initiator_address_context(self.advertising_parameters.own_address_type.clone());
        let connection_handle = self.connection_manager.create_connection(
            self.simulator,
            peer_address.clone(),
            peer_address_type.clone(),
            local_addr,
            local_addr_type,
            false,
        )?;

        self.idle_peer_bootstrap_done = true;
        if connection_handle == 0xFFFF {
            return Ok(false);
        }

        info!(
            "idle peer bootstrap created inbound connection: handle=0x{:04x} peer={} type={}",
            connection_handle, peer_address, peer_address_type
        );
        self.simulator.note_connection_handle(connection_handle);
        self.simulator.telemetry_mark_peer_created();
        self.execution_feedback.entered_connection_state = true;
        self.simulator.telemetry_mark_connection();

        if self.le_event_mask.enabled(LeEventMaskBit::LeConnectionComplete) {
            self.send_hci_event_packet(
                LeConnectionCompleteEvent {
                    status: 0x0,
                    connection_handle,
                    role: LeConnRole::Peripheral,
                    peer_address_type: peer_address_type.clone(),
                    peer_address: peer_address.clone(),
                    connection_interval: Duration::<1_250>(24),
                    peripheral_latency: 0x0,
                    supervision_timeout: Duration(0x0c80),
                    central_clock_accuracy: 0x07,
                }
                .into(),
            );
        }

        if !self.iso_session.host_iso_initialized {
            self.start_peer_interaction_for_acl(connection_handle);
        }
        self.maybe_send_cis_request_for_acl(connection_handle);
        Ok(true)
    }

    /// On idle timeout, let existing peers emit follow-up interaction packets.
    pub fn try_idle_peer_progress(&mut self) -> Result<bool, ControllerError> {
        let mut progressed = false;

        if self.connection_manager.is_empty() {
            if self.maybe_emit_periodic_adv_idle_events(false) {
                progressed = true;
                self.execution_feedback.entered_scanning_state = true;
                self.simulator.telemetry_mark_scanning();
            }
            return Ok(progressed);
        }

        progressed = self.connection_manager.drive_idle_peers();
        if self.maybe_send_gated_cis_request_on_idle() {
            progressed = true;
        }
        if self.iso_session.active_stream.is_some() && self.prob(25) {
            self.maybe_send_iso_rx_probe_packet();
            progressed = true;
        }
        if self.maybe_emit_periodic_adv_idle_events(false) {
            progressed = true;
            self.execution_feedback.entered_scanning_state = true;
            self.simulator.telemetry_mark_scanning();
        }
        if progressed {
            debug!("idle peer progress generated follow-up packets");
            self.execution_feedback.entered_connection_state = true;
            self.simulator.telemetry_mark_connection();
        }
        Ok(progressed)
    }

    pub fn send_hci_event_packet(&self, packet: HciEventPkt) {
        let packet = ControllerToHostPacket::Event(packet);
        self.simulator.send_hci_packet(packet)
    }

    pub fn enqueue_acl_packet(&mut self, packet: ControllerToHostPacket) {
        debug_assert!(matches!(packet, ControllerToHostPacket::AclData(_)));
        self.pending_acl_packets.push_back(packet);
    }

    pub fn take_sendable_acl_packets(&mut self) -> Vec<ControllerToHostPacket> {
        let mut ready = Vec::new();
        while self.host_acl_flow.can_send_acl() {
            let Some(packet) = self.pending_acl_packets.pop_front() else {
                break;
            };
            self.host_acl_flow.note_acl_sent();
            ready.push(packet);
        }
        ready
    }

    fn drop_pending_acl_for_handle(&mut self, conn_handle: u16) {
        self.pending_acl_packets.retain(|packet| {
            matches!(packet, ControllerToHostPacket::AclData(pkt) if pkt.handle != conn_handle) || !matches!(packet, ControllerToHostPacket::AclData(_))
        });
    }

    fn should_emit_le_event(&self, bit: LeEventMaskBit) -> bool {
        self.le_event_mask.enabled(bit)
    }

    fn build_periodic_adv_report_payload(&mut self) -> Vec<u8> {
        let mut ad_data = vec![
            0x02, 0x01, 0x06, // flags
            0x03, 0x03, 0x0D, 0x18, // complete 16-bit UUIDs
            0x05, 0x16, 0x0D, 0x18, 0x34, 0x12, // service data
        ];
        if self.prob(40) {
            ad_data.push(self.rng.r#gen());
        }
        if ad_data.len() > usize::from(u8::MAX) {
            ad_data.truncate(usize::from(u8::MAX));
        }

        let declared_len = ad_data.len();

        let mut payload = Vec::with_capacity(7 + ad_data.len());
        payload.extend_from_slice(&self.periodic_adv_session.sync_handle.to_le_bytes());
        payload.push(0x00); // tx_power
        payload.push(0xC4); // rssi (-60 dBm)
        payload.push(0x00); // cte_type
        payload.push(0x00); // data_status: complete
        payload.push(declared_len as u8);
        payload.extend_from_slice(&ad_data);
        payload
    }

    fn maybe_emit_periodic_adv_idle_events(&mut self, force_report: bool) -> bool {
        let conn_handle = self.connection_manager.first_handle();
        let allow_sync_evt = self.should_emit_le_event(LeEventMaskBit::LePeriodicAdvertisingSyncEstablished);
        let allow_report_evt = self.should_emit_le_event(LeEventMaskBit::LePeriodicAdvertisingReport);
        let allow_past_evt = self.should_emit_le_event(LeEventMaskBit::LePastReceived);
        let interaction_enabled =
            self.periodic_adv_session.discovery_enabled || self.periodic_adv_session.create_sync_requested || self.periodic_adv_session.past_transfer_enabled;
        if !interaction_enabled {
            return false;
        }
        info!(
            "periodic adv idle check: force={} conn_handle={:?} mask_sync={} mask_report={} mask_past={} discovery={} create_sync={} past_transfer={} sync_established={} past_emitted={}",
            force_report,
            conn_handle,
            allow_sync_evt,
            allow_report_evt,
            allow_past_evt,
            self.periodic_adv_session.discovery_enabled,
            self.periodic_adv_session.create_sync_requested,
            self.periodic_adv_session.past_transfer_enabled,
            self.periodic_adv_session.sync_established,
            self.periodic_adv_session.past_received_emitted
        );
        if !allow_sync_evt && !allow_report_evt && !allow_past_evt {
            return false;
        }

        let mut emitted = false;
        if !self.periodic_adv_session.sync_established {
            let mut established_from_past = false;
            if let Some(connection_handle) = conn_handle {
                if !self.periodic_adv_session.past_received_emitted
                    && self.periodic_adv_session.past_transfer_enabled
                    && allow_past_evt
                    && (force_report || self.prob(65))
                {
                    info!(
                        "periodic adv PAST-received injected: conn=0x{:04x} sync=0x{:04x}",
                        connection_handle, self.periodic_adv_session.sync_handle
                    );
                    self.send_hci_event_packet(
                        LePastReceivedEvent {
                            status: 0x00,
                            conn_handle: connection_handle,
                            service_data: 0x0000,
                            sync_handle: self.periodic_adv_session.sync_handle,
                            advertising_sid: self.periodic_adv_session.advertising_sid,
                            advertiser_address_type: self.periodic_adv_session.advertiser_address_type,
                            advertiser_address: self.periodic_adv_session.advertiser_address,
                            advertiser_phy: 0x01,
                            periodic_advertising_interval: self.periodic_adv_session.periodic_interval,
                            advertiser_clock_accuracy: 0x00,
                        }
                        .into(),
                    );
                    self.periodic_adv_session.sync_established = true;
                    self.periodic_adv_session.past_received_emitted = true;
                    established_from_past = true;
                    emitted = true;
                }
            }
            if !established_from_past && self.periodic_adv_session.create_sync_requested && allow_sync_evt {
                info!(
                    "periodic adv sync established injected: handle=0x{:04x} (mask_sync={}, mask_report={}, force={})",
                    self.periodic_adv_session.sync_handle, allow_sync_evt, allow_report_evt, force_report
                );
                self.send_hci_event_packet(
                    LePeriodicAdvertisingSyncEstablishedEvent {
                        status: 0x00,
                        sync_handle: self.periodic_adv_session.sync_handle,
                        advertising_sid: self.periodic_adv_session.advertising_sid,
                        advertiser_address_type: self.periodic_adv_session.advertiser_address_type,
                        advertiser_address: self.periodic_adv_session.advertiser_address,
                        advertiser_phy: 0x01,
                        periodic_advertising_interval: self.periodic_adv_session.periodic_interval,
                        advertiser_clock_accuracy: 0x00,
                    }
                    .into(),
                );
                self.periodic_adv_session.sync_established = true;
                emitted = true;
            }
        }

        let should_emit_report = force_report || self.prob(45);
        if self.periodic_adv_session.sync_established && allow_report_evt && should_emit_report {
            let payload = self.build_periodic_adv_report_payload();
            let declared_len = payload.get(6).copied().unwrap_or(0);
            info!(
                "periodic adv report injected: handle=0x{:04x} declared_len={} payload_len={}",
                self.periodic_adv_session.sync_handle,
                declared_len,
                payload.len()
            );
            self.send_hci_event_packet(LePeriodicAdvertisingReportEvent::new(payload));
            self.periodic_adv_session.reports_sent = self.periodic_adv_session.reports_sent.saturating_add(1);
            emitted = true;
        }
        emitted
    }

    #[inline]
    fn prob(&mut self, prob: usize) -> bool {
        self.rng.gen_range(0..100) < prob
    }

    pub async fn handle_hci_packet(&mut self, packet: HostToControllerPacket) -> Result<(), SimulatorError> {
        match packet {
            HostToControllerPacket::Command(p) => self.handle_hci_command_packet(&p).await?,
            HostToControllerPacket::AclData(p) => self.handle_hci_acl_data_packet(&p).await?,
            HostToControllerPacket::SyncData(p) => self.handle_hci_sync_data_packet(&p).await?,
            HostToControllerPacket::IsoData(p) => self.handle_hci_iso_data_packet(&p).await?,
        }
        Ok(())
    }

    async fn handle_hci_acl_data_packet(&mut self, packet: &HciAclDataPkt) -> Result<(), SimulatorError> {
        self.acl_rx_count = self.acl_rx_count.saturating_add(1);
        self.maybe_send_gated_cis_request_on_acl_rx(packet.handle);

        // complete this acl data packet
        self.send_hci_event_packet(NumberOfCompletetedPacketsEvent::packet_ack(packet.handle, 0x1));

        // find the connection and let the peer to handle the packet
        match self.connection_manager.get_connection_mut(packet.handle) {
            Some(peer) => {
                peer.handle_acl_data_pkt(packet)?;
                Ok(())
            }
            None => {
                // Keep unknown ACL handles non-fatal. Some hosts may emit stale/default
                // handles during role transitions; hard-failing here truncates the round
                // and prevents later semantic phases from being explored.
                warn!(
                    "drop ACL packet for unknown connection handle: 0x{:04x} (len={})",
                    packet.handle,
                    packet.data.len()
                );
                Ok(())
            }
        }
    }

    async fn handle_hci_sync_data_packet(&mut self, packet: &HciSyncDataPkt) -> Result<(), ControllerError> {
        debug!("handle sync data packet: {:?}", packet);
        Ok(())
    }

    async fn handle_hci_iso_data_packet(&mut self, packet: &HciIsoDataPkt) -> Result<(), ControllerError> {
        debug!("handle iso data packet: {:?}", packet);
        Ok(())
    }

    /// dispatches hci commands to its handler
    async fn handle_hci_command_packet(&mut self, packet: &HciCommandPkt) -> Result<(), ControllerError> {
        if self.simulator.ablation_flags().enable_random_hci_floor {
            // self.send_random_floor_response(Self::command_opcode(packet));
            self.send_hci_event_packet(CommandCompleteEvent::cmd_ack(Self::command_opcode(packet)));
            return Ok(());
        }
        match packet {
            // Vendor
            HciCommandPkt::Vendor { id, payload } => self.on_vendor(*id, payload).await,
            // M
            HciCommandPkt::LeAddDeviceToFilterAcceptList(cmd) => self.on_le_add_device_to_filter_accept_list(cmd),
            HciCommandPkt::LeClearFilterAcceptList(_) => self.on_le_clear_filter_accept_list(),
            HciCommandPkt::LeReadFilterAcceptListSize(_) => self.on_le_read_filter_accept_list_size(),
            HciCommandPkt::LeReadLocalSupportedFeatures(_) => self.on_le_read_local_supported_features(),
            HciCommandPkt::LeReadSupportedStates(_) => self.on_le_read_supported_states(),
            HciCommandPkt::LeRemoveDeviceFromFilterAcceptList(cmd) => self.on_le_remove_device_from_filter_accept_list(cmd),
            HciCommandPkt::LeSetEventMask(cmd) => self.on_le_set_event_mask(cmd),
            HciCommandPkt::ReadBdAddr(_) => self.on_read_bd_addr(),
            HciCommandPkt::ReadLocalSupportedCommands(_) => self.on_read_local_supported_commands(),
            HciCommandPkt::ReadLocalSupportedFeatures(_) => self.on_read_local_supported_features(),
            HciCommandPkt::ReadLocalVersionInformation(_) => self.on_read_local_version_information(),
            HciCommandPkt::Reset(_) => self.on_reset(),
            HciCommandPkt::SetEventMask(cmd) => self.on_set_event_mask(cmd),
            // C1
            HciCommandPkt::LeSetRandomAddress(cmd) => self.on_le_set_random_address(cmd),
            // C3
            HciCommandPkt::Disconnect(cmd) => self.on_disconnect(cmd),
            HciCommandPkt::LeConnectionUpdate(cmd) => self.on_le_connection_update(cmd),
            HciCommandPkt::LeReadChannelMap(cmd) => self.on_le_read_channel_map(cmd),
            HciCommandPkt::LeReadRemoteFeatures(cmd) => self.on_le_read_remote_features(cmd),
            HciCommandPkt::ReadRemoteVersionInformation(cmd) => self.on_read_remote_version_information(cmd),
            HciCommandPkt::ReadRssi(cmd) => self.on_read_rssi(cmd),
            HciCommandPkt::ReadTransmitPowerLevel(cmd) => self.on_read_transmit_power_level(cmd),
            HciCommandPkt::LeReadBufferSizeV1(_) => self.on_le_read_buffer_size_v1(),
            // C4
            HciCommandPkt::LeEncrypt(cmd) => self.on_le_encrypt(cmd),
            HciCommandPkt::LeRand(_) => self.on_le_rand(),
            HciCommandPkt::LeStartEncryption(cmd) => self.on_le_start_encryption(cmd),
            HciCommandPkt::LeLongTermKeyRequestReply(cmd) => self.on_le_long_term_key_request_reply(cmd),
            HciCommandPkt::LeLongTermKeyRequestNegativeReply(cmd) => self.on_le_long_term_key_request_negative_reply(cmd),
            // C8
            HciCommandPkt::LeReadMaximumDataLength(_) => self.on_le_read_maximum_data_length(),
            HciCommandPkt::LeReadSuggestedDefaultDataLength(_) => self.on_le_read_suggested_default_data_length(),
            HciCommandPkt::LeSetDataLength(cmd) => self.on_le_set_data_length(cmd),
            HciCommandPkt::LeWriteSuggestedDefaultDataLength(cmd) => self.on_le_write_suggested_default_data_length(cmd),
            HciCommandPkt::LeReadLocalP256PublicKey(_) => self.on_le_read_local_p256_public_key(),
            // C9
            HciCommandPkt::LeAddDeviceToResolvingList(cmd) => self.on_le_add_device_to_resolving_list(cmd),
            HciCommandPkt::LeClearResolvingList(_) => self.on_le_clear_resolving_list(),
            HciCommandPkt::LeReadResolvingListSize(_) => self.on_le_read_resolving_size(),
            HciCommandPkt::LeSetAddressResolutionEnable(cmd) => self.on_le_set_address_resolution_enable(cmd),
            HciCommandPkt::LeSetResolvablePrivateAddressTimeout(cmd) => self.on_le_set_resolvable_private_address_timeout(cmd),
            // C11
            HciCommandPkt::LeSetDefaultPhy(cmd) => self.on_le_set_default_phy(cmd),
            HciCommandPkt::LeSetPhy(cmd) => self.on_le_set_phy(cmd),
            // C15
            HciCommandPkt::LeSetScanResponseData(cmd) => self.on_le_set_scan_response_data(cmd),
            // C17
            HciCommandPkt::LeClearAdvertisingSets(_) => self.on_le_clear_advertising_sets(),
            HciCommandPkt::LeReadMaximumAdvertisingDataLength(_) => self.on_le_read_maximum_advertising_data_length(),
            HciCommandPkt::LeReadNumberOfSupportedAdvertisingSets(_) => self.on_le_read_number_of_supported_advertising_sets(),
            HciCommandPkt::LeRemoveAdvertisingSet(cmd) => self.on_le_remove_advertising_set(cmd),
            HciCommandPkt::LeSetAdvertisingSetRandomAddress(cmd) => self.on_le_set_advertising_set_random_address(cmd),
            HciCommandPkt::LeSetExtendedAdvertisingData(cmd) => self.on_le_set_extended_advertising_data(cmd),
            HciCommandPkt::LeSetExtendedAdvertisingEnable(cmd) => self.on_le_set_extended_advertising_enable(cmd),
            HciCommandPkt::LeSetExtendedScanResponseData(cmd) => self.on_le_set_extended_scan_response_data(cmd),
            // C19
            HciCommandPkt::LeSetExtendedScanEnable(cmd) => self.on_le_set_extended_scan_enable(cmd),
            HciCommandPkt::LeSetExtendedScanParameters(cmd) => self.on_le_set_extended_scan_paramters(cmd),
            HciCommandPkt::LePerAdvCreateSync(cmd) => self.on_le_per_adv_create_sync(cmd),
            HciCommandPkt::LePerAdvCreateSyncCancel(_) => self.on_le_per_adv_create_sync_cancel(),
            HciCommandPkt::LePerAdvTerminateSync(cmd) => self.on_le_per_adv_terminate_sync(cmd),
            // C47
            HciCommandPkt::LePerAdvSyncTransfer(cmd) => self.on_le_per_adv_sync_transfer(cmd),
            HciCommandPkt::LePerAdvSetInfoTransfer(cmd) => self.on_le_per_adv_set_info_transfer(cmd),
            HciCommandPkt::LePastParam(cmd) => self.on_le_past_param(cmd),
            HciCommandPkt::LeDefaultPastParam(cmd) => self.on_le_default_past_param(cmd),
            // C49
            HciCommandPkt::LeSetHostFeature(cmd) => self.on_le_set_host_feature(cmd),
            // C55
            HciCommandPkt::LeReadBufferSizeV2(_) => self.on_le_read_buffer_size_v2(),
            HciCommandPkt::LeAcceptCis(cmd) => self.on_le_accept_cis(cmd),
            HciCommandPkt::LeRejectCis(cmd) => self.on_le_reject_cis(cmd),
            HciCommandPkt::LeSetupIsoPath(cmd) => self.on_le_setup_iso_path(cmd),
            HciCommandPkt::LeRemoveIsoPath(cmd) => self.on_le_remove_iso_path(cmd),
            // C59
            HciCommandPkt::LeCreateConnection(cmd) => self.on_le_create_connection(cmd),
            // C64
            HciCommandPkt::LeReadTransmitPower(_) => self.on_le_read_transmit_power(),
            // C65
            HciCommandPkt::LeSetExtendedAdvertisingParametersV1(cmd) => self.on_le_set_extended_advertising_parameters_v1(cmd),
            // C66
            HciCommandPkt::LeSetExtendedAdvertisingParametersV2(cmd) => self.on_le_set_extended_advertising_parameters_v2(cmd),
            // C96
            HciCommandPkt::SetControllerToHostFlowControl(cmd) => self.on_set_controller_to_host_flow_control(cmd),
            HciCommandPkt::WriteLeHostSupport(cmd) => self.on_write_le_host_support(cmd),
            // C97
            HciCommandPkt::LeSetAdvertisingData(cmd) => self.on_le_set_advertising_data(cmd),
            HciCommandPkt::LeSetAdvertisingEnable(cmd) => self.on_le_set_advertising_enable(cmd),
            HciCommandPkt::LeSetAdvertisingParameters(cmd) => self.on_le_set_advertising_parameters(cmd),
            HciCommandPkt::LeReadAdvertisingChannelTxPower(_) => self.on_le_read_advertising_channel_tx_power(),
            // C98
            HciCommandPkt::LeSetScanEnable(cmd) => self.on_le_set_scan_enable(cmd),
            HciCommandPkt::LeSetScanParameters(cmd) => self.on_le_set_scan_parameters(cmd),
            // C107
            HciCommandPkt::HostBufferSize(cmd) => self.on_host_buffer_size(cmd),
            HciCommandPkt::HostNumberOfCompletePackets(cmd) => self.on_host_number_of_complete_packets(cmd),
            // Other
            HciCommandPkt::ReadLocalExtendedFeatures(cmd) => self.on_read_local_extended_features(cmd),
            HciCommandPkt::ReadBufferSize(_) => self.on_read_buffer_size(),
            HciCommandPkt::ReadLocalName(_) => self.on_read_local_name(),
        }
    }

    async fn on_vendor(&mut self, opcode: u16, payload: &Vec<u8>) -> Result<(), ControllerError> {
        let ogf = opcode >> 10;
        let ocf = opcode & 0b1111111111;
        debug!("[HCI CMD] vendor opcode: 0x{:04x} OGF=0x{:02x} OCF=0x{:04x}", opcode, ogf, ocf,);
        debug!("   in: {}", hex::encode_upper(payload));
        self.simulator.telemetry_note_vendor_hci_seen(opcode);

        // for P0, we don't reply vendor HCI commands
        if !self.simulator.ablation_flags().enable_vendor_hci_contract {
            return Ok(());
        }

        // Zephyr/Babblesim VS command emulation.
        match opcode {
            // BT_HCI_OP_VS_READ_VERSION_INFO
            0xFC01 => {
                let mut body = Vec::with_capacity(12);
                body.extend_from_slice(&0x0002u16.to_le_bytes()); // hw_platform: Nordic
                body.extend_from_slice(&0x0002u16.to_le_bytes()); // hw_variant: nRF52x
                body.push(0x00); // fw_variant: Standard Bluetooth controller
                body.push(0x04); // fw_version
                body.extend_from_slice(&0x0000u16.to_le_bytes()); // fw_revision
                body.extend_from_slice(&0x0000u32.to_le_bytes()); // fw_build
                self.simulator.telemetry_note_vendor_hci_specialized_response(opcode);
                self.send_hci_event_packet(CommandCompleteEvent::cmd_ret(opcode, body));
                return Ok(());
            }
            // BT_HCI_OP_VS_READ_SUPPORTED_COMMANDS
            0xFC02 => {
                let mut commands = [0u8; 64];
                // version / supported-commands / supported-features / write-bd-addr / read-build-info
                commands[0] |= (1 << 0) | (1 << 1) | (1 << 2);
                commands[0] |= (1 << 5) | (1 << 7);
                // read-static-addrs / read-key-hierarchy-roots
                commands[1] |= (1 << 0) | (1 << 1);
                self.simulator.telemetry_note_vendor_hci_specialized_response(opcode);
                self.send_hci_event_packet(CommandCompleteEvent::cmd_ret(opcode, commands.to_vec()));
                return Ok(());
            }
            // BT_HCI_OP_VS_READ_SUPPORTED_FEATURES
            0xFC03 => {
                let features = [0u8; 8];
                self.simulator.telemetry_note_vendor_hci_specialized_response(opcode);
                self.send_hci_event_packet(CommandCompleteEvent::cmd_ret(opcode, features.to_vec()));
                return Ok(());
            }
            // BT_HCI_OP_VS_WRITE_BD_ADDR
            0xFC06 => {
                if payload.len() == 6 {
                    self.public_device_address.copy_from_slice(&payload[..6]);
                }
                self.simulator.telemetry_note_vendor_hci_specialized_response(opcode);
                self.send_hci_event_packet(CommandCompleteEvent::cmd_ack(opcode));
                return Ok(());
            }
            // BT_HCI_OP_VS_READ_BUILD_INFO
            0xFC08 => {
                let mut body = Vec::new();
                body.extend_from_slice(b"VirtBLE Zephyr-HCIIPC");
                body.push(0);
                self.simulator.telemetry_note_vendor_hci_specialized_response(opcode);
                self.send_hci_event_packet(CommandCompleteEvent::cmd_ret(opcode, body));
                return Ok(());
            }
            // BT_HCI_OP_VS_READ_STATIC_ADDRS
            0xFC09 => {
                let mut body = Vec::with_capacity(23);
                body.push(1); // num_addrs
                body.extend_from_slice(&self.zephyr_vs_static_addr());
                body.extend_from_slice(&[0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F]);
                self.simulator.telemetry_note_vendor_hci_specialized_response(opcode);
                self.send_hci_event_packet(CommandCompleteEvent::cmd_ret(opcode, body));
                return Ok(());
            }
            // BT_HCI_OP_VS_READ_KEY_HIERARCHY_ROOTS
            0xFC0A => {
                let mut body = Vec::with_capacity(32);
                body.extend_from_slice(&[0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30]);
                body.extend_from_slice(&[0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40]);
                self.simulator.telemetry_note_vendor_hci_specialized_response(opcode);
                self.send_hci_event_packet(CommandCompleteEvent::cmd_ret(opcode, body));
                return Ok(());
            }
            // Xiaomi OTA/vendor paths can issue FF00 with private payload schema.
            // Returning a short success payload avoids status-only parse issues on some firmwares.
            0xFF00 => {
                let mut ret = if payload.is_empty() {
                    vec![0x07, 0x01, 0x17, 0x00, 0x64, 0x4F, 0x01, 0x00]
                } else {
                    payload.clone()
                };
                if ret.len() > 16 {
                    ret.truncate(16);
                }
                self.simulator.telemetry_note_vendor_hci_specialized_response(opcode);
                self.send_hci_event_packet(CommandCompleteEvent::cmd_ret(opcode, ret));
                return Ok(());
            }
            // Common Xiaomi vendor polling command used after FF00.
            // Return a compact "done" style payload.
            0xFF02 => {
                let ret = vec![0x00, 0x00, 0x00, 0x00, 0x00];
                self.simulator.telemetry_note_vendor_hci_specialized_response(opcode);
                self.send_hci_event_packet(CommandCompleteEvent::cmd_ret(opcode, ret));
                return Ok(());
            }
            _ => {}
        }

        // hack for ESP32
        if opcode == 0xfd0a && self.scanning_enabled && self.simulator.ablation_flags().enable_targeted_scan_response {
            self.simulator.telemetry_note_vendor_hci_specialized_response(opcode);
            self.send_legacy_scan_reports()?;
            return Ok(());
        }

        // default behavior: send ack for the vendor command
        self.simulator.telemetry_note_vendor_hci_generic_ack(opcode);
        self.send_hci_event_packet(CommandCompleteEvent::cmd_ack(opcode));
        Ok(())
    }

    // =============================================================================================
    // M: Mandatory

    /// Used to add a single device to the Filter Accept List stored in the Controller.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.8.16 LE Add Device To Filter Accept List command
    fn on_le_add_device_to_filter_accept_list(&mut self, cmd: &FilterAcceptListEntry) -> Result<(), ControllerError> {
        debug!("[HCI CMD] LE add device to filter accept command (0x2011)");
        debug!("   in: Address_Type={} Address={}", &cmd.0, &cmd.1);

        // check if the filter is using
        if self.legacy_advertising_enabled && self.advertising_parameters.advertising_filter_policy != AdvFilterPolicy::Unfiltered {
            error!("  err: advertising is enabled with filter on");
            return Err(ControllerError::RequestCrash);
        }
        // check memory capacity
        if self.filter_accept_list.insert(cmd) {
            error!("  err: failed to insert entry to filter accept list");
            self.send_hci_event_packet(CommandCompleteEvent::cmd_status(0x2011, ControllerErrorCode::MemoryCapacityExceeded as u8));
        }
        self.send_hci_event_packet(CommandCompleteEvent::cmd_ack(0x2011));
        Ok(())
    }

    /// Used to clear the Filter Accept List stored in the Controller.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.8.15 LE Clear Filter Accept List command
    fn on_le_clear_filter_accept_list(&mut self) -> Result<(), ControllerError> {
        debug!("[HCI CMD] LE clear filter accept list command (0x2010)");

        self.filter_accept_list.reset();
        self.send_hci_event_packet(CommandCompleteEvent::cmd_ack(0x2010));
        Ok(())
    }

    /// Reads the total number of Filter Accept List entries that can be stored in the Controller.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.8.14 LE Read Filter Accept List Size command
    fn on_le_read_filter_accept_list_size(&self) -> Result<(), ControllerError> {
        debug!("[HCI CMD] LE read filter accept list size command (0x200F)");

        let mut params = Vec::new();
        // Filter_Accept_List_Size
        params.push(FilterAcceptList::MAX_SIZE);
        self.send_hci_event_packet(CommandCompleteEvent::cmd_ret(0x200F, params));
        Ok(())
    }

    /// Requests the list of the supported LE features for the Controller.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.8.3 LE Read Local Supported Features command
    fn on_le_read_local_supported_features(&self) -> Result<(), ControllerError> {
        debug!("[HCI CMD] LE read local supported features command (0x2003)");

        // Keep historical baseline bits but include periodic-advertising transfer capabilities
        // so PAST receiver samples can execute their normal subscription path.
        // byte0: bit0 ENC, bit7 EXT_SCAN
        // byte1: bit0 PHY_2M, bit4 EXT_ADV, bit5 PER_ADV
        // byte3: bit0 PAST_SEND, bit1 PAST_RECV, bit7 SYNC_RECEIVER
        let ret = vec![0x81, 0x31, 0x01, 0x83, 0x00, 0x01, 0x01, 0x01];
        debug!("   ret: LE_Supported_Features={}", hex::encode_upper(&ret));
        self.send_hci_event_packet(CommandCompleteEvent::cmd_ret(0x2003, ret));
        Ok(())
    }

    /// Reads the states, roles, and combinations of states and roles that the Link Layer supports.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.8.27 LE Read Supported States command
    fn on_le_read_supported_states(&self) -> Result<(), ControllerError> {
        debug!("[HCI CMD] LE read supported states command (0x201C)");

        // Default to the historical baseline, but allow case-local overrides for stacks that
        // gate advertising / initiating on this capability bitmap (for example Bluedroid demos).
        let ret = if self.simulator.supported_states().len() == 8 {
            self.simulator.supported_states().to_vec()
        } else {
            vec![0x33, 0x33, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        };
        debug!("   ret: LE_Supported_States={}", hex::encode_upper(&ret));
        self.send_hci_event_packet(CommandCompleteEvent::cmd_ret(0x201C, ret));
        Ok(())
    }

    /// Used to remove a single device from the Filter Accept List stored in the Controller.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.8.17 LE Remove Device From Filter Accept List command
    fn on_le_remove_device_from_filter_accept_list(&mut self, cmd: &FilterAcceptListEntry) -> Result<(), ControllerError> {
        debug!("[HCI CMD] LE remove device from filter accept command (0x2012)");
        debug!("   in: Address_Type={}, Address={}", &cmd.0, &cmd.1);

        if self.filter_accept_list.remove(cmd) {
            warn!("failed to remove entry from filter accept list")
        }
        self.send_hci_event_packet(CommandCompleteEvent::cmd_ack(0x2012));
        Ok(())
    }

    /// Used to control which LE events are generated by the HCI for the Host.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.8.1 LE Set Event Mask command
    fn on_le_set_event_mask(&mut self, cmd: &LeSetEventMaskParam) -> Result<(), ControllerError> {
        debug!("[HCI CMD] LE set event mask command (0x2001)");
        debug!("   in: LE_Event_Mask={}", hex::encode_upper(&cmd.event_mask.0));

        self.le_event_mask = cmd.event_mask.clone();
        self.send_hci_event_packet(CommandCompleteEvent::cmd_ack(0x2001));
        // if self.simulator.emit_extended_adv_probe_on_le_event_mask() {
        //     self.send_extended_scan_reports();
        // }
        Ok(())
    }

    /// This command shall read the Public Device Address.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.4.6 Read BD_ADDR command
    fn on_read_bd_addr(&self) -> Result<(), ControllerError> {
        debug!("[HCI CMD] read BD_ADDR command (0x1009)");

        debug!("  ret: BD_ADDR={}", hex::encode_upper(&self.public_device_address));
        self.send_hci_event_packet(CommandCompleteEvent::cmd_ret(0x1009, self.public_device_address.to_vec()));
        Ok(())
    }

    /// reads the list of HCI commands supported for the local Controller.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.4.2 Read Local Supported Commands command
    fn on_read_local_supported_commands(&self) -> Result<(), ControllerError> {
        debug!("[HCI CMD] read local supported commands command (0x1002)");

        let mut params = vec![0; 64];
        // (02) HCI_Read_BD_ADDR
        set_octet_bit(&mut params, 15, 1, true);
        // (03) HCI_Read_Local_Supported_Features
        set_octet_bit(&mut params, 14, 5, true);
        // (03b) HCI_Read_Buffer_Size
        set_octet_bit(&mut params, 14, 7, true);
        // (04) HCI_Read_Local_Version_Information
        set_octet_bit(&mut params, 14, 3, true);
        // (05) HCI_Reset
        set_octet_bit(&mut params, 5, 7, true);
        // (06) HCI_Set_Event_Mask
        set_octet_bit(&mut params, 5, 6, true);
        // LE Commands
        params[25] = 0b1111_0111;
        params[26] = 0b1111_1111;
        params[27] = 0b1111_1111;
        params[28] = 0b0111_1111;
        for i in 33..45 {
            params[i] = 0xff;
        }
        for i in 0..=3 {
            set_octet_bit(&mut params, 33, i, false);
        }
        // disable HCI_Read_Local_Simple_Pairing_Options
        set_octet_bit(&mut params, 41, 3, false);
        set_octet_bit(&mut params, 45, 0, true);
        set_octet_bit(&mut params, 45, 6, true);
        params[46] = 0b1110_0111;
        params[47] = 0b10;
        set_octet_bit(&mut params, 27, 6, false);
        if self.disable_ext_adv_command_support {
            // BTstack uses this bit to gate extended-advertising command paths.
            // Keep ext-adv events parseable while allowing legacy scan init.
            set_octet_bit(&mut params, 36, 5, false);
        }
        debug!("   ret: supported_cmds[36]=0b{:08b} supported_cmds[44]=0b{:08b}", params[36], params[44]);
        self.send_hci_event_packet(CommandCompleteEvent::cmd_ret(0x1002, params));
        Ok(())
    }

    /// Requests a list of the supported features for the local BR/EDR Controller.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.4.3 Read Local Supported Features command
    fn on_read_local_supported_features(&self) -> Result<(), ControllerError> {
        debug!("[HCI CMD] read local supported features command (0x1003)");
        let mut params = vec![0; 8];
        // ref: 3.5.2 Devices not supporting BR/EDR
        // for LE controller, we need to set these features:
        // (37) set BR/EDR Not Supported bit
        set_octet_bit(&mut params, 4, 5, true);
        // (38) LE Supported (Controller)
        set_octet_bit(&mut params, 4, 6, true);
        // Connected ISO stream support to unlock ISO host init paths.
        set_bit(&mut params, 28, true); // CIS central
        set_bit(&mut params, 29, true); // CIS peripheral
        set_bit(&mut params, 32, true); // ISO channels
        self.send_hci_event_packet(CommandCompleteEvent::cmd_ret(0x1003, params));
        Ok(())
    }

    /// Resets the Controller and the Link Manager on the BR/EDR Controller or the Link Layer on an LE Controller.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.3.2 Reset command
    fn on_reset(&mut self) -> Result<(), ControllerError> {
        debug!("[HCI CMD] reset command (0x0C03)");

        // If we get a second reset command, we exit current execution
        // if self.reset_once {
        //     return Err(ControllerError::RequestExit);
        // }
        self.reset_once = true;
        self.filter_accept_list.reset();
        self.advertising_manager.reset();
        self.host_acl_flow.reset();
        self.pending_acl_packets.clear();
        self.iso_session.reset();
        self.periodic_adv_session.reset();
        self.mesh_entity.reset();
        self.send_hci_event_packet(CommandCompleteEvent::cmd_ack(0x0C03));
        Ok(())
    }

    /// Used to control which events are generated by the HCI for the Host.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.3.1 Set Event Mask command
    fn on_set_event_mask(&mut self, cmd: &SetEventMaskParam) -> Result<(), ControllerError> {
        debug!("[HCI CMD] set event mask command (0x0C01)");
        debug!("   in: Event_Mask={}", hex::encode_upper(&cmd.event_mask.0));

        self.event_mask = cmd.event_mask.clone();
        self.send_hci_event_packet(CommandCompleteEvent::cmd_ack(0x0C01));
        Ok(())
    }

    // =============================================================================================
    // C.1: Mandatory if the LE Controller supports transmitting packets

    /// Used by the Host to set the LE Random Device Address in the Controller.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.8.4 LE Set Random Address command
    fn on_le_set_random_address(&mut self, cmd: &LeSetRandomAddressParam) -> Result<(), ControllerError> {
        debug!("[HCI CMD] le set random address command (0x2005)");
        debug!("   in: Random_Address={}", hex::encode_upper(&cmd.random_address));

        if self.legacy_advertising_enabled || self.scanning_enabled || self.advertising_manager.has_enabled() {
            error!("  err: disallowed when advertising, scanning or initiating is enabled");
            self.send_hci_event_packet(CommandCompleteEvent::cmd_status(0x2005, ControllerErrorCode::CommandDisallowed as u8));
        } else {
            self.random_device_address = Some(cmd.random_address);
            self.send_hci_event_packet(CommandCompleteEvent::cmd_ack(0x2005));
        }
        Ok(())
    }

    // =============================================================================================
    // C.3: Mandatory if the LE Controller supports Connection State

    /// Used to terminate an existing connection.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.1.6 Disconnect command
    fn on_disconnect(&mut self, cmd: &DisconnectParam) -> Result<(), ControllerError> {
        debug!("[HCI CMD] Disconnect command (0x0406)");
        debug!(
            "   in: Connection_Handle=0x{:04x}, Reason={:?}",
            cmd.connection_handle,
            ControllerErrorCode::from(cmd.reason)
        );

        self.send_hci_event_packet(CommandStatusEvent::cmd_ack(0x0406));
        self.connection_manager.remove_connection(cmd.connection_handle);
        self.simulator.note_disconnect_handle(cmd.connection_handle);
        self.drop_pending_acl_for_handle(cmd.connection_handle);
        self.iso_session.clear_pending_for_acl(cmd.connection_handle);
        self.iso_session.clear_stream_for_acl(cmd.connection_handle);
        self.iso_session.clear_gate_for_acl(cmd.connection_handle);
        self.send_hci_event_packet(DisconnectCompleteEvent::new(0x0, cmd.connection_handle, ControllerErrorCode::ConnectionTerminatedByLocalHost as u8).warp());
        Ok(())
    }

    /// Used to update connection parameters for an existing LE connection.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.8.18 LE Connection Update command
    fn on_le_connection_update(&self, cmd: &LeConnectionUpdateParam) -> Result<(), ControllerError> {
        debug!("[HCI CMD] LE connection update command (0x2013)");
        debug!(
            "   in: Connection_Handle=0x{:04x}, Interval=[{}, {}], Latency={}, Supervision_Timeout={}",
            cmd.connection_handle, cmd.conn_interval_min, cmd.conn_interval_max, cmd.max_latency, cmd.supervision_timeout
        );

        self.send_hci_event_packet(CommandStatusEvent::cmd_ack(0x2013));
        self.send_hci_event_packet(
            LeConnectionUpdateCompleteEvent {
                status: 0x00,
                connection_handle: cmd.connection_handle,
                connection_interval: cmd.conn_interval_max.clone(),
                peripheral_latency: cmd.max_latency,
                supervision_timeout: cmd.supervision_timeout.clone(),
            }
            .warp(),
        );
        Ok(())
    }

    /// Returns the current Channel_Map for the specified Connection_Handle.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.8.20 LE Read Channel Map command
    fn on_le_read_channel_map(&self, cmd: &LeReadChannelMapParam) -> Result<(), ControllerError> {
        debug!("[HCI CMD] LE read channel map command (0x2015)");
        debug!("   in: Connection_Handle=0x{:04x}", cmd.connection_handle);

        // random channel mapping, we set channel 0, 10, 25 and 36
        let mut channel_map = vec![0x0; 5];
        for i in vec![0, 10, 25, 36] {
            set_bit(&mut channel_map, i, true);
        }

        let mut body = vec![];
        // Connection_Handle
        body.extend_from_slice(&cmd.connection_handle.to_le_bytes());
        // Channel_Map
        body.extend_from_slice(&channel_map);

        self.send_hci_event_packet(CommandCompleteEvent::cmd_ret(0x2015, body));
        Ok(())
    }

    /// This command requests, from the remote device identified by the Connection_Handle, the features used on the connection and the features supported by
    /// the remote device.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.8.21 LE Read Remote Features command
    fn on_le_read_remote_features(&self, cmd: &LeReadRemoteFeaturesParam) -> Result<(), ControllerError> {
        debug!("[HCI CMD] LE read remote features command (0x2016)");
        debug!("   in: Connection_Handle=0x{:04x}", cmd.connection_handle);
        self.send_hci_event_packet(CommandStatusEvent::cmd_ack(0x2016));

        let event = LeReadRemoteFeaturesCompleteEvent::default(cmd.connection_handle);
        self.send_hci_event_packet(event.warp());
        Ok(())
    }

    /// This command will obtain the values for the version information for the remote device identified by the Connection_Handle parameter.
    ///
    /// # Reference
    /// Vol 4, Part E, 4.13 Read remote version information
    fn on_read_remote_version_information(&self, cmd: &ReadRemoteVersionInformationParam) -> Result<(), ControllerError> {
        debug!("[HCI CMD] read remote version information command (0x041d)");
        debug!("   in: Connection_Handle=0x{:04x}", cmd.connection_handle);

        self.send_hci_event_packet(CommandStatusEvent::cmd_ack(0x041d));
        self.send_hci_event_packet(HciEventPkt::ReadRemoteVersionInformationComplete(ReadRemoteVersionInformationCompleteEvent {
            parameter_total_length: 0x8,
            status: 0x0,
            handle: cmd.connection_handle,
            version: self.local_version_information.lmp_version,
            company_identifier: self.local_version_information.company_identifier,
            subversion: self.local_version_information.lmp_subversion,
        }));
        Ok(())
    }

    /// This command reads the Received Signal Strength Indication (RSSI) value from a Controller.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.5.4 Read RSSI command
    fn on_read_rssi(&self, cmd: &ReadRssiParam) -> Result<(), ControllerError> {
        debug!("[HCI CMD] read RSSI command (0x1405)");
        debug!("   in: Handle=0x{:04x}", cmd.handle);

        let mut body = vec![];
        // handle
        body.extend_from_slice(&cmd.handle.to_le_bytes());
        // RSSI, we always return 0dBm
        body.push(0x0);

        self.send_hci_event_packet(CommandCompleteEvent::cmd_ret(0x1405, body));
        Ok(())
    }

    /// This command reads the values for the TX_Power_Level parameter for the specified Connection_Handle.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.3.35 Read Transmit Power Level command
    fn on_read_transmit_power_level(&self, cmd: &ReadTransmitPowerLevelParam) -> Result<(), ControllerError> {
        debug!("[HCI CMD] read transmit power level command (0x0C2D)");
        debug!("   in: Connection_Handle=0x{:04x} Type={:?}", cmd.connection_handle, cmd.level_type);

        let mut body = vec![];
        // connection_handle
        body.extend_from_slice(&cmd.connection_handle.to_le_bytes());
        // tx_power_level, we always return 0dBm
        body.push(0x0);
        self.send_hci_event_packet(CommandCompleteEvent::cmd_ret(0x1405, body));
        Ok(())
    }

    /// Reads the maximum size of the data portion of ACL data packets and isochronous data packets sent from the Host to the Controller.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.8.2 LE Read Buffer Size command
    fn on_le_read_buffer_size_v1(&self) -> Result<(), ControllerError> {
        debug!("[HCI CMD] LE read buffer size (v1) command (0x2002)");

        let mut params = Vec::new();
        // LE_ACL_Data_Packet_Length
        params.extend_from_slice(&1024u16.to_le_bytes());
        // Total_Num_LE_ACL_Data_Packets
        params.push(0x20);
        self.send_hci_event_packet(CommandCompleteEvent::cmd_ret(0x2002, params));
        Ok(())
    }

    // =============================================================================================
    // C4. Mandatory if LE Feature (LE Encryption) is supported

    /// Used to request the Controller to encrypt the Plaintext_Data in the command using the Key given in the command and returns the Encrypted_Data to the Host.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.8.22 LE Encrypt command
    fn on_le_encrypt(&self, cmd: &LeEncryptParam) -> Result<(), ControllerError> {
        debug!("[HCI CMD] LE encrypt command (0x2017)");
        debug!(
            "   in: Key={}, Plaintext_Data={}",
            hex::encode_upper(&cmd.key),
            hex::encode_upper(&cmd.plaintext_data)
        );

        // HCI uses little-endian byte order while AES expects big-endian block layout
        let mut key_be = cmd.key;
        key_be.reverse();
        let mut plaintext_data_be = cmd.plaintext_data;
        plaintext_data_be.reverse();

        let cipher = Aes128::new(GenericArray::from_slice(&key_be));
        let mut block = GenericArray::clone_from_slice(&plaintext_data_be);
        cipher.encrypt_block(&mut block);

        let mut encrypted_data = [0u8; 16];
        encrypted_data.copy_from_slice(&block);
        encrypted_data.reverse();

        debug!("  ret: encrypted={}", hex::encode_upper(&encrypted_data));
        self.send_hci_event_packet(CommandCompleteEvent::cmd_ret(0x2017, encrypted_data.to_vec()));
        Ok(())
    }

    /// Used to request the Controller to generate 8 octets of random data to be sent to the Host.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.8.23 LE Rand command
    fn on_le_rand(&mut self) -> Result<(), ControllerError> {
        debug!("[HCI CMD] LE rand command (0x2018)");

        let mut random_number = Vec::with_capacity(8);
        for _ in 0..8 {
            random_number.push(self.rng.r#gen());
        }

        debug!("  ret: Random_Number={}", hex::encode_upper(&random_number));
        self.send_hci_event_packet(CommandCompleteEvent::cmd_ret(0x2018, random_number));
        Ok(())
    }

    /// Used to encrypt the connection for an existing connection using the given key.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.8.24 LE Start Encryption command
    fn on_le_start_encryption(&mut self, cmd: &LeStartEncryptionParam) -> Result<(), ControllerError> {
        debug!("[HCI CMD] LE start encryption command (0x2019)");
        debug!(
            "   in: Connection_Handle=0x{:04x} Random_Number={} Encrypted_Diversifier={} Long_Term_Key={}",
            cmd.connection_handle,
            hex::encode_upper(cmd.random_number),
            cmd.encrypted_diversifier,
            hex::encode_upper(cmd.long_term_key)
        );

        if self.connection_manager.get_connection(cmd.connection_handle).is_none() {
            self.send_hci_event_packet(CommandStatusEvent::cmd_status(0x2019, 0x02));
            return Ok(());
        }

        self.send_hci_event_packet(CommandStatusEvent::cmd_ack(0x2019));
        self.send_hci_event_packet(
            EncryptionChangeEvent {
                parameter_total_length: 0x04,
                status: 0x00,
                connection_handle: cmd.connection_handle,
                encryption_enabled: 0x01,
            }
            .warp(),
        );
        if let Some(peer) = self.connection_manager.get_connection_mut(cmd.connection_handle) {
            peer.on_smp_encrypted();
        }
        Ok(())
    }

    /// Supplies the LTK after LE Long Term Key Request event.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.8.25 LE Long Term Key Request Reply command
    fn on_le_long_term_key_request_reply(&mut self, cmd: &LeLongTermKeyRequestReplyParam) -> Result<(), ControllerError> {
        debug!("[HCI CMD] LE long term key request reply command (0x201A)");
        debug!(
            "   in: Connection_Handle=0x{:04x} Long_Term_Key={}",
            cmd.connection_handle,
            hex::encode_upper(cmd.long_term_key)
        );

        if self.connection_manager.get_connection(cmd.connection_handle).is_none() {
            self.send_hci_event_packet(CommandCompleteEvent::cmd_status(0x201A, 0x02));
            return Ok(());
        }

        self.send_hci_event_packet(CommandCompleteEvent::cmd_ret(0x201A, cmd.connection_handle.to_le_bytes().to_vec()));
        self.send_hci_event_packet(
            EncryptionChangeEvent {
                parameter_total_length: 0x04,
                status: 0x00,
                connection_handle: cmd.connection_handle,
                encryption_enabled: 0x01,
            }
            .warp(),
        );
        if let Some(peer) = self.connection_manager.get_connection_mut(cmd.connection_handle) {
            peer.on_smp_encrypted();
        }
        Ok(())
    }

    /// Rejects LE Long Term Key Request.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.8.26 LE Long Term Key Request Negative Reply command
    fn on_le_long_term_key_request_negative_reply(&mut self, cmd: &LeLongTermKeyRequestNegativeReplyParam) -> Result<(), ControllerError> {
        debug!("[HCI CMD] LE long term key request negative reply command (0x201B)");
        debug!("   in: Connection_Handle=0x{:04x}", cmd.connection_handle);

        if self.connection_manager.get_connection(cmd.connection_handle).is_none() {
            self.send_hci_event_packet(CommandCompleteEvent::cmd_status(0x201B, 0x02));
            return Ok(());
        }

        self.send_hci_event_packet(CommandCompleteEvent::cmd_ret(0x201B, cmd.connection_handle.to_le_bytes().to_vec()));
        self.send_hci_event_packet(
            EncryptionChangeEvent {
                parameter_total_length: 0x04,
                status: 0x06,
                connection_handle: cmd.connection_handle,
                encryption_enabled: 0x00,
            }
            .warp(),
        );
        Ok(())
    }

    // =============================================================================================
    // C.8: Mandatory if LE Feature (LE Data Packet Length Extension) is supported

    /// Allows the Host to read the Controller’s maximum supported payload octets and packet duration times for transmission and reception.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.8.46 LE Read Maximum Data Length command.
    fn on_le_read_maximum_data_length(&self) -> Result<(), ControllerError> {
        debug!("[HCI CMD] LE read maximum data length command (0x202F)");

        let mut ret = Vec::new();
        // Supported_Max_TX_Octets
        ret.extend_from_slice(&0x00FBu16.to_le_bytes());
        // Supported_Max_TX_Time
        ret.extend_from_slice(&0x4290u16.to_le_bytes());
        // Supported_Max_RX_Octets
        ret.extend_from_slice(&0x00FBu16.to_le_bytes());
        // Supported_Max_RX_Time
        ret.extend_from_slice(&0x4290u16.to_le_bytes());
        self.send_hci_event_packet(CommandCompleteEvent::cmd_ret(0x202F, ret));
        Ok(())
    }

    /// Allows the Host to read the Host's suggested values (Suggested_Max_TX_Octets and Suggested_Max_TX_Time) for the Controller's maximum transmitted octets
    /// and maximum packet transmission time.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.8.34 LE Read Suggested Default Data Length command.
    fn on_le_read_suggested_default_data_length(&self) -> Result<(), ControllerError> {
        debug!("[HCI CMD] LE read suggested default data length command (0x2023)");
        let mut params = Vec::new();
        // Supported_Max_TX_Octets
        params.extend_from_slice(&0x00FBu16.to_le_bytes());
        // Supported_Max_TX_Time
        params.extend_from_slice(&0x4290u16.to_le_bytes());
        // Supported_Max_RX_Octets
        params.extend_from_slice(&0x00FBu16.to_le_bytes());
        // Supported_Max_RX_Time
        params.extend_from_slice(&0x4290u16.to_le_bytes());
        self.send_hci_event_packet(CommandCompleteEvent::cmd_ret(0x2023, params));
        Ok(())
    }

    /// Allows the Host to suggest the maximum transmission payload size and maximum packet transmission time be used for LL Data PDUs on a given connection.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.8.33 LE Set Data Length command.
    fn on_le_set_data_length(&self, cmd: &LeSetDataLengthParam) -> Result<(), ControllerError> {
        debug!("[HCI CMD] LE set data length command (0x2022)");
        let mut ret = Vec::new();
        // Connection Handle
        ret.extend_from_slice(&cmd.connection_handle.to_le_bytes());
        self.send_hci_event_packet(CommandCompleteEvent::cmd_ret(0x2022, ret));
        Ok(())
    }

    /// Allows the Host to specify its suggested values for the Controller's maximum transmission number of payload octets and maximum packet transmission time for packet.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.8.35 LE Write Suggested Default Data Length command
    fn on_le_write_suggested_default_data_length(&self, cmd: &LeWriteSuggestedDefaultDataLengthParam) -> Result<(), ControllerError> {
        debug!("[HCI CMD] LE write suggested default data length command (0x2024)");
        debug!(
            "   in: Suggested_Max_TX_Octets=0x{:04x}, Suggested_Max_TX_Time=0x{:04x}",
            cmd.suggested_max_tx_octets, cmd.suggested_max_tx_time
        );
        self.send_hci_event_packet(CommandCompleteEvent::cmd_ack(0x2024));
        Ok(())
    }

    /// Used by the Host to ask the Controller to generate a P-256 public/private key pair.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.8.36 LE Read Local P-256 Public Key command
    fn on_le_read_local_p256_public_key(&mut self) -> Result<(), ControllerError> {
        debug!("[HCI CMD] LE read local P-256 public key command (0x2025)");

        let mut key = [0u8; 64];
        self.rng.fill(&mut key);
        self.send_hci_event_packet(CommandStatusEvent::cmd_ack(0x2025));
        self.send_hci_event_packet(LeReadLocalP256PublicKeyCompleteEvent::new(key));
        Ok(())
    }

    // =============================================================================================
    // C.9 Mandatory if LE Feature (LL Privacy) is supported

    /// Used to add one device to the resolving list used to generate and resolve Resolvable Private Addresses in the Controller.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.8.38 LE Add Device To Resolving List command
    fn on_le_add_device_to_resolving_list(&self, cmd: &LeAddDeviceToResolvingListParam) -> Result<(), ControllerError> {
        debug!("[HCI CMD] LE add device to resolving list (0x2027)");
        debug!("   in: {}", cmd);
        self.send_hci_event_packet(CommandCompleteEvent::cmd_ack(0x2027));
        Ok(())
    }

    /// Used to remove all devices from the resolving list used to resolve Resolvable Private Addresses in the Controller.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.8.40 LE Clear Resolving List command
    fn on_le_clear_resolving_list(&self) -> Result<(), ControllerError> {
        debug!("[HCI CMD] LE clear resolving list command (0x2029)");
        self.send_hci_event_packet(CommandCompleteEvent::cmd_ack(0x2029));
        Ok(())
    }

    /// Used to read the total number of entries in the resolving list that can be stored in the Controller.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.8.41 LE Read Resolving List Size command
    fn on_le_read_resolving_size(&self) -> Result<(), ControllerError> {
        debug!("[HCI CMD] LE read resolving size command (0x202A)");
        let mut params = Vec::new();
        // Return empty resolving list capacity to keep host privacy init minimal.
        params.push(0x00);
        self.send_hci_event_packet(CommandCompleteEvent::cmd_ret(0x202A, params));
        Ok(())
    }

    /// Used to enable resolution of Resolvable Private Addresses in the Controller.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.8.44 LE Set Address Resolution Enable command
    fn on_le_set_address_resolution_enable(&self, cmd: &LeSetAddressResolutionEnableParam) -> Result<(), ControllerError> {
        debug!("[HCI CMD] LE set address resolution enable command (0x202D)");
        debug!("   in: Address_Resolution_Enable={}", cmd.enable);
        self.send_hci_event_packet(CommandCompleteEvent::cmd_ack(0x202D));
        Ok(())
    }

    /// Sets the length of time the Controller uses a Resolvable Private Address before a new resolvable private address is generated and starts being used.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.8.45 LE Set Resolvable Private Address Timeout command
    fn on_le_set_resolvable_private_address_timeout(&self, cmd: &LeSetResolvablePrivateAddressTimeoutParam) -> Result<(), ControllerError> {
        debug!("[HCI CMD] LE set resolvable private address timeout command (0x202E)");
        debug!("   in: RPA_Timeout={}", cmd.rpa_timeout);
        self.send_hci_event_packet(CommandCompleteEvent::cmd_ack(0x202E));
        Ok(())
    }

    /// Allows the Host to specify its preferred values for the transmitter PHY and receiver PHY to be used for all subsequent connections over the LE transport.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.8.48 LE Set Default PHY command
    fn on_le_set_default_phy(&self, cmd: &LeSetDefaultPhyParam) -> Result<(), ControllerError> {
        debug!("[HCI CMD] LE set default phy command (0x2031)");
        debug!("   in: All_PHYs={} TX_PHYs={} RX_PHYs={}", cmd.all_phys, cmd.tx_phys, cmd.rx_phys);
        self.send_hci_event_packet(CommandCompleteEvent::cmd_ack(0x2031));
        Ok(())
    }

    /// Allows the Host to indicate its preferred values for the transmitter PHY and receiver PHY for a specific connection.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.8.49 LE Set PHY command
    fn on_le_set_phy(&self, cmd: &LeSetPhyParam) -> Result<(), ControllerError> {
        debug!("[HCI CMD] LE set phy command (0x2032)");
        debug!("   in: {}", cmd);
        self.send_hci_event_packet(CommandStatusEvent::cmd_ack(0x2032));
        self.send_hci_event_packet(
            LePhyUpdateCompleteEvent {
                status: 0x00,
                connection_handle: cmd.connection_handle,
                tx_phy: cmd.tx_phys,
                rx_phy: cmd.rx_phys,
            }
            .warp(),
        );
        Ok(())
    }

    // =============================================================================================
    // C.15 Mandatory if LE Controller supports transmitting scannable advertisements

    /// Used to provide data used in Scanning Packets that have a data field.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.8.8 LE Set Scan Response Data command
    fn on_le_set_scan_response_data(&self, cmd: &LeSetScanResponseDataParam) -> Result<(), ControllerError> {
        debug!("[HCI CMD] LE set scan response data command (0x2009)");
        debug!(
            "   in: Scan_Response_Data_Length={}, Scan_Response_Data={}",
            cmd.scan_response_data_length,
            hex::encode_upper(&cmd.scan_response_data[..])
        );
        self.send_hci_event_packet(CommandCompleteEvent::cmd_ack(0x2009));
        Ok(())
    }

    //==============================================================================================
    // C.17: Mandatory if LE Feature (Extended Advertising) is supported and the LE Controller supports Advertising State

    /// Used to remove all existing advertising sets from the Controller.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.8.60 LE Clear Advertising Sets command
    fn on_le_clear_advertising_sets(&mut self) -> Result<(), ControllerError> {
        debug!("[HCI CMD] LE clear advertising sets command (0x203D)");

        self.send_hci_event_packet(CommandCompleteEvent::cmd_ack(0x203D));
        self.advertising_manager.reset();
        Ok(())
    }

    /// Used to read the maximum length of data supported by the Controller for use as advertisement data or scan response data in an advertising event or as
    /// periodic advertisement data.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.8.57 LE Read Maximum Advertising Data Length command
    fn on_le_read_maximum_advertising_data_length(&self) -> Result<(), ControllerError> {
        debug!("[HCI CMD] LE read maximum advertising data length command (0x203A)");

        // Max_Advertising_Data_Length (Core Spec upper bound = 229 bytes).
        let ret = vec![0xE5u8, 0x00u8];
        self.send_hci_event_packet(CommandCompleteEvent::cmd_ret(0x203A, ret));
        Ok(())
    }

    /// Used to read the maximum number of advertising sets supported by the advertising Controller at the same time.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.8.58 LE Read Number of Supported Advertising Sets command
    fn on_le_read_number_of_supported_advertising_sets(&self) -> Result<(), ControllerError> {
        debug!("[HCI CMD] LE read number of supported advertising sets command (0x203B)");

        // Num_Supported_Advertising_Sets
        let ret = vec![AdvertisingManager::MAX_SIZE];
        self.send_hci_event_packet(CommandCompleteEvent::cmd_ret(0x203B, ret));
        Ok(())
    }

    /// Used to remove an advertising set from the Controller.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.8.59 LE Remove Advertising Set command
    fn on_le_remove_advertising_set(&mut self, cmd: &LeRemoveAdvertisingSetParam) -> Result<(), ControllerError> {
        debug!("[HCI CMD] LE remove advertising set command (0x2036)");
        debug!("   in: Advertising_Handle=0x{:02x}", cmd.advertising_handle);

        self.advertising_manager.remove_advertising_set(cmd.advertising_handle);
        self.send_hci_event_packet(CommandCompleteEvent::cmd_ack(0x2036));
        Ok(())
    }

    /// Used by the Host to set the random device address specified by the Random_Address parameter.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.8.52 LE Set Advertising Set Random Address command
    fn on_le_set_advertising_set_random_address(&self, cmd: &LeSetAdvertisingSetRandomAddressParam) -> Result<(), ControllerError> {
        debug!("[HCI CMD] LE set advertising set random address command (0x2035)");
        debug!(
            "   in: Advertising_Handle=0x{:02x}, Random_Address={}",
            cmd.advertising_handle, cmd.random_address
        );

        if cmd.advertising_handle >= AdvertisingManager::MAX_SIZE {
            error!("  err: invalid advertising handle");
            self.send_hci_event_packet(CommandCompleteEvent::cmd_status(0x2035, ControllerErrorCode::MemoryCapacityExceeded as u8));
        }
        self.send_hci_event_packet(CommandCompleteEvent::cmd_ack(0x2035));
        Ok(())
    }

    /// Used to set the data used in advertising PDUs that have a data field.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.8.54 LE Set Extended Advertising Data command
    fn on_le_set_extended_advertising_data(&mut self, cmd: &LeSetExtendedAdvertisingDataParam) -> Result<(), ControllerError> {
        debug!("[HCI CMD] LE set extended advertising data command (0x2037)");
        debug!("   in: {}", cmd);

        if cmd.advertising_handle >= AdvertisingManager::MAX_SIZE {
            error!("  err: invalid advertising handle");
            self.send_hci_event_packet(CommandCompleteEvent::cmd_status(0x2037, ControllerErrorCode::MemoryCapacityExceeded as u8));
        }
        self.send_hci_event_packet(CommandCompleteEvent::cmd_ack(0x2037));

        // let mut merged_adv_data: Option<Vec<u8>> = None;
        let adv_set = self.advertising_manager.get_advertising_set_mut(cmd.advertising_handle);
        if let Some(adv_set) = adv_set {
            match cmd.operation {
                0x01 | 0x03 => adv_set.advertising_data.clone_from(&cmd.advertising_data),
                0x00 | 0x02 => adv_set.advertising_data.extend_from_slice(&cmd.advertising_data),
                _ => {}
            }
            // merged_adv_data = Some(adv_set.advertising_data.clone());
            if adv_set.enabled {
                self.mesh_entity.on_extended_advertising(&adv_set.advertising_data, self.scanning_enabled)?;
            }
        }

        // let uuid_changed = if let Some(data) = merged_adv_data.as_deref() {
        //     self.mesh_entity.observe_ad_payload(data)
        // } else {
        //     self.mesh_entity.observe_ad_payload(&cmd.advertising_data)
        // };
        // if uuid_changed {
        //     self.maybe_emit_scan_reports_after_mesh_uuid_refresh();
        // }
        Ok(())
    }

    /// Used to request the Controller to enable or disable one or more advertising sets using the advertising sets identified by the Advertising_Handle[i] parameter.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.8.56 LE Set Extended Advertising Enable command
    fn on_le_set_extended_advertising_enable(&mut self, cmd: &LeSetExtendedAdvertisingEnableParam) -> Result<(), ControllerError> {
        debug!("[HCI CMD] LE set extended advertising enable command (0x2039)");
        debug!("   in: {}", cmd);

        if cmd.enable == 0x1 {
            self.execution_feedback.entered_advertising_state = true;
            self.simulator.telemetry_mark_advertising();
        }

        for set in &cmd.sets {
            let adv_set = self.advertising_manager.get_advertising_set_mut(set.advertising_handle);
            if adv_set.is_some() {
                adv_set.as_mut().unwrap().enabled = cmd.enable == 0x1;
            }
        }
        self.send_hci_event_packet(CommandCompleteEvent::cmd_ack(0x2039));

        if !self.simulator.ablation_flags().enable_dynamic_peer_creation {
            debug!("  ret: peer synthesis disabled by ablation preset");
            return Ok(());
        }

        if cmd.enable == 0x1 {
            for set in &cmd.sets {
                if let Some(Some(adv_set)) = self.advertising_manager.get_advertising_set(set.advertising_handle) {
                    if adv_set.is_connectable() {
                        // get address type and address of the peer
                        let (peer_address_type, peer_address) = if adv_set.is_directed() {
                            // for directed advertise -> reply with correct address and type
                            (adv_set.peer_address_type, adv_set.peer_address)
                        } else {
                            // for indirected advertise -> generate new address for peer
                            let addr = vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
                            (
                                AddrKind::Public,
                                BdAddr {
                                    addr: addr.try_into().unwrap(),
                                },
                            )
                        };

                        // create virtual peer
                        let (local_addr, local_addr_type) = self.initiator_address_context(adv_set.own_addr_kind.clone());
                        if !self.simulator.ablation_flags().enable_dynamic_peer_creation {
                            continue;
                        }
                        let connection_handle = self.connection_manager.create_connection(
                            self.simulator,
                            peer_address.clone(),
                            peer_address_type.clone(),
                            local_addr,
                            local_addr_type,
                            false,
                        )?;
                        if connection_handle != 0xFFFF && self.le_event_mask.enabled(LeEventMaskBit::LeConnectionComplete) {
                            self.simulator.note_connection_handle(connection_handle);
                            self.simulator.telemetry_mark_peer_created();
                            self.execution_feedback.entered_connection_state = true;
                            self.simulator.telemetry_mark_connection();
                            debug!("  ret: peer created: Peer_Address={}, Peer_Address_Type={}", peer_address, peer_address_type);
                            self.send_hci_event_packet(
                                LeConnectionCompleteEvent {
                                    status: 0x0,
                                    connection_handle,
                                    role: LeConnRole::Peripheral,
                                    peer_address_type,
                                    peer_address,
                                    // we use a small connection interval and lantency
                                    connection_interval: Duration(0x0006),
                                    peripheral_latency: 0x0000,
                                    // we use the maximum of the supervision timeout
                                    supervision_timeout: Duration(0x0c80),
                                    central_clock_accuracy: 0x07,
                                }
                                .into(),
                            );
                            self.send_hci_event_packet(
                                LeAdvertisingSetTerminatedEvent {
                                    status: 0x0,
                                    advertising_handle: set.advertising_handle,
                                    connection_handle,
                                    num_completed_extended_advertising_events: 1,
                                }
                                .into(),
                            );
                            // Send advertising data to mesh entity
                            self.mesh_entity.set_addr(&peer_address, &peer_address_type);
                            self.mesh_entity.on_extended_advertising(&adv_set.advertising_data, self.scanning_enabled)?;
                            // let uuid_changed = self.mesh_entity.observe_ad_payload(&self.advertising_data);
                            // if uuid_changed {
                            //     self.maybe_emit_scan_reports_after_mesh_uuid_refresh();
                            // }

                            // Keep ISO handshake ordering stable: when ISO is initialized on host side,
                            // defer peer interaction until CIS request emission.
                            if !self.iso_session.host_iso_initialized {
                                self.start_peer_interaction_for_acl(connection_handle);
                            }
                            self.maybe_send_cis_request_for_acl(connection_handle);
                        }
                    } else {
                        self.send_hci_event_packet(
                            LeAdvertisingSetTerminatedEvent {
                                status: 0x43,
                                advertising_handle: set.advertising_handle,
                                connection_handle: 0x0,
                                num_completed_extended_advertising_events: 1,
                            }
                            .into(),
                        );
                    }
                }
            }
        }
        Ok(())
    }

    /// Used to provide scan response data used in scanning response PDUs.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.8.55 LE Set Extended Scan Response Data command
    fn on_le_set_extended_scan_response_data(&mut self, cmd: &LeSetExtendedAdvertisingDataParam) -> Result<(), ControllerError> {
        debug!("[HCI CMD] LE set extended scan response data command (0x2038)");
        debug!("   in: {}", cmd);

        if cmd.advertising_handle >= AdvertisingManager::MAX_SIZE {
            error!("  err: invalid advertising handle");
            self.send_hci_event_packet(CommandCompleteEvent::cmd_status(0x2038, ControllerErrorCode::MemoryCapacityExceeded as u8));
        }
        // let mut merged_scan_rsp_data: Option<Vec<u8>> = None;
        let adv_set = self.advertising_manager.get_advertising_set_mut(cmd.advertising_handle);
        if let Some(adv_set) = adv_set {
            match cmd.operation {
                0x01 | 0x03 => adv_set.scan_response_data.clone_from(&cmd.advertising_data),
                0x00 | 0x02 => adv_set.scan_response_data.extend_from_slice(&cmd.advertising_data),
                _ => {}
            }
            // merged_scan_rsp_data = Some(adv_set.scan_response_data.clone());
        }
        // let uuid_changed = if let Some(data) = merged_scan_rsp_data.as_deref() {
        //     self.mesh_entity.observe_ad_payload(data)
        // } else {
        //     self.mesh_entity.observe_ad_payload(&cmd.advertising_data)
        // };
        // if uuid_changed {
        //     self.maybe_emit_scan_reports_after_mesh_uuid_refresh();
        // }
        self.send_hci_event_packet(CommandCompleteEvent::cmd_ack(0x2038));
        Ok(())
    }

    //==============================================================================================
    // C.19: Mandatory if LE Feature (Extended Advertising) is supported and the LE Controller supports Scanning State, otherwise excluded.

    /// Used to enable or disable scanning for both legacy and extended advertising PDUs.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.8.65 LE Set Extended Scan Enable command
    fn on_le_set_extended_scan_enable(&mut self, cmd: &LeSetExtendedScanEnableParam) -> Result<(), ControllerError> {
        debug!("[HCI CMD] LE set extended scan enable command (0x2042)");
        if self.disable_ext_adv_command_support {
            debug!("   ret: unsupported while ext-adv command support is disabled");
            self.send_hci_event_packet(CommandCompleteEvent::cmd_unsupported(0x2042));
            return Ok(());
        }
        debug!("   in: {:?}", cmd);

        self.scanning_enabled = cmd.enable == 0x1;
        if self.scanning_enabled {
            self.periodic_adv_session.discovery_enabled = true;
        }
        self.send_hci_event_packet(CommandCompleteEvent::cmd_ack(0x2042));

        if cmd.enable == 0x1 {
            // mark we reach legacy scan
            self.execution_feedback.entered_scanning_state = true;
            self.simulator.telemetry_mark_scanning();

            // for P0/P1, no virtual peer is created
            if !self.simulator.ablation_flags().enable_dynamic_peer_creation {
                return Ok(());
            }

            // for P2/P3, create virtual peer with default scan report
            self.send_extended_scan_reports()?;
        }
        Ok(())
    }

    /// Used to set the extended scan parameters to be used on the advertising physical channels.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.8.64 LE Set Extended Scan Parameters command
    fn on_le_set_extended_scan_paramters(&mut self, cmd: &LeSetExtendedScanParametersParam) -> Result<(), ControllerError> {
        debug!("[HCI CMD] LE set extended scan parameters command (0x2041)");
        if self.disable_ext_adv_command_support {
            debug!("   ret: unsupported while ext-adv command support is disabled");
            self.send_hci_event_packet(CommandCompleteEvent::cmd_unsupported(0x2041));
            return Ok(());
        }
        debug!("   in: {}", &cmd);
        self.send_hci_event_packet(CommandCompleteEvent::cmd_ack(0x2041));

        // if self.simulator.ablation_flags().enable_dynamic_peer_creation {
        //     self.execution_feedback.entered_scanning_state = true;
        //     self.simulator.telemetry_mark_scanning();
        //     self.periodic_adv_session.discovery_enabled = true;
        //     self.send_extended_scan_reports();
        // }
        Ok(())
    }

    /// Requests synchronization with a periodic advertiser.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.8.68 LE Periodic Advertising Create Sync command
    fn on_le_per_adv_create_sync(&mut self, cmd: &LePerAdvCreateSyncParam) -> Result<(), ControllerError> {
        debug!("[HCI CMD] LE periodic advertising create sync command (0x2044)");
        debug!(
            "   in: options=0x{:02x} sid=0x{:02x} addr_type={:?} addr={} skip={} timeout={} cte_type=0x{:02x}",
            cmd.options, cmd.sid, cmd.address_type, cmd.address, cmd.skip, cmd.sync_timeout, cmd.cte_type
        );

        self.periodic_adv_session.sync_established = false;
        self.periodic_adv_session.past_received_emitted = false;
        self.periodic_adv_session.reports_sent = 0;
        self.periodic_adv_session.create_sync_requested = true;
        self.periodic_adv_session.discovery_enabled = true;
        self.periodic_adv_session.advertising_sid = cmd.sid;
        self.periodic_adv_session.advertiser_address_type = cmd.address_type;
        self.periodic_adv_session.advertiser_address = cmd.address;
        self.send_hci_event_packet(CommandCompleteEvent::cmd_ack(0x2044));
        Ok(())
    }

    /// Cancels pending synchronization creation.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.8.69 LE Periodic Advertising Create Sync Cancel command
    fn on_le_per_adv_create_sync_cancel(&mut self) -> Result<(), ControllerError> {
        debug!("[HCI CMD] LE periodic advertising create sync cancel command (0x2045)");
        self.periodic_adv_session.sync_established = false;
        self.periodic_adv_session.past_received_emitted = false;
        self.periodic_adv_session.create_sync_requested = false;
        self.send_hci_event_packet(CommandCompleteEvent::cmd_ack(0x2045));
        Ok(())
    }

    /// Terminates an existing periodic advertising sync.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.8.70 LE Periodic Advertising Terminate Sync command
    fn on_le_per_adv_terminate_sync(&mut self, cmd: &LePerAdvTerminateSyncParam) -> Result<(), ControllerError> {
        debug!("[HCI CMD] LE periodic advertising terminate sync command (0x2046)");
        debug!("   in: handle=0x{:04x}", cmd.handle);
        if cmd.handle == self.periodic_adv_session.sync_handle {
            self.periodic_adv_session.sync_established = false;
            self.periodic_adv_session.past_received_emitted = false;
            self.periodic_adv_session.reports_sent = 0;
            self.periodic_adv_session.create_sync_requested = false;
        }
        self.send_hci_event_packet(CommandCompleteEvent::cmd_ack(0x2046));
        Ok(())
    }

    /// Transfers periodic advertising sync information over an active LE connection.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.8.90 LE Periodic Advertising Sync Transfer command
    fn on_le_per_adv_sync_transfer(&self, cmd: &LePerAdvSyncTransferParam) -> Result<(), ControllerError> {
        debug!("[HCI CMD] LE periodic advertising sync transfer command (0x205A)");
        debug!(
            "   in: Conn_Handle=0x{:04x}, Service_Data=0x{:04x}, Sync_Handle=0x{:04x}",
            cmd.conn_handle, cmd.service_data, cmd.sync_handle
        );
        let mut ret = vec![0x00];
        ret.extend_from_slice(&cmd.conn_handle.to_le_bytes());
        self.send_hci_event_packet(CommandCompleteEvent::cmd_ret(0x205A, ret));
        Ok(())
    }

    /// Transfers periodic advertising set information over an active LE connection.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.8.91 LE Periodic Advertising Set Info Transfer command
    fn on_le_per_adv_set_info_transfer(&self, cmd: &LePerAdvSetInfoTransferParam) -> Result<(), ControllerError> {
        debug!("[HCI CMD] LE periodic advertising set info transfer command (0x205B)");
        debug!(
            "   in: Conn_Handle=0x{:04x}, Service_Data=0x{:04x}, Adv_Handle=0x{:02x}",
            cmd.conn_handle, cmd.service_data, cmd.advertising_handle
        );
        let mut ret = vec![0x00];
        ret.extend_from_slice(&cmd.conn_handle.to_le_bytes());
        self.send_hci_event_packet(CommandCompleteEvent::cmd_ret(0x205B, ret));
        Ok(())
    }

    /// Configures PAST receive parameters for a specific connection.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.8.92 LE Set Periodic Advertising Sync Transfer Parameters command
    fn on_le_past_param(&mut self, cmd: &LePastParam) -> Result<(), ControllerError> {
        debug!("[HCI CMD] LE set PAST params command (0x205C)");
        debug!(
            "   in: Conn_Handle=0x{:04x}, Mode=0x{:02x}, Skip={}, Timeout={}, CTE_Type=0x{:02x}",
            cmd.conn_handle, cmd.mode, cmd.skip, cmd.timeout, cmd.cte_type
        );
        self.periodic_adv_session.past_transfer_enabled = cmd.mode != 0;
        if self.periodic_adv_session.past_transfer_enabled {
            self.periodic_adv_session.discovery_enabled = true;
        }
        let mut ret = vec![0x00];
        ret.extend_from_slice(&cmd.conn_handle.to_le_bytes());
        self.send_hci_event_packet(CommandCompleteEvent::cmd_ret(0x205C, ret));
        Ok(())
    }

    /// Configures default PAST receive parameters.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.8.93 LE Set Default Periodic Advertising Sync Transfer Parameters command
    fn on_le_default_past_param(&mut self, cmd: &LeDefaultPastParam) -> Result<(), ControllerError> {
        debug!("[HCI CMD] LE set default PAST params command (0x205D)");
        debug!(
            "   in: Mode=0x{:02x}, Skip={}, Timeout={}, CTE_Type=0x{:02x}",
            cmd.mode, cmd.skip, cmd.timeout, cmd.cte_type
        );
        self.periodic_adv_session.past_transfer_enabled = cmd.mode != 0;
        if self.periodic_adv_session.past_transfer_enabled {
            self.periodic_adv_session.discovery_enabled = true;
        }
        self.send_hci_event_packet(CommandCompleteEvent::cmd_ack(0x205D));
        Ok(())
    }

    // =============================================================================================
    // C.49 Mandatory if LE Feature (Connected Isochronous Stream - Central) or LE Feature (Connected Isochronous Stream - Peripheral) or LE Feature
    //      (Connection Subrating) is supported, otherwise optional

    /// Used by the Host to set or clear a bit controlled by the Host in the Link Layer FeatureSet stored in the Controller.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.8.115 LE Set Host Feature command
    fn on_le_set_host_feature(&mut self, cmd: &LeSetHostFeatureParam) -> Result<(), ControllerError> {
        debug!("[HCI CMD] LE set host feature command (0x2074)");
        debug!("   in: Bit_Number={}, Bit_Value={}", cmd.bit_number, cmd.bit_value);
        if cmd.bit_number == 32 && cmd.bit_value != 0 {
            self.iso_session.mark_host_iso_initialized();
        }
        self.send_hci_event_packet(CommandCompleteEvent::cmd_ack(0x2074));
        Ok(())
    }

    // =============================================================================================
    // C.55 Mandatory if LE Feature (Connected Isochronous Stream - Central), or LE Feature (Connected Isochronous Stream - Peripheral), or LE Feature
    //      (Isochronous Broadcaster) is supported, otherwise optional if the LE Controller supports Connection State, otherwise excluded

    /// Reads the maximum size of the data portion of ACL data packets and isochronous data packets sent from the Host to the Controller.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.8.2 LE Read Buffer Size command
    fn on_le_read_buffer_size_v2(&mut self) -> Result<(), ControllerError> {
        debug!("[HCI CMD] LE read buffer size (v2) command (0x2060)");
        self.iso_session.mark_host_iso_initialized();
        let mut params = Vec::new();
        // LE_ACL_Data_Packet_Length
        params.extend_from_slice(&1024u16.to_le_bytes());
        // Total_Num_LE_ACL_Data_Packets
        params.push(0x20);
        // ISO_Data_Packet_Length
        params.extend_from_slice(&1024u16.to_le_bytes());
        // Total_Num_ISO_Data_Packets
        params.push(0x1);
        self.send_hci_event_packet(CommandCompleteEvent::cmd_ret(0x2060, params));
        Ok(())
    }

    // =============================================================================================
    // C.59 Mandatory if the LE Controller supports Central role, otherwise excluded.

    /// Used to create an ACL connection, with the local device in the Central role, to a connectable advertiser.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.8.12 LE Create Connection command
    fn on_le_create_connection(&mut self, cmd: &LeCreateConnectionParam) -> Result<(), ControllerError> {
        debug!("[HCI CMD] LE create connection command (0x200D)");
        debug!(
            "   in: Peer_Address_Type={}, Peer_Address={}, Own_Address_Type={}, Initiator_Filter_Policy={}",
            cmd.peer_addr_kind, cmd.peer_addr, cmd.own_addr_kind, cmd.use_filter_accept_list
        );
        self.send_hci_event_packet(CommandStatusEvent::cmd_ack(0x200D));

        if !self.simulator.ablation_flags().enable_dynamic_peer_creation {
            debug!("  ret: peer synthesis disabled by ablation preset");
            return Ok(());
        }

        // Even for direct create-connection flows (without prior scan-enable),
        // emit one synthetic extended advertising report so host parser paths
        // remain reachable in a controller-driven, protocol-valid way.
        // if !self.scanning_enabled {
        //     self.send_extended_scan_reports();
        // }

        // create connection and peer
        let (local_addr, local_addr_type) = self.initiator_address_context(cmd.own_addr_kind.clone());
        let connection_handle = self.connection_manager.create_connection(
            self.simulator,
            cmd.peer_addr.clone(),
            cmd.peer_addr_kind.clone(),
            local_addr,
            local_addr_type,
            true,
        )?;
        if connection_handle != 0xFFFF {
            self.simulator.note_connection_handle(connection_handle);
            self.simulator.telemetry_mark_peer_created();
            self.execution_feedback.entered_connection_state = true;
            self.simulator.telemetry_mark_connection();
            self.send_hci_event_packet(
                LeConnectionCompleteEvent {
                    status: 0x0,
                    connection_handle,
                    role: LeConnRole::Central,
                    peer_address_type: cmd.peer_addr_kind.clone(),
                    peer_address: cmd.peer_addr.clone(),
                    connection_interval: cmd.conn_interval_max.clone(),
                    peripheral_latency: 0x0,
                    supervision_timeout: Duration(0x0c80),
                    central_clock_accuracy: 0x07,
                }
                .into(),
            );

            // Keep behavior aligned with advertising-created connections.
            if !self.iso_session.host_iso_initialized {
                self.start_peer_interaction_for_acl(connection_handle);
            }
            self.maybe_send_cis_request_for_acl(connection_handle);
        }

        Ok(())
    }

    //==============================================================================================
    // C.64 Optional if the Controller supports transmitting packets, otherwise excluded.

    /// Used to read the minimum and maximum transmit powers supported by the Controller across all supported PHYs.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.8.74 LE Read Transmit Power command
    fn on_le_read_transmit_power(&self) -> Result<(), ControllerError> {
        debug!("[HCI CMD] LE read transmit power command (0x204b)");
        let params = vec![0x0, 0x0];
        self.send_hci_event_packet(CommandCompleteEvent::cmd_ret(0x204b, params));
        Ok(())
    }

    //==============================================================================================
    // C.65 Mandatory if LE Set Extended Advertising Parameters command [v2] is supported, otherwise mandatory if LE Feature (Extended Advertising) is supported
    //      and the LE Controller supports Advertising State, otherwise excluded.

    /// Used by the Host to set the advertising parameters.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.8.53 LE Set Extended Advertising Parameters command
    fn on_le_set_extended_advertising_parameters_v1(&mut self, cmd: &LeSetExtendedAdvertisingParametersV1Param) -> Result<(), ControllerError> {
        debug!("[HCI CMD] LE set extended advertising parameters v1 command (0x2036)");
        debug!("   in: {}", cmd);

        if cmd.advertising_handle >= AdvertisingManager::MAX_SIZE {
            error!("  err: invalid advertising handle");
            self.send_hci_event_packet(CommandCompleteEvent::cmd_status(0x2036, ControllerErrorCode::MemoryCapacityExceeded as u8));
        }
        let adv_set = self.advertising_manager.get_advertising_set_mut(cmd.advertising_handle);
        if adv_set.is_none() {
            *adv_set = Some(AdvertisingSet::new(
                cmd.advertising_event_priorities,
                cmd.own_address_type.clone(),
                cmd.peer_address_type,
                cmd.peer_address,
                cmd.advertising_filter_policy.clone(),
            ));
        } else {
            adv_set.as_mut().unwrap().set_param(
                cmd.advertising_event_priorities,
                cmd.own_address_type.clone(),
                cmd.peer_address_type,
                cmd.peer_address,
                cmd.advertising_filter_policy.clone(),
            );
        }
        // Selected_TX_Power
        let ret = vec![0x0u8];
        self.send_hci_event_packet(CommandCompleteEvent::cmd_ret(0x2036, ret));
        Ok(())
    }

    //==============================================================================================
    // C.66 Mandatory if LE Feature (Advertising Coding Selection) is supported, otherwise optional if LE Feature (Extended Advertising) is supported and the
    //      LE Controller supports Advertising state, otherwise excluded.

    /// Used by the Host to set the advertising parameters.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.8.53 LE Set Extended Advertising Parameters command
    fn on_le_set_extended_advertising_parameters_v2(&mut self, cmd: &LeSetExtendedAdvertisingParametersV2Param) -> Result<(), ControllerError> {
        debug!("[HCI CMD] LE set extended advertising parameters v2 command (0x207F)");
        debug!("   in: {}", cmd);

        if cmd.advertising_handle >= AdvertisingManager::MAX_SIZE {
            error!("  err: invalid advertising handle");
            self.send_hci_event_packet(CommandCompleteEvent::cmd_status(0x2036, ControllerErrorCode::MemoryCapacityExceeded as u8));
        }
        let adv_set = self.advertising_manager.get_advertising_set_mut(cmd.advertising_handle);
        if adv_set.is_none() {
            *adv_set = Some(AdvertisingSet::new(
                cmd.advertising_event_priorities,
                cmd.own_address_type.clone(),
                cmd.peer_address_type,
                cmd.peer_address,
                cmd.advertising_filter_policy.clone(),
            ));
        } else {
            adv_set.as_mut().unwrap().set_param(
                cmd.advertising_event_priorities,
                cmd.own_address_type.clone(),
                cmd.peer_address_type,
                cmd.peer_address,
                cmd.advertising_filter_policy.clone(),
            );
        }
        // Selected_TX_Power
        let ret = vec![0x0u8];
        self.send_hci_event_packet(CommandCompleteEvent::cmd_ret(0x207F, ret));
        Ok(())
    }

    // =============================================================================================
    // C.96 Optional if the LE Controller supports Connection State, otherwise excluded.

    /// Used by the Host to turn flow control on or off for data and/or voice sent in the direction from the Controller to the Host.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.3.38 Set Controller To Host Flow Control command
    fn on_set_controller_to_host_flow_control(&mut self, cmd: &SetControllerToHostFlowControlParam) -> Result<(), ControllerError> {
        debug!("[HCI CMD] Set controller to host flow control (0x0C31)");
        debug!("   in: Flow_Control_Enable=0x{:x}", cmd.enable);
        self.host_acl_flow.set_enabled(cmd.enable != 0);
        self.send_hci_event_packet(CommandCompleteEvent::cmd_ack(0x0C31));
        Ok(())
    }

    /// Used by the Host to indicate its LE support capability.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.3.69 Write LE Host Support command
    fn on_write_le_host_support(&self, cmd: &WriteLeHostSupportParam) -> Result<(), ControllerError> {
        debug!("[HCI CMD] Write LE host support (0x0C6D)");
        debug!(
            "   in: LE_Supported_Host=0x{:02x}, Simultaneous_LE_Host=0x{:02x}",
            cmd.le_supported_host, cmd.simultaneous_le_host
        );
        self.send_hci_event_packet(CommandCompleteEvent::cmd_ack(0x0C6D));
        Ok(())
    }

    // =============================================================================================
    // C.97 Mandatory if Advertising State is supported, otherwise excluded.

    /// Used to set the data used in advertising packets that have a data field.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.8.7 LE Set Advertising Data command
    fn on_le_set_advertising_data(&mut self, cmd: &LeSetAdvertisingDataParam) -> Result<(), ControllerError> {
        debug!("[HCI CMD] LE set advertising data command (0x2008)");
        debug!("   in: {}", cmd);

        let data_len = usize::from(cmd.data_len).min(cmd.data.len());
        self.advertising_data = cmd.data[..data_len].to_vec();
        self.send_hci_event_packet(CommandCompleteEvent::cmd_ack(0x2008));

        if self.legacy_advertising_enabled {
            self.mesh_entity.on_legacy_advertising(&self.advertising_data, self.scanning_enabled)?;
        }
        Ok(())
    }

    /// Used to request the Controller to start or stop advertising.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.8.9 LE Set Advertising Enable command
    fn on_le_set_advertising_enable(&mut self, cmd: &LeSetAdvertisingEnableParam) -> Result<(), ControllerError> {
        debug!("[HCI CMD] LE set advertising enable command (0x200A)");
        debug!("   in: Advertising_Enable={}", cmd.enable);

        // check random address is valid
        if cmd.enable == 0x1 && self.advertising_parameters.own_address_type == AddrKind::Random && self.random_device_address.is_none() {
            let auto_random = [0xC1, 0xDE, 0xA5, 0xBE, 0xEF, 0x01];
            warn!(
                "random device address was not set; auto-assigning static random address {}",
                hex::encode_upper(auto_random)
            );
            self.random_device_address = Some(auto_random);
        }

        self.legacy_advertising_enabled = cmd.enable == 0x1;
        self.send_hci_event_packet(CommandCompleteEvent::cmd_ack(0x200A));
        if cmd.enable == 0x0 {
            return Ok(());
        }
        self.execution_feedback.entered_advertising_state = true;
        self.simulator.telemetry_mark_advertising();
        if !self.advertising_parameters.advertising_type.is_connectable() {
            debug!("  ret: unconnectable advertising, no peer created");
            return Ok(());
        }
        if !self.simulator.ablation_flags().enable_dynamic_peer_creation {
            debug!("  ret: peer synthesis disabled by ablation preset");
            return Ok(());
        }

        // get address type and address of the peer
        let (peer_address_type, peer_address) = if self.advertising_parameters.advertising_type.is_directed() {
            // for directed advertise -> reply with correct address and type
            (self.advertising_parameters.peer_address_type, self.advertising_parameters.peer_address)
        } else {
            // for indirected advertise -> generate new address for peer
            let addr = vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
            (
                AddrKind::Public,
                BdAddr {
                    addr: addr.try_into().unwrap(),
                },
            )
        };

        // create virtual peer
        debug!("  ret: peer created: Peer_Address={}, Peer_Address_Type={}", peer_address, peer_address_type);
        let (local_addr, local_addr_type) = self.initiator_address_context(self.advertising_parameters.own_address_type.clone());
        let connection_handle = self.connection_manager.create_connection(
            self.simulator,
            peer_address.clone(),
            peer_address_type.clone(),
            local_addr,
            local_addr_type,
            false,
        )?;
        if connection_handle != 0xFFFF {
            self.simulator.note_connection_handle(connection_handle);
            self.simulator.telemetry_mark_peer_created();
            self.execution_feedback.entered_connection_state = true;
            self.simulator.telemetry_mark_connection();
            self.send_hci_event_packet(
                LeConnectionCompleteEvent {
                    status: 0x0,
                    connection_handle,
                    role: LeConnRole::Peripheral,
                    peer_address_type,
                    peer_address,
                    // we use a small connection interval and lantency
                    connection_interval: Duration(0x0006),
                    peripheral_latency: 0x0000,
                    // we use the maximum of the supervision timeout
                    supervision_timeout: Duration(0x0c80),
                    central_clock_accuracy: 0x07,
                }
                .into(),
            );

            // Send advertising data to mesh entity
            self.mesh_entity.set_addr(&peer_address, &peer_address_type);
            self.mesh_entity.on_legacy_advertising(&self.advertising_data, self.scanning_enabled)?;
            // let uuid_changed = self.mesh_entity.observe_ad_payload(&self.advertising_data);
            // if uuid_changed {
            //     self.maybe_emit_scan_reports_after_mesh_uuid_refresh();
            // }

            if !self.iso_session.host_iso_initialized {
                self.start_peer_interaction_for_acl(connection_handle);
            }
            self.maybe_send_cis_request_for_acl(connection_handle);
        }
        Ok(())
    }

    /// Used by the Host to set the advertising parameters.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.8.5 LE Set Advertising Parameters command
    fn on_le_set_advertising_parameters(&mut self, cmd: &AdvertisingParameters) -> Result<(), ControllerError> {
        debug!("[HCI CMD] LE set advertising parameters command (0x2006)");
        debug!("   in: {}", &cmd);

        if self.legacy_advertising_enabled {
            self.send_hci_event_packet(CommandCompleteEvent::cmd_status(0x2006, ControllerErrorCode::CommandDisallowed as u8));
        } else {
            self.advertising_parameters.clone_from(&cmd);
            self.send_hci_event_packet(CommandCompleteEvent::cmd_ack(0x2006));
        }
        Ok(())
    }

    /// Used by the Host to read the transmit power level used for LE advertising physical channel packets.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.8.6 LE Read Advertising Physical Channel Tx Power command
    fn on_le_read_advertising_channel_tx_power(&self) -> Result<(), ControllerError> {
        debug!("[HCI CMD] LE read advertising channel tx power command (0x2007)");
        let ret = vec![0x0];
        self.send_hci_event_packet(CommandCompleteEvent::cmd_ret(0x2007, ret));
        Ok(())
    }

    // =============================================================================================
    // C.98 Mandatory if Scanning State is supported, otherwise excluded

    /// Used to start and stop scanning for legacy PDUs.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.8.11 LE Set Scan Enable command
    fn on_le_set_scan_enable(&mut self, cmd: &LeSetScanEnableParam) -> Result<(), ControllerError> {
        debug!("[HCI CMD] LE set scan enable command (0x200C)");
        debug!("   in: LE_Scan_Enable={}, Filter_Duplicates={}", cmd.le_scan_enable, cmd.filter_duplicates);
        self.scanning_enabled = cmd.le_scan_enable == 0x1;
        if self.scanning_enabled {
            self.periodic_adv_session.discovery_enabled = true;
        }
        self.send_hci_event_packet(CommandCompleteEvent::cmd_ack(0x200C));

        if cmd.le_scan_enable == 0x1 {
            // mark we reach legacy scan
            self.execution_feedback.entered_scanning_state = true;
            self.simulator.telemetry_mark_scanning();

            // for P0/P1, no virtual peer is created
            if !self.simulator.ablation_flags().enable_dynamic_peer_creation {
                return Ok(());
            }

            // for P2/P3, create virtual peer with default scan report
            self.send_legacy_scan_reports()?;
        }
        Ok(())
    }

    /// Sets the scan parameters.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.8.10 LE Set Scan Parameters command
    fn on_le_set_scan_parameters(&self, cmd: &LeSetScanParametersParam) -> Result<(), ControllerError> {
        debug!("[HCI CMD] LE set scan parameters command (0x200B)");
        debug!(
            "   in: LE_Scan_Type={}, LE_Scan_Interval={}, LE_Scan_Window={}, Own_Address_Type={}, Scanning_Filter_Policy={}",
            cmd.le_scan_kind, cmd.le_scan_interval, cmd.le_scan_window, cmd.own_addr_kind, cmd.scanning_filter_policy
        );
        self.send_hci_event_packet(CommandCompleteEvent::cmd_ack(0x200B));
        Ok(())
    }

    // =============================================================================================
    // C.107 Mandatory if the Set Controller To Host Flow Control command is supported, otherwise excluded.

    /// Used by the Host to notify the Controller about the maximum size of the data portion of HCI ACL and Synchronous Data packets sent from the Controller
    /// to the Host.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.3.39 Host Buffer Size command
    fn on_host_buffer_size(&mut self, cmd: &HostBufferSizeParam) -> Result<(), ControllerError> {
        debug!("[HCI CMD] host buffer size command (0x0C33)");
        debug!(
            "   in: Host_ACL_Data_Packet_Length=0x{:04x} Host_Synchronous_Data_Packet_Length=0x{:02x} Host_Total_Num_ACL_Data_Packets=0x{:04x} Host_Total_Num_Synchronous_Data_Packets=0x{:04x}",
            cmd.host_acl_data_packet_length, cmd.host_sync_data_packet_length, cmd.host_total_num_acl_data_packet, cmd.host_total_num_sync_data_packet
        );
        self.host_acl_flow
            .update_host_buffer_size(cmd.host_acl_data_packet_length, cmd.host_total_num_acl_data_packet);
        self.send_hci_event_packet(CommandCompleteEvent::cmd_ack(0x0C33));
        Ok(())
    }

    /// Used by the Host to indicate to the Controller the number of HCI Data packets that have been completed for each Connection_Handle since the previous
    /// HCI_Host_Number_Of_Completed_Packets command was sent to the Controller.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.3.40 Host Number Of Completed Packets command
    fn on_host_number_of_complete_packets(&mut self, cmd: &HostNumberOfCompletePacketsParam) -> Result<(), ControllerError> {
        debug!("[HCI CMD] host number of complete packets command (0x0C35)");
        let mut total_completed = 0u16;
        for (i, unit) in cmd.units.iter().enumerate() {
            debug!(
                "   in{}: connection_handle=0x{:04x} num_complete=0x{:004x}",
                i + 1,
                unit.connection_handle,
                unit.host_num_completed_packets
            );
            total_completed = total_completed.saturating_add(unit.host_num_completed_packets);
        }
        self.host_acl_flow.reclaim_completed(total_completed);
        Ok(())
    }

    // =============================================================================================
    // Other

    /// Provides the ability to read the stored user-friendly name for the BR/EDR Controller.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.3.12 Read Local Name command
    fn on_read_local_name(&self) -> Result<(), ControllerError> {
        debug!("[HCI CMD] read local name command (0x0C14)");
        let mut ret = self.local_name.clone().into_bytes();
        ret.resize(248, 0x0);
        self.send_hci_event_packet(CommandCompleteEvent::cmd_ret(0x0C14, ret));
        Ok(())
    }

    /// Reads the values for the version information for the local Controller.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.4.1 Read Local Version Information command
    fn on_read_local_version_information(&self) -> Result<(), ControllerError> {
        debug!("[HCI CMD] read local version information command (0x1001)");
        debug!(
            "   ret: hci_version=0x{:02x}, hci_subversion=0x{:04x}, lmp_version=0x{:02x}, company=0x{:04x}, lmp_subversion=0x{:04x}",
            self.local_version_information.hci_version,
            self.local_version_information.hci_subversion,
            self.local_version_information.lmp_version,
            self.local_version_information.company_identifier,
            self.local_version_information.lmp_subversion
        );

        self.send_hci_event_packet(CommandCompleteEvent::cmd_ret(0x1001, self.local_version_information.to_bytes().unwrap()));
        Ok(())
    }

    /// Used to read the maximum size of the data portion of HCI ACL and Synchronous Data packets sent from the Host to the Controller.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.4.5 Read Buffer Size command
    fn on_read_buffer_size(&self) -> Result<(), ControllerError> {
        debug!("[HCI CMD] read buffer size command (0x1005)");
        let mut ret = Vec::new();
        ret.extend_from_slice(&1024u16.to_le_bytes());
        ret.push(0xff);
        ret.extend_from_slice(&0x10u16.to_le_bytes());
        ret.extend_from_slice(&0x0u16.to_le_bytes());
        self.send_hci_event_packet(CommandCompleteEvent::cmd_ret(0x1005, ret));
        Ok(())
    }

    /// Returns the requested page of the extended LMP features.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.4.4 Read Local Extended Features command
    fn on_read_local_extended_features(&self, cmd: &ReadLocalExtendedFeaturesParam) -> Result<(), ControllerError> {
        debug!("[HCI CMD] read local extended features command (0x1004)");
        debug!("   in: Page_Number={}", cmd.page_number);

        let ret = vec![0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0];
        self.send_hci_event_packet(CommandCompleteEvent::cmd_ret(0x1004, ret));
        Ok(())
    }

    fn initiator_address_context(&self, own_addr_kind: AddrKind) -> (BdAddr, AddrKind) {
        match own_addr_kind {
            AddrKind::Random | AddrKind::ResolvablePrivateOrRandom => {
                if let Some(addr) = self.random_device_address {
                    (BdAddr { addr }, AddrKind::Random)
                } else {
                    (
                        BdAddr {
                            addr: self.public_device_address,
                        },
                        AddrKind::Public,
                    )
                }
            }
            AddrKind::ResolvablePrivateOrPublic | AddrKind::Public => (
                BdAddr {
                    addr: self.public_device_address,
                },
                AddrKind::Public,
            ),
            AddrKind::AnonymousAdv => (
                BdAddr {
                    addr: self.public_device_address,
                },
                AddrKind::Public,
            ),
        }
    }

    // fn maybe_emit_scan_reports_after_mesh_uuid_refresh(&mut self) {
    //     if !self.simulator.ablation_flags().enable_dynamic_peer_creation {
    //         return;
    //     }
    //     if !(self.scanning_enabled || self.periodic_adv_session.discovery_enabled) {
    //         return;
    //     }
    //     self.send_extended_scan_reports();
    // }

    /// send legacy scan report craft from config.
    fn send_legacy_scan_reports(&mut self) -> Result<(), ControllerError> {
        if !self.le_event_mask.enabled(LeEventMaskBit::LeAdvertisingReport) {
            warn!("LE_Advertising_Report_Event Masked");
            return Ok(());
        }
        if !self.simulator.ablation_flags().enable_dynamic_peer_creation {
            return Ok(());
        }
        // Let mesh entity handle the packet
        self.mesh_entity.send_legacy_scan_report()?;
        // Send simple scan report from config file
        let reports_cfg = self.simulator.legacy_scan_reports();
        if reports_cfg.is_empty() {
            debug!("skip legacy scan reports: no reports configured");
            return Ok(());
        }
        let mut reports = Vec::with_capacity(reports_cfg.len());
        for cfg in reports_cfg {
            reports.push(AdvertisingReport {
                event_type: cfg.event_type,
                address_type: cfg.address_type.clone(),
                address: BdAddr { addr: cfg.address },
                data_length: cfg.data.len() as u8,
                data: cfg.data.clone(),
                rssi: cfg.rssi as u8,
            });
        }
        debug!("send legacy scan reports: reports={}", reports.len());
        self.send_hci_event_packet(LeAdvertisingReportEvent::new(reports));
        Ok(())
    }

    fn maybe_emit_mesh_pbadv_probe_reports(&mut self, address: [u8; 6], rssi: i8) {
        let Some((open_payload, start_payload)) = self.mesh_entity.build_pbadv_probe_reports(
            self.periodic_adv_session.advertiser_address_type.clone(),
            self.periodic_adv_session.advertising_sid,
            self.periodic_adv_session.periodic_interval,
            address,
            rssi,
        ) else {
            return;
        };

        self.send_hci_event_packet(LeExtendedAdvertisingReportEvent::new(open_payload));
        self.send_hci_event_packet(LeExtendedAdvertisingReportEvent::new(start_payload));
    }

    /// send extended scan report craft from config.
    fn send_extended_scan_reports(&mut self) -> Result<(), ControllerError> {
        let reports_cfg = self.simulator.legacy_scan_reports();
        debug!("emit extended scan reports: configured_reports={}", reports_cfg.len());

        if !self.simulator.ablation_flags().enable_dynamic_peer_creation {
            return Ok(());
        }

        // Let mesh entity handle the packet
        self.mesh_entity.send_extended_scan_report()?;
        if reports_cfg.is_empty() {
            warn!("no legacy scan report config available for extended scan report");
            return Ok(());
        }
        let mut mesh_probe_addr: Option<[u8; 6]> = None;
        let mut mesh_probe_rssi: i8 = -45;
        for cfg in reports_cfg {
            if mesh_probe_addr.is_none() {
                mesh_probe_addr = Some(cfg.address);
                mesh_probe_rssi = cfg.rssi;
            }
            let buf = MeshEntity::build_extended_scan_report_payload(
                self.periodic_adv_session.advertiser_address_type.clone(),
                self.periodic_adv_session.advertising_sid,
                self.periodic_adv_session.periodic_interval,
                cfg.address,
                cfg.rssi,
                &cfg.data,
            );
            debug!(
                "emit extended scan report: payload_len={} sid=0x{:02x} addr={}",
                buf.len(),
                self.periodic_adv_session.advertising_sid,
                hex::encode_upper(cfg.address)
            );
            self.send_hci_event_packet(LeExtendedAdvertisingReportEvent::new(buf));
        }
        if let Some(addr) = mesh_probe_addr {
            self.maybe_emit_mesh_pbadv_probe_reports(addr, mesh_probe_rssi);
        }
        Ok(())
    }
}
