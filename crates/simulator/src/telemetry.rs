use serde::Serialize;
use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    path::Path,
    time::Instant,
};

#[derive(Debug, Clone, Serialize, Default)]
pub struct RunTelemetry {
    pub case_name: String,
    pub preset: String,
    pub run_id: u64,
    pub crashed: bool,
    pub timed_out: bool,
    pub bootstrap_success: bool,
    pub bootstrap_stabilized: bool,
    pub entered_scanning: bool,
    pub entered_advertising: bool,
    pub entered_connection: bool,
    pub peer_created: bool,
    pub entered_pairing: bool,
    pub pairing_completed: bool,
    pub discovery_started: bool,
    pub discovery_completed: bool,
    pub semantic_interaction_started: bool,
    pub semantic_probe_sent: u64,
    pub semantic_probe_success: u64,
    pub known_handle_count_end_of_run: usize,
    pub mutable_hci_units_delivered: u64,
    pub total_mutable_units_available: u64,
    pub host_visible_mutation_delivery_ratio: f64,
    pub round_host_hci_packets: u64,
    pub vendor_hci_packets_seen: u64,
    pub vendor_hci_unique_opcodes_seen: Vec<u16>,
    pub vendor_hci_specialized_response_packets: u64,
    pub vendor_hci_specialized_response_opcodes: Vec<u16>,
    pub vendor_hci_generic_ack_packets: u64,
    pub vendor_hci_generic_ack_opcodes: Vec<u16>,
    pub time_to_first_scanning_packets: Option<u64>,
    pub time_to_first_advertising_packets: Option<u64>,
    pub time_to_first_connection_packets: Option<u64>,
    pub time_to_first_pairing_packets: Option<u64>,
    pub time_to_first_discovery_packets: Option<u64>,
    pub time_to_first_semantic_packets: Option<u64>,
    pub bootstrap_stabilization_latency_packets: Option<u64>,
    pub time_to_first_scanning_secs: Option<f64>,
    pub time_to_first_advertising_secs: Option<f64>,
    pub time_to_first_connection_secs: Option<f64>,
    pub time_to_first_pairing_secs: Option<f64>,
    pub time_to_first_discovery_secs: Option<f64>,
    pub time_to_first_semantic_secs: Option<f64>,
    pub bootstrap_stabilization_latency_secs: Option<f64>,
}

impl RunTelemetry {
    pub fn new(case_name: &str, preset: &str, run_id: u64) -> Self {
        Self {
            case_name: case_name.to_string(),
            preset: preset.to_string(),
            run_id,
            ..Self::default()
        }
    }

    fn push_unique_opcode(values: &mut Vec<u16>, opcode: u16) {
        if values.contains(&opcode) {
            return;
        }
        values.push(opcode);
        values.sort_unstable();
    }

    pub fn mark_scanning(&mut self, packet_idx: u64, elapsed_secs: f64) {
        self.entered_scanning = true;
        self.time_to_first_scanning_packets.get_or_insert(packet_idx);
        self.time_to_first_scanning_secs.get_or_insert(elapsed_secs);
    }

    pub fn mark_advertising(&mut self, packet_idx: u64, elapsed_secs: f64) {
        self.entered_advertising = true;
        self.time_to_first_advertising_packets.get_or_insert(packet_idx);
        self.time_to_first_advertising_secs.get_or_insert(elapsed_secs);
    }

    pub fn mark_connection(&mut self, packet_idx: u64, elapsed_secs: f64) {
        self.entered_connection = true;
        self.time_to_first_connection_packets.get_or_insert(packet_idx);
        self.time_to_first_connection_secs.get_or_insert(elapsed_secs);
    }

    pub fn mark_peer_created(&mut self) {
        self.peer_created = true;
    }

    pub fn mark_pairing_started(&mut self, packet_idx: u64, elapsed_secs: f64) {
        self.entered_pairing = true;
        self.time_to_first_pairing_packets.get_or_insert(packet_idx);
        self.time_to_first_pairing_secs.get_or_insert(elapsed_secs);
    }

    pub fn mark_pairing_completed(&mut self) {
        self.pairing_completed = true;
    }

    pub fn mark_discovery_started(&mut self, packet_idx: u64, elapsed_secs: f64) {
        self.discovery_started = true;
        self.time_to_first_discovery_packets.get_or_insert(packet_idx);
        self.time_to_first_discovery_secs.get_or_insert(elapsed_secs);
    }

    pub fn mark_discovery_completed(&mut self) {
        self.discovery_completed = true;
    }

    pub fn mark_semantic_interaction_started(&mut self, packet_idx: u64, elapsed_secs: f64) {
        self.semantic_interaction_started = true;
        self.time_to_first_semantic_packets.get_or_insert(packet_idx);
        self.time_to_first_semantic_secs.get_or_insert(elapsed_secs);
    }

    pub fn mark_semantic_probe_sent(&mut self) {
        self.semantic_probe_sent = self.semantic_probe_sent.saturating_add(1);
    }

    pub fn mark_semantic_probe_success(&mut self) {
        self.semantic_probe_success = self.semantic_probe_success.saturating_add(1);
    }

    pub fn mark_vendor_hci_seen(&mut self, opcode: u16) {
        self.vendor_hci_packets_seen = self.vendor_hci_packets_seen.saturating_add(1);
        Self::push_unique_opcode(&mut self.vendor_hci_unique_opcodes_seen, opcode);
    }

    pub fn mark_vendor_hci_specialized_response(&mut self, opcode: u16) {
        self.vendor_hci_specialized_response_packets = self.vendor_hci_specialized_response_packets.saturating_add(1);
        Self::push_unique_opcode(&mut self.vendor_hci_specialized_response_opcodes, opcode);
    }

    pub fn mark_vendor_hci_generic_ack(&mut self, opcode: u16) {
        self.vendor_hci_generic_ack_packets = self.vendor_hci_generic_ack_packets.saturating_add(1);
        Self::push_unique_opcode(&mut self.vendor_hci_generic_ack_opcodes, opcode);
    }
}

#[derive(Debug, Default)]
pub struct TelemetryState {
    next_run_id: u64,
    current_run: Option<RunTelemetry>,
    current_run_started_at: Option<Instant>,
}

impl TelemetryState {
    pub fn begin_run(&mut self, case_name: &str, preset: &str) {
        self.next_run_id = self.next_run_id.saturating_add(1);
        self.current_run = Some(RunTelemetry::new(case_name, preset, self.next_run_id));
        self.current_run_started_at = Some(Instant::now());
    }

    pub fn current_run_mut(&mut self) -> Option<&mut RunTelemetry> {
        self.current_run.as_mut()
    }

    pub fn current_run(&self) -> Option<&RunTelemetry> {
        self.current_run.as_ref()
    }

    pub fn current_run_elapsed_secs(&self) -> Option<f64> {
        self.current_run_started_at.map(|started_at| started_at.elapsed().as_secs_f64())
    }
}

pub fn write_run_jsonl(dir: &Path, run: &RunTelemetry) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    let mut file = OpenOptions::new().create(true).append(true).open(dir.join("run_telemetry.jsonl"))?;
    serde_json::to_writer(&mut file, run)?;
    file.write_all(b"\n")?;
    Ok(())
}
