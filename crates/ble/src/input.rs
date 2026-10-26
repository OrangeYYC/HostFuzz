use crate::hci::ControllerToHostPacket;
use libafl::{corpus::CorpusId, inputs::Input};
use libafl_bolts::{HasLen, generic_hash_std};
#[cfg(feature = "fuzzware_input")]
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::{hash::Hash, sync::OnceLock, time::Instant};
use tracing::debug;

#[cfg(feature = "fuzzware_input")]
const FUZZWARE_MMIO_SEED_SIZE: usize = 4096;
#[cfg(feature = "fuzzware_input")]
const FUZZWARE_MMIO_MIN_SIZE: usize = 4096;

/// InteractPhase contains controller reply packets for each host HCI packet
pub type InteractPhase = Vec<ControllerToHostPacket>;

/// Local version information returned by `HCI_Read_Local_Version_Information`.
#[derive(Debug, Clone, Serialize, Deserialize, Hash)]
pub struct LocalVersionInformation {
    pub hci_version: u8,
    pub hci_subversion: u16,
    pub lmp_version: u8,
    pub company_identifier: u16,
    pub lmp_subversion: u16,
}

impl Default for LocalVersionInformation {
    fn default() -> Self {
        Self {
            // Match nRF52 Zephyr controller defaults more closely to keep startup paths aligned.
            hci_version: 0x0D,
            hci_subversion: 0x0000,
            lmp_version: 0x0D,
            company_identifier: 1521,
            lmp_subversion: 0xFFFF,
        }
    }
}

/// Mutating strategy for local version fields.
#[derive(Debug, Clone, Serialize, Deserialize, Hash)]
pub struct VersionMutationState {
    /// If true, mutator should stop touching version fields.
    pub freeze: bool,
    /// If true, mutator should prioritize mutating `hci_version` in the next round.
    #[serde(default)]
    pub prioritize_hci_version: bool,
    /// If true, mutator should prioritize mutating `hci_subversion`.
    pub prioritize_hci_subversion: bool,
    /// Next `hci_version` candidate in incremental exploration.
    #[serde(default)]
    pub next_hci_version: u8,
    /// Next `hci_subversion` candidate in incremental exploration.
    pub next_hci_subversion: u16,
}

impl Default for VersionMutationState {
    fn default() -> Self {
        let default_hci_version = LocalVersionInformation::default().hci_version;
        let default_hci_subversion = LocalVersionInformation::default().hci_subversion;
        Self {
            freeze: false,
            prioritize_hci_version: true,
            prioritize_hci_subversion: true,
            next_hci_version: default_hci_version.wrapping_add(1),
            next_hci_subversion: default_hci_subversion.wrapping_add(1),
        }
    }
}

/// Mutating strategy for vendor command response events.
#[derive(Debug, Clone, Serialize, Deserialize, Hash)]
pub struct VendorResponseMutationState {
    /// If true, mutator should stop touching vendor response events.
    pub freeze: bool,
    /// If true, mutator should prioritize mutating vendor response events.
    pub prioritize: bool,
}

impl Default for VendorResponseMutationState {
    fn default() -> Self {
        Self {
            freeze: false,
            prioritize: true,
        }
    }
}

/// Runtime behavior observed in one fuzz execution.
#[derive(Debug, Clone, Serialize, Deserialize, Hash, Default)]
pub struct ExecutionFeedback {
    pub entered_connection_state: bool,
    pub entered_advertising_state: bool,
    pub entered_scanning_state: bool,
    pub timed_out: bool,
}

impl ExecutionFeedback {
    #[inline]
    pub fn entered_target_state(&self) -> bool {
        self.entered_connection_state || self.entered_advertising_state || self.entered_scanning_state
    }
}

/// MetaInput contains controller configuration, packets in interaction phases and other stuffs
#[derive(Debug, Clone, Serialize, Deserialize, Hash)]
pub struct MetaInput {
    mutate_start: usize,
    phases: Vec<InteractPhase>,
    #[cfg(feature = "fuzzware_input")]
    #[serde(default = "default_mmio_bytes_seed")]
    mmio_bytes: Vec<u8>,
    #[serde(default)]
    local_version_information: LocalVersionInformation,
    #[serde(default)]
    version_mutation_state: VersionMutationState,
    #[serde(default)]
    vendor_response_mutation_state: VendorResponseMutationState,
    /// Vendor response event marks with the same shape as `phases`.
    /// `vendor_response_marks[p][i] == true` means `phases[p][i]` is a response event generated for a Vendor command.
    #[serde(default)]
    vendor_response_marks: Vec<Vec<bool>>,
    #[serde(default)]
    last_execution_feedback: ExecutionFeedback,
}

impl MetaInput {
    pub fn blank() -> Self {
        Self {
            mutate_start: 0,
            phases: Vec::new(),
            #[cfg(feature = "fuzzware_input")]
            mmio_bytes: default_mmio_bytes_seed(),
            local_version_information: LocalVersionInformation::default(),
            version_mutation_state: VersionMutationState::default(),
            vendor_response_mutation_state: VendorResponseMutationState::default(),
            vendor_response_marks: Vec::new(),
            last_execution_feedback: ExecutionFeedback::default(),
        }
    }

    pub fn phases(&self) -> &Vec<InteractPhase> {
        &self.phases
    }

    pub fn phases_mut(&mut self) -> &mut Vec<InteractPhase> {
        &mut self.phases
    }

    #[cfg(feature = "fuzzware_input")]
    pub fn mmio_bytes(&self) -> &Vec<u8> {
        &self.mmio_bytes
    }

    #[cfg(feature = "fuzzware_input")]
    pub fn mmio_bytes_mut(&mut self) -> &mut Vec<u8> {
        &mut self.mmio_bytes
    }

    #[cfg(feature = "fuzzware_input")]
    pub fn ensure_mmio_bytes_seed(&mut self) {
        if self.mmio_bytes.len() < FUZZWARE_MMIO_MIN_SIZE {
            let old_len = self.mmio_bytes.len();
            self.mmio_bytes.resize(FUZZWARE_MMIO_MIN_SIZE, 0);
            rand::thread_rng().fill_bytes(&mut self.mmio_bytes[old_len..]);
        }
    }

    pub fn mutate_start(&self) -> &usize {
        &self.mutate_start
    }

    pub fn mutate_start_mut(&mut self) -> &mut usize {
        &mut self.mutate_start
    }

    pub fn local_version_information(&self) -> &LocalVersionInformation {
        &self.local_version_information
    }

    pub fn local_version_information_mut(&mut self) -> &mut LocalVersionInformation {
        &mut self.local_version_information
    }

    pub fn version_mutation_state(&self) -> &VersionMutationState {
        &self.version_mutation_state
    }

    pub fn version_mutation_state_mut(&mut self) -> &mut VersionMutationState {
        &mut self.version_mutation_state
    }

    pub fn vendor_response_mutation_state(&self) -> &VendorResponseMutationState {
        &self.vendor_response_mutation_state
    }

    pub fn vendor_response_mutation_state_mut(&mut self) -> &mut VendorResponseMutationState {
        &mut self.vendor_response_mutation_state
    }

    pub fn vendor_response_marks(&self) -> &Vec<Vec<bool>> {
        &self.vendor_response_marks
    }

    pub fn vendor_response_marks_mut(&mut self) -> &mut Vec<Vec<bool>> {
        &mut self.vendor_response_marks
    }

    /// Ensures vendor response marks have the same shape as phases.
    pub fn normalize_vendor_response_marks(&mut self) {
        if self.vendor_response_marks.len() > self.phases.len() {
            self.vendor_response_marks.truncate(self.phases.len());
        }
        while self.vendor_response_marks.len() < self.phases.len() {
            self.vendor_response_marks.push(Vec::new());
        }
        for (phase_marks, phase_packets) in self.vendor_response_marks.iter_mut().zip(self.phases.iter()) {
            if phase_marks.len() > phase_packets.len() {
                phase_marks.truncate(phase_packets.len());
            } else if phase_marks.len() < phase_packets.len() {
                phase_marks.resize(phase_packets.len(), false);
            }
        }
    }

    /// Marks a packet range in one phase as vendor responses.
    pub fn mark_vendor_response_range(&mut self, phase_idx: usize, start: usize, end: usize) {
        self.normalize_vendor_response_marks();
        if phase_idx >= self.vendor_response_marks.len() || start >= end {
            return;
        }
        let marks = &mut self.vendor_response_marks[phase_idx];
        let range_end = end.min(marks.len());
        for mark in marks.iter_mut().take(range_end).skip(start) {
            *mark = true;
        }
    }

    pub fn last_execution_feedback(&self) -> &ExecutionFeedback {
        &self.last_execution_feedback
    }

    pub fn clear_last_execution_feedback(&mut self) {
        self.last_execution_feedback = ExecutionFeedback::default();
    }

    /// Updates runtime feedback and adjusts mutation strategy for next run.
    pub fn apply_execution_feedback_with_policy(
        &mut self,
        feedback: ExecutionFeedback,
        enable_version_search: bool,
        enable_vendor_search: bool,
        enable_bootstrap_freeze: bool,
    ) {
        let entered_target_state = feedback.entered_target_state();
        self.last_execution_feedback = feedback;

        if entered_target_state && enable_bootstrap_freeze {
            self.version_mutation_state.freeze = true;
            self.version_mutation_state.prioritize_hci_version = false;
            self.version_mutation_state.prioritize_hci_subversion = false;
            self.vendor_response_mutation_state.freeze = true;
            self.vendor_response_mutation_state.prioritize = false;
            debug!(
                "execution feedback: entered target state, freeze version/vendor mutation (hci_version=0x{:02x}, hci_subversion=0x{:04x})",
                self.local_version_information.hci_version,
                self.local_version_information.hci_subversion
            );
            return;
        }

        // Respect externally configured freeze flags. If mutation is already frozen,
        // keep it frozen and only ensure prioritize flag is off.
        if self.version_mutation_state.freeze {
            self.version_mutation_state.prioritize_hci_version = false;
            self.version_mutation_state.prioritize_hci_subversion = false;
        } else if !enable_version_search {
            self.version_mutation_state.prioritize_hci_version = false;
            self.version_mutation_state.prioritize_hci_subversion = false;
        } else {
            // Preserve the next-field toggle across runs so the mutator can cover
            // both hci_version and hci_subversion incrementally.
            self.version_mutation_state.prioritize_hci_subversion = true;
        }
        if self.vendor_response_mutation_state.freeze {
            self.vendor_response_mutation_state.prioritize = false;
        } else if enable_vendor_search {
            self.vendor_response_mutation_state.prioritize = true;
        } else {
            self.vendor_response_mutation_state.prioritize = false;
        }
        debug!(
            "execution feedback: no target state, version(freeze={}, prioritize_hci_version={}, prioritize_hci_subversion={}, next_hci_version=0x{:02x}, next_hci_subversion=0x{:04x}) vendor(freeze={}, prioritize={})",
            self.version_mutation_state.freeze,
            self.version_mutation_state.prioritize_hci_version,
            self.version_mutation_state.prioritize_hci_subversion,
            self.version_mutation_state.next_hci_version,
            self.version_mutation_state.next_hci_subversion,
            self.vendor_response_mutation_state.freeze,
            self.vendor_response_mutation_state.prioritize
        );
    }

    /// Updates runtime feedback and adjusts version mutation strategy for next run.
    pub fn apply_execution_feedback(&mut self, feedback: ExecutionFeedback) {
        self.apply_execution_feedback_with_policy(feedback, true, true, true);
    }
}

impl Input for MetaInput {
    fn generate_name(&self, _id: Option<CorpusId>) -> String {
        static START: OnceLock<Instant> = OnceLock::new();
        let start = START.get_or_init(Instant::now);
        format!("{}-{:016x}", start.elapsed().as_millis(), generic_hash_std(self))
    }
}

impl HasLen for MetaInput {
    fn is_empty(&self) -> bool {
        self.phases().is_empty()
    }

    fn len(&self) -> usize {
        self.phases().len()
    }
}

#[cfg(feature = "fuzzware_input")]
fn default_mmio_bytes_seed() -> Vec<u8> {
    let mut seed = vec![0u8; FUZZWARE_MMIO_SEED_SIZE];
    rand::thread_rng().fill_bytes(&mut seed);
    seed
}
