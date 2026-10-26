use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AblationMode {
    HciRandomFloor,
    M1Only,
    M1M2,
    #[default]
    Full,
}

impl AblationMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HciRandomFloor => "hci_random_floor",
            Self::M1Only => "m1_only",
            Self::M1M2 => "m1_m2",
            Self::Full => "full",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct AblationFlags {
    pub enable_vendor_hci_contract: bool,
    pub enable_vendor_bootstrap_search: bool,
    pub enable_vendor_response_marking: bool,
    pub enable_vendor_bootstrap_freeze: bool,
    pub enable_generic_scan_floor: bool,
    // P0, P1: False; P2, P3: True
    pub enable_targeted_scan_response: bool,
    // P0, P1: False; P2, P3: True
    pub enable_dynamic_peer_creation: bool,
    pub enable_peer_interaction_pipeline: bool,
    pub enable_runtime_profile_feedback: bool,
    pub enable_semantic_probe_generation: bool,
    // P0, P1, P2: False; P3: True
    pub enable_profile_aware_mutation: bool,
    pub enable_random_hci_floor: bool,
}

impl AblationFlags {
    pub const fn from_mode(mode: AblationMode) -> Self {
        match mode {
            AblationMode::HciRandomFloor => Self {
                enable_vendor_hci_contract: false,
                enable_vendor_bootstrap_search: false,
                enable_vendor_response_marking: false,
                enable_vendor_bootstrap_freeze: false,
                enable_generic_scan_floor: false,
                enable_targeted_scan_response: false,
                enable_dynamic_peer_creation: false,
                enable_peer_interaction_pipeline: false,
                enable_runtime_profile_feedback: false,
                enable_semantic_probe_generation: false,
                enable_profile_aware_mutation: false,
                enable_random_hci_floor: true,
            },
            AblationMode::M1Only => Self {
                enable_vendor_hci_contract: true,
                enable_vendor_bootstrap_search: true,
                enable_vendor_response_marking: true,
                enable_vendor_bootstrap_freeze: true,
                enable_generic_scan_floor: true,
                enable_targeted_scan_response: false,
                enable_dynamic_peer_creation: false,
                enable_peer_interaction_pipeline: false,
                enable_runtime_profile_feedback: false,
                enable_semantic_probe_generation: false,
                enable_profile_aware_mutation: false,
                enable_random_hci_floor: false,
            },
            AblationMode::M1M2 => Self {
                enable_vendor_hci_contract: true,
                enable_vendor_bootstrap_search: true,
                enable_vendor_response_marking: true,
                enable_vendor_bootstrap_freeze: true,
                enable_generic_scan_floor: true,
                enable_targeted_scan_response: true,
                enable_dynamic_peer_creation: true,
                enable_peer_interaction_pipeline: true,
                enable_runtime_profile_feedback: false,
                enable_semantic_probe_generation: false,
                enable_profile_aware_mutation: false,
                enable_random_hci_floor: false,
            },
            AblationMode::Full => Self {
                enable_vendor_hci_contract: true,
                enable_vendor_bootstrap_search: true,
                enable_vendor_response_marking: true,
                enable_vendor_bootstrap_freeze: true,
                enable_generic_scan_floor: true,
                enable_targeted_scan_response: true,
                enable_dynamic_peer_creation: true,
                enable_peer_interaction_pipeline: true,
                enable_runtime_profile_feedback: true,
                enable_semantic_probe_generation: true,
                enable_profile_aware_mutation: true,
                enable_random_hci_floor: false,
            },
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct AblationConfig {
    #[serde(default)]
    pub mode: AblationMode,
    #[serde(default)]
    pub record_telemetry: bool,
    #[serde(default)]
    pub telemetry_dir: Option<String>,
    #[serde(default)]
    pub case_name: Option<String>,
}

impl AblationConfig {
    pub const fn resolved_flags(&self) -> AblationFlags {
        AblationFlags::from_mode(self.mode)
    }
}

#[cfg(test)]
mod tests {
    use super::{AblationFlags, AblationMode};

    #[test]
    fn ablation_mode_mappings_are_stable() {
        let p0 = AblationFlags::from_mode(AblationMode::HciRandomFloor);
        assert!(p0.enable_random_hci_floor);
        assert!(!p0.enable_dynamic_peer_creation);
        assert!(!p0.enable_profile_aware_mutation);

        let p1 = AblationFlags::from_mode(AblationMode::M1Only);
        assert!(p1.enable_vendor_hci_contract);
        assert!(p1.enable_generic_scan_floor);
        assert!(!p1.enable_dynamic_peer_creation);
        assert!(!p1.enable_profile_aware_mutation);

        let p2 = AblationFlags::from_mode(AblationMode::M1M2);
        assert!(p2.enable_generic_scan_floor);
        assert!(p2.enable_dynamic_peer_creation);
        assert!(p2.enable_peer_interaction_pipeline);
        assert!(!p2.enable_profile_aware_mutation);

        let p3 = AblationFlags::from_mode(AblationMode::Full);
        assert!(p3.enable_generic_scan_floor);
        assert!(p3.enable_dynamic_peer_creation);
        assert!(p3.enable_profile_aware_mutation);
        assert!(p3.enable_semantic_probe_generation);
    }
}
