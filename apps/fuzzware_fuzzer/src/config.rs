use fuzzer::resolve_path;
use serde::Deserialize;
use std::{collections::HashMap, path::PathBuf};

#[derive(Clone, Debug, Deserialize)]
pub struct FuzzwareConfig {
    harness_python: Option<String>,
    modeling_python: Option<String>,
    harness_module: Option<String>,
    harness_root: PathBuf,
    harness_config: PathBuf,
    hook_module_dir: Option<PathBuf>,
    #[serde(default)]
    extra_python_paths: Vec<PathBuf>,
    work_dir: Option<PathBuf>,
    #[serde(default)]
    harness_args: Vec<String>,
    #[serde(default)]
    env: HashMap<String, String>,
    udp_bind: Option<String>,
    udp_remote: Option<String>,
    #[serde(default = "default_udp_timeout_ms")]
    udp_timeout_ms: u64,
    #[serde(default = "default_run_timeout_ms")]
    run_timeout_ms: u64,
    #[serde(default)]
    allow_nonzero_exit: bool,
    #[serde(default = "default_auto_modeling")]
    auto_modeling: bool,
    #[serde(default = "default_model_timeout_sec")]
    model_timeout_sec: u64,
    #[serde(default = "default_model_max_states")]
    model_max_states: usize,
}

impl FuzzwareConfig {
    pub fn harness_python(&self) -> &str {
        self.harness_python.as_deref().unwrap_or("python3")
    }

    pub fn modeling_python(&self) -> &str {
        if let Some(path) = self.modeling_python.as_deref() {
            path
        } else if let Some(path) = default_modeling_python_path() {
            path
        } else {
            self.harness_python()
        }
    }

    pub fn harness_module(&self) -> &str {
        self.harness_module.as_deref().unwrap_or("fuzzware_harness.harness")
    }

    pub fn harness_root(&self) -> PathBuf {
        resolve_path(&self.harness_root)
    }

    pub fn harness_config(&self) -> PathBuf {
        resolve_path(&self.harness_config)
    }

    pub fn hook_module_dir(&self) -> Option<PathBuf> {
        self.hook_module_dir.as_ref().map(resolve_path)
    }

    pub fn extra_python_paths(&self) -> Vec<PathBuf> {
        self.extra_python_paths.iter().map(resolve_path).collect()
    }

    pub fn work_dir(&self) -> Option<PathBuf> {
        self.work_dir.as_ref().map(resolve_path)
    }

    pub fn harness_args(&self) -> &[String] {
        &self.harness_args
    }

    pub fn env(&self) -> &HashMap<String, String> {
        &self.env
    }

    pub fn udp_bind(&self) -> Option<&str> {
        self.udp_bind.as_deref()
    }

    pub fn udp_remote(&self) -> Option<&str> {
        self.udp_remote.as_deref()
    }

    pub fn udp_timeout_ms(&self) -> u64 {
        self.udp_timeout_ms
    }

    pub fn run_timeout_ms(&self) -> u64 {
        self.run_timeout_ms
    }

    pub fn allow_nonzero_exit(&self) -> bool {
        self.allow_nonzero_exit
    }

    pub fn auto_modeling(&self) -> bool {
        self.auto_modeling
    }

    pub fn model_timeout_sec(&self) -> u64 {
        self.model_timeout_sec
    }

    pub fn model_max_states(&self) -> usize {
        self.model_max_states
    }
}

fn default_udp_timeout_ms() -> u64 {
    80
}

fn default_run_timeout_ms() -> u64 {
    1000
}

fn default_auto_modeling() -> bool {
    true
}

fn default_model_timeout_sec() -> u64 {
    8
}

fn default_model_max_states() -> usize {
    8
}

fn default_modeling_python_path() -> Option<&'static str> {
    const CANDIDATE: &str = "/opt/venvs/fuzzware-modeling/bin/python";
    if std::path::Path::new(CANDIDATE).exists() {
        Some(CANDIDATE)
    } else {
        None
    }
}
