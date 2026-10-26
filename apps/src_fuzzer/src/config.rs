use fuzzer::resolve_path;
use serde::Deserialize;
use std::{collections::HashMap, path::PathBuf};

/// Config for AFL-instrumented source targets.
#[derive(Clone, Debug, Deserialize)]
pub struct SrcConfig {
    // Path to the target executable instrumented by afl-gcc/afl-clang-fast.
    target_path: PathBuf,
    // Command line args for the target executable.
    #[serde(default)]
    cmd_args: Vec<String>,
    // Optional working directory for launching the target.
    work_dir: Option<PathBuf>,
    // Extra environment variables for the target.
    #[serde(default)]
    pub env: HashMap<String, String>,
    // Treat non-zero process exit codes as normal completion.
    #[serde(default)]
    allow_nonzero_exit: bool,
    // Auto append BabbleSim arguments `-s` and `-d`.
    #[serde(default = "default_auto_append_sim_args")]
    auto_append_sim_args: bool,
    // Simulation id passed as `-s=<sim_id>` when auto_append_sim_args is true.
    #[serde(default = "default_sim_id")]
    sim_id: String,
    // Device id passed as `-d=<device_id>` when auto_append_sim_args is true.
    #[serde(default)]
    device_id: u32,
    // Per-run timeout for one target execution (milliseconds).
    #[serde(default = "default_run_timeout_ms")]
    run_timeout_ms: u64,
}

impl SrcConfig {
    pub fn target_path(&self) -> PathBuf {
        resolve_path(&self.target_path)
    }

    pub fn cmd_args(&self) -> &[String] {
        &self.cmd_args
    }

    pub fn work_dir(&self) -> Option<PathBuf> {
        self.work_dir.as_ref().map(resolve_path)
    }

    pub fn allow_nonzero_exit(&self) -> bool {
        self.allow_nonzero_exit
    }

    pub fn auto_append_sim_args(&self) -> bool {
        self.auto_append_sim_args
    }

    pub fn sim_id(&self) -> &str {
        &self.sim_id
    }

    pub fn device_id(&self) -> u32 {
        self.device_id
    }

    pub fn run_timeout_ms(&self) -> u64 {
        self.run_timeout_ms
    }
}

fn default_auto_append_sim_args() -> bool {
    true
}

fn default_sim_id() -> String {
    "trial_sim".to_string()
}

fn default_run_timeout_ms() -> u64 {
    600
}
