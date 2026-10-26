use crate::config::SrcConfig;
use ble::input::MetaInput;
use fuzzer::{AppConfig, EDGE_MAP_SIZE, MetaExecutor, MetaExecutorError, MetaExecutorExitReason, MetaState};

use std::{
    collections::HashMap,
    os::unix::process::CommandExt,
    path::PathBuf,
    process::{Child, Command, ExitStatus},
    thread,
    time::{Duration, Instant},
};
use tracing::{debug, warn};

/// Executor for AFL-instrumented source targets.
pub struct SrcExecutor {
    // Pointer to coverage map owned by fuzzer.
    map_ptr: *mut u8,
    // Executable path.
    target_path: PathBuf,
    // Command line args.
    cmd_args: Vec<String>,
    // Optional working directory.
    work_dir: Option<PathBuf>,
    // Extra env vars.
    env: HashMap<String, String>,
    // If true, non-zero exit code is not treated as crash.
    allow_nonzero_exit: bool,
    // Auto append BabbleSim args (`-s/-d`) when missing.
    auto_append_sim_args: bool,
    // Simulation id used by `-s`.
    sim_id: String,
    // Device id used by `-d`.
    device_id: u32,
    // Timeout for one execution round.
    run_timeout: Duration,
}

impl MetaExecutor for SrcExecutor {
    type MetaExecutorConfig = SrcConfig;

    fn new(config: &AppConfig<SrcConfig>, map_ptr: *mut u8) -> Self {
        Self {
            map_ptr,
            target_path: config.executor.target_path(),
            cmd_args: config.executor.cmd_args().to_vec(),
            work_dir: config.executor.work_dir(),
            env: config.executor.env.clone(),
            allow_nonzero_exit: config.executor.allow_nonzero_exit(),
            auto_append_sim_args: config.executor.auto_append_sim_args(),
            sim_id: config.executor.sim_id().to_string(),
            device_id: config.executor.device_id(),
            run_timeout: Duration::from_millis(config.executor.run_timeout_ms()),
        }
    }

    fn run(&mut self, _state: &mut MetaState, _input: &MetaInput) -> Result<MetaExecutorExitReason, MetaExecutorError> {
        unsafe {
            std::ptr::write_bytes(self.map_ptr, 0, EDGE_MAP_SIZE);
        }

        let (status, timed_out) = self.run_target_once()?;

        if timed_out {
            return Ok(MetaExecutorExitReason::Timeout);
        }

        let is_success = status.success() || (self.allow_nonzero_exit && status.code().is_some() && status.code().unwrap() != 1);
        if is_success {
            Ok(MetaExecutorExitReason::Ok)
        } else {
            warn!("src target exits abnormally: {:?}", status);
            Ok(MetaExecutorExitReason::Crash)
        }
    }
}

impl SrcExecutor {
    fn run_target_once(&self) -> Result<(ExitStatus, bool), MetaExecutorError> {
        let mut args = self.cmd_args.clone();
        if self.auto_append_sim_args {
            // `-nosim` disables BabbleSim communication and must be removed here.
            args.retain(|arg| arg != "-nosim" && arg != "--nosim");
            if !contains_bsim_arg(&args, "-s") {
                args.push(format!("-s={}", self.sim_id));
            }
            if !contains_bsim_arg(&args, "-d") {
                args.push(format!("-d={}", self.device_id));
            }
        }

        let mut command = Command::new(&self.target_path);
        command.args(&args);

        if let Some(work_dir) = &self.work_dir {
            command.current_dir(work_dir);
        }

        if std::env::var("__AFL_SHM_ID").is_err() {
            return Err(MetaExecutorError::InitErr(
                "missing __AFL_SHM_ID env for AFL-instrumented target; export edge shmem id before running target".to_string(),
            ));
        }
        command.env("AFL_MAP_SIZE", EDGE_MAP_SIZE.to_string());
        for (key, value) in &self.env {
            command.env(key, value);
        }

        // Ensure spawned target process is killed when this child executor exits by timeout/signal.
        unsafe {
            command.pre_exec(|| {
                let ret = libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
                if ret != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }

        debug!("running src target: {:?} {:?}", self.target_path, args);
        let mut child = command
            .spawn()
            .map_err(|err| MetaExecutorError::ExecErr(format!("failed to run source target: {}", err)))?;

        wait_child_with_timeout(&mut child, self.run_timeout)
    }
}

fn wait_child_with_timeout(child: &mut Child, timeout: Duration) -> Result<(ExitStatus, bool), MetaExecutorError> {
    let start = Instant::now();
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|err| MetaExecutorError::ExecErr(format!("failed to wait source target: {}", err)))?
        {
            debug!("src target exited: {:?}", status);
            return Ok((status, false));
        }

        if timeout.as_millis() > 0 && start.elapsed() >= timeout {
            warn!("src target timed out after {:?}, killing child", timeout);
            child
                .kill()
                .map_err(|err| MetaExecutorError::ExecErr(format!("failed to kill timed-out source target: {}", err)))?;
            let status = child
                .wait()
                .map_err(|err| MetaExecutorError::ExecErr(format!("failed to reap timed-out source target: {}", err)))?;
            debug!("timed-out src target reaped: {:?}", status);
            return Ok((status, true));
        }

        thread::sleep(Duration::from_millis(1));
    }
}

fn contains_bsim_arg(args: &[String], key: &str) -> bool {
    args.iter().any(|arg| arg == key || arg.starts_with(&format!("{key}=")))
}
