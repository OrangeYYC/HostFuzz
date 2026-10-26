use crate::config::FuzzwareConfig;
use ble::input::MetaInput;
use fuzzer::{AppConfig, EDGE_MAP_SIZE, MetaExecutor, MetaExecutorError, MetaExecutorExitReason, MetaState, resolve_path};
use libafl::executors::ExitKind;
use libafl::state::HasCorpus;
use serde_yaml::Value;
use std::{
    collections::{HashMap, HashSet},
    fs,
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus},
    thread,
    time::{Duration, Instant},
};
use tracing::{debug, warn};

const MAX_MODELING_RERUNS_PER_INPUT: usize = 10000;

pub struct FuzzwareExecutor {
    map_ptr: *mut u8,
    harness_python: String,
    modeling_python: String,
    harness_module: String,
    source_harness_config: PathBuf,
    harness_config: PathBuf,
    configured_runtime_root: Option<PathBuf>,
    python_paths: Vec<PathBuf>,
    harness_args: Vec<String>,
    env: HashMap<String, String>,
    udp_bind: String,
    udp_remote: String,
    udp_timeout: Duration,
    run_timeout: Duration,
    allow_nonzero_exit: bool,
    auto_modeling: bool,
    model_timeout_sec: u64,
    model_max_states: usize,
    runtime_initialized: bool,
    runtime_dir: PathBuf,
    runtime_input_path: PathBuf,
    runtime_state_dir: PathBuf,
}

impl MetaExecutor for FuzzwareExecutor {
    type MetaExecutorConfig = FuzzwareConfig;

    fn new(config: &AppConfig<FuzzwareConfig>, map_ptr: *mut u8) -> Self {
        let source_harness_config = config.executor.harness_config();
        let hook_dir = config
            .executor
            .hook_module_dir()
            .or_else(|| source_harness_config.parent().map(|v| v.to_path_buf()))
            .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
        let mut python_paths = vec![config.executor.harness_root()];
        if !python_paths.contains(&hook_dir) {
            python_paths.push(hook_dir);
        }
        for p in config.executor.extra_python_paths() {
            if !python_paths.contains(&p) {
                python_paths.push(p);
            }
        }

        let (default_bind, default_remote) =
            parse_udp_transport(&config.simulator.transport).unwrap_or_else(|| ("127.0.0.1:6667".to_string(), "127.0.0.1:6666".to_string()));

        Self {
            map_ptr,
            harness_python: config.executor.harness_python().to_string(),
            modeling_python: config.executor.modeling_python().to_string(),
            harness_module: config.executor.harness_module().to_string(),
            source_harness_config: source_harness_config.clone(),
            harness_config: source_harness_config,
            configured_runtime_root: config
                .executor
                .work_dir()
                .or_else(|| Some(resolve_path(&PathBuf::from(&config.fuzzer.work_dir)))),
            python_paths,
            harness_args: config.executor.harness_args().to_vec(),
            env: config.executor.env().clone(),
            udp_bind: config.executor.udp_bind().unwrap_or(&default_bind).to_string(),
            udp_remote: config.executor.udp_remote().unwrap_or(&default_remote).to_string(),
            udp_timeout: Duration::from_millis(config.executor.udp_timeout_ms()),
            run_timeout: Duration::from_millis(config.executor.run_timeout_ms()),
            allow_nonzero_exit: config.executor.allow_nonzero_exit(),
            auto_modeling: config.executor.auto_modeling(),
            model_timeout_sec: config.executor.model_timeout_sec(),
            model_max_states: config.executor.model_max_states(),
            runtime_initialized: false,
            runtime_input_path: PathBuf::new(),
            runtime_state_dir: PathBuf::new(),
            runtime_dir: PathBuf::new(),
        }
    }

    fn first_exec(&mut self, state: &mut MetaState) {
        if self.runtime_initialized {
            return;
        }
        if let Err(err) = self.initialize_runtime_layout(Some(state)) {
            panic!("failed to initialize fuzzware runtime layout: {:?}", err);
        }
    }

    fn run(&mut self, state: &mut MetaState, input: &MetaInput) -> Result<MetaExecutorExitReason, MetaExecutorError> {
        if std::env::var("__AFL_SHM_ID").is_err() {
            return Err(MetaExecutorError::InitErr("missing __AFL_SHM_ID env for fuzzware coverage bitmap".to_string()));
        }
        if !self.runtime_initialized {
            self.initialize_runtime_layout(Some(state))?;
        }

        self.prepare_round_files(input)?;
        let mut modeling_update_reruns = 0usize;
        loop {
            self.clear_edge_map();
            // let (exec_status, exec_timed_out) = self.run_harness_once(false)?;
            // let exec_ok = exec_status.success() || (self.allow_nonzero_exit && exec_status.code().is_some());
            // if !exec_ok && !exec_timed_out {
            //     warn!("fuzzware harness exits abnormally: {:?}", exec_status);
            //     return Ok(MetaExecutorExitReason::Crash);
            // }
            // if exec_timed_out {
            //     warn!("fuzzware harness timeout after {:?}", self.run_timeout);
            //     return Ok(MetaExecutorExitReason::Timeout);
            // }
            // let primary_coverage = self.snapshot_edge_map();

            self.reset_runtime_state_dir()?;
            let (model_status, model_timed_out) = self.run_harness_once(true)?;
            let primary_coverage = self.snapshot_edge_map();
            let model_ok = model_status.success() || (self.allow_nonzero_exit && model_status.code().is_some());
            if !model_ok && !model_timed_out {
                warn!("fuzzware harness exits abnormally during modeling sidecar pass: {:?}", model_status);
                // self.restore_edge_map(&primary_coverage);
                return Ok(MetaExecutorExitReason::Crash);
            }
            if !self.auto_modeling {
                // self.restore_edge_map(&primary_coverage);
                return Ok(MetaExecutorExitReason::Ok);
            }

            let state_infos = self.collect_mmio_state_infos(&self.runtime_state_dir)?;
            if state_infos.is_empty() {
                if model_timed_out {
                    warn!(
                        "fuzzware harness timeout after {:?} during modeling sidecar pass and no mmio states dumped; keep primary execution result",
                        self.run_timeout
                    );
                }
                // self.restore_edge_map(&primary_coverage);
                return Ok(MetaExecutorExitReason::Ok);
            }

            let known_addrs_before = self.mmio_address_sets_from_config()?;
            let mut new_addrs: HashSet<u64> = HashSet::new();
            for info in &state_infos {
                if !known_addrs_before.resolved.contains(&info.addr) {
                    new_addrs.insert(info.addr);
                }
            }

            if new_addrs.is_empty() {
                debug!("no new mmio addresses discovered in modeling sidecar pass");
                self.restore_edge_map(&primary_coverage);
                return Ok(MetaExecutorExitReason::Ok);
            }

            if model_timed_out {
                warn!(
                    "fuzzware harness timeout after {:?} during modeling sidecar pass, syncing new mmio addresses: {}",
                    self.run_timeout,
                    format_addr_set(&new_addrs)
                );
            }

            let modeling = self.sync_modeling_config(&state_infos, Some(&new_addrs))?;
            if modeling.config_updated {
                if modeling_update_reruns >= MAX_MODELING_RERUNS_PER_INPUT {
                    warn!(
                        "fuzzware modeling updated config repeatedly (>{}) for one input, stop rerun loop",
                        MAX_MODELING_RERUNS_PER_INPUT
                    );
                    self.restore_edge_map(&primary_coverage);
                    return Ok(MetaExecutorExitReason::Ok);
                }
                modeling_update_reruns += 1;
                debug!(
                    "fuzzware modeling updated config, rerunning current input (attempt {}/{})",
                    modeling_update_reruns, MAX_MODELING_RERUNS_PER_INPUT
                );
                self.reset_runtime_state_dir()?;
                continue;
            }

            let known_addrs_after = self.mmio_address_sets_from_config()?;
            let unresolved: HashSet<u64> = new_addrs
                .iter()
                .filter_map(|addr| if known_addrs_after.resolved.contains(addr) { None } else { Some(*addr) })
                .collect();
            if !unresolved.is_empty() {
                warn!(
                    "fuzzware modeling keeps unresolved addresses without config progress, keep primary execution result: {}",
                    format_addr_set(&unresolved)
                );
            }

            self.restore_edge_map(&primary_coverage);
            return Ok(MetaExecutorExitReason::Ok);
        }
    }

    fn keep_child_running_after_controller_ok(&self) -> bool {
        true
    }

    fn post_exec(&mut self, _input: &MetaInput, _observers: &mut fuzzer::MetaObserverTuple, _state: &mut MetaState, _exit_kind: &mut ExitKind) {}
}

impl FuzzwareExecutor {
    fn clear_edge_map(&self) {
        unsafe {
            std::ptr::write_bytes(self.map_ptr, 0, EDGE_MAP_SIZE);
        }
    }

    fn snapshot_edge_map(&self) -> Vec<u8> {
        unsafe { std::slice::from_raw_parts(self.map_ptr, EDGE_MAP_SIZE).to_vec() }
    }

    fn restore_edge_map(&self, data: &[u8]) {
        if data.len() != EDGE_MAP_SIZE {
            return;
        }
        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr(), self.map_ptr, EDGE_MAP_SIZE);
        }
    }

    fn initialize_runtime_layout(&mut self, state: Option<&MetaState>) -> Result<(), MetaExecutorError> {
        let runtime_root = state
            .and_then(|s| s.corpus().dir_path().parent().map(|p| p.to_path_buf()))
            .or_else(|| self.configured_runtime_root.clone())
            .ok_or_else(|| MetaExecutorError::InitErr("unable to resolve fuzzware runtime root directory".to_string()))?;

        self.runtime_dir = runtime_root.join("fuzzware-runtime");
        fs::create_dir_all(&self.runtime_dir)
            .map_err(|err| MetaExecutorError::InitErr(format!("failed to create fuzzware runtime dir {}: {}", self.runtime_dir.display(), err)))?;

        self.runtime_state_dir = self.runtime_dir.join("states");
        fs::create_dir_all(&self.runtime_state_dir).map_err(|err| {
            MetaExecutorError::InitErr(format!(
                "failed to create fuzzware runtime state dir {}: {}",
                self.runtime_state_dir.display(),
                err
            ))
        })?;

        self.runtime_input_path = self.runtime_dir.join("input.bin");
        let runtime_config_name = self
            .source_harness_config
            .file_name()
            .and_then(|v| v.to_str())
            .unwrap_or("fuzzware_runtime.yml");
        let runtime_harness_config = self.runtime_dir.join(runtime_config_name);
        prepare_runtime_harness_config(&self.source_harness_config, &runtime_harness_config)?;
        self.harness_config = runtime_harness_config;
        self.runtime_initialized = true;
        Ok(())
    }

    fn prepare_round_files(&self, input: &MetaInput) -> Result<(), MetaExecutorError> {
        if !self.runtime_initialized {
            return Err(MetaExecutorError::InitErr("fuzzware runtime is not initialized".to_string()));
        }
        self.reset_runtime_state_dir()?;

        fs::write(&self.runtime_input_path, input.mmio_bytes()).map_err(|err| MetaExecutorError::ExecErr(format!("failed to write fuzzware input: {}", err)))
    }

    fn reset_runtime_state_dir(&self) -> Result<(), MetaExecutorError> {
        if self.runtime_state_dir.exists() {
            fs::remove_dir_all(&self.runtime_state_dir)
                .map_err(|err| MetaExecutorError::ExecErr(format!("failed to clear runtime state dir {}: {}", self.runtime_state_dir.display(), err)))?;
        }
        fs::create_dir_all(&self.runtime_state_dir)
            .map_err(|err| MetaExecutorError::ExecErr(format!("failed to recreate runtime state dir {}: {}", self.runtime_state_dir.display(), err)))?;
        Ok(())
    }

    fn run_harness_once(&self, dump_states: bool) -> Result<(ExitStatus, bool), MetaExecutorError> {
        let mut command = Command::new(&self.harness_python);
        command
            .arg("-m")
            .arg(&self.harness_module)
            .arg(&self.runtime_input_path)
            .arg("-c")
            .arg(&self.harness_config)
            .args(&self.harness_args);
        if dump_states {
            command.arg("--state-out").arg(&self.runtime_state_dir).arg("--dump-mmio-states");
        }
        command.current_dir(&self.runtime_dir);

        let python_path = self.build_pythonpath()?;
        command.env("PYTHONPATH", python_path);
        command.env("AFL_MAP_SIZE", EDGE_MAP_SIZE.to_string());
        command.env("VIRTBLE_FUZZWARE_UDP_BIND", &self.udp_bind);
        command.env("VIRTBLE_FUZZWARE_UDP_REMOTE", &self.udp_remote);
        command.env("VIRTBLE_FUZZWARE_UDP_TIMEOUT_MS", self.udp_timeout.as_millis().to_string());

        for (k, v) in &self.env {
            command.env(k, v);
        }

        unsafe {
            command.pre_exec(|| {
                let ret = libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
                if ret != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }

        debug!(
            "running fuzzware harness: {} -m {} {} -c {} (dump_states={}, run_timeout_ms={})",
            self.harness_python,
            self.harness_module,
            self.runtime_input_path.display(),
            self.harness_config.display(),
            dump_states,
            self.run_timeout.as_millis()
        );
        let mut child = command
            .spawn()
            .map_err(|err| MetaExecutorError::ExecErr(format!("failed to spawn fuzzware harness: {}", err)))?;

        wait_child_with_timeout(&mut child, self.run_timeout)
    }

    fn build_pythonpath(&self) -> Result<std::ffi::OsString, MetaExecutorError> {
        let mut py_paths: Vec<PathBuf> = self.python_paths.clone();
        if let Some(old) = std::env::var_os("PYTHONPATH") {
            for p in std::env::split_paths(&old) {
                py_paths.push(p);
            }
        }
        std::env::join_paths(py_paths).map_err(|err| MetaExecutorError::ExecErr(format!("failed to build PYTHONPATH: {}", err)))
    }

    fn sync_modeling_config(&self, state_infos: &[MmioStateInfo], only_addrs: Option<&HashSet<u64>>) -> Result<ModelingSyncResult, MetaExecutorError> {
        if state_infos.is_empty() {
            return Ok(ModelingSyncResult::default());
        }

        let mut state_files = Vec::new();
        let mut picked_addr = HashSet::new();
        for info in state_infos {
            if let Some(addrs) = only_addrs
                && !addrs.contains(&info.addr)
            {
                continue;
            }
            if picked_addr.insert(info.addr) {
                state_files.push(info.path.clone());
            }
        }
        if state_files.is_empty() {
            return Ok(ModelingSyncResult::default());
        }

        state_files.sort();
        if state_files.len() > self.model_max_states {
            state_files.truncate(self.model_max_states);
        }
        let before_cfg = fs::read(&self.harness_config).ok();

        let mut command = Command::new(&self.modeling_python);
        command
            .arg("-c")
            .arg("import fuzzware_modeling; fuzzware_modeling.main()")
            .arg("-c")
            .arg(&self.harness_config)
            .arg("-C")
            .arg(&self.harness_config)
            .arg("-t")
            .arg(self.model_timeout_sec.to_string());
        for path in &state_files {
            command.arg(path);
        }
        command.current_dir(&self.runtime_dir);
        command.env("PYTHONPATH", self.build_pythonpath()?);
        for (k, v) in &self.env {
            command.env(k, v);
        }

        let status = command
            .status()
            .map_err(|err| MetaExecutorError::ExecErr(format!("failed to run fuzzware_modeling: {}", err)))?;
        if !status.success() {
            warn!("fuzzware_modeling exits abnormally ({:?}) for {}", status, self.harness_config.display());
            return Ok(ModelingSyncResult { config_updated: false });
        }

        let after_cfg = fs::read(&self.harness_config).ok();
        let config_updated = match (before_cfg, after_cfg) {
            (Some(before), Some(after)) => before != after,
            _ => true,
        };

        Ok(ModelingSyncResult { config_updated })
    }

    fn mmio_address_sets_from_config(&self) -> Result<MmioAddressSets, MetaExecutorError> {
        let config_raw = fs::read_to_string(&self.harness_config)
            .map_err(|err| MetaExecutorError::ExecErr(format!("failed to read harness config {}: {}", self.harness_config.display(), err)))?;
        let cfg: Value = serde_yaml::from_str(&config_raw)
            .map_err(|err| MetaExecutorError::ExecErr(format!("failed to parse harness config {}: {}", self.harness_config.display(), err)))?;
        let root = cfg
            .as_mapping()
            .ok_or_else(|| MetaExecutorError::ExecErr(format!("invalid harness config (not mapping): {}", self.harness_config.display())))?;

        let mut resolved = HashSet::new();
        let mut unresolved = HashSet::new();
        let Some(mmio_models) = root.get("mmio_models").and_then(|v| v.as_mapping()) else {
            return Ok(MmioAddressSets { resolved });
        };

        for (model_group_name, model_group) in mmio_models {
            let is_unmodeled_group = matches!(model_group_name, Value::String(name) if name == "unmodeled");
            let Some(group_map) = model_group.as_mapping() else {
                continue;
            };
            for (_, entry) in group_map {
                let Some(entry_map) = entry.as_mapping() else {
                    continue;
                };
                if let Some(addr) = entry_map.get("addr").and_then(value_to_u64) {
                    if is_unmodeled_group {
                        unresolved.insert(addr);
                    } else {
                        resolved.insert(addr);
                    }
                }
            }
        }
        if !unresolved.is_empty() {
            debug!("known unresolved mmio model addresses: {}", format_addr_set(&unresolved));
        }
        Ok(MmioAddressSets { resolved })
    }

    fn collect_mmio_state_infos(&self, state_out_dir: &PathBuf) -> Result<Vec<MmioStateInfo>, MetaExecutorError> {
        if !state_out_dir.exists() {
            return Ok(Vec::new());
        }
        let mut infos = Vec::new();
        for entry in
            fs::read_dir(state_out_dir).map_err(|err| MetaExecutorError::ExecErr(format!("failed to read state dir {}: {}", state_out_dir.display(), err)))?
        {
            let entry = entry.map_err(|err| MetaExecutorError::ExecErr(format!("failed to read state dir entry: {}", err)))?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let file_name = path.file_name().and_then(|v| v.to_str()).unwrap_or("");
            if !file_name.contains("state") || file_name.contains("bbtrace") || file_name.contains("ramtrace") || file_name.contains("mmiotrace") {
                continue;
            }
            let Some((pc, addr)) = parse_mmio_state_file_name(file_name) else {
                continue;
            };
            infos.push(MmioStateInfo { path, pc, addr });
        }
        infos.sort_by_key(|v| (v.addr, v.pc, v.path.clone()));
        Ok(infos)
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct ModelingSyncResult {
    config_updated: bool,
}

#[derive(Debug, Clone)]
struct MmioStateInfo {
    path: PathBuf,
    pc: u64,
    addr: u64,
}

#[derive(Debug, Default)]
struct MmioAddressSets {
    resolved: HashSet<u64>,
}

fn wait_child_with_timeout(child: &mut Child, timeout: Duration) -> Result<(ExitStatus, bool), MetaExecutorError> {
    let start = Instant::now();
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|err| MetaExecutorError::ExecErr(format!("failed to wait fuzzware harness: {}", err)))?
        {
            return Ok((status, false));
        }

        if timeout.as_millis() > 0 && start.elapsed() >= timeout {
            child
                .kill()
                .map_err(|err| MetaExecutorError::ExecErr(format!("failed to kill timed-out fuzzware harness: {}", err)))?;
            let status = child
                .wait()
                .map_err(|err| MetaExecutorError::ExecErr(format!("failed to reap timed-out fuzzware harness: {}", err)))?;
            return Ok((status, true));
        }

        thread::sleep(Duration::from_millis(1));
    }
}

fn prepare_runtime_harness_config(source: &Path, runtime: &Path) -> Result<(), MetaExecutorError> {
    let source_content =
        fs::read_to_string(source).map_err(|err| MetaExecutorError::InitErr(format!("failed to read source harness config {}: {}", source.display(), err)))?;
    let mut source_yaml: Value = serde_yaml::from_str(&source_content)
        .map_err(|err| MetaExecutorError::InitErr(format!("failed to parse source harness config {}: {}", source.display(), err)))?;

    let source_dir = source
        .parent()
        .ok_or_else(|| MetaExecutorError::InitErr(format!("harness config {} has no parent directory", source.display())))?;
    absolutize_harness_config_paths(&mut source_yaml, source_dir);

    let runtime_content = serde_yaml::to_string(&source_yaml)
        .map_err(|err| MetaExecutorError::InitErr(format!("failed to serialize runtime harness config {}: {}", runtime.display(), err)))?;
    fs::write(runtime, runtime_content)
        .map_err(|err| MetaExecutorError::InitErr(format!("failed to write runtime harness config {}: {}", runtime.display(), err)))?;
    Ok(())
}

fn absolutize_harness_config_paths(config: &mut Value, source_dir: &Path) {
    let Value::Mapping(root_map) = config else {
        return;
    };

    let include_key = Value::String("include".to_string());
    if let Some(Value::Sequence(include_seq)) = root_map.get_mut(&include_key) {
        for entry in include_seq.iter_mut() {
            if let Value::String(path) = entry {
                *path = absolutize_path(source_dir, path);
            }
        }
    }

    let mem_map_key = Value::String("memory_map".to_string());
    let file_key = Value::String("file".to_string());
    if let Some(Value::Mapping(mem_map)) = root_map.get_mut(&mem_map_key) {
        for (_, region) in mem_map.iter_mut() {
            if let Value::Mapping(region_map) = region
                && let Some(Value::String(file_path)) = region_map.get_mut(&file_key)
            {
                *file_path = absolutize_path(source_dir, file_path);
            }
        }
    }
}

fn absolutize_path(base_dir: &Path, raw_path: &str) -> String {
    let path = Path::new(raw_path);
    if path.is_absolute() {
        raw_path.to_string()
    } else {
        base_dir.join(path).to_string_lossy().into_owned()
    }
}

fn parse_udp_transport(transport: &str) -> Option<(String, String)> {
    let udp = transport.strip_prefix("udp-sync@").or_else(|| transport.strip_prefix("udp-async@"))?;
    let (host, controller) = udp.split_once('-')?;
    Some((host.to_string(), controller.to_string()))
}

fn value_to_u64(value: &Value) -> Option<u64> {
    match value {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => parse_int_like_u64(s),
        _ => None,
    }
}

fn parse_int_like_u64(raw: &str) -> Option<u64> {
    let s = raw.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse::<u64>().ok()
    }
}

fn parse_mmio_state_file_name(file_name: &str) -> Option<(u64, u64)> {
    // Expected pattern:
    // *mmio_access_state_pc_<hex>_addr_<hex>_<input>
    let pc_token = "_pc_";
    let addr_token = "_addr_";
    let pc_start = file_name.find(pc_token)? + pc_token.len();
    let addr_start = file_name[pc_start..].find(addr_token)? + pc_start + addr_token.len();
    let pc_hex = &file_name[pc_start..(addr_start - addr_token.len())];
    let addr_hex_end = file_name[addr_start..].find('_').map(|idx| addr_start + idx).unwrap_or(file_name.len());
    let addr_hex = &file_name[addr_start..addr_hex_end];
    let pc = u64::from_str_radix(pc_hex, 16).ok()?;
    let addr = u64::from_str_radix(addr_hex, 16).ok()?;
    Some((pc, addr))
}

fn format_addr_set(addrs: &HashSet<u64>) -> String {
    let mut v: Vec<u64> = addrs.iter().copied().collect();
    v.sort_unstable();
    v.into_iter().map(|x| format!("0x{:08x}", x)).collect::<Vec<_>>().join(",")
}
