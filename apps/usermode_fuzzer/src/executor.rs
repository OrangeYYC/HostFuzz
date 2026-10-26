use ble::input::MetaInput;
use fuzzer::{AppConfig, EDGE_MAP_SIZE, MetaExecutor, MetaExecutorError, MetaExecutorExitReason, MetaState, resolve_path};
use libafl::observers::{CanTrack, ConstMapObserver, HitcountsMapObserver};
use libafl_bolts::tuples::tuple_list;
use libafl_qemu::{
    Emulator, EmulatorExitResult, GuestAddr, SYS_sched_setaffinity,
    command::NopCommand,
    emu::EmulatorModules,
    modules::{
        EdgeCoverageModule, EmulatorModule, EmulatorModuleTuple,
        edges::{EdgeCoverageChildVariant, StdEdgeCoverageChildModule},
        utils::filters::{HasAddressFilter, StdAddressFilter, StdPageFilter},
    },
    qemu::{Hook, SyscallHookResult},
};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    env,
    ffi::CString,
    io,
    path::{Path, PathBuf},
    process::Command,
    ptr::NonNull,
    thread,
    time::{Duration, Instant},
};
use tracing::{error, warn};

/// Config for Usermode.
#[derive(Clone, Debug, Deserialize)]
pub struct UsermodeConfig {
    // Path to the ELF executable of the target
    elf_path: PathBuf,
    // Command args
    cmd_args: Vec<String>,
    // Environment variables to forward into QEMU usermode target.
    #[serde(default)]
    env: BTreeMap<String, String>,
    // Path to the Root of the target
    pub chroot_path: Option<PathBuf>,
    // Redirect target stdio to a PTY to satisfy programs requiring tty ioctls.
    #[serde(default)]
    pub allocate_stdio_pty: bool,
}

impl UsermodeConfig {
    /// Formates ELF executable path.
    fn elf_arg(&self) -> String {
        format!("{}", resolve_path(&self.elf_path).to_str().expect("invalid elf path"))
    }

    /// Crafts QEMU command line args.
    pub fn craft_args(&self) -> Vec<String> {
        let current_exe_path = String::from(
            env::current_exe()
                .expect("get current exe path fail")
                .to_str()
                .expect("invalid current exe path"),
        );

        let mut ret = vec![current_exe_path];
        for (key, value) in self.forwarded_env() {
            ret.push("-E".to_string());
            ret.push(format!("{key}={value}"));
        }
        let elf_arg = self.elf_arg();
        ret.push(elf_arg);
        ret.extend_from_slice(&self.cmd_args);
        ret
    }

    fn forwarded_env(&self) -> BTreeMap<String, String> {
        let mut forwarded = self.env.clone();

        for (key, value) in env::vars() {
            if key == "BTSTACK_UART_DEVICE" || key == "QEMU_SET_ENV" || key.starts_with("BTSTACK_") || key.starts_with("BSIM_") {
                forwarded.entry(key).or_insert(value);
            }
        }

        forwarded
    }
}

#[derive(Debug, Default)]
struct SchedSetaffinityBypassModule;

impl<I, S> EmulatorModule<I, S> for SchedSetaffinityBypassModule
where
    I: Unpin,
    S: Unpin,
{
    fn first_exec<ET>(
        &mut self,
        _qemu: libafl_qemu::Qemu,
        emulator_modules: &mut EmulatorModules<ET, I, S>,
        _state: &mut S,
    ) where
        ET: EmulatorModuleTuple<I, S>,
    {
        emulator_modules.pre_syscalls(Hook::Function(sched_setaffinity_hook::<ET, I, S>));
    }
}

#[expect(clippy::too_many_arguments)]
fn sched_setaffinity_hook<ET, I, S>(
    _qemu: libafl_qemu::Qemu,
    _emulator_modules: &mut EmulatorModules<ET, I, S>,
    _state: Option<&mut S>,
    syscall: i32,
    _x0: GuestAddr,
    _x1: GuestAddr,
    _x2: GuestAddr,
    _x3: GuestAddr,
    _x4: GuestAddr,
    _x5: GuestAddr,
    _x6: GuestAddr,
    _x7: GuestAddr,
) -> SyscallHookResult
where
    ET: EmulatorModuleTuple<I, S>,
    I: Unpin,
    S: Unpin,
{
    if syscall == SYS_sched_setaffinity as i32 {
        return SyscallHookResult::Skip(0);
    }
    SyscallHookResult::Run
}

/// Executor for Usermode.
pub struct UsermodeExecutor {
    // Pointer to coverage map
    map_ptr: *mut u8,
    // Reusable QEMU command line args
    qemu_args: Vec<String>,
    // AppConfig from parent
    config: AppConfig<UsermodeConfig>,
}

type EdgeModuleConstMap =
    EdgeCoverageModule<StdAddressFilter, StdPageFilter, EdgeCoverageChildVariant, true, EDGE_MAP_SIZE>;

fn parse_bool_env(var: &str) -> bool {
    env::var(var)
        .ok()
        .map(|value| matches!(value.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}

impl MetaExecutor for UsermodeExecutor {
    type MetaExecutorConfig = UsermodeConfig;

    fn new(config: &AppConfig<UsermodeConfig>, map_ptr: *mut u8) -> Self {
        Self {
            map_ptr,
            config: config.clone(),
            qemu_args: config.executor.craft_args(),
        }
    }

    fn run(&mut self, state: &mut MetaState, _input: &MetaInput) -> Result<MetaExecutorExitReason, MetaExecutorError> {
        if self.config.executor.allocate_stdio_pty {
            Self::setup_stdio_pty()?;
        }

        if parse_bool_env("VIRTBLE_USE_SYSTEM_QEMU") {
            return self.run_with_system_qemu();
        }

        Self::install_qemu_guest_env(&self.config.executor.forwarded_env());

        // change root now
        if let Some(chroot_path) = &self.config.executor.chroot_path {
            let abs_chroot_path = resolve_path(chroot_path);
            warn!("changing root into {:?}", abs_chroot_path);
            let ret = unsafe {
                libc::chroot(
                    CString::new(format!("{}", resolve_path(&abs_chroot_path).to_str().expect("invalid chroot path")))
                        .unwrap()
                        .as_ptr(),
                )
            };
            if ret != 0 {
                return Err(MetaExecutorError::InitErr(format!("failed to chroot: {}", io::Error::last_os_error())));
            }
        }

        // creates qemu modules for map observer
        let mut edges_observer = unsafe {
            HitcountsMapObserver::new(ConstMapObserver::from_mut_ptr(
                "edges",
                NonNull::new(self.map_ptr)
                    .ok_or(MetaExecutorError::InitErr(format!("failed to create observer from coverage map")))?
                    .cast::<[u8; EDGE_MAP_SIZE]>(),
            ))
            .track_indices()
        };
        let qemu_modules = tuple_list!(
            SchedSetaffinityBypassModule,
            StdEdgeCoverageChildModule::builder()
                .const_map_observer(edges_observer.as_mut())
                .build()
                .unwrap(),
        );

        // create emulator
        let mut emulator = Emulator::<NopCommand, _, _, _, MetaInput, MetaState, _>::empty()
            .qemu_parameters(&self.qemu_args)
            .modules(qemu_modules)
            .build()
            .expect("Failed to build emulator");

        // initialize this emulator
        emulator.first_exec(state);

        if self.config.executor.chroot_path.is_some() {
            // Known issue: querying usermode mappings around chrooted targets can destabilize
            // some MIIOT binaries and lead to immediate seed-time crashes.
            warn!("coverage filter disabled for chrooted target");
        } else if parse_bool_env("VIRTBLE_DISABLE_TARGET_COVERAGE_FILTER") {
            warn!("coverage filter disabled by VIRTBLE_DISABLE_TARGET_COVERAGE_FILTER");
        } else {
            // Restrict coverage to executable mappings that belong to the target ELF.
            // This prevents shared-library edges from dominating corpus coverage.
            let target_elf = resolve_path(&self.config.executor.elf_path);
            let target_elf_canon = target_elf.canonicalize().unwrap_or_else(|_| target_elf.clone());
            let target_name = target_elf_canon
                .file_name()
                .and_then(|name| name.to_str())
                .map(|name| name.to_string());
            let mut target_exec_ranges = Vec::new();
            for map in emulator.mappings() {
                if !map.flags().executable() {
                    continue;
                }
                let Some(path) = map.path() else {
                    continue;
                };
                if !Self::mapping_matches_target(path, &target_elf_canon, target_name.as_deref()) {
                    continue;
                }
                let start = map.start() as GuestAddr;
                let end = map.end() as GuestAddr;
                if start < end {
                    target_exec_ranges.push(start..end);
                }
            }
            if target_exec_ranges.is_empty() {
                warn!(
                    "coverage filter fallback: no executable mapping matched target ELF {}",
                    target_elf_canon.display()
                );
            } else {
                let qemu = emulator.qemu();
                if let Some(edges_module) = emulator.modules_mut().get_mut::<EdgeModuleConstMap>() {
                    edges_module.update_address_filter(qemu, StdAddressFilter::allow_list(Vec::new()));
                    for range in &target_exec_ranges {
                        edges_module.allow_address_range(range);
                    }
                    warn!(
                        "coverage filter applied: {} executable mapping range(s) for {}",
                        target_exec_ranges.len(),
                        target_elf_canon.display()
                    );
                } else {
                    warn!("coverage filter fallback: edge coverage module not found");
                }
            }
        }

        match unsafe { emulator.run_qemu() } {
            Ok(EmulatorExitResult::Timeout) => Ok(MetaExecutorExitReason::Timeout),
            Ok(EmulatorExitResult::QemuExit(ret)) => {
                error!("qemu exit: {:?}", ret);
                Ok(MetaExecutorExitReason::Ok)
            }
            Ok(_) => Ok(MetaExecutorExitReason::Crash),
            Err(err) => Err(MetaExecutorError::ExecErr(format!("{:?}", err))),
        }
    }
}

impl UsermodeExecutor {
    fn default_system_qemu_bin() -> &'static str {
        #[cfg(feature = "x86_64")]
        {
            return "qemu-x86_64";
        }
        #[cfg(feature = "i386")]
        {
            return "qemu-i386";
        }
        #[cfg(feature = "arm")]
        {
            return "qemu-arm";
        }
        #[cfg(feature = "aarch64")]
        {
            return "qemu-aarch64";
        }
        #[allow(unreachable_code)]
        "qemu-x86_64"
    }

    fn run_with_system_qemu(&mut self) -> Result<MetaExecutorExitReason, MetaExecutorError> {
        unsafe {
            std::ptr::write_bytes(self.map_ptr, 0, EDGE_MAP_SIZE);
        }

        if self.config.executor.chroot_path.is_some() {
            return Err(MetaExecutorError::InitErr(
                "VIRTBLE_USE_SYSTEM_QEMU does not support chroot targets".to_string(),
            ));
        }

        let qemu_bin = env::var("VIRTBLE_SYSTEM_QEMU_BIN")
            .unwrap_or_else(|_| Self::default_system_qemu_bin().to_string());
        let timeout_ms = env::var("VIRTBLE_SYSTEM_QEMU_TIMEOUT_MS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(1500);

        let mut cmd = Command::new(&qemu_bin);
        for (key, value) in self.config.executor.forwarded_env() {
            cmd.arg("-E").arg(format!("{key}={value}"));
        }
        cmd.arg(resolve_path(&self.config.executor.elf_path));
        cmd.args(&self.config.executor.cmd_args);

        let mut child = cmd
            .spawn()
            .map_err(|err| MetaExecutorError::ExecErr(format!("failed to spawn system qemu '{qemu_bin}': {err}")))?;

        let start = Instant::now();
        let timeout = Duration::from_millis(timeout_ms);
        loop {
            if let Some(status) = child
                .try_wait()
                .map_err(|err| MetaExecutorError::ExecErr(format!("failed waiting system qemu child: {err}")))?
            {
                if status.success() {
                    return Ok(MetaExecutorExitReason::Ok);
                }
                return Ok(MetaExecutorExitReason::Crash);
            }

            if timeout_ms > 0 && start.elapsed() >= timeout {
                let _ = child.kill();
                let _ = child.wait();
                return Ok(MetaExecutorExitReason::Timeout);
            }

            thread::sleep(Duration::from_millis(1));
        }
    }

    fn mapping_matches_target(map_path: &str, target_elf: &Path, target_name: Option<&str>) -> bool {
        let cleaned = map_path.strip_suffix(" (deleted)").unwrap_or(map_path);
        let mapping_path = Path::new(cleaned);
        if mapping_path == target_elf {
            return true;
        }
        if let Ok(canonical_mapping) = mapping_path.canonicalize() {
            if canonical_mapping == target_elf {
                return true;
            }
        }
        if let (Some(target_name), Some(mapping_name)) =
            (target_name, mapping_path.file_name().and_then(|name| name.to_str()))
        {
            if mapping_name == target_name {
                return true;
            }
        }
        false
    }

    fn install_qemu_guest_env(forwarded_env: &BTreeMap<String, String>) {
        if forwarded_env.is_empty() {
            return;
        }

        let joined = forwarded_env
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<_>>()
            .join(",");
        // QEMU usermode also accepts guest env passthrough via QEMU_SET_ENV.
        unsafe {
            env::set_var("QEMU_SET_ENV", joined);
        }
    }

    fn setup_stdio_pty() -> Result<(), MetaExecutorError> {
        let mut master_fd: libc::c_int = -1;
        let mut slave_fd: libc::c_int = -1;
        let ret = unsafe {
            libc::openpty(
                &mut master_fd as *mut libc::c_int,
                &mut slave_fd as *mut libc::c_int,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        if ret != 0 {
            return Err(MetaExecutorError::InitErr(format!(
                "failed to allocate pty for target stdio: {}",
                io::Error::last_os_error()
            )));
        }

        // Make this process a session leader and attach slave PTY as controlling terminal.
        unsafe {
            libc::setsid();
            libc::ioctl(slave_fd, libc::TIOCSCTTY as _, 0);
        }

        for fd in [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO] {
            let dup_ret = unsafe { libc::dup2(slave_fd, fd) };
            if dup_ret < 0 {
                unsafe {
                    libc::close(master_fd);
                    libc::close(slave_fd);
                }
                return Err(MetaExecutorError::InitErr(format!(
                    "failed to dup stdio to pty: {}",
                    io::Error::last_os_error()
                )));
            }
        }

        // Keep master fd open in this process lifetime; closing it can make the slave side see
        // hangup/EIO immediately on some targets.
        unsafe {
            if slave_fd > libc::STDERR_FILENO {
                libc::close(slave_fd);
            }
        }
        Ok(())
    }
}
