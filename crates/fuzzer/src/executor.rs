/*!
 * Abstraction for executors.
 */
use crate::{AppConfig, MetaEventManager, MetaFuzzer, MetaObserverTuple, MetaShmemProvider, MetaState};
use ble::input::MetaInput;
use simulator::{
    Simulator, SimulatorError,
    controller::{ControllerError, ControllerExitReason},
    hci::{protocol::ProtocolError, transport::TransportError},
};

use core::sync::atomic::Ordering;
use libafl::{
    executors::{Executor, ExitKind, HasObservers, common_signals, hooks::ExecutorHook},
    inputs::Input,
    observers::ObserversTuple,
    state::HasExecutions,
};
use libafl_bolts::{
    os::unix_signals::{Signal, SignalHandler, setup_signal_handler, siginfo_t, ucontext_t},
    shmem::ShMemProvider,
    tuples::RefIndexable,
};
use libafl_core::ErrorBacktrace;
use nix::{
    sys::{
        signal::{
            Signal::{SIGALRM, SIGUSR2},
            kill,
        },
        wait::{WaitPidFlag, WaitStatus, waitpid},
    },
    unistd::{ForkResult, Pid, close, fork, pipe, read},
};
use serde::de::DeserializeOwned;
use std::{
    io,
    mem::transmute,
    os::{fd::OwnedFd, raw::c_void},
    ptr::{null, write_volatile},
    sync::atomic::compiler_fence,
    time::{Duration, Instant},
};
use tracing::{error, info, trace, warn};

/// Exit reason of the [`MetaExecutor`] and [`MetaExecutorWrapper`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[repr(i32)]
pub enum MetaExecutorExitReason {
    // Normal exit
    Ok = 0x0,
    // Target crash
    Crash = 0x1,
    // Target timeout
    Timeout = 0x2,
    // Engine internal error
    Internal = 0x3,
}

/// Error of the [`MetaExecutor`] and [`MetaExecutorWrapper`].
#[derive(Debug)]
pub enum MetaExecutorError {
    InitErr(String),
    InternalErr(String),
    ExecErr(String),
}

#[inline]
fn runtime_error(context: impl Into<String>) -> libafl::Error {
    libafl::Error::Runtime(context.into(), ErrorBacktrace::capture())
}

/// Trait for all customized executor.
pub trait MetaExecutor {
    /// Inner config for the executor. We use serde to deserialize the config from yaml file, so
    /// the config struct should be `DeserializeOwned`.
    type MetaExecutorConfig: DeserializeOwned;

    /// Creates new instance of the executor.
    ///
    /// # Note
    /// [`crate::app::app`] uses this API to create executor.
    fn new(config: &AppConfig<Self::MetaExecutorConfig>, edge_map: *mut u8) -> Self;

    /// First time behavior.
    ///
    /// # Note
    /// This function is called by [`MetaExecutorWrapper`] in parent process.
    fn first_exec(&mut self, _state: &mut MetaState) {}

    /// Actions before execute.
    ///
    /// # Note
    /// This function is called by [`MetaExecutorWrapper`] in parent process before fork.
    fn pre_exec(&mut self, _state: &mut MetaState, _input: &MetaInput) {}

    /// Actions after execute.
    ///
    /// # Note
    /// This function is called by [`MetaExecutorWrapper`] in parent process after child exits. If
    /// the child process exit with [`MetaExecutorExitReason::Internal`] or parent process gets
    /// [`MetaExecutorError`], this callback will **NOT** be called.
    fn post_exec(&mut self, _input: &MetaInput, _observers: &mut MetaObserverTuple, _state: &mut MetaState, _exit_kind: &mut ExitKind) {}

    /// Executes the target.
    ///
    /// # Note
    /// This function is called by [`MetaExecutorWrapper`] in **child** process after fork.
    fn run(&mut self, state: &mut MetaState, input: &MetaInput) -> Result<MetaExecutorExitReason, MetaExecutorError>;

    /// Whether parent should keep child running when simulator exits with `ControllerExitReason::Ok`.
    ///
    /// Default behavior keeps existing semantics for other fuzzers: parent sends stop signal
    /// immediately once simulator loop decides to exit.
    fn keep_child_running_after_controller_ok(&self) -> bool {
        false
    }
}

/// Wapper of the [`MetaExecutor`]. This struct acts like real executor in libafl.
pub struct MetaExecutorWrapper<'a, E> {
    // Simulator's tokio runtime
    rt: tokio::runtime::Runtime,
    // Reference to the simulator
    simulator: &'a Simulator,
    // Executor Inner
    executor: E,
    // Fuzz hooks for signals
    hooks: FuzzHooks,
    // Shared memory provider
    shmem_provider: MetaShmemProvider,
    // Edge and time observer
    observers: MetaObserverTuple,
    // Flag for first time execution
    first_exec: bool,
}

impl<'a, E: MetaExecutor> MetaExecutorWrapper<'a, E> {
    #[inline]
    /// This function marks the boundary between the fuzzer and the target.
    pub fn enter_target(&mut self, state: &mut MetaState, input: &MetaInput) {
        unsafe {
            let data = &raw mut FUZZ_EXECUTOR_GLOBAL_DATA;
            write_volatile(&raw mut (*data).executor_ptr, std::ptr::from_ref(self) as *const c_void);
            write_volatile(&raw mut (*data).current_input_ptr, std::ptr::from_ref(input) as *const c_void);
            write_volatile(&raw mut ((*data).state_ptr), std::ptr::from_mut(state) as *mut c_void);
            compiler_fence(Ordering::SeqCst);
        }
    }

    /// Crates new [`MetaExecutorWrapper`] with given simulator, state, executor and so on.
    pub fn new(
        executor: E,
        simulator: &'a Simulator,
        state: &mut MetaState,
        shmem_provider: MetaShmemProvider,
        observers: MetaObserverTuple,
    ) -> Result<Self, libafl::Error> {
        // hook timeout and crash with the default in child process hooks
        let mut hooks = FuzzHooks::new::<E>()?;
        hooks.init(state);
        // start tokio runtime, avoid building runtime every loop
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|err| runtime_error(format!("failed to build tokio runtime: {}", err)))?;
        Ok(Self {
            rt,
            simulator,
            executor,
            hooks,
            shmem_provider,
            observers,
            first_exec: true,
        })
    }

    /// Actions before enter the child. Prepares shared memory provider, hooks and observers.
    ///
    /// # Note
    /// This function is called in **child** process.
    fn pre_run_target_child(&mut self, state: &mut MetaState, input: &MetaInput) -> Result<(), libafl::Error> {
        self.shmem_provider.post_fork(true)?;
        self.enter_target(state, input);
        self.hooks.pre_exec(state, input);
        self.observers.pre_exec_child_all(state, input).expect("Failed to run post_exec on observers");
        Ok(())
    }

    /// Actions after the child exits. Maintains observers and hooks.
    ///
    /// # Note
    /// This function is called in **child** process.
    fn post_run_target_child(&mut self, state: &mut MetaState, input: &MetaInput) {
        self.observers
            .post_exec_child_all(state, input, &ExitKind::Ok)
            .expect("Failed to run post_exec on observers");
        self.hooks.post_exec(state, input);
    }

    /// Parent function in one execution loop.
    fn parent(&mut self, pipe_fd: OwnedFd, child: Pid, input: &MetaInput) -> Result<ExitKind, libafl::Error> {
        let finalize = |simulator: &Simulator, exit_kind: ExitKind| -> Result<ExitKind, libafl::Error> {
            if let Err(err) = simulator.record_run_outcome(matches!(exit_kind, ExitKind::Crash), matches!(exit_kind, ExitKind::Timeout)) {
                warn!("failed to write ablation telemetry: {}", err);
            }
            Ok(exit_kind)
        };

        // setup share memory
        self.shmem_provider.post_fork(false)?;

        // parent will act as controller in the async runtime
        let controller_ret = self.rt.block_on(async { self.simulator.fuzz_once(Some(pipe_fd), Some(child), input).await });

        // kill the child and wait for the child to stop
        let child_ret = if let Ok(ControllerExitReason::ChildExit(exit_reason)) = controller_ret {
            exit_reason
        } else if matches!(controller_ret, Ok(ControllerExitReason::Ok)) && self.executor.keep_child_running_after_controller_ok() {
            // Some executors (for example fuzzware-based ones) need extra time after simulator
            // stops receiving HCI to finish their own dump/modeling side effects.
            waitpid(child, None).map_err(|err| runtime_error(format!("waitpid failed: {}", err)))?
        } else {
            let stop_sig = match controller_ret {
                Ok(ControllerExitReason::Ok) => SIGUSR2,
                _ => SIGALRM,
            };
            kill(child, stop_sig).map_err(|err| runtime_error(format!("kill failed: {}", err)))?;
            match waitpid_with_grace(child, Duration::from_millis(200)).map_err(|err| runtime_error(format!("waitpid grace failed: {}", err)))? {
                Some(status) => status,
                None => {
                    warn!("child pid={} did not exit after {:?}, escalating to SIGKILL", child, stop_sig);
                    kill(child, nix::sys::signal::Signal::SIGKILL).map_err(|err| runtime_error(format!("kill SIGKILL failed: {}", err)))?;
                    waitpid(child, None).map_err(|err| runtime_error(format!("waitpid after SIGKILL failed: {}", err)))?
                }
            }
        };
        trace!("child exit reason: controller={:?} child={:?}", controller_ret, child_ret);

        // check simulator error
        if let Err(err) = &controller_ret {
            match err {
                SimulatorError::TargetCrash => return finalize(self.simulator, ExitKind::Crash),
                SimulatorError::ControllerError(ControllerError::RequestExit) => return finalize(self.simulator, ExitKind::Ok),
                SimulatorError::ControllerError(ControllerError::RequestCrash) => return finalize(self.simulator, ExitKind::Crash),
                // Invalid ACL handle (for example, mutated handle with no active link) is a
                // protocol-state mismatch, not a target process crash. Treat it as normal run to
                // avoid polluting objective/crashes with false positives.
                SimulatorError::ControllerError(ControllerError::InvalidConnection) => return finalize(self.simulator, ExitKind::Ok),
                SimulatorError::ControllerError(ControllerError::CreateFail) => return finalize(self.simulator, ExitKind::Crash),
                SimulatorError::HciError(ProtocolError::TransportFail(TransportError::ReadFail(io_err)))
                | SimulatorError::HciError(ProtocolError::TransportFail(TransportError::WriteFail(io_err))) => {
                    // When target dies, PTY often reports EIO/BrokenPipe before waitpid observes
                    // the signal. Treat this as target crash instead of fuzzer runtime failure.
                    let crash_like = matches!(
                        io_err.kind(),
                        io::ErrorKind::BrokenPipe | io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset
                    ) || io_err.raw_os_error() == Some(libc::EIO);
                    if crash_like {
                        return finalize(self.simulator, ExitKind::Crash);
                    }
                }
                _ => {
                    error!("simulator error: {:?}", err);
                    let crash_input = format!("/tmp/crash-{}.input", std::process::id());
                    if let Err(save_err) = input.to_file(&crash_input) {
                        error!("failed to save crashing input to {}: {}", crash_input, save_err);
                    } else {
                        error!("input is saved to {}", crash_input);
                    }
                    let _ = self.simulator.record_run_outcome(false, false);
                    return Err(libafl::Error::Runtime(format!("simulator error: {:?}", err), ErrorBacktrace::capture()));
                }
            }
        }

        // check return result
        let ret_code = match child_ret {
            WaitStatus::Exited(_, code) => code,
            WaitStatus::Signaled(_, sig, _) => {
                if sig == SIGUSR2 {
                    info!("child terminated by SIGUSR2 (requested normal stop)");
                    MetaExecutorExitReason::Ok as i32
                } else {
                    warn!("child exit because of unhandled signal {:?}", sig);
                    MetaExecutorExitReason::Crash as i32
                }
            }
            _ => {
                return Err(libafl::Error::Runtime(String::from("unexpected child exit reason"), ErrorBacktrace::capture()));
            }
        };

        match ret_code {
            val if val == MetaExecutorExitReason::Crash as i32 => finalize(self.simulator, ExitKind::Crash),
            val if val == MetaExecutorExitReason::Timeout as i32 => finalize(self.simulator, ExitKind::Timeout),
            val if val == MetaExecutorExitReason::Internal as i32 => Err(libafl::Error::Runtime(
                String::from("child exit because of internal error"),
                ErrorBacktrace::capture(),
            )),
            255 => Err(libafl::Error::Runtime(
                String::from("child exit because of internal error"),
                ErrorBacktrace::capture(),
            )),
            _ => finalize(self.simulator, ExitKind::Ok),
        }
    }

    /// Child function in one execution loop.
    fn child(&mut self, pipe_fd: OwnedFd, state: &mut MetaState, input: &MetaInput) -> Result<ExitKind, libafl::Error> {
        // setup hooks, share memory and observers
        self.pre_run_target_child(state, input)?;

        // wait for the running signal via pipe from parent
        trace!("target: waiting for parent signal...");
        let mut buf = [0u8; 1];
        let len = read(&pipe_fd, &mut buf).map_err(|err| runtime_error(format!("pipe read failed: {}", err)))?;
        close(pipe_fd).map_err(|err| runtime_error(format!("pipe close failed: {}", err)))?;
        if len == 0 {
            // failed to read from pipe, do not run the target
            error!("failed to read running signal from pipe");
            unsafe {
                libc::_exit(MetaExecutorExitReason::Internal as i32);
            }
        }

        // jump into fire...
        trace!("target: signal get, start running now");

        match self.executor.run(state, input) {
            Ok(exit_reason) => {
                // unset hooks and obervers after the child exit
                self.post_run_target_child(state, input);
                warn!("meta-executor child pid={} exiting with {:?}", std::process::id(), exit_reason);
                unsafe {
                    libc::_exit(exit_reason as i32);
                }
            }
            Err(err) => {
                error!("child exit with error {:?}", err);
                unsafe {
                    libc::_exit(MetaExecutorExitReason::Internal as i32);
                }
            }
        }
    }
}

fn waitpid_with_grace(pid: Pid, grace: Duration) -> nix::Result<Option<WaitStatus>> {
    let start = Instant::now();
    loop {
        match waitpid(pid, Some(WaitPidFlag::WNOHANG))? {
            WaitStatus::StillAlive => {
                if start.elapsed() >= grace {
                    return Ok(None);
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            status => return Ok(Some(status)),
        }
    }
}

impl<'a, E> Executor<MetaEventManager, MetaInput, MetaState, MetaFuzzer<'a>> for MetaExecutorWrapper<'a, E>
where
    E: MetaExecutor,
{
    fn run_target(&mut self, _: &mut MetaFuzzer<'a>, state: &mut MetaState, _: &mut MetaEventManager, input: &MetaInput) -> Result<ExitKind, libafl::Error> {
        if self.first_exec {
            self.executor.first_exec(state);
            self.first_exec = false;
        }

        self.executor.pre_exec(state, input);

        trace!("start run target");
        let mut exit_kind = unsafe {
            let (read_end, write_end) = pipe().map_err(|err| runtime_error(format!("pipe create failed: {}", err)))?;
            self.shmem_provider.pre_fork()?;
            match fork() {
                // child side
                Ok(ForkResult::Child) => {
                    // child do not use the write side of the pipe
                    close(write_end).map_err(|err| runtime_error(format!("close write end failed: {}", err)))?;
                    self.child(read_end, state, input)?;
                    unreachable!("child should never return from here");
                }
                // parent side
                Ok(ForkResult::Parent { child }) => {
                    // parent do not use the read side of the pipe
                    close(read_end).map_err(|err| runtime_error(format!("close read end failed: {}", err)))?;
                    self.parent(write_end, child, input)
                }
                Err(err) => Err(runtime_error(format!("fork failed: {}", err))),
            }
        }?;

        // Use state.executions as "HCI packets sent to target" instead of fuzz iterations.
        let sent_packets = self.simulator.last_round_sent_hci_packets();
        *state.executions_mut() = state.executions().saturating_add(sent_packets);

        self.executor.post_exec(input, &mut self.observers, state, &mut exit_kind);

        Ok(exit_kind)
    }
}

/// HasObservers trait for MetaExecutorWrapper
impl<'a, E> HasObservers for MetaExecutorWrapper<'a, E> {
    type Observers = MetaObserverTuple;

    fn observers(&self) -> RefIndexable<&Self::Observers, Self::Observers> {
        RefIndexable::from(&self.observers)
    }

    fn observers_mut(&mut self) -> RefIndexable<&mut Self::Observers, Self::Observers> {
        RefIndexable::from(&mut self.observers)
    }
}

/// The global state of the in-process-fork harness.
#[derive(Debug)]
pub(crate) struct MetaExecutorWrapperGlobalData {
    /// Stores a pointer to the fork executor struct
    pub executor_ptr: *const c_void,
    /// Stores a pointer to the state
    pub state_ptr: *const c_void,
    /// Stores a pointer to the current input
    pub current_input_ptr: *const c_void,
    /// Stores a pointer to the `crash_handler` function
    pub crash_handler: *const c_void,
    /// Stores a pointer to the `timeout_handler` function
    pub timeout_handler: *const c_void,
    /// Stores a pointer to the `exit_handler` function
    pub exit_handler: *const c_void,
}
unsafe impl Sync for MetaExecutorWrapperGlobalData {}
unsafe impl Send for MetaExecutorWrapperGlobalData {}

impl MetaExecutorWrapperGlobalData {
    /// # Safety
    /// Only safe if not called twice and if the executor is not used from another borrow after this.
    pub unsafe fn executor_mut<'a, E: MetaExecutor>(&self) -> &'a mut MetaExecutorWrapper<'a, E> {
        unsafe { (self.executor_ptr as *mut MetaExecutorWrapper<'a, E>).as_mut().unwrap() }
    }

    /// # Safety
    /// Only safe if not called twice and if the state is not used from another borrow after this.
    pub unsafe fn state_mut<'a>(&self) -> &'a mut MetaState {
        unsafe { (self.state_ptr as *mut MetaState).as_mut().unwrap() }
    }

    /// # Safety
    /// Only safe if not called concurrently.
    pub unsafe fn take_current_input<'a>(&mut self) -> &'a MetaInput {
        let r = unsafe { (self.current_input_ptr as *const MetaInput).as_ref().unwrap() };
        self.current_input_ptr = null();
        r
    }

    pub fn is_valid(&self) -> bool {
        !self.current_input_ptr.is_null()
    }
}

/// A static variable storing the global state.
/// On parent fuzzer process, all pointers are null so that we skip the hook of signals.
/// On child target process, we set pointers to hook the signals.
static mut FUZZ_EXECUTOR_GLOBAL_DATA: MetaExecutorWrapperGlobalData = MetaExecutorWrapperGlobalData {
    executor_ptr: null(),
    state_ptr: null(),
    current_input_ptr: null(),
    crash_handler: null(),
    timeout_handler: null(),
    exit_handler: null(),
};

type ForkHandlerFuncPtr = unsafe fn(Signal, &mut siginfo_t, Option<&mut ucontext_t>, data: *mut MetaExecutorWrapperGlobalData);

impl SignalHandler for MetaExecutorWrapperGlobalData {
    unsafe fn handle(&mut self, signal: Signal, info: &mut siginfo_t, context: Option<&mut ucontext_t>) {
        match signal {
            // SigAlarm is used for kill when timeout
            Signal::SigAlarm => unsafe {
                if !FUZZ_EXECUTOR_GLOBAL_DATA.timeout_handler.is_null() {
                    let func: ForkHandlerFuncPtr = transmute(FUZZ_EXECUTOR_GLOBAL_DATA.timeout_handler);
                    (func)(signal, info, context, &raw mut FUZZ_EXECUTOR_GLOBAL_DATA);
                }
            },
            // SigUser2 is used for exit normal when request
            Signal::SigUser2 => unsafe {
                if !FUZZ_EXECUTOR_GLOBAL_DATA.exit_handler.is_null() {
                    let func: ForkHandlerFuncPtr = transmute(FUZZ_EXECUTOR_GLOBAL_DATA.exit_handler);
                    (func)(signal, info, context, &raw mut FUZZ_EXECUTOR_GLOBAL_DATA);
                }
            },
            // crash signals
            _ => unsafe {
                if !FUZZ_EXECUTOR_GLOBAL_DATA.crash_handler.is_null() {
                    let func: ForkHandlerFuncPtr = transmute(FUZZ_EXECUTOR_GLOBAL_DATA.crash_handler);
                    (func)(signal, info, context, &raw mut FUZZ_EXECUTOR_GLOBAL_DATA);
                }
            },
        }
    }

    fn signals(&self) -> Vec<Signal> {
        common_signals()
    }
}

/// The executor's hooks.
struct FuzzHooks {
    /// On crash C function pointer
    pub crash_handler: *const c_void,
    /// On timeout C function pointer
    pub timeout_handler: *const c_void,
    /// On exit C function pointer
    pub exit_handler: *const c_void,
}

impl ExecutorHook<MetaInput, MetaState> for FuzzHooks {
    fn init(&mut self, _state: &mut MetaState) {}

    /// Call before running a target.
    fn pre_exec(&mut self, _state: &mut MetaState, _input: &MetaInput) {
        unsafe {
            let data = &raw mut FUZZ_EXECUTOR_GLOBAL_DATA;
            (*data).crash_handler = self.crash_handler;
            (*data).timeout_handler = self.timeout_handler;
            (*data).exit_handler = self.exit_handler;
            compiler_fence(Ordering::SeqCst);
        }
    }

    /// Call after running a target.
    fn post_exec(&mut self, _state: &mut MetaState, _input: &MetaInput) {
        unsafe {
            let data = &raw mut FUZZ_EXECUTOR_GLOBAL_DATA;
            (*data).crash_handler = null();
            (*data).timeout_handler = null();
            (*data).exit_handler = null();
        }
    }
}

impl FuzzHooks {
    pub fn new<'a, E>() -> Result<Self, libafl::Error>
    where
        E: MetaExecutor,
    {
        unsafe {
            let data = &raw mut FUZZ_EXECUTOR_GLOBAL_DATA;
            setup_signal_handler(data)?;
            compiler_fence(Ordering::SeqCst);
            Ok(Self {
                crash_handler: child_crash_handler::<E> as *const c_void,
                timeout_handler: child_timeout_handler::<E> as *const c_void,
                exit_handler: child_exit_handler::<E> as *const c_void,
            })
        }
    }

    /// Replace the hooks with `nop` hooks, deactivating the hooks
    #[allow(dead_code)]
    pub fn nop() -> Self {
        Self {
            crash_handler: null(),
            timeout_handler: null(),
            exit_handler: null(),
        }
    }
}

/// Signal handler for child when CRASH.
unsafe fn child_crash_handler<E: MetaExecutor>(
    _signal: Signal,
    _info: &mut siginfo_t,
    _context: Option<&mut ucontext_t>,
    data: &mut MetaExecutorWrapperGlobalData,
) {
    unsafe {
        if data.is_valid() {
            let executor = data.executor_mut::<E>();
            let mut observers = executor.observers_mut();
            let state = data.state_mut();
            let input = data.take_current_input();
            if let Err(_) = observers.post_exec_child_all(state, input, &ExitKind::Crash) {
                libc::_exit(MetaExecutorExitReason::Internal as i32);
            }
        }
        libc::_exit(MetaExecutorExitReason::Crash as i32);
    }
}

/// Signal handler for child when TIMEOUT. Exit value = Timeout.
///
/// # Note
/// We treat all timeout as successfull run. This behavior is different to the normal fuzzer.
unsafe fn child_timeout_handler<E: MetaExecutor>(
    #[cfg(unix)] _signal: Signal,
    _info: &mut siginfo_t,
    _context: Option<&mut ucontext_t>,
    data: &mut MetaExecutorWrapperGlobalData,
) {
    unsafe {
        if data.is_valid() {
            let executor = data.executor_mut::<E>();
            let mut observers = executor.observers_mut();
            let state = data.state_mut();
            let input = data.take_current_input();
            if let Err(_) = observers.post_exec_child_all(state, input, &ExitKind::Timeout) {
                libc::_exit(MetaExecutorExitReason::Internal as i32);
            }
        }
        libc::_exit(MetaExecutorExitReason::Timeout as i32);
    }
}

/// Signal handler for child EXIT. Exit value = Ok.
unsafe fn child_exit_handler<E: MetaExecutor>(
    #[cfg(unix)] _signal: Signal,
    _info: &mut siginfo_t,
    _context: Option<&mut ucontext_t>,
    data: &mut MetaExecutorWrapperGlobalData,
) {
    unsafe {
        if data.is_valid() {
            let executor = data.executor_mut::<E>();
            let mut observers = executor.observers_mut();
            let state = data.state_mut();
            let input = data.take_current_input();
            if let Err(_) = observers.post_exec_child_all(state, input, &ExitKind::Ok) {
                libc::_exit(MetaExecutorExitReason::Internal as i32);
            }
        }
        libc::_exit(MetaExecutorExitReason::Ok as i32);
    }
}
