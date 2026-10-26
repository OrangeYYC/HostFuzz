/*!
 * General functions to implement an application with run, fuzz and coverage mode.
 */
use crate::{
    CoverageTimelineRecorder, EDGE_MAP_SIZE, MetaCorpus, MetaEventManager, MetaExecutor, MetaExecutorWrapper, MetaFuzzer, MetaMapFeedback, MetaMonitor,
    MetaMutator, MetaObjective, MetaShmemProvider, MetaSolutions, MetaState, MetaTimeFeedback, MetaTimeObserver,
};
use ble::input::MetaInput;
use simulator::{Simulator, SimulatorConfig};

use clap::{Arg, Command};
use libafl::{
    Evaluator, Fuzzer, HasFeedback, HasScheduler,
    corpus::Corpus,
    corpus::Testcase,
    events::ProgressReporter,
    executors::{ExitKind, HasObservers},
    feedback_or,
    feedbacks::Feedback,
    inputs::Input,
    observers::{CanTrack, ConstMapObserver, HitcountsMapObserver},
    schedulers::{IndexesLenTimeMinimizerScheduler, PowerQueueScheduler, Scheduler, powersched::PowerSchedule},
    stages::StdMutationalStage,
    state::HasCorpus,
    state::HasExecutions,
};
use libafl_bolts::{
    AsSliceMut,
    rands::StdRand,
    shmem::{ShMem, ShMemProvider},
    tuples::tuple_list,
};
use serde::Deserialize;
use std::{
    env, fs,
    path::{Path, PathBuf},
    ptr::NonNull,
    sync::{
        OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tempfile::tempdir;
use tracing::warn;
use tracing_subscriber::EnvFilter;

/// Config for the fuzzer.
#[derive(Clone, Debug, Deserialize)]
pub struct FuzzerConfig {
    // Path to the working directory
    pub work_dir: String,
}

/// Config for the application. Fuzzer with different executor can use `AppConfig<E>` to group their
/// own config with type `E`.
#[derive(Clone, Debug, Deserialize)]
pub struct AppConfig<E> {
    // Config for fuzzer
    pub fuzzer: FuzzerConfig,
    // Config for Simulator
    pub simulator: SimulatorConfig,
    // Config for Executor
    pub executor: E,
}

/// Main entry to application. `E` is the type of the `MetaExecutor`, see [`MetaExecutor`].
pub fn app<E: MetaExecutor>() {
    let cmd_args = Command::new("MetaBLE APP")
        .arg(
            Arg::new("run")
                .short('r')
                .long("run")
                .help("Run the target with single input")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("fuzz")
                .short('f')
                .long("fuzz")
                .help("Fuzz the target")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("coverage")
                .short('c')
                .long("coverage")
                .help("Check the covergae of the target with given input")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("log")
                .short('l')
                .long("log")
                .help("Log level: trace, debug, info, warn, error(default)"),
        )
        .arg(Arg::new("target").required(true).index(1).help("Path to the config file of the target"))
        .arg(Arg::new("input").index(2).help("Path to the input file"))
        .arg(Arg::new("output").index(3).help("Path to the output file"))
        .get_matches();

    // set log level
    let default_log_level = String::from("error");
    let log_level = cmd_args.get_one::<String>("log").unwrap_or_else(|| &default_log_level);
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive(log_level.parse().unwrap()))
        .init();

    // check application mode, should be one of "run", "fuzz" or "coverage"
    let run = cmd_args.get_flag("run");
    let fuzz = cmd_args.get_flag("fuzz");
    let coverage = cmd_args.get_flag("coverage");
    if run as u8 + fuzz as u8 + coverage as u8 != 1 {
        panic!("only one option in run, fuzz and coverage should be set");
    }

    // check target config file
    let target = cmd_args.get_one::<String>("target").expect("option target is missing");
    CONFIG_FILE_PATH.set(target.clone()).unwrap();
    let content = fs::read_to_string(target).expect("failed to read target config");
    let mut config: AppConfig<E::MetaExecutorConfig> = serde_yaml::from_str(&content).unwrap();
    apply_fuzz_work_dir_override(&mut config.fuzzer.work_dir);
    let case_name = Path::new(target)
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("unknown_case")
        .to_string();
    if config.simulator.ablation.case_name.is_none() {
        config.simulator.ablation.case_name = Some(case_name.clone());
    }
    if config.simulator.ablation.record_telemetry {
        let telemetry_dir = if let Some(dir) = config.simulator.ablation.telemetry_dir.clone() {
            resolve_path(&PathBuf::from(dir))
        } else {
            resolve_path(&PathBuf::from(format!("./ablation-results/{}", case_name)))
        };
        fs::create_dir_all(&telemetry_dir).expect("failed to create telemetry output dir");
        fs::write(telemetry_dir.join("config.snapshot.yaml"), &content).expect("failed to write telemetry config snapshot");
        config.simulator.ablation.telemetry_dir = Some(telemetry_dir.to_string_lossy().into_owned());
    }

    // create simulator
    let simulator = Simulator::new(&config.simulator, run);

    if fuzz {
        install_shutdown_signal_handlers();
        return fuzz_mode::<E>(config, simulator);
    }

    let input = cmd_args.get_one::<String>("input").expect("option input is missing");
    let output = cmd_args.get_one::<String>("output").expect("option output is missing");

    if run {
        return run_mode::<E>(config, simulator, input, output);
    } else {
        return coverage_mode::<E>(config, simulator, input, output);
    }
}

fn run_mode<E: MetaExecutor>(config: AppConfig<E::MetaExecutorConfig>, simulator: Simulator, input: &String, output: &String) {
    let corpus_dir = tempdir().expect("failed to get temp dir for input");
    let objective_dir = tempdir().expect("failed to get temp dir for objective");

    // create shared memory for edges
    let mut shmem_provider = MetaShmemProvider::new().expect("failed to create shared memory provider");
    let mut edges_shmem = shmem_provider.new_shmem(EDGE_MAP_SIZE).expect("failed to create shared memory for coverage");
    unsafe {
        edges_shmem
            .write_to_env("__AFL_SHM_ID")
            .expect("failed to export edge map shared memory to __AFL_SHM_ID");
    }
    let edges = edges_shmem.as_slice_mut();
    let edge_map_ptr = edges.as_mut_ptr();

    // create an event manager with simple monitor
    let mut event_manager = MetaEventManager::new(MetaMonitor::new(monitor_print_fn));

    // create observers
    let edges_observer = unsafe {
        HitcountsMapObserver::new(ConstMapObserver::from_mut_ptr(
            "edges",
            NonNull::new(edges.as_mut_ptr())
                .expect("coverage edge map pointer is null.")
                .cast::<[u8; EDGE_MAP_SIZE]>(),
        ))
        .track_indices()
    };
    let time_observer = MetaTimeObserver::new("time");

    // create feedback and objective
    let mut feedback = feedback_or!(MetaMapFeedback::new(&edges_observer), MetaTimeFeedback::new(&time_observer));
    let mut objective = MetaObjective::new();

    // create executor with config and edge map
    let meta_executor = E::new(&config, edge_map_ptr);

    // create state
    let mut state = MetaState::new(
        configured_rand(),
        MetaCorpus::new(&corpus_dir).unwrap(),
        MetaSolutions::new(&objective_dir).unwrap(),
        &mut feedback,
        &mut objective,
    )
    .unwrap();

    // create scheduler
    let scheduler = IndexesLenTimeMinimizerScheduler::new(&edges_observer, PowerQueueScheduler::new(&mut state, &edges_observer, PowerSchedule::fast()));

    // create executor
    let mut executor = MetaExecutorWrapper::new(
        meta_executor,
        &simulator,
        &mut state,
        shmem_provider,
        tuple_list!(edges_observer, time_observer),
    )
    .unwrap();

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = MetaFuzzer::new(scheduler, feedback, objective, &simulator);
    fuzzer
        .add_input(
            &mut state,
            &mut executor,
            &mut event_manager,
            MetaInput::from_file(input).expect("failed to load input from file"),
        )
        .expect("failed to execute input");

    simulator.pcap_dumper().dump(&output);
}

fn coverage_mode<E: MetaExecutor>(_config: AppConfig<E::MetaExecutorConfig>, _simulator: Simulator, _input: &String, _output: &String) {}

fn fuzz_mode<E: MetaExecutor>(config: AppConfig<E::MetaExecutorConfig>, simulator: Simulator) {
    // create and check the output directory
    let mut corpus_dir = resolve_path(&PathBuf::from(&format!(
        "{}-{}",
        config.fuzzer.work_dir,
        chrono::Local::now().format("%Y-%m-%d-%H-%M-%S").to_string()
    )));
    if fs::create_dir(&corpus_dir).is_err() {
        if !corpus_dir.is_dir() {
            panic!("output dir at {:?} is not a valid directory!", &corpus_dir);
        } else {
            panic!("output dir at {:?} already exists", &corpus_dir);
        }
    }
    let mut objective_dir = corpus_dir.clone();
    objective_dir.push("crashes");
    corpus_dir.push("queue");

    // create shared memory for edges
    let mut shmem_provider = MetaShmemProvider::new().expect("failed to create shared memory provider");
    let mut edges_shmem = shmem_provider.new_shmem(EDGE_MAP_SIZE).expect("failed to create shared memory for coverage");
    unsafe {
        edges_shmem
            .write_to_env("__AFL_SHM_ID")
            .expect("failed to export edge map shared memory to __AFL_SHM_ID");
    }
    let edges = edges_shmem.as_slice_mut();
    let edge_map_ptr = edges.as_mut_ptr();

    // create an event manager with simple monitor
    let mut event_manager = MetaEventManager::new(MetaMonitor::new(monitor_print_fn));

    // create observers
    let edges_observer = unsafe {
        HitcountsMapObserver::new(ConstMapObserver::from_mut_ptr(
            "edges",
            NonNull::new(edges.as_mut_ptr())
                .expect("coverage edge map pointer is null.")
                .cast::<[u8; EDGE_MAP_SIZE]>(),
        ))
        .track_indices()
    };
    let time_observer = MetaTimeObserver::new("time");

    // create feedback and objective
    let mut feedback = feedback_or!(MetaMapFeedback::new(&edges_observer), MetaTimeFeedback::new(&time_observer));
    let mut objective = MetaObjective::new();

    // create executor with config and edge map
    let meta_executor = E::new(&config, edge_map_ptr);

    // create state
    let mut state = MetaState::new(
        configured_rand(),
        MetaCorpus::new(&corpus_dir).unwrap(),
        MetaSolutions::new(&objective_dir).unwrap(),
        &mut feedback,
        &mut objective,
    )
    .unwrap();

    let case_name = config.simulator.ablation.case_name.clone().unwrap_or_else(|| String::from("unknown_case"));
    let preset_name = config.simulator.ablation.mode.as_str().to_string();
    let mut coverage_timeline = config
        .simulator
        .ablation
        .telemetry_dir
        .as_ref()
        .map(PathBuf::from)
        .filter(|_| config.simulator.ablation.record_telemetry)
        .map(|dir| CoverageTimelineRecorder::new(&dir, case_name.clone(), preset_name.clone(), coverage_sample_interval()))
        .transpose()
        .expect("failed to initialize coverage-over-time recorder");
    if let Some(recorder) = coverage_timeline.as_mut() {
        recorder
            .record_initial(&state, current_raw_covered_edges(edges))
            .expect("failed to write initial coverage sample");
    }

    // create mutator and stages
    let mutator = StdMutationalStage::new(MetaMutator::new(&simulator));
    let mut stages = tuple_list!(mutator);

    // create scheduler
    let scheduler = IndexesLenTimeMinimizerScheduler::new(&edges_observer, PowerQueueScheduler::new(&mut state, &edges_observer, PowerSchedule::fast()));

    // create executor
    let mut executor = MetaExecutorWrapper::new(
        meta_executor,
        &simulator,
        &mut state,
        shmem_provider,
        tuple_list!(edges_observer, time_observer),
    )
    .unwrap();

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = MetaFuzzer::new(scheduler, feedback, objective, &simulator);
    let initial_input_opt = configured_initial_input();
    let initial_input_from_env = initial_input_opt.is_some();
    let mut initial_input = initial_input_opt.unwrap_or_else(MetaInput::blank);
    let module_flags = config.simulator.module_flags();
    if !initial_input_from_env {
        if let Some(version) = config.simulator.initial_local_version_information.clone() {
            *initial_input.local_version_information_mut() = version.clone();
            initial_input.version_mutation_state_mut().next_hci_subversion = version.hci_subversion.wrapping_add(1);
        }
    } else {
        // Preserve replay/bootstrap seed metadata when initial input is provided explicitly.
        initial_input.normalize_vendor_response_marks();
    }
    if config.simulator.freeze_version_mutation || !module_flags.enable_vendor_bootstrap_search {
        initial_input.version_mutation_state_mut().freeze = true;
        initial_input.version_mutation_state_mut().prioritize_hci_subversion = false;
    }
    if config.simulator.freeze_vendor_response_mutation || !module_flags.enable_vendor_response_marking {
        initial_input.vendor_response_mutation_state_mut().freeze = true;
        initial_input.vendor_response_mutation_state_mut().prioritize = false;
    }
    // Some targets classify the first blank seed as a crash/objective and leave corpus empty.
    // Retry a few nearby subversions so fuzz loop can always start with at least one corpus item.
    let mut seed_input = initial_input;
    let mut seeded = false;
    let mut seed_rescue_input: Option<MetaInput> = None;
    for attempt in 0..100u16 {
        fuzzer
            .add_input(&mut state, &mut executor, &mut event_manager, seed_input.clone())
            .expect("failed to add initial input");
        if state.corpus().count() > 0 {
            seeded = true;
            break;
        }
        let rescue_candidate = simulator.clone_input();
        if !rescue_candidate.phases().is_empty() {
            seed_rescue_input = Some(rescue_candidate);
        }
        if !config.simulator.freeze_version_mutation && module_flags.enable_vendor_bootstrap_search {
            let next = seed_input.local_version_information().hci_subversion.wrapping_add(1);
            seed_input.local_version_information_mut().hci_subversion = next;
            seed_input.version_mutation_state_mut().next_hci_subversion = next.wrapping_add(1);
            println!(
                "[seed-retry] initial input hit objective, retry {}/100 with hci_subversion=0x{:04x}",
                attempt + 1,
                next
            );
        }
    }
    if !seeded && module_flags.enable_random_hci_floor {
        if let Some(rescue_input) = seed_rescue_input.take() {
            let mut testcase = Testcase::from(rescue_input);
            testcase.set_executions(*state.executions());
            let observers = executor.observers();
            let rescue_exit_kind = ExitKind::Crash;
            let _ = fuzzer
                .feedback_mut()
                .is_interesting(
                    &mut state,
                    &mut event_manager,
                    testcase.input().as_ref().unwrap(),
                    &*observers,
                    &rescue_exit_kind,
                )
                .expect("failed to evaluate rescue seed feedback");
            fuzzer
                .feedback_mut()
                .append_metadata(&mut state, &mut event_manager, &*observers, &mut testcase)
                .expect("failed to append rescue seed metadata");
            let id = state.corpus_mut().add(testcase).expect("failed to add rescue seed to corpus");
            fuzzer.scheduler_mut().on_add(&mut state, id).expect("failed to schedule rescue seed");
            seeded = true;
            println!("[seed-rescue] inserted last objective input into corpus for hci_random_floor");
        }
    }
    if !seeded && initial_input_from_env {
        if let Some(rescue_input) = seed_rescue_input.take() {
            let mut testcase = Testcase::from(rescue_input);
            testcase.set_executions(*state.executions());
            let observers = executor.observers();
            let rescue_exit_kind = ExitKind::Crash;
            let _ = fuzzer
                .feedback_mut()
                .is_interesting(
                    &mut state,
                    &mut event_manager,
                    testcase.input().as_ref().unwrap(),
                    &*observers,
                    &rescue_exit_kind,
                )
                .expect("failed to evaluate env seed feedback");
            fuzzer
                .feedback_mut()
                .append_metadata(&mut state, &mut event_manager, &*observers, &mut testcase)
                .expect("failed to append env seed metadata");
            let id = state.corpus_mut().add(testcase).expect("failed to add env seed to corpus");
            fuzzer.scheduler_mut().on_add(&mut state, id).expect("failed to schedule env seed");
            seeded = true;
            println!("[seed-rescue] inserted last objective input into corpus for env-provided initial seed");
        }
    }
    if !seeded {
        if let Some(recorder) = coverage_timeline.as_mut() {
            let raw_covered_edges = current_raw_covered_edges(edges);
            recorder
                .record_seed_failure(&state, raw_covered_edges)
                .expect("failed to write seed-failure coverage sample");
            recorder
                .record_final(&state, raw_covered_edges)
                .expect("failed to write final coverage sample after seed failure");
        }
        panic!("failed to seed corpus after 100 attempts");
    }
    if let Some(recorder) = coverage_timeline.as_mut() {
        recorder
            .record_post_seed(&state, current_raw_covered_edges(edges))
            .expect("failed to write post-seed coverage sample");
    }

    let monitor_timeout = Duration::from_secs(15);
    loop {
        if shutdown_requested() {
            if let Some(recorder) = coverage_timeline.as_mut() {
                recorder
                    .record_final(&state, current_raw_covered_edges(edges))
                    .expect("failed to write final coverage sample after shutdown signal");
            }
            break;
        }

        event_manager
            .maybe_report_progress(&mut state, monitor_timeout)
            .expect("failed to report fuzz progress");

        match fuzzer.fuzz_one(&mut stages, &mut executor, &mut state, &mut event_manager) {
            Ok(_) => {
                if let Some(recorder) = coverage_timeline.as_mut() {
                    recorder
                        .maybe_record_periodic(&state, current_raw_covered_edges(edges))
                        .expect("failed to write periodic coverage sample");
                }
                if shutdown_requested() {
                    if let Some(recorder) = coverage_timeline.as_mut() {
                        recorder
                            .record_final(&state, current_raw_covered_edges(edges))
                            .expect("failed to write final coverage sample after shutdown signal");
                    }
                    break;
                }
            }
            Err(libafl::Error::ShuttingDown) => {
                if let Some(recorder) = coverage_timeline.as_mut() {
                    recorder
                        .record_final(&state, current_raw_covered_edges(edges))
                        .expect("failed to write final coverage sample");
                }
                break;
            }
            Err(err) => {
                if let Some(recorder) = coverage_timeline.as_mut() {
                    let raw_covered_edges = current_raw_covered_edges(edges);
                    if let Err(io_err) = recorder.record_final(&state, raw_covered_edges) {
                        warn!("failed to write final coverage sample after fuzz error: {}", io_err);
                    }
                }
                panic!("error in the fuzzing loop: {}", err);
            }
        }
    }
}

fn current_raw_covered_edges(edges: &[u8]) -> usize {
    edges.iter().filter(|&&value| value != 0).count()
}

fn parse_seed(raw: &str) -> Option<u64> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(hex) = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")) {
        return u64::from_str_radix(hex, 16).ok();
    }
    trimmed.parse::<u64>().ok()
}

fn configured_initial_input() -> Option<MetaInput> {
    for key in ["VIRTBLE_INITIAL_INPUT", "INITIAL_INPUT", "FUZZ_INITIAL_INPUT"] {
        let Ok(raw) = env::var(key) else {
            continue;
        };
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        let path = resolve_path(&PathBuf::from(trimmed));
        if !path.is_file() {
            warn!("ignoring initial input from {}={}, file not found", key, path.display());
            continue;
        }
        match MetaInput::from_file(path.to_string_lossy().as_ref()) {
            Ok(mut input) => {
                input.normalize_vendor_response_marks();
                warn!("using initial fuzz input from {}={}", key, path.display());
                return Some(input);
            }
            Err(err) => {
                warn!("failed to load initial input from {}={}: {}", key, path.display(), err);
            }
        }
    }
    None
}

const DEFAULT_FUZZ_SEED: u64 = 12345;

fn configured_seed() -> u64 {
    for key in ["VIRTBLE_FUZZ_SEED", "FUZZ_SEED"] {
        let Ok(raw) = env::var(key) else {
            continue;
        };
        if raw.trim().is_empty() {
            continue;
        }
        match parse_seed(&raw) {
            Some(seed) => {
                warn!("using deterministic fuzz seed from {}={}", key, seed);
                return seed;
            }
            None => {
                warn!(
                    "ignoring invalid fuzz seed in {}={:?}, fallback to default {}",
                    key, raw, DEFAULT_FUZZ_SEED
                );
            }
        }
    }
    warn!(
        "no fuzz seed configured in env, using default deterministic fuzz seed={}",
        DEFAULT_FUZZ_SEED
    );
    DEFAULT_FUZZ_SEED
}

fn configured_rand() -> StdRand {
    StdRand::with_seed(configured_seed())
}

static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);
static SHUTDOWN_HANDLER_INSTALLED: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_shutdown_signal(_signal: i32) {
    SHUTDOWN_REQUESTED.store(true, Ordering::Relaxed);
}

fn install_shutdown_signal_handlers() {
    use nix::sys::signal::{SaFlags, SigAction, SigHandler, SigSet, Signal, sigaction};

    if SHUTDOWN_HANDLER_INSTALLED.swap(true, Ordering::SeqCst) {
        SHUTDOWN_REQUESTED.store(false, Ordering::Relaxed);
        return;
    }

    SHUTDOWN_REQUESTED.store(false, Ordering::Relaxed);
    let action = SigAction::new(SigHandler::Handler(handle_shutdown_signal), SaFlags::empty(), SigSet::empty());
    unsafe {
        sigaction(Signal::SIGINT, &action).expect("failed to install SIGINT handler");
        sigaction(Signal::SIGTERM, &action).expect("failed to install SIGTERM handler");
    }
}

fn shutdown_requested() -> bool {
    SHUTDOWN_REQUESTED.load(Ordering::Relaxed)
}

fn monitor_print_fn(message: &str) {
    println!("{}", message)
}

fn apply_fuzz_work_dir_override(work_dir: &mut String) {
    let override_dir = ["VIRTBLE_FUZZ_WORK_DIR", "FUZZ_WORK_ROOT"]
        .into_iter()
        .find_map(|key| env::var(key).ok())
        .filter(|value| !value.trim().is_empty());
    if let Some(dir) = override_dir {
        *work_dir = resolve_path(&PathBuf::from(dir)).to_string_lossy().into_owned();
    }
}

fn coverage_sample_interval() -> Duration {
    let secs = env::var("VIRTBLE_COVERAGE_INTERVAL_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(5);
    Duration::from_secs(secs)
}

static CONFIG_FILE_PATH: OnceLock<String> = OnceLock::new();

/// Transfers relative path in config yaml file into absolute path.
pub fn resolve_path(path_str: &PathBuf) -> PathBuf {
    let config_path = Path::new(CONFIG_FILE_PATH.get().unwrap());
    let path = Path::new(path_str);

    if path.is_absolute() {
        path.to_path_buf()
    } else {
        let base_dir_override = env::var("VIRTBLE_CFG_BASE_DIR")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(PathBuf::from);
        let base_dir = base_dir_override
            .as_deref()
            .unwrap_or_else(|| config_path.parent().expect("config path must have a parent directory"));
        base_dir.join(path).canonicalize().unwrap_or_else(|_| base_dir.join(path))
    }
}
