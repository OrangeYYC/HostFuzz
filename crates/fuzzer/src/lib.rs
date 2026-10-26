use ble::input::MetaInput;

use libafl::{
    corpus::{InMemoryOnDiskCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    feedbacks::{CombinedFeedback, CrashFeedback, LogicEagerOr, MaxMapFeedback, TimeFeedback},
    monitors::SimpleMonitor,
    observers::{ConstMapObserver, ExplicitTracking, HitcountsMapObserver, TimeObserver},
    schedulers::{IndexesLenTimeMinimizerScheduler, PowerQueueScheduler},
    stages::StdMutationalStage,
    state::StdState,
};
use libafl_bolts::{
    rands::StdRand,
    shmem::{StdShMem, StdShMemProvider},
};

pub const EDGE_MAP_SIZE: usize = 65536;

pub type MetaShmem = StdShMem;

pub type MetaShmemProvider = StdShMemProvider;

pub type MetaMonitor = SimpleMonitor<fn(&str)>;

pub type MetaEventManager = SimpleEventManager<MetaInput, MetaMonitor, MetaState>;

pub type MetaEdgeObserverInner = HitcountsMapObserver<ConstMapObserver<'static, u8, EDGE_MAP_SIZE>>;

pub type MetaEdgeObserver = ExplicitTracking<MetaEdgeObserverInner, true, false>;

pub type MetaTimeObserver = TimeObserver;

pub type MetaObserverTuple = (MetaEdgeObserver, (MetaTimeObserver, ()));

pub type MetaMapFeedback = MaxMapFeedback<MetaEdgeObserver, HitcountsMapObserver<ConstMapObserver<'static, u8, EDGE_MAP_SIZE>>>;

pub type MetaTimeFeedback = TimeFeedback;

pub type MetaFeedback = CombinedFeedback<MetaMapFeedback, MetaTimeFeedback, LogicEagerOr>;

pub type MetaObjective = CrashFeedback;

pub type MetaCorpus = InMemoryOnDiskCorpus<MetaInput>;

pub type MetaSolutions = OnDiskCorpus<MetaInput>;

pub type MetaState = StdState<MetaCorpus, MetaInput, StdRand, MetaSolutions>;

pub type MetaScheduler = IndexesLenTimeMinimizerScheduler<PowerQueueScheduler<MetaEdgeObserver, MetaEdgeObserverInner>, MetaInput, MetaEdgeObserver>;

pub type MetaStages<'a, R> = (
    StdMutationalStage<MetaExecutorWrapper<'a, R>, MetaEventManager, MetaInput, MetaInput, MetaMutator<'a>, MetaState, MetaFuzzer<'a>>,
    (),
);

pub mod campaign;
pub use campaign::CoverageTimelineRecorder;

pub mod executor;
pub use executor::{MetaExecutor, MetaExecutorError, MetaExecutorExitReason, MetaExecutorWrapper};

pub mod fuzzer;
pub use fuzzer::MetaFuzzer;

pub mod mutator;
pub use mutator::MetaMutator;

pub mod app;
pub use app::{AppConfig, FuzzerConfig, app, resolve_path};
