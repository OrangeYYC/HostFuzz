use crate::{EDGE_MAP_SIZE, MetaState};
use libafl::{
    HasNamedMetadata,
    corpus::Corpus,
    feedbacks::MapFeedbackMetadata,
    state::{HasCorpus, HasExecutions, HasSolutions},
};
use std::{
    fs::{self, File},
    io::{self, BufWriter, Write},
    path::Path,
    time::{Duration, Instant},
};

pub struct CoverageTimelineRecorder {
    writer: BufWriter<File>,
    started_at: Instant,
    interval: Duration,
    next_sample_at: Duration,
    sample_index: u64,
    max_covered_edges: usize,
    case_name: String,
    preset: String,
}

impl CoverageTimelineRecorder {
    pub fn new(dir: &Path, case_name: impl Into<String>, preset: impl Into<String>, interval: Duration) -> io::Result<Self> {
        fs::create_dir_all(dir)?;
        let mut writer = BufWriter::new(File::create(dir.join("coverage_over_time.csv"))?);
        writeln!(
            writer,
            "case_name,preset,sample_kind,sample_index,elapsed_ms,elapsed_bucket_seconds,executions,corpus_size,objective_size,covered_edges,coverage_ratio"
        )?;
        writer.flush()?;

        Ok(Self {
            writer,
            started_at: Instant::now(),
            interval,
            next_sample_at: Duration::ZERO,
            sample_index: 0,
            max_covered_edges: 0,
            case_name: case_name.into(),
            preset: preset.into(),
        })
    }

    pub fn record_initial(&mut self, state: &MetaState, raw_covered_edges: usize) -> io::Result<()> {
        let _ = state;
        let _ = raw_covered_edges;
        self.next_sample_at = self.interval;
        Ok(())
    }

    pub fn record_post_seed(&mut self, state: &MetaState, raw_covered_edges: usize) -> io::Result<()> {
        self.record_sample(state, self.started_at.elapsed(), "post_seed", raw_covered_edges)
    }

    pub fn record_seed_failure(&mut self, state: &MetaState, raw_covered_edges: usize) -> io::Result<()> {
        self.record_sample(state, self.started_at.elapsed(), "seed_failure", raw_covered_edges)
    }

    pub fn maybe_record_periodic(&mut self, state: &MetaState, raw_covered_edges: usize) -> io::Result<()> {
        let elapsed = self.started_at.elapsed();
        if elapsed < self.next_sample_at {
            return Ok(());
        }

        self.record_sample(state, elapsed, "periodic", raw_covered_edges)?;
        while self.next_sample_at <= elapsed {
            self.next_sample_at = self.next_sample_at.saturating_add(self.interval);
        }
        Ok(())
    }

    pub fn record_final(&mut self, state: &MetaState, raw_covered_edges: usize) -> io::Result<()> {
        self.record_sample(state, self.started_at.elapsed(), "final", raw_covered_edges)
    }

    fn record_sample(&mut self, state: &MetaState, elapsed: Duration, sample_kind: &str, raw_covered_edges: usize) -> io::Result<()> {
        let metadata_edges = state
            .named_metadata_map()
            .get::<MapFeedbackMetadata<u8>>("edges")
            .map(|metadata| metadata.num_covered_map_indexes)
            .unwrap_or(0);
        // Prefer LibAFL metadata as the primary source. Fallback to raw bitmap count only
        // when metadata is unavailable. Then enforce monotonic growth for timeline stability.
        let instant_edges = if metadata_edges > 0 {
            metadata_edges
        } else {
            raw_covered_edges
        };
        let covered_edges = self.max_covered_edges.max(instant_edges);
        self.max_covered_edges = covered_edges;
        let coverage_ratio = covered_edges as f64 / EDGE_MAP_SIZE as f64;
        let elapsed_bucket_seconds = if self.interval.is_zero() {
            elapsed.as_secs()
        } else {
            let bucket = self.interval.as_secs().max(1);
            (elapsed.as_secs() / bucket) * bucket
        };

        writeln!(
            self.writer,
            "{},{},{},{},{},{},{},{},{},{},{:.6}",
            self.case_name,
            self.preset,
            sample_kind,
            self.sample_index,
            elapsed.as_millis(),
            elapsed_bucket_seconds,
            *state.executions(),
            state.corpus().count(),
            state.solutions().count(),
            covered_edges,
            coverage_ratio,
        )?;
        self.writer.flush()?;
        self.sample_index = self.sample_index.saturating_add(1);
        Ok(())
    }
}
