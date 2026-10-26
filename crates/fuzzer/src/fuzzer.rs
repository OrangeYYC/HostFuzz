/*!
 * Fuzzer with BLE simulation.
 */
use crate::{MetaEventManager, MetaExecutor, MetaExecutorWrapper, MetaFeedback, MetaObjective, MetaObserverTuple, MetaScheduler, MetaStages, MetaState};
use ble::input::MetaInput;
use simulator::Simulator;

use libafl::{
    Error, Evaluator, EvaluatorObservers, EventProcessor, ExecuteInputResult, ExecutesInput, ExecutionProcessor, Fuzzer, HasFeedback, HasObjective,
    HasScheduler,
    corpus::{Corpus, HasCurrentCorpusId, HasTestcase, Testcase},
    events::{Event, EventConfig, EventFirer, EventReceiver, EventWithStats, ProgressReporter, SendExiting},
    executors::{Executor, ExitKind, HasObservers},
    feedbacks::Feedback,
    observers::ObserversTuple,
    schedulers::Scheduler,
    stages::StagesTuple,
    state::{HasCorpus, HasCurrentTestcase, HasExecutions, HasImported, HasLastFoundTime, HasSolutions, Stoppable},
};
use libafl_bolts::current_time;
use std::time::Duration;
use tracing::debug;

/// Fuzzer with the Meta BLE controller
#[derive(Debug)]
pub struct MetaFuzzer<'a> {
    scheduler: MetaScheduler,
    feedback: MetaFeedback,
    objective: MetaObjective,
    share_objectives: bool,
    simulator: &'a Simulator,
}

impl<'a> MetaFuzzer<'a> {
    pub fn new(scheduler: MetaScheduler, feedback: MetaFeedback, objective: MetaObjective, simulator: &'a Simulator) -> Self {
        Self {
            scheduler,
            feedback,
            objective,
            share_objectives: true,
            simulator,
        }
    }
}

/// HasScheduler trait for MetaFuzzer
impl<'a> HasScheduler<MetaInput, MetaState> for MetaFuzzer<'a> {
    type Scheduler = MetaScheduler;

    fn scheduler(&self) -> &Self::Scheduler {
        &self.scheduler
    }

    fn scheduler_mut(&mut self) -> &mut Self::Scheduler {
        &mut self.scheduler
    }
}

/// HasFeedback trait for MetaFuzzer
impl<'a> HasFeedback for MetaFuzzer<'a> {
    type Feedback = MetaFeedback;

    fn feedback(&self) -> &Self::Feedback {
        &self.feedback
    }

    fn feedback_mut(&mut self) -> &mut Self::Feedback {
        &mut self.feedback
    }
}

/// HasObjective trait for MetaFuzzer
impl<'a> HasObjective for MetaFuzzer<'a> {
    type Objective = MetaObjective;

    fn objective(&self) -> &Self::Objective {
        &self.objective
    }

    fn objective_mut(&mut self) -> &mut Self::Objective {
        &mut self.objective
    }

    fn set_share_objectives(&mut self, share_objectives: bool) {
        self.share_objectives = share_objectives;
    }

    fn share_objectives(&self) -> bool {
        self.share_objectives
    }
}

/// ExecutionProcessor trait for MetaFuzzer
impl<'a> ExecutionProcessor<MetaEventManager, MetaInput, MetaObserverTuple, MetaState> for MetaFuzzer<'a> {
    /// Use object and feedback to check the execution result
    fn check_results(
        &mut self,
        state: &mut MetaState,
        manager: &mut MetaEventManager,
        input: &MetaInput,
        observers: &MetaObserverTuple,
        exit_kind: &ExitKind,
    ) -> Result<ExecuteInputResult, Error> {
        // check for potential solutions
        if self.objective_mut().is_interesting(state, manager, input, observers, exit_kind)? {
            return Ok(ExecuteInputResult::Solution);
        }
        // check for potential corpus
        if self.feedback_mut().is_interesting(state, manager, input, observers, exit_kind)? {
            return Ok(ExecuteInputResult::Corpus);
        }
        Ok(ExecuteInputResult::None)
    }

    /// Post process a testcase depending the testcase execution results
    fn process_execution(
        &mut self,
        state: &mut MetaState,
        manager: &mut MetaEventManager,
        _input: &MetaInput,
        exec_res: &ExecuteInputResult,
        _exit_kind: &ExitKind,
        observers: &MetaObserverTuple,
    ) -> Result<Option<libafl::corpus::CorpusId>, Error> {
        match exec_res {
            ExecuteInputResult::None => Ok(None),
            ExecuteInputResult::Corpus => {
                let mut testcase = Testcase::from(self.simulator.clone_input());
                self.feedback_mut().append_metadata(state, manager, observers, &mut testcase)?;
                let id = state.corpus_mut().add(testcase)?;
                self.scheduler_mut().on_add(state, id)?;
                Ok(Some(id))
            }
            ExecuteInputResult::Solution => {
                // The input is a solution, add it to the respective corpus
                let mut testcase = Testcase::from(self.simulator.clone_input());
                testcase.set_parent_id_optional(*state.corpus().current());
                if let Ok(mut tc) = state.current_testcase_mut() {
                    tc.found_objective();
                }
                self.objective_mut().append_metadata(state, manager, observers, &mut testcase)?;
                state.solutions_mut().add(testcase)?;

                Ok(None)
            }
        }
    }

    fn serialize_and_dispatch(
        &mut self,
        state: &mut MetaState,
        manager: &mut MetaEventManager,
        input: &MetaInput,
        exec_res: &ExecuteInputResult,
        observers: &MetaObserverTuple,
        exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        // Now send off the event
        let observers_buf = match exec_res {
            ExecuteInputResult::Corpus => {
                if manager.should_send() {
                    // TODO set None for fast targets
                    if manager.configuration() == EventConfig::AlwaysUnique {
                        None
                    } else {
                        Some(postcard::to_allocvec(observers)?)
                    }
                } else {
                    None
                }
            }
            _ => None,
        };

        self.dispatch_event(state, manager, input, exec_res, observers_buf, exit_kind)?;
        Ok(())
    }

    fn dispatch_event(
        &mut self,
        state: &mut MetaState,
        manager: &mut MetaEventManager,
        input: &MetaInput,
        exec_res: &ExecuteInputResult,
        observers_buf: Option<Vec<u8>>,
        exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        // Now send off the event
        match exec_res {
            ExecuteInputResult::Corpus => {
                if manager.should_send() {
                    manager.fire(
                        state,
                        EventWithStats::with_current_time(
                            Event::NewTestcase {
                                input: input.clone(),
                                observers_buf,
                                exit_kind: *exit_kind,
                                corpus_size: state.corpus().count(),
                                client_config: manager.configuration(),
                                forward_id: None,
                            },
                            *state.executions(),
                        ),
                    )?;
                }
            }
            ExecuteInputResult::Solution => {
                if manager.should_send() {
                    manager.fire(
                        state,
                        EventWithStats::with_current_time(
                            Event::Objective {
                                input: self.share_objectives.then_some(input.clone()),
                                objective_size: state.solutions().count(),
                            },
                            *state.executions(),
                        ),
                    )?;
                }
            }
            ExecuteInputResult::None => (),
        }

        Ok(())
    }

    fn evaluate_execution(
        &mut self,
        state: &mut MetaState,
        manager: &mut MetaEventManager,
        input: &MetaInput,
        observers: &MetaObserverTuple,
        exit_kind: &ExitKind,
        send_events: bool,
    ) -> Result<(ExecuteInputResult, Option<libafl::corpus::CorpusId>), Error> {
        let exec_res = self.check_results(state, manager, input, observers, exit_kind)?;
        let corpus_id = self.process_execution(state, manager, input, &exec_res, exit_kind, observers)?;
        if send_events {
            self.serialize_and_dispatch(state, manager, input, &exec_res, observers, exit_kind)?;
        }
        if exec_res != ExecuteInputResult::None {
            *state.last_found_time_mut() = current_time();
        }
        Ok((exec_res, corpus_id))
    }
}

/// EvaluatorObservers trait for MetaFuzzer
impl<'a, R> EvaluatorObservers<MetaExecutorWrapper<'a, R>, MetaEventManager, MetaInput, MetaState> for MetaFuzzer<'a>
where
    R: MetaExecutor,
{
    /// Process one input, adding to the respective corpora if needed and firing the right events
    #[inline]
    fn evaluate_input_with_observers(
        &mut self,
        state: &mut MetaState,
        executor: &mut MetaExecutorWrapper<'a, R>,
        manager: &mut MetaEventManager,
        input: &MetaInput,
        send_events: bool,
    ) -> Result<(ExecuteInputResult, Option<libafl::corpus::CorpusId>), Error> {
        let exit_kind = self.execute_input(state, executor, manager, input)?;
        let observers = executor.observers();

        self.scheduler.on_evaluation(state, input, &*observers)?;

        self.evaluate_execution(state, manager, input, &*observers, &exit_kind, send_events)
    }
}

impl<'a, R> Evaluator<MetaExecutorWrapper<'a, R>, MetaEventManager, MetaInput, MetaState> for MetaFuzzer<'a>
where
    R: MetaExecutor,
{
    #[inline]
    fn evaluate_filtered(
        &mut self,
        state: &mut MetaState,
        executor: &mut MetaExecutorWrapper<'a, R>,
        manager: &mut MetaEventManager,
        input: &MetaInput,
    ) -> Result<(ExecuteInputResult, Option<libafl::corpus::CorpusId>), Error> {
        self.evaluate_input(state, executor, manager, input)
    }

    #[inline]
    fn evaluate_input(
        &mut self,
        state: &mut MetaState,
        executor: &mut MetaExecutorWrapper<'a, R>,
        manager: &mut MetaEventManager,
        input: &MetaInput,
    ) -> Result<(ExecuteInputResult, Option<libafl::corpus::CorpusId>), Error> {
        self.evaluate_input_with_observers(state, executor, manager, input, true)
    }

    /// Adds an input, even if it's not considered `interesting` by any of the executors
    /// If you are using inprocess executor, be careful.
    /// Your crash-causing testcase will *NOT* be added into the corpus (only to solution)
    fn add_input(
        &mut self,
        state: &mut MetaState,
        executor: &mut MetaExecutorWrapper<'a, R>,
        manager: &mut MetaEventManager,
        input: MetaInput,
    ) -> Result<libafl::corpus::CorpusId, Error> {
        *state.last_found_time_mut() = current_time();

        let exit_kind = self.execute_input(state, executor, manager, &input)?;
        let observers = executor.observers();
        // Always consider this to be "interesting"
        let mut testcase = Testcase::from(self.simulator.clone_input());
        testcase.set_executions(*state.executions());

        // Maybe a solution
        let is_solution: bool = self.objective_mut().is_interesting(state, manager, &input, &*observers, &exit_kind)?;

        if is_solution {
            self.objective_mut().append_metadata(state, manager, &*observers, &mut testcase)?;
            // we don't care about solution id
            let id = state.solutions_mut().add(testcase)?;

            manager.fire(
                state,
                EventWithStats::with_current_time(
                    Event::Objective {
                        input: self.share_objectives.then_some(input.clone()),
                        objective_size: state.solutions().count(),
                    },
                    *state.executions(),
                ),
            )?;

            return Ok(id);
        }

        // several is_interesting implementations collect some data about the run, later used in
        // append_metadata; we *must* invoke is_interesting here to collect it
        let _corpus_worthy = self.feedback_mut().is_interesting(state, manager, &input, &*observers, &exit_kind)?;

        // Add the input to the main corpus
        self.feedback_mut().append_metadata(state, manager, &*observers, &mut testcase)?;
        let id = state.corpus_mut().add(testcase)?;
        self.scheduler_mut().on_add(state, id)?;

        let observers_buf = if manager.configuration() == EventConfig::AlwaysUnique {
            None
        } else {
            Some(postcard::to_allocvec(&*observers)?)
        };
        manager.fire(
            state,
            EventWithStats::with_current_time(
                Event::NewTestcase {
                    input,
                    observers_buf,
                    exit_kind,
                    corpus_size: state.corpus().count(),
                    client_config: manager.configuration(),
                    forward_id: None,
                },
                *state.executions(),
            ),
        )?;
        Ok(id)
    }

    fn add_disabled_input(&mut self, state: &mut MetaState, input: MetaInput) -> Result<libafl::corpus::CorpusId, Error> {
        let mut testcase = Testcase::from(input.clone());
        testcase.set_executions(*state.executions());
        testcase.set_disabled(true);
        // Add the disabled input to the main corpus
        let id = state.corpus_mut().add_disabled(testcase)?;
        Ok(id)
    }
}

impl<'a, R> EventProcessor<MetaExecutorWrapper<'a, R>, MetaEventManager, MetaInput, MetaState> for MetaFuzzer<'a>
where
    R: MetaExecutor,
{
    fn process_events(&mut self, state: &mut MetaState, executor: &mut MetaExecutorWrapper<'a, R>, manager: &mut MetaEventManager) -> Result<(), Error> {
        // Execute the manager
        while let Some((event, with_observers)) = manager.try_receive(state)? {
            // at this point event is either newtestcase or objectives
            let res = if with_observers {
                match event.event() {
                    Event::NewTestcase {
                        input,
                        observers_buf,
                        exit_kind,
                        ..
                    } => {
                        let observers = postcard::from_bytes(observers_buf.as_ref().unwrap())?;
                        let res = self.evaluate_execution(state, manager, input, &observers, &exit_kind, false)?;
                        res.1
                    }
                    _ => None,
                }
            } else {
                match event.event() {
                    Event::NewTestcase { input, .. } => {
                        let res = self.evaluate_input_with_observers(state, executor, manager, input, false)?;
                        res.1
                    }
                    Event::Objective {
                        input: Some(unwrapped_input), ..
                    } => {
                        let res = self.evaluate_input_with_observers(state, executor, manager, unwrapped_input, false)?;
                        res.1
                    }
                    _ => None,
                }
            };
            if let Some(item) = res {
                *state.imported_mut() += 1;
                debug!("Added received input as item #{item}");

                // for centralize
                manager.on_interesting(state, event)?;
            } else {
                debug!("Received input was discarded");
            }
        }
        Ok(())
    }
}

impl<'a, R> Fuzzer<MetaExecutorWrapper<'a, R>, MetaEventManager, MetaInput, MetaState, MetaStages<'a, R>> for MetaFuzzer<'a>
where
    R: MetaExecutor,
{
    fn fuzz_one(
        &mut self,
        stages: &mut MetaStages<'a, R>,
        executor: &mut MetaExecutorWrapper<'a, R>,
        state: &mut MetaState,
        manager: &mut MetaEventManager,
    ) -> Result<libafl::corpus::CorpusId, Error> {
        // Get the next index from the scheduler
        let id = if let Some(id) = state.current_corpus_id()? {
            id // we are resuming
        } else {
            let id = self.scheduler.next(state)?;
            state.set_corpus_id(id)?; // set up for resume
            id
        };

        // Execute all stages
        stages.perform_all(self, executor, state, manager)?;

        self.process_events(state, executor, manager)?;

        {
            if let Ok(mut testcase) = state.testcase_mut(id) {
                let scheduled_count = testcase.scheduled_count();
                // increase scheduled count, this was fuzz_level in afl
                testcase.set_scheduled_count(scheduled_count + 1);
            }
        }

        state.clear_corpus_id()?;

        if state.stop_requested() {
            state.discard_stop_request();
            manager.on_shutdown()?;
            return Err(Error::shutting_down());
        }

        Ok(id)
    }

    fn fuzz_loop(
        &mut self,
        stages: &mut MetaStages<'a, R>,
        executor: &mut MetaExecutorWrapper<'a, R>,
        state: &mut MetaState,
        manager: &mut MetaEventManager,
    ) -> Result<(), Error> {
        let monitor_timeout = Duration::from_secs(15);
        loop {
            manager.maybe_report_progress(state, monitor_timeout)?;
            self.fuzz_one(stages, executor, state, manager)?;
        }
    }

    fn fuzz_loop_for(
        &mut self,
        stages: &mut MetaStages<'a, R>,
        executor: &mut MetaExecutorWrapper<'a, R>,
        state: &mut MetaState,
        manager: &mut MetaEventManager,
        iters: u64,
    ) -> Result<libafl::corpus::CorpusId, Error> {
        let mut ret = None;
        let monitor_timeout = Duration::from_secs(15);

        for _ in 0..iters {
            manager.maybe_report_progress(state, monitor_timeout)?;
            ret = Some(self.fuzz_one(stages, executor, state, manager)?);
        }

        manager.report_progress(state)?;
        Ok(ret.unwrap())
    }
}

impl<'a, 'de, R> ExecutesInput<MetaExecutorWrapper<'a, R>, MetaEventManager, MetaInput, MetaState> for MetaFuzzer<'a>
where
    R: MetaExecutor,
{
    /// Runs the input and triggers observers and feedback
    fn execute_input(
        &mut self,
        state: &mut MetaState,
        executor: &mut MetaExecutorWrapper<'a, R>,
        event_mgr: &mut MetaEventManager,
        input: &MetaInput,
    ) -> Result<ExitKind, Error> {
        executor.observers_mut().pre_exec_all(state, input)?;
        let exit_kind = executor.run_target(self, state, event_mgr, input)?;
        executor.observers_mut().post_exec_all(state, input, &exit_kind)?;
        Ok(exit_kind)
    }
}
