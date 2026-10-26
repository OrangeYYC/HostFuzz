/*!
 * Executor for ESP32.
 */
use crate::{config::Esp32Config, emulator::Esp32Qemu};
use ble::input::MetaInput;
use fuzzer::{
    executor::{MetaExecutor, MetaExecutorError, MetaExecutorExitReason},
    AppConfig, MetaState, EDGE_MAP_SIZE,
};

use libafl::observers::{CanTrack, ConstMapObserver, HitcountsMapObserver};
use libafl_bolts::tuples::tuple_list;
use libafl_qemu::{command::NopCommand, modules::edges::StdEdgeCoverageChildModule, Emulator, QemuExitReason};
use std::ptr::NonNull;

/// Executor for ESP32.
pub struct Esp32Executor {
    // Pointer to coverage map
    map_ptr: *mut u8,
    // Reusable QEMU command line args
    qemu_args: Vec<String>,
    // AppConfig from parent
    config: Option<AppConfig<Esp32Config>>,
}

impl MetaExecutor for Esp32Executor {
    type MetaExecutorConfig = Esp32Config;

    fn new(config: &AppConfig<Esp32Config>, map_ptr: *mut u8) -> Self {
        Self {
            map_ptr,
            config: Some(config.clone()),
            qemu_args: config.executor.craft_args(),
        }
    }

    fn run(&mut self, state: &mut MetaState, _input: &MetaInput) -> Result<MetaExecutorExitReason, MetaExecutorError> {
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
        let qemu_modules = tuple_list!(StdEdgeCoverageChildModule::builder()
            .const_map_observer(edges_observer.as_mut())
            .build()
            .unwrap(),);

        // create emulator
        let mut emulator = Emulator::<NopCommand, _, _, _, MetaInput, MetaState, _>::empty()
            .qemu_parameters(&self.qemu_args)
            .modules(qemu_modules)
            .build()
            .expect("Failed to build emulator");

        // initialize this emulator
        emulator.first_exec(state);

        // create ESP qemu
        let mut esp_qemu = Esp32Qemu::new(self.config.take().unwrap(), emulator)?;
        match esp_qemu.run()? {
            QemuExitReason::Crash => Ok(MetaExecutorExitReason::Crash),
            _ => Ok(MetaExecutorExitReason::Ok),
        }
    }
}
