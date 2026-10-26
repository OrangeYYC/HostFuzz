/*!
 * Config and hooks for ESP32.
 */
use fuzzer::resolve_path;
use libafl_qemu::GuestAddr;
use serde::Deserialize;
use std::{env, fmt::Debug, path::PathBuf};

/// Heap sanitizer hooks for ESP32.
#[derive(Clone, Debug, Deserialize)]
pub struct SanitizerHooks {
    pub malloc_enter: GuestAddr,
    pub malloc_return: GuestAddr,
    pub calloc_enter: GuestAddr,
    pub calloc_return: GuestAddr,
    pub pv_port_malloc_enter: GuestAddr,
    pub pv_port_malloc_return: GuestAddr,
    pub free_enter: GuestAddr,
    pub v_port_free_enter: GuestAddr,
    pub panic_handler: GuestAddr,
    pub esp_panic_handler: GuestAddr,
    #[serde(default)]
    pub assert: GuestAddr,
    #[serde(default)]
    pub assert_func: GuestAddr,
    pub heap_area: Vec<(GuestAddr /*start*/, GuestAddr /*size*/)>,
    pub code_area: Vec<(GuestAddr /*start*/, GuestAddr /*size*/)>,
}

/// Simulator interaction hooks for ESP32.
#[derive(Clone, Debug, Deserialize)]
pub struct ControllerHooks {
    pub esp_bt_controller_init: GuestAddr,
    pub esp_bt_controller_enable: GuestAddr,
    pub esp_bt_controller_get_status: GuestAddr,
    pub esp_bt_controller_mem_release: GuestAddr,
    pub esp_ble_tx_power_get: GuestAddr,
    pub esp_vhci_host_register_callback: GuestAddr,
    pub esp_vhci_host_check_send_available: GuestAddr,
    pub esp_vhci_host_send_packet: GuestAddr,
}

/// Hooks for ESP32.
#[derive(Clone, Debug, Deserialize)]
pub struct Esp32Hooks {
    pub controller: ControllerHooks,
    pub sanitizer: SanitizerHooks,
}

/// Config for ESP32.
#[derive(Clone, Debug, Deserialize)]
pub struct Esp32Config {
    // Path to the flash.bin of the target
    flash_path: PathBuf,
    // Path to the efuse.bin of the target
    efuse_path: PathBuf,
    // Path to the pc_bios directory which contains the esp32-v3-rom*.bin
    pc_bios_path: PathBuf,
    // Hooks for sanitizer and simulator
    pub hooks: Esp32Hooks,
}

impl Esp32Config {
    /// Formats QEMU flash arg: `file=/path/to/flash,if=mtd,format=raw`.
    fn flash_arg(&self) -> String {
        format!(
            "file={},if=mtd,format=raw",
            resolve_path(&self.flash_path).to_str().expect("invalid flash path")
        )
    }

    /// Formats QEMU efuse arg: `file=/path/to/efuse,if=none,format=raw,id=efuse`.
    fn efuse_arg(&self) -> String {
        format!(
            "file={},if=none,format=raw,id=efuse",
            resolve_path(&self.efuse_path).to_str().expect("invalid efuse path")
        )
    }

    /// Formates QEMU -L option arg which points to BIOS path.
    fn bios_arg(&self) -> String {
        format!("{}", resolve_path(&self.pc_bios_path).to_str().expect("invalid bios path"))
    }

    /// Crafts QEMU command line args.
    pub fn craft_args(&self) -> Vec<String> {
        let current_exe_path = String::from(
            env::current_exe()
                .expect("get current exe path fail")
                .to_str()
                .expect("invalid current exe path"),
        );

        vec![
            current_exe_path,
            String::from("-L"),
            self.bios_arg(),
            String::from("-M"),
            String::from("esp32"),
            String::from("-m"),
            String::from("4M"),
            String::from("-drive"),
            self.flash_arg(),
            String::from("-drive"),
            self.efuse_arg(),
            String::from("-global"),
            String::from("driver=nvram.esp32.efuse,property=drive,value=efuse"),
            String::from("-global"),
            String::from("driver=timer.esp32.timg,property=wdt_disable,value=true"),
            String::from("-nic"),
            String::from("user,model=open_eth"),
            String::from("-nographic"),
            String::from("-serial"),
            String::from("mon:stdio"),
        ]
    }
}
