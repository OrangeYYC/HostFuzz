use crate::executor::Esp32Executor;

fn ensure_qemu_xtensa_window_regs() {
    unsafe {
        libc::setenv(c"QEMU_XTENSA_COUNT_WINDOW_REGS".as_ptr(), c"1".as_ptr(), 1);
    }
}

// QEMU's Xtensa core registration runs from C constructors before `main`.
// Install the env var in an earlier init-array slot so direct binary launches
// behave the same as `cargo run`.
#[used]
#[cfg_attr(target_os = "linux", unsafe(link_section = ".init_array.00099"))]
static INIT_QEMU_XTENSA_WINDOW_REGS: extern "C" fn() = {
    extern "C" fn init() {
        ensure_qemu_xtensa_window_regs();
    }
    init
};

pub fn app() {
    ensure_qemu_xtensa_window_regs();
    fuzzer::app::<Esp32Executor>();
}
