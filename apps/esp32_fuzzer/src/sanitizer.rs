/*!
 * Heap sanitizer for ESP32.
 */
use crate::config::SanitizerHooks;
use fuzzer::executor::MetaExecutorExitReason;

use libafl_qemu::{GuestAddr, Qemu, QemuHooks, Regs};
use spin::Lazy;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::{collections::BTreeMap, ops::Range};
use tracing::{error, trace, warn};

static HEAP_SAN: Lazy<Mutex<HeapSanitizer>> = Lazy::new(|| Mutex::new(HeapSanitizer::new()));

#[derive(Clone, Debug)]
#[repr(u8)]
pub enum CheckRangeReturn {
    InUse,
    Overlap,
    Free,
}

impl CheckRangeReturn {
    /// If the range is not in use or overlap, returns `true`.
    pub fn valid_for_alloc(&self) -> bool {
        match &self {
            Self::Free => true,
            _ => false,
        }
    }
}

/// ESP32 Sanitizer for heap management.
pub struct HeapSanitizer {
    mem_blocks: BTreeMap<GuestAddr, Range<GuestAddr>>,
    heap_areas: Vec<Range<GuestAddr>>,
    code_areas: Vec<Range<GuestAddr>>,
}

impl HeapSanitizer {
    /// Gets the global sanitizer.
    pub fn get<'a>() -> MutexGuard<'a, HeapSanitizer> {
        HEAP_SAN.lock().unwrap()
    }

    // Registers read/write and instruction hooks to impl sanitizer.
    pub fn register_hooks<'a>(hook_addrs: &'a SanitizerHooks) {
        // reset
        let mut san = HeapSanitizer::get();
        san.reset();
        for area in &hook_addrs.heap_area {
            san.add_heap_area(area.0..(area.0 + area.1));
        }
        for area in &hook_addrs.code_area {
            san.add_code_area(area.0..(area.0 + area.1));
        }

        let hooks = QemuHooks::get().unwrap();
        // hook `malloc` and `pv_port_malloc` enter
        for addr in vec![hook_addrs.malloc_enter, hook_addrs.pv_port_malloc_enter] {
            hooks.add_instruction_hooks(0u64, addr, on_malloc_enter, false);
        }
        // hook `calloc` enter
        hooks.add_instruction_hooks(0u64, hook_addrs.calloc_enter, on_calloc_enter, false);
        // hook `malloc`, `calloc` and `pv_port_malloc` return
        for addr in vec![hook_addrs.malloc_return, hook_addrs.calloc_return, hook_addrs.pv_port_malloc_return] {
            hooks.add_instruction_hooks(0u64, addr, on_alloc_return, false);
        }
        // hook `free` and `v_port_free` enter
        for addr in vec![hook_addrs.free_enter, hook_addrs.v_port_free_enter] {
            hooks.add_instruction_hooks(0u64, addr, on_free_enter, false);
        }
        // hook memory read
        hooks.add_read_hooks(0u64, None, None, None, None, None, Some(on_mem_read));
        // hook memory write
        hooks.add_write_hooks(0u64, None, None, None, None, None, Some(on_mem_write));
    }

    /// Clears all memory blocks.
    pub fn reset(&mut self) {
        self.mem_blocks.clear();
        self.heap_areas.clear();
        self.code_areas.clear();
    }

    /// Adds `range` to interesting code.
    pub fn add_code_area(&mut self, range: Range<GuestAddr>) {
        self.code_areas.push(range);
    }

    /// Adds `range` to heap area.
    pub fn add_heap_area(&mut self, range: Range<GuestAddr>) {
        self.heap_areas.push(range);
    }

    /// Returns `true` if the `pc` is in interesting code range and `addr` is in heap.
    pub fn is_interested(&self, pc: GuestAddr, addr: GuestAddr) -> bool {
        self.is_in_heap(addr) && self.is_in_code_area(pc)
    }

    /// Checks if the range [`start`, `end`) belongs to a valid memory block.
    pub fn check_range(&mut self, range: &Range<GuestAddr>) -> CheckRangeReturn {
        for (_, block) in self.mem_blocks.range(0..range.end).rev() {
            // sub-range in current memory block
            if block.start <= range.start && block.end >= range.end {
                return CheckRangeReturn::InUse;
            }
            // cross the lower boundary
            if block.start >= range.start && block.start < range.end {
                return CheckRangeReturn::Overlap;
            }
            // cross the upper boundary
            if block.end <= range.end && block.end > range.start {
                return CheckRangeReturn::Overlap;
            }
            // no blocks left, returns false
            if block.end <= range.start {
                return CheckRangeReturn::Free;
            }
        }
        CheckRangeReturn::Free
    }

    /// Track new memory block at `ptr` with `size` bytes.
    pub fn alloc(&mut self, ptr: GuestAddr, size: GuestAddr) {
        let range = ptr..(ptr + size);

        if self.check_range(&range).valid_for_alloc() {
            self.mem_blocks.insert(ptr, range);
        } else {
            warn!("allocted at 0x{:x} with 0x{:x} bytes failed, skip this allocation", ptr, size);
        }
    }

    /// Free memory block at `ptr`.
    pub fn free(&mut self, ptr: GuestAddr) {
        match self.mem_blocks.get_mut(&ptr) {
            Some(_) => {
                self.mem_blocks.remove(&ptr);
            }
            None => {}
        }
    }

    fn new() -> Self {
        Self {
            mem_blocks: BTreeMap::new(),
            heap_areas: Vec::new(),
            code_areas: Vec::new(),
        }
    }

    fn is_in_heap(&self, addr: GuestAddr) -> bool {
        for area in &self.heap_areas {
            if area.contains(&addr) {
                return true;
            }
        }
        return false;
    }

    fn is_in_code_area(&self, pc: GuestAddr) -> bool {
        for area in &self.code_areas {
            if area.contains(&pc) {
                return true;
            }
        }
        return false;
    }
}

/// Restores the size of the current `malloc` or `calloc`
static LAST_MALLOC_SIZE: Lazy<AtomicU32> = Lazy::new(|| AtomicU32::new(0));

/// Callback for `malloc` enter.
unsafe extern "C" fn on_malloc_enter(_: u64, _: GuestAddr) {
    let qemu = Qemu::get().unwrap();
    let size = qemu.read_reg(Regs::A10).unwrap();

    LAST_MALLOC_SIZE.store(size, Ordering::SeqCst);
}

/// Callback for `calloc` enter.
unsafe extern "C" fn on_calloc_enter(_: u64, _: GuestAddr) {
    let qemu = Qemu::get().unwrap();
    let size = qemu.read_reg(Regs::A10).unwrap();
    let count = qemu.read_reg(Regs::A11).unwrap();

    LAST_MALLOC_SIZE.store(size * count, Ordering::SeqCst);
}

/// Callback for `alloc` return.
unsafe extern "C" fn on_alloc_return(_: u64, _: GuestAddr) {
    let qemu = Qemu::get().unwrap();
    let size = LAST_MALLOC_SIZE.load(Ordering::SeqCst);
    let ptr = qemu.read_reg(Regs::A2).unwrap();

    if size > 0 {
        let mut sanitizer = HeapSanitizer::get();
        sanitizer.alloc(ptr, size);
    }

    LAST_MALLOC_SIZE.store(0, Ordering::SeqCst);
}

/// Callback for `free` enter.
unsafe extern "C" fn on_free_enter(_: u64, _: GuestAddr) {
    let qemu = Qemu::get().unwrap();
    let ptr = qemu.read_reg(Regs::A10).unwrap();

    if ptr != 0 {
        let mut sanitizer = HeapSanitizer::get();
        sanitizer.free(ptr);
    }
}

/// Checks memory read and write. Directly exit the execution when invalid access happens.
fn on_mem_rw(is_write: bool, pc: GuestAddr, addr: GuestAddr, len: usize) {
    let mut sanitizer = HeapSanitizer::get();
    if sanitizer.is_interested(pc, addr) {
        trace!(
            "memory {}: pc=0x{:04x} addr=0x{:04x} len={}",
            if is_write { "write" } else { "read" },
            pc,
            addr,
            len
        );
        let range = addr..(addr + len as GuestAddr);
        match sanitizer.check_range(&range) {
            CheckRangeReturn::InUse => {
                return;
            }
            _ => {
                error!(
                    "invalid memory {}, pc=0x{:04x} addr=0x{:04x} len=0x{:x}",
                    if is_write { "write" } else { "read" },
                    pc,
                    addr,
                    len
                );
                unsafe {
                    libc::_exit(MetaExecutorExitReason::Crash as i32);
                };
            }
        }
    }
}

/// Callback for memory read.
unsafe extern "C" fn on_mem_read(_: u64, _: u64, pc: GuestAddr, addr: GuestAddr, len: usize) {
    on_mem_rw(false, pc, addr, len);
}

/// Callback for memory write.
unsafe extern "C" fn on_mem_write(_: u64, _: u64, pc: GuestAddr, addr: GuestAddr, len: usize) {
    on_mem_rw(true, pc, addr, len);
}
