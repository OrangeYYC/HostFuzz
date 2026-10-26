/*!
 * Emulator for ESP32.
 */
use crate::{config::Esp32Config, sanitizer::HeapSanitizer};
use fuzzer::{executor::MetaExecutorError, AppConfig};

use libafl_qemu::{modules::EmulatorModuleTuple, Emulator, GuestAddr, GuestReg, QemuExitReason, Regs};
use std::{fmt::Debug, io::ErrorKind, net::UdpSocket};
use tracing::{error, trace};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u32)]
enum EspReturn {
    Ok = 0x0,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u32)]
enum EspBtControllerStatus {
    Idle = 0x0,
    Inited = 0x1,
    Enabled = 0x2,
}

/// Warps the libafl-qemu Emulator for ESP32 with Simulator interaction hooks.
pub struct Esp32Qemu<C, CM, ED, ET, I, S, SM> {
    emulator: Emulator<C, CM, ED, ET, I, S, SM>,
    socket: UdpSocket,
    config: Esp32Config,
    status: EspBtControllerStatus,
    notify_host_send_available: GuestAddr,
    notify_host_recv: GuestAddr,
    in_notify_host_send_available: bool,
}

impl<C, CM, ED, ET, I, S, SM> Esp32Qemu<C, CM, ED, ET, I, S, SM>
where
    I: Unpin,
    S: Unpin,
    ET: EmulatorModuleTuple<I, S>,
{
    pub fn new(config: AppConfig<Esp32Config>, emulator: Emulator<C, CM, ED, ET, I, S, SM>) -> Result<Self, MetaExecutorError> {
        // create socket for controller
        let (host_addr, controller_addr) = config
            .simulator
            .transport
            .split_once('@')
            .ok_or(MetaExecutorError::InitErr(format!("invalid transport")))?
            .1
            .split_once('-')
            .ok_or(MetaExecutorError::InitErr(format!("invalid transport")))?;
        let socket = UdpSocket::bind(host_addr).map_err(|x| MetaExecutorError::InitErr(format!("udp bind fail: {:?}", x)))?;
        socket
            .connect(controller_addr)
            .map_err(|x| MetaExecutorError::InitErr(format!("udp connect fail: {:?}", x)))?;

        // set hook point to the qemu
        let config = config.executor;
        let qemu = emulator.qemu();
        let set_breakpoint_if_present = |addr: GuestAddr| {
            if addr != 0 {
                qemu.set_breakpoint(addr);
            }
        };
        set_breakpoint_if_present(config.hooks.controller.esp_bt_controller_init);
        set_breakpoint_if_present(config.hooks.controller.esp_bt_controller_enable);
        set_breakpoint_if_present(config.hooks.controller.esp_bt_controller_get_status);
        set_breakpoint_if_present(config.hooks.controller.esp_bt_controller_mem_release);
        set_breakpoint_if_present(config.hooks.controller.esp_ble_tx_power_get);
        set_breakpoint_if_present(config.hooks.controller.esp_vhci_host_register_callback);
        set_breakpoint_if_present(config.hooks.controller.esp_vhci_host_check_send_available);
        set_breakpoint_if_present(config.hooks.controller.esp_vhci_host_send_packet);
        set_breakpoint_if_present(config.hooks.sanitizer.panic_handler);
        set_breakpoint_if_present(config.hooks.sanitizer.esp_panic_handler);
        set_breakpoint_if_present(config.hooks.sanitizer.assert);
        set_breakpoint_if_present(config.hooks.sanitizer.assert_func);

        // sanitiser
        HeapSanitizer::register_hooks(&config.hooks.sanitizer);

        Ok(Self {
            config,
            emulator,
            socket,
            status: EspBtControllerStatus::Idle,
            notify_host_send_available: 0u32,
            notify_host_recv: 0u32,
            in_notify_host_send_available: false,
        })
    }

    /// Starts the mainloop of the QEMU. Runs until exit or error.
    pub fn run(&mut self) -> Result<QemuExitReason, MetaExecutorError> {
        match self.run_to(0xffffffff) {
            Err(error) => {
                error!("The executor crashed in child process, err={:?}", error);
                Err(error)
            }
            Ok(exit) => {
                self.socket.send(&[0xff]).map_err(|x| {
                    error!("failed to noitify execution end: {:?}", x);
                    MetaExecutorError::InternalErr(format!("failed to noitify execution end: {:?}", x))
                })?;
                Ok(exit)
            }
        }
    }

    /// Starts the mainloop of the QEMU. Runs until exit, error or PC equals to `stop_addr`.
    pub fn run_to(&mut self, stop_addr: GuestAddr) -> Result<QemuExitReason, MetaExecutorError> {
        loop {
            match unsafe { self.emulator.qemu().run() } {
                Ok(QemuExitReason::Breakpoint(addr)) if self.is_sanitizer_fatal(addr) => {
                    if addr == self.config.hooks.sanitizer.assert || addr == self.config.hooks.sanitizer.assert_func {
                        error!("sanitizer_fatal: assert hook hit at 0x{:08x}", addr);
                    } else {
                        error!("sanitizer_fatal: panic hook hit at 0x{:08x}", addr);
                    }
                    return Ok(QemuExitReason::Crash);
                }
                Ok(QemuExitReason::Breakpoint(addr)) => {
                    if addr == stop_addr {
                        return Ok(QemuExitReason::Breakpoint(stop_addr));
                    }
                    self.handle_break_point(addr)?;
                }
                Ok(reason) => return Ok(reason),
                Err(error) => {
                    return Err(MetaExecutorError::ExecErr(format!("QEMU execution error: {:?}", error)));
                }
            }
        }
    }

    fn is_sanitizer_fatal(&self, addr: GuestAddr) -> bool {
        addr == self.config.hooks.sanitizer.panic_handler
            || addr == self.config.hooks.sanitizer.esp_panic_handler
            || addr == self.config.hooks.sanitizer.assert
            || addr == self.config.hooks.sanitizer.assert_func
    }

    /// Handles the breakpoint at address `addr`.
    #[rustfmt::skip]
    fn handle_break_point(&mut self, addr: GuestAddr) -> Result<(), MetaExecutorError> {
        match addr {
            x if x == self.config.hooks.controller.esp_bt_controller_init => {
                self.esp_bt_controller_init()
            }
            x if x == self.config.hooks.controller.esp_bt_controller_enable => {
                self.esp_bt_controller_enable()
            }
            x if x == self.config.hooks.controller.esp_bt_controller_get_status => {
                self.esp_bt_controller_get_status()
            }
            x if x == self.config.hooks.controller.esp_vhci_host_register_callback => {
                self.esp_vhci_host_register_callback()
            }
            x if x == self.config.hooks.controller.esp_vhci_host_check_send_available => {
                self.esp_vhci_host_check_send_available()
            }
            x if x == self.config.hooks.controller.esp_vhci_host_send_packet => {
                self.esp_vhci_host_send_packet()
            }
            x if x == self.config.hooks.controller.esp_bt_controller_mem_release => {
                self.esp_bt_controller_mem_release()
            }
            x if x == self.config.hooks.controller.esp_ble_tx_power_get => {
                self.esp_ble_tx_power_get()
            }
            _ => {
                Err(MetaExecutorError::ExecErr(
                    format!("Unhandled QEMU breakpoint at 0x{:04x}", addr)
                ))
            }
        }
    }

    /// Reads register `reg` from QEMU.
    pub fn read_reg<R>(&self, reg: R) -> Result<GuestReg, MetaExecutorError>
    where
        R: Into<i32> + Clone + Debug,
    {
        self.emulator
            .qemu()
            .read_reg(reg.clone())
            .map_err(|x| MetaExecutorError::InternalErr(format!("Failed to read register {:?}, error {:?}", reg, x)))
    }

    /// Reads memory at `addr` from QEMU.
    pub fn read_mem_val<T>(&self, addr: GuestAddr) -> Result<T, MetaExecutorError> {
        unsafe {
            self.emulator
                .qemu()
                .read_mem_val(addr)
                .map_err(|x| MetaExecutorError::InternalErr(format!("Failed to read memory 0x{:04x}, error {:?}", addr, x)))
        }
    }

    /// Reads memory at `addr` with specific `len` from QEMU.
    pub fn read_mem_vec(&self, addr: GuestAddr, len: usize) -> Result<Vec<u8>, MetaExecutorError> {
        self.emulator
            .qemu()
            .read_mem_vec(addr, len)
            .map_err(|x| MetaExecutorError::InternalErr(format!("Failed to read memory 0x{:04x} with length {}, error {:?}", addr, len, x)))
    }

    /// Writes `value` to register `reg` of QEMU.
    pub fn write_reg<R>(&self, reg: R, value: GuestReg) -> Result<(), MetaExecutorError>
    where
        R: Into<i32> + Clone + Debug,
    {
        self.emulator
            .qemu()
            .write_reg(reg.clone(), value)
            .map_err(|x| MetaExecutorError::InternalErr(format!("Failed to write 0x{:04x} to register {:?}, error {:?}", value, reg, x)))
    }

    /// Writes bytes in `buf` to memory at `addr` of QEMU.
    pub fn write_mem(&self, addr: GuestAddr, buf: &[u8]) -> Result<(), MetaExecutorError> {
        self.emulator
            .qemu()
            .write_mem(addr, buf)
            .map_err(|x| MetaExecutorError::InternalErr(format!("Failed to write memory 0x{:04x}, error {:?}", addr, x)))
    }

    /// Dumps current register value.
    pub fn dump_regs(&self) -> Result<(), MetaExecutorError> {
        trace!("dump_regs:");
        trace!("  PS: 0x{:x}", self.read_reg(Regs::Ps)?);
        for i in 0..9 {
            trace!("  A{}: 0x{:x}", i, self.read_reg(Regs::A0 as i32 + i)?);
        }
        Ok(())
    }

    /// Emulates the return from call8 instruction for QEMU.
    /// The PC and A8 register should be the current PC and the return address.
    pub fn call8_ret(&self) -> Result<(), MetaExecutorError> {
        const PC_WINDOW: u32 = 0xC0000000;

        let pc = self.read_reg(Regs::Pc)?;
        let a8 = self.read_reg(Regs::A8)?;
        let ret_addr = (a8 & !PC_WINDOW) | (pc & PC_WINDOW);

        trace!("emu_call8_ret: pc=0x{:04x}, a8=0x{:04x}, ret_addr=0x{:04x}", pc, a8, ret_addr);
        self.write_reg(Regs::Pc, ret_addr)
    }

    /// Emulates the call of the function.
    pub fn call8(&mut self, func: GuestAddr, args: Vec<GuestReg>, name_for_trace: &'static str) -> Result<GuestReg, MetaExecutorError> {
        const PS_CALLINC: u32 = 0x30000;
        const PC_WINDOW: u32 = 0xC0000000;

        trace!("{}: func=0x{:x}, args={:?}", name_for_trace, func, &args);

        // ps.callinc = 0x10 (move window at 8)
        let old_ps = self.read_reg(Regs::Ps)?;
        let new_ps = (old_ps & (!PS_CALLINC)) | 0x20000;
        self.write_reg(Regs::Ps, new_ps)?;

        // return address is set to PC
        let old_a8 = self.read_reg(Regs::A8)?;
        let old_pc = self.read_reg(Regs::Pc)?;
        let ret_addr = old_pc;
        let new_a8 = (ret_addr & (!PC_WINDOW)) | 0x80000000;

        // jump to function
        self.write_reg(Regs::Pc, func)?;
        self.write_reg(Regs::A8, new_a8)?;
        for (i, arg) in args.into_iter().enumerate() {
            self.write_reg(Regs::A10 as i32 + i as i32, arg)?;
        }

        // jump into fire
        self.run_to(ret_addr)?;
        self.write_reg(Regs::A8, old_a8)?;
        let ret = self.read_reg(Regs::A10)?;
        trace!("{}_ret: return=0x{:04x}", name_for_trace, ret);

        Ok(ret)
    }

    /// Emulates the `malloc` function.
    pub fn malloc(&mut self, size: GuestReg) -> Result<GuestReg, MetaExecutorError> {
        self.dump_regs()?;
        let args = vec![size];
        let ret = self.call8(self.config.hooks.sanitizer.malloc_enter, args, "malloc")?;
        self.dump_regs()?;
        Ok(ret)
    }

    /// Emulates the `free` function.
    pub fn free(&mut self, ptr: GuestReg) -> Result<GuestReg, MetaExecutorError> {
        self.dump_regs()?;
        let args = vec![ptr];
        let ret = self.call8(self.config.hooks.sanitizer.free_enter, args, "free")?;
        self.dump_regs()?;
        Ok(ret)
    }

    /// Emulates the `notify_host_recv` callback funcion.
    pub fn callback_notify_host_recv(&mut self, addr: GuestReg, len: GuestReg) -> Result<(), MetaExecutorError> {
        self.dump_regs()?;
        let args = vec![addr, len];
        self.call8(self.notify_host_recv, args, "callback_notify_host_recv")?;
        self.dump_regs()
    }

    /// Emulates the `notify_host_send_available` callback function.
    pub fn callback_notify_host_send_available(&mut self) -> Result<(), MetaExecutorError> {
        if self.notify_host_send_available == 0 {
            trace!("callback_notify_host_send_available: callback not registered, skip");
            return Ok(());
        }
        if self.in_notify_host_send_available {
            trace!("callback_notify_host_send_available: reentrant call detected, skip");
            return Ok(());
        }

        self.in_notify_host_send_available = true;
        self.dump_regs()?;
        let call_ret = self.call8(
            self.notify_host_send_available,
            Vec::new(),
            "callback_notify_host_send_available",
        );
        let dump_ret = self.dump_regs();
        self.in_notify_host_send_available = false;

        call_ret?;
        dump_ret
    }

    /// Emulates the `esp_bt_controller_init` function.
    pub fn esp_bt_controller_init(&mut self) -> Result<(), MetaExecutorError> {
        let cfg = self.read_reg(Regs::A10)?;
        trace!("emu_esp_bt_controller_init: cfg=0x{:x}", cfg);

        self.status = EspBtControllerStatus::Inited;
        self.write_reg(Regs::A10, EspReturn::Ok as GuestReg)?;
        self.call8_ret()
    }

    /// Emulates the `esp_bt_controller_enable` function.
    pub fn esp_bt_controller_enable(&mut self) -> Result<(), MetaExecutorError> {
        let mode = self.read_reg(Regs::A10)?;
        trace!("emu_esp_bt_controller_enable: mode=0x{:x}", mode);

        self.status = EspBtControllerStatus::Enabled;
        self.write_reg(Regs::A10, EspReturn::Ok as GuestReg)?;
        self.call8_ret()
    }

    /// Emulates the `esp_bt_controller_get_status` function.
    pub fn esp_bt_controller_get_status(&self) -> Result<(), MetaExecutorError> {
        trace!("esp_bt_controller_get_status");

        self.write_reg(Regs::A10, self.status as GuestReg)?;
        self.call8_ret()
    }

    /// Emulates the `esp_bt_controller_mem_release` function.
    pub fn esp_bt_controller_mem_release(&self) -> Result<(), MetaExecutorError> {
        trace!("esp_bt_controller_mem_release");

        self.write_reg(Regs::A10, EspReturn::Ok as GuestReg)?;
        self.call8_ret()
    }

    /// Emulates the `esp_ble_tx_power_get` function.
    pub fn esp_ble_tx_power_get(&self) -> Result<(), MetaExecutorError> {
        trace!("esp_ble_tx_power_get");

        self.write_reg(Regs::A10, EspReturn::Ok as GuestReg)?;
        self.call8_ret()
    }

    /// Emulates the `esp_vhci_host_register_callback` function.
    pub fn esp_vhci_host_register_callback(&mut self) -> Result<(), MetaExecutorError> {
        let callback = self.read_reg(Regs::A10)?;
        self.notify_host_send_available = self.read_mem_val(callback)?;
        self.notify_host_recv = self.read_mem_val(callback + 0x4)?;
        trace!(
            "esp_vhci_host_register_callback: send_ava=0x{:x} host_recv=0x{:x}",
            self.notify_host_send_available,
            self.notify_host_recv
        );

        self.write_reg(Regs::A10, EspReturn::Ok as GuestReg)?;
        self.call8_ret()
    }

    /// Emualtes the `esp_vhci_host_check_send_available` function.
    pub fn esp_vhci_host_check_send_available(&mut self) -> Result<(), MetaExecutorError> {
        trace!("esp_vhci_host_check_send_available");

        // Allow host-side polling to pull controller-initiated traffic.
        self.drain_controller_packets(false)?;
        self.write_reg(Regs::A10, 0x1u32 /*True*/)?;
        self.call8_ret()
    }

    /// Emulates the `esp_vhci_host_send_packet` function.
    pub fn esp_vhci_host_send_packet(&mut self) -> Result<(), MetaExecutorError> {
        let data_ptr = self.read_reg(Regs::A10)?;
        let data_len = self.read_reg(Regs::A11)?;
        trace!("esp_vhci_host_send_packet: data=0x{:x} len={}", data_ptr, data_len);

        let hci_packet = self.read_mem_vec(data_ptr, data_len as usize)?;
        trace!("esp_vhci_host_send_packet: get HCI packet: {}", hex::encode_upper(&hci_packet));

        self.socket
            .send(&hci_packet)
            .map_err(|x| MetaExecutorError::InternalErr(format!("failed to connect to controller, {:?}", x)))?;
        self.drain_controller_packets(true)?;
        // Notify host side that controller is ready for next host->controller packet.
        // We allow callback on command packets and on fixed L2CAP channels only. For dynamic
        // LE CoC channels, continuous callbacks can over-drive send pacing and destabilize some
        // demos.
        let should_notify_send_available = match hci_packet.first().copied() {
            Some(0x01) => true, // HCI Command
            Some(0x02) if hci_packet.len() >= 9 => {
                // HCI ACL + L2CAP header
                let l2cap_cid = u16::from_le_bytes([hci_packet[7], hci_packet[8]]);
                l2cap_cid <= 0x0006
            }
            _ => false,
        };
        if should_notify_send_available {
            self.callback_notify_host_send_available()?;
        }
        self.call8_ret()
    }

    fn dispatch_controller_packet(&mut self, packet: &[u8]) -> Result<(), MetaExecutorError> {
        let addr = self.malloc(packet.len() as u32)?;
        self.write_mem(addr, packet)?;
        self.callback_notify_host_recv(addr, packet.len() as u32)?;
        self.free(addr)?;
        Ok(())
    }

    fn drain_controller_packets(&mut self, wait_for_round_terminator: bool) -> Result<(), MetaExecutorError> {
        let mut buf = [0u8; 2048];

        if wait_for_round_terminator {
            loop {
                match self.socket.recv(buf.as_mut_slice()) {
                    Ok(0) => {
                        return Err(MetaExecutorError::InternalErr(String::from(
                            "failed to connect to controller: recv len is 0",
                        )));
                    }
                    Ok(len) => {
                        if len == 1 && buf[0] == 0xff {
                            break;
                        }
                        self.dispatch_controller_packet(&buf[..len])?;
                    }
                    Err(error) => {
                        return Err(MetaExecutorError::InternalErr(format!(
                            "failed to connect to controller: {:?}",
                            error
                        )));
                    }
                }
            }
            return Ok(());
        }

        self.socket
            .set_nonblocking(true)
            .map_err(|x| MetaExecutorError::InternalErr(format!("failed to switch controller socket nonblocking: {:?}", x)))?;
        let mut drain_result = Ok(());
        loop {
            match self.socket.recv(buf.as_mut_slice()) {
                Ok(0) => {
                    drain_result = Err(MetaExecutorError::InternalErr(String::from(
                        "failed to connect to controller: recv len is 0",
                    )));
                    break;
                }
                Ok(len) => {
                    // Unsolicited timeout phases can include this sentinel; ignore it.
                    if len == 1 && buf[0] == 0xff {
                        continue;
                    }
                    if let Err(err) = self.dispatch_controller_packet(&buf[..len]) {
                        drain_result = Err(err);
                        break;
                    }
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    break;
                }
                Err(error) if error.kind() == ErrorKind::Interrupted => {
                    continue;
                }
                Err(error) => {
                    drain_result = Err(MetaExecutorError::InternalErr(format!(
                        "failed to connect to controller: {:?}",
                        error
                    )));
                    break;
                }
            }
        }
        self.socket
            .set_nonblocking(false)
            .map_err(|x| MetaExecutorError::InternalErr(format!("failed to restore controller socket blocking mode: {:?}", x)))?;
        drain_result
    }
}
