use std::mem::size_of;
use std::sync::OnceLock;

use capstone::arch::BuildsCapstone;
use enum_map::{EnumMap, enum_map};
use num_enum::{IntoPrimitive, TryFromPrimitive};
#[cfg(feature = "python")]
#[allow(unused)]
use pyo3::prelude::*;
pub use strum_macros::EnumIter;
pub use syscall_numbers::arm::*;

use crate::{CallingConvention, GuestAddr, QemuRWError, QemuRWErrorKind, sync_exit::ExitArgs};

#[expect(non_upper_case_globals)]
impl CallingConvention {
    pub const Default: CallingConvention = CallingConvention::Aapcs;
}

#[derive(IntoPrimitive, TryFromPrimitive, Debug, Copy, Clone, EnumIter)]
#[repr(i32)]
pub enum Regs {
    Pc = 0,
    Ps = 73,
    A0 = 157,
    A1 = 158,
    A2 = 159,
    A3 = 160,
    A4 = 161,
    A5 = 162,
    A6 = 163,
    A7 = 164,
    A8 = 165,
    A9 = 166,
    A10 = 167,
    A11 = 168,
    A12 = 169,
    A13 = 170,
    A14 = 171,
    A15 = 172,
    PsCallInc = 193,
}

static EXIT_ARCH_REGS: OnceLock<EnumMap<ExitArgs, Regs>> = OnceLock::new();

pub fn get_exit_arch_regs() -> &'static EnumMap<ExitArgs, Regs> {
    EXIT_ARCH_REGS.get_or_init(|| {
        enum_map! {
            ExitArgs::Ret  => Regs::A0,
            ExitArgs::Cmd  => Regs::A0,
            ExitArgs::Arg1 => Regs::A2,
            ExitArgs::Arg2 => Regs::A3,
            ExitArgs::Arg3 => Regs::A4,
            ExitArgs::Arg4 => Regs::A5,
            ExitArgs::Arg5 => Regs::A6,
            ExitArgs::Arg6 => Regs::A7,
        }
    })
}

#[expect(non_upper_case_globals)]
impl Regs {
    pub const Ra: Regs = Regs::A0;
    pub const Sp: Regs = Regs::A1;
    // pub const Pc: Regs = Regs::A15;
}

pub fn capstone() -> capstone::arch::arm::ArchCapstoneBuilder {
    capstone::Capstone::new()
        .arm()
        .mode(capstone::arch::arm::ArchMode::Arm)
}

pub type GuestReg = u32;

impl crate::ArchExtras for crate::CPU {
    fn read_return_address(&self) -> Result<GuestReg, QemuRWError> {
        self.read_reg(Regs::Ra)
    }

    fn write_return_address<T>(&self, val: T) -> Result<(), QemuRWError>
    where
        T: Into<GuestReg>,
    {
        self.write_reg(Regs::Ra, val)
    }

    fn read_function_argument_with_cc(
        &self,
        idx: u8,
        conv: CallingConvention,
    ) -> Result<GuestReg, QemuRWError> {
        QemuRWError::check_conv(QemuRWErrorKind::Read, CallingConvention::Aapcs, conv)?;

        match idx {
            0 => self.read_reg(Regs::A2),
            1 => self.read_reg(Regs::A3),
            2 => self.read_reg(Regs::A4),
            3 => self.read_reg(Regs::A5),
            4 => self.read_reg(Regs::A6),
            5 => self.read_reg(Regs::A7),
            _ => {
                // arguments beyond 6 are on stack. Xtensa stack grows downwards; SP in A1.
                const SIZE: usize = size_of::<GuestReg>();
                let stack_ptr: GuestAddr = self.read_reg(Regs::Sp)?;
                // In Xtensa, the first stack argument (i.e. arg index 6) is at SP + offset.
                // We follow a simple model: offset = SIZE * (idx - 5)
                // (matches: idx 6 -> offset SIZE * 1)
                let offset = (SIZE as GuestAddr) * (GuestAddr::from(idx) - 5u8 as GuestAddr);
                let mut buf = [0u8; size_of::<GuestReg>()];
                self.read_mem(stack_ptr + offset, &mut buf)?;

                #[cfg(feature = "be")]
                {
                    Ok(GuestReg::from_be_bytes(buf).into())
                }
                #[cfg(not(feature = "be"))]
                {
                    Ok(GuestReg::from_le_bytes(buf).into())
                }
            }
        }
    }

    fn write_function_argument_with_cc<T>(
        &self,
        idx: u8,
        val: T,
        conv: CallingConvention,
    ) -> Result<(), QemuRWError>
    where
        T: Into<GuestReg>,
    {
        QemuRWError::check_conv(QemuRWErrorKind::Write, CallingConvention::Aapcs, conv)?;

        let val: GuestReg = val.into();
        match idx {
            0 => self.write_reg(Regs::A2, val),
            1 => self.write_reg(Regs::A3, val),
            2 => self.write_reg(Regs::A4, val),
            3 => self.write_reg(Regs::A5, val),
            4 => self.write_reg(Regs::A6, val),
            5 => self.write_reg(Regs::A7, val),
            _ => {
                let stack_ptr: GuestAddr = self.read_reg(Regs::Sp)?;
                let size: GuestAddr = size_of::<GuestReg>() as GuestAddr;
                let offset = size * (GuestAddr::from(idx) - 5u8 as GuestAddr);

                #[cfg(feature = "be")]
                let arg = val.to_be_bytes();

                #[cfg(not(feature = "be"))]
                let arg = val.to_le_bytes();

                self.write_mem(stack_ptr + offset, &arg)?;
                Ok(())
            }
        }
    }
}
