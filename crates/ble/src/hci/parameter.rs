use deku::prelude::*;
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::helper::get_bit;

#[derive(Debug)]
#[repr(u8)]
pub enum ControllerErrorCode {
    Ok = 0x00,
    AuthenticationFailure = 0x05,
    MemoryCapacityExceeded = 0x07,
    CommandDisallowed = 0x0C,
    InvalidHciCommandParameters = 0x12,
    RemoteUserTerminatedConnection = 0x13,
    RemoteDeviceTerminatedConnectionLowResources = 0x14,
    RemoteDeviceTerminatedConnectionPowerOff = 0x15,
    ConnectionTerminatedByLocalHost = 0x16,
    UnsupportedRemoteFeature = 0x1A,
    ParingWithUnitKeyNotSupported = 0x29,
    UnacceptableConnectionParameters = 0x3B,
    Unknown = 0xff,
}

impl From<u8> for ControllerErrorCode {
    fn from(value: u8) -> Self {
        match value {
            0x0 => Self::Ok,
            0x05 => Self::AuthenticationFailure,
            0x07 => Self::MemoryCapacityExceeded,
            0x0C => Self::CommandDisallowed,
            0x12 => Self::InvalidHciCommandParameters,
            0x13 => Self::RemoteUserTerminatedConnection,
            0x14 => Self::RemoteDeviceTerminatedConnectionLowResources,
            0x15 => Self::RemoteDeviceTerminatedConnectionPowerOff,
            0x16 => Self::ConnectionTerminatedByLocalHost,
            0x1A => Self::UnsupportedRemoteFeature,
            0x29 => Self::ParingWithUnitKeyNotSupported,
            0x3B => Self::UnacceptableConnectionParameters,
            _ => Self::Unknown,
        }
    }
}

/// boundary flag of the higher layer message in ACL data packet header.
#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite, Deserialize, Serialize, Hash)]
#[deku(id_type = "u8", bits = 2, bit_order = "lsb")]
#[repr(u8)]
pub enum AclPacketBoundaryFlag {
    HostToControllerStart = 0b00,
    Continuing = 0b01,
    ControllerToHostStart = 0b10,
}

/// broadcast flag in ACL data packet header, should always be 0b00 for LE-U.
#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite, Deserialize, Serialize, Hash)]
#[deku(id_type = "u8", bits = 2, bit_order = "lsb")]
#[repr(u8)]
pub enum BroadcastFlag {
    PointToPoint = 0b00,
}

/// Erroneous_Data_Reporting flags in sync packets sent by the Controller.
#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite, Deserialize, Serialize, Hash)]
#[deku(id_type = "u8", bits = 2, bit_order = "lsb")]
#[repr(u8)]
pub enum SyncPacketStatusFlag {
    Correct = 0b00,
    PossiblyInvalid = 0b01,
    NoData = 0b10,
    PartiallyLost = 0b11,
}

/// boundary flag of the higher layer message in ISO data packet header.
#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite, Deserialize, Serialize, Hash)]
#[deku(id_type = "u8", bits = 2, bit_order = "lsb")]
#[repr(u8)]
pub enum IsoPacketBoundaryFlag {
    FirstFragment = 0b00,
    ContinuationFragment = 0b01,
    Complete = 0b10,
    LastFragment = 0b11,
}

#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "little")]
pub struct ReadLocalVersionInformationReturn {
    pub hci_version: u8,
    pub hci_subversion: u16,
    pub lmp_version: u8,
    pub company_identifier: u16,
    pub lmp_subversion: u16,
}

#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite)]
#[deku(id_type = "u8")]
#[repr(u8)]
pub enum LeScanKind {
    Passive = 0,
    Active = 1,
}

impl fmt::Display for LeScanKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LeScanKind::Active => write!(f, "Active"),
            LeScanKind::Passive => write!(f, "Passive"),
        }
    }
}

#[derive(Debug, PartialEq, DekuRead, DekuWrite, Clone, Deserialize, Serialize, Hash)]
#[deku(endian = "little")]
pub struct Duration<const US: u32 = 625>(pub u16);

impl<const US: u32> fmt::Display for Duration<US> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}ms", self.0 as u32 * 1000 / US)
    }
}

#[derive(Debug, Copy, PartialEq, DekuRead, DekuWrite, PartialOrd, Eq, Ord, Clone, Deserialize, Serialize, Hash)]
#[deku(id_type = "u8")]
#[repr(u8)]
pub enum AddrKind {
    Public = 0x00,
    Random = 0x01,
    ResolvablePrivateOrPublic = 0x02,
    ResolvablePrivateOrRandom = 0x03,
    AnonymousAdv = 0xff,
}

impl fmt::Display for AddrKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AddrKind::Public => write!(f, "Public"),
            AddrKind::Random => write!(f, "Random"),
            AddrKind::ResolvablePrivateOrPublic => write!(f, "ResolvablePrivateOrPublic"),
            AddrKind::ResolvablePrivateOrRandom => write!(f, "ResolvablePrivateOrRandom"),
            AddrKind::AnonymousAdv => write!(f, "AnonymousAdv"),
        }
    }
}

#[derive(Debug, PartialEq, DekuRead, DekuWrite, PartialOrd, Eq, Ord, Clone, Deserialize, Serialize, Hash)]
#[deku(id_type = "u8")]
#[repr(u8)]
pub enum LeConnRole {
    Central = 0,
    Peripheral = 1,
}

impl fmt::Display for LeConnRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LeConnRole::Central => write!(f, "Central"),
            LeConnRole::Peripheral => write!(f, "Peripheral"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite)]
#[deku(id_type = "u8")]
#[repr(u8)]
pub enum ScanningFilterPolicy {
    BasicUnfiltered = 0,
    BasicFiltered = 1,
    ExtUnfiltered = 2,
    ExtFiltered = 3,
}

impl fmt::Display for ScanningFilterPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScanningFilterPolicy::BasicUnfiltered => write!(f, "BasicUnfiltered"),
            ScanningFilterPolicy::BasicFiltered => write!(f, "BasicFiltered"),
            ScanningFilterPolicy::ExtUnfiltered => write!(f, "ExtUnfiltered"),
            ScanningFilterPolicy::ExtFiltered => write!(f, "ExtFiltered"),
        }
    }
}

#[derive(Debug, Copy, PartialEq, DekuRead, DekuWrite, PartialOrd, Eq, Ord, Clone, Deserialize, Serialize, Hash)]
#[deku()]
pub struct BdAddr {
    pub addr: [u8; 6],
}

impl BdAddr {
    pub fn default() -> Self {
        Self { addr: [0x0u8; 6] }
    }
}

impl fmt::Display for BdAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for i in 0..5 {
            write!(f, "{:02x}:", self.addr[i])?;
        }
        write!(f, "{:02x}", self.addr[5])
    }
}

#[derive(Debug, PartialEq, DekuRead, DekuWrite, PartialOrd, Eq, Ord, Clone)]
#[deku()]
pub struct FilterAcceptListEntry(pub AddrKind, pub BdAddr);

#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite)]
#[deku(id_type = "u8")]
#[repr(u8)]
pub enum AdvKind {
    AdvInd = 0,
    AdvDirectIndHigh = 1,
    AdvScanInd = 2,
    AdvNonconnInd = 3,
    AdvDirectIndLow = 4,
}

impl AdvKind {
    pub fn is_connectable(&self) -> bool {
        *self == Self::AdvInd || *self == Self::AdvDirectIndHigh || *self == Self::AdvDirectIndLow
    }

    pub fn is_directed(&self) -> bool {
        *self == Self::AdvDirectIndHigh || *self == Self::AdvDirectIndLow
    }
}

impl fmt::Display for AdvKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AdvKind::AdvInd => write!(f, "AdvInd"),
            AdvKind::AdvDirectIndHigh => write!(f, "AdvDirectIndHigh"),
            AdvKind::AdvScanInd => write!(f, "AdvScanInd"),
            AdvKind::AdvNonconnInd => write!(f, "AdvNonconnInd"),
            AdvKind::AdvDirectIndLow => write!(f, "AdvDirectIndLow"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite)]
#[deku(id_type = "u8")]
#[repr(u8)]
pub enum AdvFilterPolicy {
    Unfiltered = 0,
    FilterScan = 1,
    FilterConn = 2,
    FilterConnAndScan = 3,
}

impl fmt::Display for AdvFilterPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AdvFilterPolicy::Unfiltered => write!(f, "Unfiltered"),
            AdvFilterPolicy::FilterScan => write!(f, "FilterScan"),
            AdvFilterPolicy::FilterConn => write!(f, "FilterConn"),
            AdvFilterPolicy::FilterConnAndScan => write!(f, "FilterConnAndScan"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite)]
#[deku(id_type = "u8")]
#[repr(u8)]
pub enum PowerLevelKind {
    Current = 0,
    Maximum = 1,
}

#[repr(u8)]
pub enum EventMaskBit {
    LeConnectionComplete = 0,
    LeAdvertisingReport = 1,
}

#[derive(Debug, Clone, PartialEq, DekuWrite, DekuRead)]
#[deku()]
pub struct EventMask(pub [u8; 8]);

impl From<[u8; 8]> for EventMask {
    fn from(value: [u8; 8]) -> Self {
        Self(value)
    }
}

impl Default for EventMask {
    fn default() -> Self {
        Self([0xff, 0xff, 0xff, 0xff, 0xff, 0x1f, 0x00, 0x00])
    }
}

impl EventMask {
    pub fn new() -> Self {
        Self([0x0; 8])
    }

    pub fn enabled(&self, bit: EventMaskBit) -> bool {
        get_bit(&self.0, bit as usize)
    }
}

#[repr(u8)]
pub enum LeEventMaskBit {
    LeConnectionComplete = 0,
    LeAdvertisingReport = 1,
    LePeriodicAdvertisingSyncEstablished = 13,
    LePeriodicAdvertisingReport = 14,
    LePeriodicAdvertisingSyncLost = 15,
    LePastReceived = 23,
    LeCisEstablished = 24,
    LeCisRequest = 25,
}

#[derive(Debug, Clone, PartialEq, DekuWrite, DekuRead)]
#[deku()]
pub struct LeEventMask(pub [u8; 8]);

impl From<[u8; 8]> for LeEventMask {
    fn from(value: [u8; 8]) -> Self {
        Self(value)
    }
}

impl Default for LeEventMask {
    fn default() -> Self {
        Self([0x1f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    }
}

impl LeEventMask {
    pub fn new() -> Self {
        Self([0x0; 8])
    }

    pub fn enabled(&self, bit: LeEventMaskBit) -> bool {
        get_bit(&self.0, bit as usize)
    }
}
