pub mod command;
pub mod event;
pub mod parameter;

use command::*;
use deku::prelude::*;
use event::*;
use parameter::*;
use serde::{Deserialize, Serialize};

/// HCI packets from controller to host.
#[derive(Debug, Clone, PartialEq, DekuWrite, Deserialize, Serialize, Hash)]
#[deku(id_type = "u8")]
pub enum ControllerToHostPacket {
    #[deku(id = 0x02)]
    AclData(HciAclDataPkt),
    #[deku(id = 0x03)]
    SyncData(HciSyncDataPkt),
    #[deku(id = 0x04)]
    Event(HciEventPkt),
    #[deku(id = 0x05)]
    IsoData(HciIsoDataPkt),
}

/// HCI packets from host to controller.
#[derive(Debug, Clone, PartialEq, DekuWrite, DekuRead)]
#[deku(id_type = "u8")]
pub enum HostToControllerPacket {
    #[deku(id = 0x01)]
    Command(HciCommandPkt),
    #[deku(id = 0x02)]
    AclData(HciAclDataPkt),
    #[deku(id = 0x03)]
    SyncData(HciSyncDataPkt),
    #[deku(id = 0x05)]
    IsoData(HciIsoDataPkt),
}

pub enum HciPacket {
    HostToController(HostToControllerPacket),
    ControllerToHost(ControllerToHostPacket),
}

/// HCI ACL Data packets are used to exchange data between the Host and
/// Controller.
#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite, Deserialize, Serialize, Hash)]
#[deku]
pub struct HciAclDataPkt {
    #[deku(bits = 12, bit_order = "lsb")]
    pub handle: u16,
    pub packet_boundary_flag: AclPacketBoundaryFlag,
    pub broadcast_flag: BroadcastFlag,
    #[deku(update = "self.data.len()")]
    pub data_total_length: u16,
    #[deku(count = "data_total_length")]
    pub data: Vec<u8>,
}

/// HCI Synchronous Data packets are used to exchange synchronous data (SCO and
/// eSCO) between the Host and Controller.
#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite, Deserialize, Serialize, Hash)]
#[deku]
pub struct HciSyncDataPkt {
    #[deku(bits = 12, bit_order = "lsb")]
    pub handle: u16,
    pub packet_status_flag: SyncPacketStatusFlag,
    #[deku(bits = 2, bit_order = "lsb")]
    reserved_for_use: u8,
    #[deku(update = "self.data.len()")]
    pub data_total_length: u16,
    #[deku(count = "data_total_length")]
    pub data: Vec<u8>,
}

/// HCI ISO Data packets are used to exchange isochronous data between the Host
/// and Controller.
#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite, Deserialize, Serialize, Hash)]
#[deku]
pub struct HciIsoDataPkt {
    #[deku(bits = 12, bit_order = "lsb")]
    pub handle: u16,
    pub packet_boundary_flag: IsoPacketBoundaryFlag,
    #[deku(bits = 1)]
    pub time_stamp_flag: u8,
    #[deku(bits = 1)]
    pub reserved_for_use1: u8,
    #[deku(bits = 14, update = "self.data.len()")]
    pub data_total_length: u16,
    #[deku(bits = 2)]
    pub reserved_for_use2: u8,
    #[deku(count = "data_total_length")]
    pub data: Vec<u8>,
}

/// The HCI Command packet is used to send commands to the Controller from the
/// Host.
#[derive(Debug, Clone, PartialEq, DekuWrite, DekuRead)]
#[deku(id_type = "u16")]
pub enum HciCommandPkt {
    #[deku(id = 0x0406)]
    Disconnect(DisconnectParam),
    #[deku(id = 0x041d)]
    ReadRemoteVersionInformation(ReadRemoteVersionInformationParam),
    #[deku(id = 0x0C01)]
    SetEventMask(SetEventMaskParam),
    #[deku(id = 0x0C03)]
    Reset(NoParam),
    #[deku(id = 0x0C14)]
    ReadLocalName(NoParam),
    #[deku(id = 0x0C2D)]
    ReadTransmitPowerLevel(ReadTransmitPowerLevelParam),
    #[deku(id = 0x0C31)]
    SetControllerToHostFlowControl(SetControllerToHostFlowControlParam),
    #[deku(id = 0x0C33)]
    HostBufferSize(HostBufferSizeParam),
    #[deku(id = 0x0C35)]
    HostNumberOfCompletePackets(HostNumberOfCompletePacketsParam),
    #[deku(id = 0x0C6D)]
    WriteLeHostSupport(WriteLeHostSupportParam),
    #[deku(id = 0x1001)]
    ReadLocalVersionInformation(NoParam),
    #[deku(id = 0x1002)]
    ReadLocalSupportedCommands(NoParam),
    #[deku(id = 0x1003)]
    ReadLocalSupportedFeatures(NoParam),
    #[deku(id = 0x1004)]
    ReadLocalExtendedFeatures(ReadLocalExtendedFeaturesParam),
    #[deku(id = 0x1005)]
    ReadBufferSize(NoParam),
    #[deku(id = 0x1009)]
    ReadBdAddr(NoParam),
    #[deku(id = 0x1405)]
    ReadRssi(ReadRssiParam),
    #[deku(id = 0x2001)]
    LeSetEventMask(LeSetEventMaskParam),
    #[deku(id = 0x2002)]
    LeReadBufferSizeV1(NoParam),
    #[deku(id = 0x2003)]
    LeReadLocalSupportedFeatures(NoParam),
    #[deku(id = 0x2005)]
    LeSetRandomAddress(LeSetRandomAddressParam),
    #[deku(id = 0x2006)]
    LeSetAdvertisingParameters(AdvertisingParameters),
    #[deku(id = 0x2007)]
    LeReadAdvertisingChannelTxPower(NoParam),
    #[deku(id = 0x2008)]
    LeSetAdvertisingData(LeSetAdvertisingDataParam),
    #[deku(id = 0x200A)]
    LeSetAdvertisingEnable(LeSetAdvertisingEnableParam),
    #[deku(id = 0x200B)]
    LeSetScanParameters(LeSetScanParametersParam),
    #[deku(id = 0x200C)]
    LeSetScanEnable(LeSetScanEnableParam),
    #[deku(id = 0x200D)]
    LeCreateConnection(LeCreateConnectionParam),
    #[deku(id = 0x200F)]
    LeReadFilterAcceptListSize(NoParam),
    #[deku(id = 0x2009)]
    LeSetScanResponseData(LeSetScanResponseDataParam),
    #[deku(id = 0x2010)]
    LeClearFilterAcceptList(NoParam),
    #[deku(id = 0x2011)]
    LeAddDeviceToFilterAcceptList(FilterAcceptListEntry),
    #[deku(id = 0x2012)]
    LeRemoveDeviceFromFilterAcceptList(FilterAcceptListEntry),
    #[deku(id = 0x2013)]
    LeConnectionUpdate(LeConnectionUpdateParam),
    #[deku(id = 0x2015)]
    LeReadChannelMap(LeReadChannelMapParam),
    #[deku(id = 0x2016)]
    LeReadRemoteFeatures(LeReadRemoteFeaturesParam),
    #[deku(id = 0x2017)]
    LeEncrypt(LeEncryptParam),
    #[deku(id = 0x2018)]
    LeRand(NoParam),
    #[deku(id = 0x2019)]
    LeStartEncryption(LeStartEncryptionParam),
    #[deku(id = 0x201A)]
    LeLongTermKeyRequestReply(LeLongTermKeyRequestReplyParam),
    #[deku(id = 0x201B)]
    LeLongTermKeyRequestNegativeReply(LeLongTermKeyRequestNegativeReplyParam),
    #[deku(id = 0x201C)]
    LeReadSupportedStates(NoParam),
    #[deku(id = 0x2022)]
    LeSetDataLength(LeSetDataLengthParam),
    #[deku(id = 0x2023)]
    LeReadSuggestedDefaultDataLength(NoParam),
    #[deku(id = 0x2024)]
    LeWriteSuggestedDefaultDataLength(LeWriteSuggestedDefaultDataLengthParam),
    #[deku(id = 0x2025)]
    LeReadLocalP256PublicKey(NoParam),
    #[deku(id = 0x2027)]
    LeAddDeviceToResolvingList(LeAddDeviceToResolvingListParam),
    #[deku(id = 0x2029)]
    LeClearResolvingList(NoParam),
    #[deku(id = 0x202A)]
    LeReadResolvingListSize(NoParam),
    #[deku(id = 0x202D)]
    LeSetAddressResolutionEnable(LeSetAddressResolutionEnableParam),
    #[deku(id = 0x202E)]
    LeSetResolvablePrivateAddressTimeout(LeSetResolvablePrivateAddressTimeoutParam),
    #[deku(id = 0x202F)]
    LeReadMaximumDataLength(NoParam),
    #[deku(id = 0x2031)]
    LeSetDefaultPhy(LeSetDefaultPhyParam),
    #[deku(id = 0x2032)]
    LeSetPhy(LeSetPhyParam),
    #[deku(id = 0x2035)]
    LeSetAdvertisingSetRandomAddress(LeSetAdvertisingSetRandomAddressParam),
    #[deku(id = 0x2036)]
    LeSetExtendedAdvertisingParametersV1(LeSetExtendedAdvertisingParametersV1Param),
    #[deku(id = 0x2037)]
    LeSetExtendedAdvertisingData(LeSetExtendedAdvertisingDataParam),
    #[deku(id = 0x2038)]
    LeSetExtendedScanResponseData(LeSetExtendedAdvertisingDataParam),
    #[deku(id = 0x2039)]
    LeSetExtendedAdvertisingEnable(LeSetExtendedAdvertisingEnableParam),
    #[deku(id = 0x203A)]
    LeReadMaximumAdvertisingDataLength(NoParam),
    #[deku(id = 0x203B)]
    LeReadNumberOfSupportedAdvertisingSets(NoParam),
    #[deku(id = 0x203C)]
    LeRemoveAdvertisingSet(LeRemoveAdvertisingSetParam),
    #[deku(id = 0x203D)]
    LeClearAdvertisingSets(NoParam),
    #[deku(id = 0x2041)]
    LeSetExtendedScanParameters(LeSetExtendedScanParametersParam),
    #[deku(id = 0x2042)]
    LeSetExtendedScanEnable(LeSetExtendedScanEnableParam),
    #[deku(id = 0x2044)]
    LePerAdvCreateSync(LePerAdvCreateSyncParam),
    #[deku(id = 0x2045)]
    LePerAdvCreateSyncCancel(NoParam),
    #[deku(id = 0x2046)]
    LePerAdvTerminateSync(LePerAdvTerminateSyncParam),
    #[deku(id = 0x204B)]
    LeReadTransmitPower(NoParam),
    #[deku(id = 0x205A)]
    LePerAdvSyncTransfer(LePerAdvSyncTransferParam),
    #[deku(id = 0x205B)]
    LePerAdvSetInfoTransfer(LePerAdvSetInfoTransferParam),
    #[deku(id = 0x205C)]
    LePastParam(LePastParam),
    #[deku(id = 0x205D)]
    LeDefaultPastParam(LeDefaultPastParam),
    #[deku(id = 0x2060)]
    LeReadBufferSizeV2(NoParam),
    #[deku(id = 0x2066)]
    LeAcceptCis(LeAcceptCisParam),
    #[deku(id = 0x2067)]
    LeRejectCis(LeRejectCisParam),
    #[deku(id = 0x206E)]
    LeSetupIsoPath(LeSetupIsoPathParam),
    #[deku(id = 0x206F)]
    LeRemoveIsoPath(LeRemoveIsoPathParam),
    #[deku(id = 0x2074)]
    LeSetHostFeature(LeSetHostFeatureParam),
    #[deku(id = 0x207F)]
    LeSetExtendedAdvertisingParametersV2(LeSetExtendedAdvertisingParametersV2Param),
    #[deku(id_pat = "0xfc00..=0xffff")]
    Vendor {
        id: u16,
        #[deku(read_all)]
        payload: Vec<u8>,
    },
}

/// The HCI Event packet is used by the Controller to notify the Host when
/// events occur.
#[derive(Debug, Clone, PartialEq, DekuWrite, Deserialize, Serialize, Hash)]
#[deku(id_type = "u8")]
pub enum HciEventPkt {
    #[deku(id = 0x05)]
    DisconnectComplete(DisconnectCompleteEvent),
    #[deku(id = 0x0C)]
    ReadRemoteVersionInformationComplete(ReadRemoteVersionInformationCompleteEvent),
    #[deku(id = 0x0E)]
    CommandComplete(CommandCompleteEvent),
    #[deku(id = 0x0F)]
    CommandStatus(CommandStatusEvent),
    #[deku(id = 0x13)]
    NumberOfCompletetedPackets(NumberOfCompletetedPacketsEvent),
    #[deku(id = 0x3E)]
    LeMata(LeMetaEvent),
    #[deku(id = 0x08)]
    EncryptionChange(EncryptionChangeEvent),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hci_acl_data_pkt() {
        let data: Vec<u8> = vec![0x12, 0x03, 0x03, 0x00, 0xAA, 0xBB, 0xCC];
        match HciAclDataPkt::from_bytes((data.as_ref(), 0)) {
            Ok(val) => println!("{:?}", val),
            Err(e) => eprintln!("{:?}", e),
        }
    }
}
