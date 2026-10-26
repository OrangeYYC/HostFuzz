use super::parameter::*;
use deku::prelude::*;
use std::fmt;

#[derive(Debug, Clone, PartialEq, DekuWrite, DekuRead)]
#[deku()]
pub struct NoParam {
    #[deku(pad_bytes_before = "1")]
    _empty: (),
}

/// HCI_Disconnect
/// ref: 7.1.6 Disconnect command
#[derive(Debug, Clone, PartialEq, DekuWrite, DekuRead)]
#[deku()]
pub struct DisconnectParam {
    #[deku(pad_bytes_before = "1")]
    pub connection_handle: u16,
    pub reason: u8,
}

/// HCI_Read_Remote_Version_Information
/// ref: 7.1.23 Read Remote Version Information command
#[derive(Debug, Clone, PartialEq, DekuWrite, DekuRead)]
#[deku()]
pub struct ReadRemoteVersionInformationParam {
    #[deku(pad_bytes_before = "1")]
    pub connection_handle: u16,
}

/// HCI_Set_Event_Mask
/// ref: 7.3.1 Set Event Mask command
#[derive(Debug, Clone, PartialEq, DekuWrite, DekuRead)]
#[deku()]
pub struct SetEventMaskParam {
    #[deku(pad_bytes_before = "1")]
    pub event_mask: EventMask,
}

/// HCI_Read_Transmit_Power_Level
/// ref: 7.3.35 Read Transmit Power Level command
#[derive(Debug, Clone, PartialEq, DekuWrite, DekuRead)]
#[deku()]
pub struct ReadTransmitPowerLevelParam {
    #[deku(pad_bytes_before = "1")]
    pub connection_handle: u16,
    pub level_type: PowerLevelKind,
}

/// HCI_Set_Controller_To_Host_Flow_Control
/// ref: 7.3.38 Set Controller To Host Flow Control command
#[derive(Debug, Clone, PartialEq, DekuWrite, DekuRead)]
#[deku()]
pub struct SetControllerToHostFlowControlParam {
    #[deku(pad_bytes_before = "1")]
    pub enable: u8,
}

/// HCI_Host_Buffer_Size
/// ref: 7.3.39 Host Buffer Size command
#[derive(Debug, Clone, PartialEq, DekuWrite, DekuRead)]
#[deku()]
pub struct HostBufferSizeParam {
    #[deku(pad_bytes_before = "1")]
    pub host_acl_data_packet_length: u16,
    pub host_sync_data_packet_length: u8,
    pub host_total_num_acl_data_packet: u16,
    pub host_total_num_sync_data_packet: u16,
}

/// HCI_Write_LE_Host_Support
/// ref: 7.3.69 Write LE Host Support command
#[derive(Debug, Clone, PartialEq, DekuWrite, DekuRead)]
#[deku()]
pub struct WriteLeHostSupportParam {
    #[deku(pad_bytes_before = "1")]
    pub le_supported_host: u8,
    pub simultaneous_le_host: u8,
}

/// Sub-unit of HCI_Host_Number_Of_Completed_Packets
/// ref: 7.3.40 Host Number Of Completed Packets command
#[derive(Debug, Clone, PartialEq, DekuWrite, DekuRead)]
#[deku()]
pub struct HostNumberOfCompletePacketsParamUnit {
    pub connection_handle: u16,
    pub host_num_completed_packets: u16,
}

/// HCI_Host_Number_Of_Completed_Packets
/// ref: 7.3.40 Host Number Of Completed Packets command
#[derive(Debug, Clone, PartialEq, DekuWrite, DekuRead)]
#[deku()]
pub struct HostNumberOfCompletePacketsParam {
    #[deku(pad_bytes_before = "1")]
    pub num_handles: u8,
    #[deku(count = "num_handles")]
    pub units: Vec<HostNumberOfCompletePacketsParamUnit>,
}

/// HCI_Read_Local_Extended_Features
/// ref: 7.4.4 Read Local Extended Features command
#[derive(Debug, Clone, PartialEq, DekuWrite, DekuRead)]
#[deku()]
pub struct ReadLocalExtendedFeaturesParam {
    #[deku(pad_bytes_before = "1")]
    pub page_number: u8,
}

/// HCI_Read_RSSI
/// ref: 7.5.4 Read RSSI command
#[derive(Debug, Clone, PartialEq, DekuWrite, DekuRead)]
#[deku()]
pub struct ReadRssiParam {
    #[deku(pad_bytes_before = "1")]
    pub handle: u16,
}

/// HCI_LE_Set_Event_Mask
/// ref: 7.8.1 LE Set Event Mask command
#[derive(Debug, Clone, PartialEq, DekuWrite, DekuRead)]
#[deku()]
pub struct LeSetEventMaskParam {
    #[deku(pad_bytes_before = "1")]
    pub event_mask: LeEventMask,
}

/// HCI_LE_Set_Random_Address
/// ref: 7.8.4 LE Set Random Address command
#[derive(Debug, Clone, PartialEq, DekuWrite, DekuRead)]
#[deku()]
pub struct LeSetRandomAddressParam {
    #[deku(pad_bytes_before = "1")]
    pub random_address: [u8; 6],
}

/// HCI_LE_Set_Advertising_Parameters
/// ref: 7.8.5 LE Set Advertising Parameters command
#[derive(Debug, Clone, PartialEq, DekuWrite, DekuRead)]
#[deku()]
pub struct AdvertisingParameters {
    #[deku(pad_bytes_before = "1")]
    pub advertising_interval_min: Duration<625>,
    pub advertising_interval_max: Duration<625>,
    pub advertising_type: AdvKind,
    pub own_address_type: AddrKind,
    pub peer_address_type: AddrKind,
    pub peer_address: BdAddr,
    pub advertising_channel_map: u8,
    pub advertising_filter_policy: AdvFilterPolicy,
}

impl fmt::Display for AdvertisingParameters {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Advertising_Interval_Min={}, Advertising_Interval_Max={}, Advertising_Type={}, Own_Address_Type={}, Peer_Address_Type={}, Peer_Address={}, Advertising_Channel_Map={}, Advertising_Filter_Policy={}",
            self.advertising_interval_min,
            self.advertising_interval_max,
            self.advertising_type,
            self.own_address_type,
            self.peer_address_type,
            self.peer_address,
            self.advertising_channel_map,
            self.advertising_filter_policy,
        )
    }
}

impl Default for AdvertisingParameters {
    fn default() -> Self {
        Self {
            advertising_interval_min: Duration(0x0800),
            advertising_interval_max: Duration(0x0800),
            advertising_type: AdvKind::AdvInd,
            own_address_type: AddrKind::Public,
            peer_address_type: AddrKind::Public,
            peer_address: BdAddr { addr: [0x0; 6] },
            advertising_channel_map: 0x7,
            advertising_filter_policy: AdvFilterPolicy::Unfiltered,
        }
    }
}

/// HCI_LE_Set_Advertising_Data
/// ref: 7.8.7 LE Set Advertising Data command
#[derive(Debug, Clone, PartialEq, DekuWrite, DekuRead)]
#[deku()]
pub struct LeSetAdvertisingDataParam {
    #[deku(pad_bytes_before = "1")]
    pub data_len: u8,
    pub data: [u8; 31],
}

pub struct LeAdvertisingData {
    pub ad_type: u8,
    pub ad_data: Vec<u8>,
}

impl LeSetAdvertisingDataParam {
    pub fn format_data(&self) -> Vec<LeAdvertisingData> {
        let mut ret = Vec::new();
        let mut i = 0;

        while i < self.data.len() {
            let len = self.data[i] as usize;
            i += 1;
            if len == 0 {
                return ret;
            }
            let end = i + len;
            if end > self.data.len() {
                return ret;
            }
            let ad_type = self.data[i];
            let ad_data = self.data[i + 1..end].to_vec();
            ret.push(LeAdvertisingData { ad_type, ad_data });
            i = end;
        }
        ret
    }
}

impl fmt::Display for LeSetAdvertisingDataParam {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[")?;
        for data in self.format_data() {
            write!(f, "{{0x{:02x}, {}}}", data.ad_type, hex::encode_upper(&data.ad_data))?;
        }
        write!(f, "]")
    }
}

/// HCI_LE_Set_Advertising_Enable
/// ref: 7.8.9 LE Set Advertising Enable command
#[derive(Debug, Clone, PartialEq, DekuWrite, DekuRead)]
#[deku()]
pub struct LeSetAdvertisingEnableParam {
    #[deku(pad_bytes_before = "1")]
    pub enable: u8,
}

/// HCI_LE_Set_Scan_Parameters
/// ref: 7.8.10 LE Set Scan Parameters command
#[derive(Debug, Clone, PartialEq, DekuWrite, DekuRead)]
#[deku()]
pub struct LeSetScanParametersParam {
    #[deku(pad_bytes_before = "1")]
    pub le_scan_kind: LeScanKind,
    pub le_scan_interval: Duration<10_000>,
    pub le_scan_window: Duration<10_000>,
    pub own_addr_kind: AddrKind,
    pub scanning_filter_policy: ScanningFilterPolicy,
}

/// HCI_LE_Set_Scan_Enable
/// ref: 7.8.11 LE Set Scan Enable command
#[derive(Debug, Clone, PartialEq, DekuWrite, DekuRead)]
#[deku()]
pub struct LeSetScanEnableParam {
    #[deku(pad_bytes_before = "1")]
    pub le_scan_enable: u8,
    pub filter_duplicates: u8,
}

/// HCI_LE_Create_Connection
/// ref: 7.8.12 LE Create Connection command
#[derive(Debug, Clone, PartialEq, DekuWrite, DekuRead)]
#[deku()]
pub struct LeCreateConnectionParam {
    #[deku(pad_bytes_before = "1")]
    pub le_scan_interval: Duration<10_000>,
    pub le_scan_window: Duration<10_000>,
    pub use_filter_accept_list: u8,
    pub peer_addr_kind: AddrKind,
    pub peer_addr: BdAddr,
    pub own_addr_kind: AddrKind,
    pub conn_interval_min: Duration<1_250>,
    pub conn_interval_max: Duration<1_250>,
    pub max_latency: u16,
    pub supervision_timeout: Duration<10_000>,
    pub min_ce_length: Duration<625>,
    pub max_ce_length: Duration<625>,
}

/// HCI_LE_Connection_Update
/// ref: 7.8.18 LE Connection Update command
#[derive(Debug, Clone, PartialEq, DekuWrite, DekuRead)]
#[deku()]
pub struct LeConnectionUpdateParam {
    #[deku(pad_bytes_before = "1")]
    pub connection_handle: u16,
    pub conn_interval_min: Duration<1_250>,
    pub conn_interval_max: Duration<1_250>,
    pub max_latency: u16,
    pub supervision_timeout: Duration<10_000>,
    pub min_ce_length: Duration<625>,
    pub max_ce_length: Duration<625>,
}

/// HCI_LE_Set_Scan_Response_Data
/// ref: 7.8.8 LE Set Scan Response Data command
#[derive(Debug, Clone, PartialEq, DekuWrite, DekuRead)]
#[deku()]
pub struct LeSetScanResponseDataParam {
    #[deku(pad_bytes_before = "1")]
    pub scan_response_data_length: u8,
    pub scan_response_data: [u8; 31],
}

/// HCI_LE_Read_Channel_Map
/// ref: 7.8.20 LE Read Channel Map command
#[derive(Debug, Clone, PartialEq, DekuWrite, DekuRead)]
#[deku()]
pub struct LeReadChannelMapParam {
    #[deku(pad_bytes_before = "1")]
    pub connection_handle: u16,
}

/// HCI_LE_Read_Remote_Features
/// ref: 7.8.21 LE Read Remote Features command
#[derive(Debug, Clone, PartialEq, DekuWrite, DekuRead)]
#[deku()]
pub struct LeReadRemoteFeaturesParam {
    #[deku(pad_bytes_before = "1")]
    pub connection_handle: u16,
}

/// HCI_LE_Encrypt
/// ref: 7.8.22 LE Encrypt command
#[derive(Debug, Clone, PartialEq, DekuWrite, DekuRead)]
#[deku()]
pub struct LeEncryptParam {
    #[deku(pad_bytes_before = "1")]
    pub key: [u8; 16],
    pub plaintext_data: [u8; 16],
}

/// HCI_LE_Start_Encryption
/// ref: 7.8.24 LE Start Encryption command
#[derive(Debug, Clone, PartialEq, DekuWrite, DekuRead)]
#[deku()]
pub struct LeStartEncryptionParam {
    #[deku(pad_bytes_before = "1")]
    pub connection_handle: u16,
    pub random_number: [u8; 8],
    pub encrypted_diversifier: u16,
    pub long_term_key: [u8; 16],
}

/// HCI_LE_Long_Term_Key_Request_Reply
/// ref: 7.8.25 LE Long Term Key Request Reply command
#[derive(Debug, Clone, PartialEq, DekuWrite, DekuRead)]
#[deku()]
pub struct LeLongTermKeyRequestReplyParam {
    #[deku(pad_bytes_before = "1")]
    pub connection_handle: u16,
    pub long_term_key: [u8; 16],
}

/// HCI_LE_Long_Term_Key_Request_Negative_Reply
/// ref: 7.8.26 LE Long Term Key Request Negative Reply command
#[derive(Debug, Clone, PartialEq, DekuWrite, DekuRead)]
#[deku()]
pub struct LeLongTermKeyRequestNegativeReplyParam {
    #[deku(pad_bytes_before = "1")]
    pub connection_handle: u16,
}

/// HCI_LE_Set_Data_Length
/// ref: 7.8.33 LE Set Data Length command
#[derive(Debug, Clone, PartialEq, DekuWrite, DekuRead)]
#[deku()]
pub struct LeSetDataLengthParam {
    #[deku(pad_bytes_before = "1")]
    pub connection_handle: u16,
    pub tx_octets: u16,
    pub tx_time: u16,
}

/// HCI_LE_Write_Suggested_Default_Data_Length
/// ref: 7.8.35 LE Write Suggested Default Data Length command
#[derive(Debug, Clone, PartialEq, DekuWrite, DekuRead)]
#[deku(endian = "little", bit_order = "lsb")]
pub struct LeWriteSuggestedDefaultDataLengthParam {
    #[deku(pad_bytes_before = "1")]
    pub suggested_max_tx_octets: u16,
    pub suggested_max_tx_time: u16,
}

/// HCI_LE_Add_Device_To_Resolving_List
/// ref: 7.8.38 LE Add Device To Resolving List command
#[derive(Debug, Clone, PartialEq, DekuWrite, DekuRead)]
#[deku()]
pub struct LeAddDeviceToResolvingListParam {
    #[deku(pad_bytes_before = "1")]
    pub peer_id_addr_kind: AddrKind,
    pub peer_id_addr: BdAddr,
    pub peer_irk: [u8; 16],
    pub local_irk: [u8; 16],
}

impl fmt::Display for LeAddDeviceToResolvingListParam {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Peer_Identity_Address_Type={}, Peer_Identity_Address={}, Peer_IRK={}, Local_IRK={}",
            self.peer_id_addr_kind,
            self.peer_id_addr,
            hex::encode_upper(self.peer_irk),
            hex::encode_upper(self.local_irk)
        )
    }
}

/// HCI_LE_Set_Address_Resolution_Enable
/// ref: 7.8.44 LE Set Address Resolution Enable command
#[derive(Debug, Clone, PartialEq, DekuWrite, DekuRead)]
#[deku()]
pub struct LeSetAddressResolutionEnableParam {
    #[deku(pad_bytes_before = "1")]
    pub enable: u8,
}

/// HCI_LE_Set_Resolvable_Private_Address_Timeout
/// ref: 7.8.45 LE Set Resolvable Private Address Timeout command
#[derive(Debug, Clone, PartialEq, DekuWrite, DekuRead)]
#[deku()]
pub struct LeSetResolvablePrivateAddressTimeoutParam {
    #[deku(pad_bytes_before = "1")]
    pub rpa_timeout: u16,
}

/// HCI_LE_Set_Default_PHY
/// ref: 7.8.48 LE Set Default PHY command
#[derive(Debug, Clone, PartialEq, DekuWrite, DekuRead)]
#[deku()]
pub struct LeSetDefaultPhyParam {
    #[deku(pad_bytes_before = "1")]
    pub all_phys: u8,
    pub tx_phys: u8,
    pub rx_phys: u8,
}

/// HCI_LE_Set_PHY
/// ref: 7.8.49 LE Set PHY command
#[derive(Debug, Clone, PartialEq, DekuWrite, DekuRead)]
#[deku()]
pub struct LeSetPhyParam {
    #[deku(pad_bytes_before = "1")]
    pub connection_handle: u16,
    pub all_phys: u8,
    pub tx_phys: u8,
    pub rx_phys: u8,
    pub phy_options: u16,
}

impl fmt::Display for LeSetPhyParam {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Connection_Handle=0x{:04x}, All_PHYs=0x{:02x}, TX_PHYs=0x{:02x}, RX_PHYs=0x{:02x}, PHY_Options=0x{:04x}",
            self.connection_handle, self.all_phys, self.tx_phys, self.rx_phys, self.phy_options
        )
    }
}

/// HCI_LE_Set_Address_Resolution_Enable
/// ref: 7.8.44 LE Set Address Resolution Enable command
#[derive(Debug, Clone, PartialEq, DekuWrite, DekuRead)]
#[deku()]
pub struct LeSetAdvertisingSetRandomAddressParam {
    #[deku(pad_bytes_before = "1")]
    pub advertising_handle: u8,
    pub random_address: BdAddr,
}

/// HCI_LE_Set_Extended_Advertising_Parameters
/// ref: 7.8.53 LE Set Extended Advertising Parameters command
#[derive(Debug, Clone, PartialEq, DekuWrite, DekuRead)]
#[deku()]
pub struct LeSetExtendedAdvertisingParametersV1Param {
    #[deku(pad_bytes_before = "1")]
    pub advertising_handle: u8,
    pub advertising_event_priorities: u16,
    pub primary_advertising_interval_min: [u8; 3],
    pub primary_advertising_interval_max: [u8; 3],
    pub primary_advertising_channel_map: u8,
    pub own_address_type: AddrKind,
    pub peer_address_type: AddrKind,
    pub peer_address: BdAddr,
    pub advertising_filter_policy: AdvFilterPolicy,
    pub advertising_tx_power: u8,
    pub primary_advertising_phy: u8,
    pub secondary_advertising_max_skip: u8,
    pub secondary_advertising_phy: u8,
    pub advertising_sid: u8,
    pub scan_request_notification_enable: u8,
}

impl fmt::Display for LeSetExtendedAdvertisingParametersV1Param {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Advertising_Handle=0x{:02x}, Advertising_Event_Priorities=0x{:04x}, Own_Address_Type={}, Peer_Address_Type={}, Peer_Address={}, Advertising_Filter_Policy={}",
            self.advertising_handle,
            self.advertising_event_priorities,
            self.own_address_type,
            self.peer_address_type,
            self.peer_address,
            self.advertising_filter_policy,
        )
    }
}

/// HCI_LE_Set_Extended_Advertising_Data
/// HCI_LE_Set_Extended_Scan_Response_Data
/// ref: 7.8.54 LE Set Extended Advertising Data command
/// ref: 7.8.55 LE Set Extended Scan Response Data command
#[derive(Debug, Clone, PartialEq, DekuWrite, DekuRead)]
#[deku()]
pub struct LeSetExtendedAdvertisingDataParam {
    #[deku(pad_bytes_before = "1")]
    pub advertising_handle: u8,
    pub operation: u8,
    pub fragment_preference: u8,
    pub advertising_data_length: u8,
    #[deku(count = "advertising_data_length")]
    pub advertising_data: Vec<u8>,
}

impl fmt::Display for LeSetExtendedAdvertisingDataParam {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Advertising_Handle=0x{:02x}, Operation=0x{:04x}, Fragment_Preference={}, Data_Length={}, Data={}",
            &self.advertising_handle,
            &self.operation,
            &self.fragment_preference,
            &self.advertising_data_length,
            hex::encode_upper(&self.advertising_data),
        )
    }
}

/// Sub-unit of HCI_LE_Set_Extended_Advertising_Enable
/// ref: 7.8.56 LE Set Extended Advertising Enable command
#[derive(Debug, Clone, PartialEq, DekuWrite, DekuRead)]
#[deku()]
pub struct LeSetExtendedAdvertisingEnableParamSet {
    pub advertising_handle: u8,
    pub duration: Duration<10_000>,
    pub max_extended_advertising_events: u8,
}

/// HCI_LE_Set_Extended_Advertising_Enable
/// ref: 7.8.56 LE Set Extended Advertising Enable command
#[derive(Debug, Clone, PartialEq, DekuWrite, DekuRead)]
#[deku()]
pub struct LeSetExtendedAdvertisingEnableParam {
    #[deku(pad_bytes_before = "1")]
    pub enable: u8,
    pub num_sets: u8,
    #[deku(count = "num_sets")]
    pub sets: Vec<LeSetExtendedAdvertisingEnableParamSet>,
}

impl fmt::Display for LeSetExtendedAdvertisingEnableParam {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Enable=0x{:02x}, Num_Sets=0x{:04x}, Sets=[", &self.enable, &self.num_sets)?;
        for set in &self.sets {
            write!(
                f,
                "{{Advertising_Handle=0x{:02x}, Duration={}, Max_Events=0x{:02x}}}",
                set.advertising_handle, set.duration, set.max_extended_advertising_events
            )?;
        }
        write!(f, "]")
    }
}

/// HCI_LE_Remove_Advertising_Set
/// ref: 7.8.59 LE Remove Advertising Set command
#[derive(Debug, Clone, PartialEq, DekuWrite, DekuRead)]
#[deku()]
pub struct LeRemoveAdvertisingSetParam {
    #[deku(pad_bytes_before = "1")]
    pub advertising_handle: u8,
}

/// Sub-unit of HCI_LE_Set_Extended_Advertising_Parameters
/// ref: 7.8.53 LE Set Extended Advertising Parameters command
#[derive(Debug, Clone, PartialEq, DekuWrite, DekuRead)]
#[deku()]
pub struct LeSetExtendedScanParametersUnit {
    pub scan_type: u8,
    pub scan_interval: Duration<625>,
    pub scan_window: Duration<625>,
}

/// HCI_LE_Set_Extended_Advertising_Parameters
/// ref: 7.8.53 LE Set Extended Advertising Parameters command
#[derive(Debug, Clone, PartialEq, DekuWrite, DekuRead)]
#[deku()]
pub struct LeSetExtendedScanParametersParam {
    #[deku(pad_bytes_before = "1")]
    pub own_address_type: u8,
    pub scanning_filter_policy: ScanningFilterPolicy,
    pub scanning_phys: u8,
    #[deku(count = "scanning_phys.count_ones() as usize")]
    pub units: Vec<LeSetExtendedScanParametersUnit>,
}

impl fmt::Display for LeSetExtendedScanParametersParam {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Own_Address_Type=0x{:02x}, Scanning_Filter_Policy={}",
            self.own_address_type, self.scanning_filter_policy,
        )?;
        write!(f, ", PHYs=[")?;
        for unit in &self.units {
            write!(f, "{{Scan_Type=0x{:02x}}}", unit.scan_type)?;
        }
        write!(f, "]")
    }
}

/// HCI_LE_Set_Extended_Advertising_Enable
/// ref: 7.8.56 LE Set Extended Advertising Enable command
#[derive(Debug, Clone, PartialEq, DekuWrite, DekuRead)]
#[deku()]
pub struct LeSetExtendedScanEnableParam {
    #[deku(pad_bytes_before = "1")]
    pub enable: u8,
    pub filter_duplicates: u8,
    pub duration: u16,
    pub period: u16,
}

/// HCI_LE_Periodic_Advertising_Create_Sync
/// ref: 7.8.68 LE Periodic Advertising Create Sync command
#[derive(Debug, Clone, PartialEq, DekuWrite, DekuRead)]
#[deku()]
pub struct LePerAdvCreateSyncParam {
    #[deku(pad_bytes_before = "1")]
    pub options: u8,
    pub sid: u8,
    pub address_type: AddrKind,
    pub address: BdAddr,
    pub skip: u16,
    pub sync_timeout: u16,
    pub cte_type: u8,
}

/// HCI_LE_Periodic_Advertising_Terminate_Sync
/// ref: 7.8.70 LE Periodic Advertising Terminate Sync command
#[derive(Debug, Clone, PartialEq, DekuWrite, DekuRead)]
#[deku()]
pub struct LePerAdvTerminateSyncParam {
    #[deku(pad_bytes_before = "1")]
    pub handle: u16,
}

/// HCI_LE_Periodic_Advertising_Sync_Transfer
/// ref: 7.8.90 LE Periodic Advertising Sync Transfer command
#[derive(Debug, Clone, PartialEq, DekuWrite, DekuRead)]
#[deku()]
pub struct LePerAdvSyncTransferParam {
    #[deku(pad_bytes_before = "1")]
    pub conn_handle: u16,
    pub service_data: u16,
    pub sync_handle: u16,
}

/// HCI_LE_Periodic_Advertising_Set_Info_Transfer
/// ref: 7.8.91 LE Periodic Advertising Set Info Transfer command
#[derive(Debug, Clone, PartialEq, DekuWrite, DekuRead)]
#[deku()]
pub struct LePerAdvSetInfoTransferParam {
    #[deku(pad_bytes_before = "1")]
    pub conn_handle: u16,
    pub service_data: u16,
    pub advertising_handle: u8,
}

/// HCI_LE_Set_Periodic_Advertising_Sync_Transfer_Parameters
/// ref: 7.8.92 LE Set Periodic Advertising Sync Transfer Parameters command
#[derive(Debug, Clone, PartialEq, DekuWrite, DekuRead)]
#[deku()]
pub struct LePastParam {
    #[deku(pad_bytes_before = "1")]
    pub conn_handle: u16,
    pub mode: u8,
    pub skip: u16,
    pub timeout: u16,
    pub cte_type: u8,
}

/// HCI_LE_Set_Default_Periodic_Advertising_Sync_Transfer_Parameters
/// ref: 7.8.93 LE Set Default Periodic Advertising Sync Transfer Parameters command
#[derive(Debug, Clone, PartialEq, DekuWrite, DekuRead)]
#[deku()]
pub struct LeDefaultPastParam {
    #[deku(pad_bytes_before = "1")]
    pub mode: u8,
    pub skip: u16,
    pub timeout: u16,
    pub cte_type: u8,
}

/// HCI_LE_Set_Host_Feature
/// ref: 7.8.115 LE Set Host Feature command
#[derive(Debug, Clone, PartialEq, DekuWrite, DekuRead)]
#[deku(endian = "little", bit_order = "lsb")]
pub struct LeSetHostFeatureParam {
    #[deku(pad_bytes_before = "1")]
    pub bit_number: u8,
    pub bit_value: u8,
}

/// HCI_LE_Accept_CIS_Request
/// ref: 7.8.107 LE Accept CIS Request command
#[derive(Debug, Clone, PartialEq, DekuWrite, DekuRead)]
#[deku()]
pub struct LeAcceptCisParam {
    #[deku(pad_bytes_before = "1")]
    pub connection_handle: u16,
}

/// HCI_LE_Reject_CIS_Request
/// ref: 7.8.108 LE Reject CIS Request command
#[derive(Debug, Clone, PartialEq, DekuWrite, DekuRead)]
#[deku()]
pub struct LeRejectCisParam {
    #[deku(pad_bytes_before = "1")]
    pub connection_handle: u16,
    pub reason: u8,
}

/// HCI_LE_Setup_ISO_Data_Path
/// ref: 7.8.111 LE Setup ISO Data Path command
#[derive(Debug, Clone, PartialEq, DekuWrite, DekuRead)]
#[deku()]
pub struct LeSetupIsoPathParam {
    #[deku(pad_bytes_before = "1")]
    pub connection_handle: u16,
    pub data_path_direction: u8,
    pub data_path_id: u8,
    pub codec_id: [u8; 5],
    pub controller_delay: [u8; 3],
    pub codec_configuration_length: u8,
    #[deku(count = "codec_configuration_length")]
    pub codec_configuration: Vec<u8>,
}

/// HCI_LE_Remove_ISO_Data_Path
/// ref: 7.8.112 LE Remove ISO Data Path command
#[derive(Debug, Clone, PartialEq, DekuWrite, DekuRead)]
#[deku()]
pub struct LeRemoveIsoPathParam {
    #[deku(pad_bytes_before = "1")]
    pub connection_handle: u16,
    pub data_path_direction: u8,
}

/// HCI_LE_Set_Extended_Advertising_Parameters [v2]
/// ref: 7.8.53 LE Set Extended Advertising Parameters command
#[derive(Debug, Clone, PartialEq, DekuWrite, DekuRead)]
#[deku()]
pub struct LeSetExtendedAdvertisingParametersV2Param {
    #[deku(pad_bytes_before = "1")]
    pub advertising_handle: u8,
    pub advertising_event_priorities: u16,
    pub primary_advertising_interval_min: [u8; 3],
    pub primary_advertising_interval_max: [u8; 3],
    pub primary_advertising_channel_map: u8,
    pub own_address_type: AddrKind,
    pub peer_address_type: AddrKind,
    pub peer_address: BdAddr,
    pub advertising_filter_policy: AdvFilterPolicy,
    pub advertising_tx_power: u8,
    pub primary_advertising_phy: u8,
    pub secondary_advertising_max_skip: u8,
    pub secondary_advertising_phy: u8,
    pub advertising_sid: u8,
    pub scan_request_notification_enable: u8,
    pub primary_advertising_phy_options: u8,
    pub secondary_advertising_phy_options: u8,
}

impl fmt::Display for LeSetExtendedAdvertisingParametersV2Param {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Advertising_Handle=0x{:02x}, Advertising_Event_Priorities=0x{:04x}, Own_Address_Type={}, Peer_Address_Type={}, Peer_Address={}, Advertising_Filter_Policy={}",
            self.advertising_handle,
            self.advertising_event_priorities,
            self.own_address_type,
            self.peer_address_type,
            self.peer_address,
            self.advertising_filter_policy,
        )
    }
}
