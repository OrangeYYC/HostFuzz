use crate::helper::set_bit;

use super::HciEventPkt;
use super::parameter::*;
use deku::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, DekuWrite, Deserialize, Serialize, Hash)]
#[deku()]
pub struct CommandCompleteEvent {
    pub parameter_total_length: u8,
    pub num_hci_command_packets: u8,
    pub command_opcode: u16,
    pub return_parameters: Vec<u8>,
}

impl CommandCompleteEvent {
    pub fn cmd_ack(opcode: u16) -> HciEventPkt {
        CommandCompleteEvent::cmd_status(opcode, 0x0)
    }

    pub fn cmd_unsupported(opcode: u16) -> HciEventPkt {
        CommandCompleteEvent::cmd_status(opcode, 0x1)
    }

    pub fn cmd_ret(opcode: u16, body: Vec<u8>) -> HciEventPkt {
        let mut params = vec![0x00];
        params.extend_from_slice(&body);
        HciEventPkt::CommandComplete(Self {
            num_hci_command_packets: 0x1,
            command_opcode: opcode,
            parameter_total_length: 0x3 + u8::try_from(params.len()).unwrap(),
            return_parameters: params,
        })
    }

    pub fn cmd_status(opcode: u16, status: u8) -> HciEventPkt {
        HciEventPkt::CommandComplete(Self {
            num_hci_command_packets: 0x1,
            command_opcode: opcode,
            parameter_total_length: 0x4,
            return_parameters: vec![status],
        })
    }
}

#[derive(Debug, Clone, PartialEq, DekuWrite, Deserialize, Serialize, Hash)]
#[deku(endian = "little")]
pub struct CommandStatusEvent {
    pub parameter_total_length: u8,
    pub status: u8,
    pub num_hci_command_packets: u8,
    pub command_opcode: u16,
}

impl CommandStatusEvent {
    pub fn cmd_ack(opcode: u16) -> HciEventPkt {
        CommandStatusEvent::cmd_status(opcode, 0x0)
    }

    pub fn cmd_status(opcode: u16, status: u8) -> HciEventPkt {
        HciEventPkt::CommandStatus(Self {
            num_hci_command_packets: 0x1,
            status,
            parameter_total_length: 0x4,
            command_opcode: opcode,
        })
    }
}

#[derive(Debug, Clone, PartialEq, DekuWrite, Deserialize, Serialize, Hash)]
#[deku(endian = "little")]
pub struct EncryptionChangeEvent {
    pub parameter_total_length: u8,
    pub status: u8,
    pub connection_handle: u16,
    pub encryption_enabled: u8,
}

impl EncryptionChangeEvent {
    pub fn warp(self) -> HciEventPkt {
        HciEventPkt::EncryptionChange(self)
    }
}

#[derive(Debug, Clone, PartialEq, DekuWrite, Deserialize, Serialize, Hash)]
#[deku(endian = "little")]
pub struct NumberOfCompletetedPacketsEvent {
    pub parameter_total_length: u8,
    pub num_handlers: u8,
    pub connection_handle: u16,
    pub num_completeted_packets: u16,
}

impl NumberOfCompletetedPacketsEvent {
    pub fn packet_ack(handle: u16, num_packets: u16) -> HciEventPkt {
        HciEventPkt::NumberOfCompletetedPackets(Self {
            parameter_total_length: 0x5,
            num_handlers: 0x1,
            connection_handle: handle,
            num_completeted_packets: num_packets,
        })
    }
}

#[derive(Debug, Clone, PartialEq, DekuWrite, Deserialize, Serialize, Hash)]
#[deku(endian = "little")]
pub struct ReadRemoteVersionInformationCompleteEvent {
    pub parameter_total_length: u8,
    pub status: u8,
    pub handle: u16,
    pub version: u8,
    pub company_identifier: u16,
    pub subversion: u16,
}

#[derive(Debug, Clone, PartialEq, DekuWrite, Deserialize, Serialize, Hash)]
#[deku()]
pub struct LeMetaEvent {
    pub parameter_total_length: u8,
    pub body: LeMetaEventBody,
}

#[derive(Debug, Clone, PartialEq, DekuWrite, Deserialize, Serialize, Hash)]
#[deku(id_type = "u8")]
pub enum LeMetaEventBody {
    #[deku(id = 0x01)]
    ConnectionComplete(LeConnectionCompleteEvent),
    #[deku(id = 0x02)]
    AdvertisingReport(LeAdvertisingReportEvent),
    #[deku(id = 0x03)]
    ConnectionUpdateComplete(LeConnectionUpdateCompleteEvent),
    #[deku(id = 0x04)]
    ReadRemoteFeatureComplete(LeReadRemoteFeaturesCompleteEvent),
    #[deku(id = 0x05)]
    LongTermKeyRequest(LeLongTermKeyRequestEvent),
    #[deku(id = 0x08)]
    ReadLocalP256PublicKeyComplete(LeReadLocalP256PublicKeyCompleteEvent),
    #[deku(id = 0x0C)]
    PhyUpdateComplete(LePhyUpdateCompleteEvent),
    #[deku(id = 0x0D)]
    ExtendedAdvertisingReport(LeExtendedAdvertisingReportEvent),
    #[deku(id = 0x0E)]
    PeriodicAdvertisingSyncEstablished(LePeriodicAdvertisingSyncEstablishedEvent),
    #[deku(id = 0x0F)]
    PeriodicAdvertisingReport(LePeriodicAdvertisingReportEvent),
    #[deku(id = 0x18)]
    PastReceived(LePastReceivedEvent),
    #[deku(id = 0x12)]
    AdvertisingSetTerminated(LeAdvertisingSetTerminatedEvent),
    #[deku(id = 0x19)]
    CisEstablished(LeCisEstablishedEvent),
    #[deku(id = 0x1A)]
    CisRequest(LeCisRequestEvent),
}

#[derive(Debug, Clone, PartialEq, DekuWrite, Deserialize, Serialize, Hash)]
#[deku()]
pub struct LeCisRequestEvent {
    pub acl_handle: u16,
    pub cis_handle: u16,
    pub cig_id: u8,
    pub cis_id: u8,
}

impl LeCisRequestEvent {
    pub fn warp(self) -> HciEventPkt {
        HciEventPkt::LeMata(LeMetaEvent {
            parameter_total_length: 7,
            body: LeMetaEventBody::CisRequest(self),
        })
    }
}

impl From<LeCisRequestEvent> for HciEventPkt {
    fn from(value: LeCisRequestEvent) -> Self {
        LeCisRequestEvent::warp(value)
    }
}

#[derive(Debug, Clone, PartialEq, DekuWrite, Deserialize, Serialize, Hash)]
#[deku()]
pub struct LeCisEstablishedEvent {
    pub status: u8,
    pub connection_handle: u16,
    pub cig_sync_delay: [u8; 3],
    pub cis_sync_delay: [u8; 3],
    pub c_latency: [u8; 3],
    pub p_latency: [u8; 3],
    pub c_phy: u8,
    pub p_phy: u8,
    pub nse: u8,
    pub c_bn: u8,
    pub p_bn: u8,
    pub c_ft: u8,
    pub p_ft: u8,
    pub c_max_pdu: u16,
    pub p_max_pdu: u16,
    pub interval: u16,
}

impl LeCisEstablishedEvent {
    pub fn warp(self) -> HciEventPkt {
        HciEventPkt::LeMata(LeMetaEvent {
            parameter_total_length: 29,
            body: LeMetaEventBody::CisEstablished(self),
        })
    }
}

impl From<LeCisEstablishedEvent> for HciEventPkt {
    fn from(value: LeCisEstablishedEvent) -> Self {
        LeCisEstablishedEvent::warp(value)
    }
}

#[derive(Debug, Clone, PartialEq, DekuWrite, Deserialize, Serialize, Hash)]
#[deku()]
pub struct LePeriodicAdvertisingSyncEstablishedEvent {
    pub status: u8,
    pub sync_handle: u16,
    pub advertising_sid: u8,
    pub advertiser_address_type: AddrKind,
    pub advertiser_address: BdAddr,
    pub advertiser_phy: u8,
    pub periodic_advertising_interval: u16,
    pub advertiser_clock_accuracy: u8,
}

impl LePeriodicAdvertisingSyncEstablishedEvent {
    pub fn warp(self) -> HciEventPkt {
        HciEventPkt::LeMata(LeMetaEvent {
            // Sub-event (1) + payload (15)
            parameter_total_length: 16,
            body: LeMetaEventBody::PeriodicAdvertisingSyncEstablished(self),
        })
    }
}

impl From<LePeriodicAdvertisingSyncEstablishedEvent> for HciEventPkt {
    fn from(value: LePeriodicAdvertisingSyncEstablishedEvent) -> Self {
        LePeriodicAdvertisingSyncEstablishedEvent::warp(value)
    }
}

#[derive(Debug, Clone, PartialEq, DekuWrite, Deserialize, Serialize, Hash)]
#[deku()]
pub struct LePeriodicAdvertisingReportEvent {
    /// Raw report payload kept mutable-friendly so mutators can desync internal
    /// data_length from actual tail bytes for parser robustness fuzzing.
    pub payload: Vec<u8>,
}

impl LePeriodicAdvertisingReportEvent {
    pub fn new(payload: Vec<u8>) -> HciEventPkt {
        HciEventPkt::LeMata(LeMetaEvent {
            parameter_total_length: 1 + payload.len().min(usize::from(u8::MAX - 1)) as u8,
            body: LeMetaEventBody::PeriodicAdvertisingReport(Self { payload }),
        })
    }
}

#[derive(Debug, Clone, PartialEq, DekuWrite, Deserialize, Serialize, Hash)]
#[deku()]
pub struct LePastReceivedEvent {
    pub status: u8,
    pub conn_handle: u16,
    pub service_data: u16,
    pub sync_handle: u16,
    pub advertising_sid: u8,
    pub advertiser_address_type: AddrKind,
    pub advertiser_address: BdAddr,
    pub advertiser_phy: u8,
    pub periodic_advertising_interval: u16,
    pub advertiser_clock_accuracy: u8,
}

impl LePastReceivedEvent {
    pub fn warp(self) -> HciEventPkt {
        HciEventPkt::LeMata(LeMetaEvent {
            // Sub-event (1) + payload (19)
            parameter_total_length: 20,
            body: LeMetaEventBody::PastReceived(self),
        })
    }
}

impl From<LePastReceivedEvent> for HciEventPkt {
    fn from(value: LePastReceivedEvent) -> Self {
        LePastReceivedEvent::warp(value)
    }
}

#[derive(Debug, Clone, PartialEq, DekuWrite, Deserialize, Serialize, Hash)]
#[deku()]
pub struct LeLongTermKeyRequestEvent {
    pub connection_handle: u16,
    pub random_number: [u8; 8],
    pub encrypted_diversifier: u16,
}

impl LeLongTermKeyRequestEvent {
    pub fn new(connection_handle: u16, random_number: [u8; 8], encrypted_diversifier: u16) -> HciEventPkt {
        HciEventPkt::LeMata(LeMetaEvent {
            parameter_total_length: 13,
            body: LeMetaEventBody::LongTermKeyRequest(Self {
                connection_handle,
                random_number,
                encrypted_diversifier,
            }),
        })
    }
}

#[derive(Debug, Clone, PartialEq, DekuWrite, Deserialize, Serialize, Hash)]
#[deku(endian = "little")]
pub struct LePhyUpdateCompleteEvent {
    pub status: u8,
    pub connection_handle: u16,
    pub tx_phy: u8,
    pub rx_phy: u8,
}

impl LePhyUpdateCompleteEvent {
    pub fn warp(self) -> HciEventPkt {
        HciEventPkt::LeMata(LeMetaEvent {
            parameter_total_length: 1 + 5,
            body: LeMetaEventBody::PhyUpdateComplete(self),
        })
    }
}

#[derive(Debug, Clone, PartialEq, DekuWrite, Deserialize, Serialize, Hash)]
#[deku()]
pub struct AdvertisingReport {
    pub event_type: u8,
    pub address_type: AddrKind,
    pub address: BdAddr,
    pub data_length: u8,
    pub data: Vec<u8>,
    pub rssi: u8,
}

impl AdvertisingReport {
    pub fn size(&self) -> u8 {
        1 + 1 + 6 + 1 + self.data.len() as u8 + 1
    }
}

#[derive(Debug, Clone, PartialEq, DekuWrite, Deserialize, Serialize, Hash)]
#[deku()]
pub struct LeAdvertisingReportEvent {
    pub num_reports: u8,
    pub reports: Vec<AdvertisingReport>,
}

impl LeAdvertisingReportEvent {
    pub fn new(reports: Vec<AdvertisingReport>) -> HciEventPkt {
        let mut parameter_total_length = 0x2;
        for report in &reports {
            parameter_total_length += report.size();
        }
        HciEventPkt::LeMata(LeMetaEvent {
            parameter_total_length,
            body: LeMetaEventBody::AdvertisingReport(Self {
                num_reports: reports.len() as u8,
                reports,
            }),
        })
    }

    pub fn parameter_total_length(&self) -> u8 {
        let mut parameter_total_length = 0x2;
        for report in &self.reports {
            parameter_total_length += report.size();
        }
        parameter_total_length
    }
}

#[derive(Debug, Clone, PartialEq, DekuWrite, Deserialize, Serialize, Hash)]
#[deku()]
pub struct LeConnectionCompleteEvent {
    pub status: u8,
    pub connection_handle: u16,
    pub role: LeConnRole,
    pub peer_address_type: AddrKind,
    pub peer_address: BdAddr,
    pub connection_interval: Duration<1_250>,
    pub peripheral_latency: u16,
    pub supervision_timeout: Duration<10_000>,
    pub central_clock_accuracy: u8,
}

impl LeConnectionCompleteEvent {
    pub fn warp(self) -> HciEventPkt {
        HciEventPkt::LeMata(LeMetaEvent {
            parameter_total_length: 19,
            body: LeMetaEventBody::ConnectionComplete(self),
        })
    }
}

impl From<LeConnectionCompleteEvent> for HciEventPkt {
    fn from(value: LeConnectionCompleteEvent) -> Self {
        LeConnectionCompleteEvent::warp(value)
    }
}

#[derive(Debug, Clone, PartialEq, DekuWrite, Deserialize, Serialize, Hash)]
#[deku()]
pub struct LeConnectionUpdateCompleteEvent {
    pub status: u8,
    pub connection_handle: u16,
    pub connection_interval: Duration<1_250>,
    pub peripheral_latency: u16,
    pub supervision_timeout: Duration<10_000>,
}

impl LeConnectionUpdateCompleteEvent {
    pub fn warp(self) -> HciEventPkt {
        HciEventPkt::LeMata(LeMetaEvent {
            parameter_total_length: 10,
            body: LeMetaEventBody::ConnectionUpdateComplete(self),
        })
    }
}

#[derive(Debug, Clone, PartialEq, DekuWrite, Deserialize, Serialize, Hash)]
#[deku()]
pub struct LeReadRemoteFeaturesCompleteEvent {
    pub status: u8,
    pub handle: u16,
    pub le_features: [u8; 8],
}

impl LeReadRemoteFeaturesCompleteEvent {
    pub fn default(conn_handle: u16) -> Self {
        let mut ret = vec![0x1; 8];
        // Host Controlled
        set_bit(&mut ret[..], 32, false);
        set_bit(&mut ret[..], 38, false);
        set_bit(&mut ret[..], 42, false);
        for i in 58..64 {
            set_bit(&mut ret[..], i, false);
        }
        Self {
            status: 0x0,
            handle: conn_handle,
            le_features: ret.try_into().unwrap(),
        }
    }

    pub fn warp(self) -> HciEventPkt {
        HciEventPkt::LeMata(LeMetaEvent {
            parameter_total_length: 12,
            body: LeMetaEventBody::ReadRemoteFeatureComplete(self),
        })
    }
}

#[derive(Debug, Clone, PartialEq, DekuWrite, Deserialize, Serialize, Hash)]
#[deku()]
pub struct LeReadLocalP256PublicKeyCompleteEvent {
    pub status: u8,
    pub local_p256_public_key: Vec<u8>,
}

impl LeReadLocalP256PublicKeyCompleteEvent {
    pub fn new(local_p256_public_key: [u8; 64]) -> HciEventPkt {
        HciEventPkt::LeMata(LeMetaEvent {
            parameter_total_length: 66,
            body: LeMetaEventBody::ReadLocalP256PublicKeyComplete(Self {
                status: 0x0,
                local_p256_public_key: local_p256_public_key.to_vec(),
            }),
        })
    }
}

#[derive(Debug, Clone, PartialEq, DekuWrite, Deserialize, Serialize, Hash)]
#[deku()]
pub struct DisconnectCompleteEvent {
    pub parameter_total_length: u8,
    pub status: u8,
    pub handle: u16,
    pub reason: u8,
}

impl DisconnectCompleteEvent {
    pub fn new(status: u8, handle: u16, reason: u8) -> Self {
        DisconnectCompleteEvent {
            parameter_total_length: 0x04,
            status,
            handle,
            reason,
        }
    }

    pub fn warp(self) -> HciEventPkt {
        HciEventPkt::DisconnectComplete(self)
    }
}

#[derive(Debug, Clone, PartialEq, DekuWrite, Deserialize, Serialize, Hash)]
#[deku()]
pub struct LeExtendedAdvertisingReportEvent {
    pub num_reports: u8,
    pub payload: Vec<u8>,
}

impl LeExtendedAdvertisingReportEvent {
    pub fn new(payload: Vec<u8>) -> HciEventPkt {
        HciEventPkt::LeMata(LeMetaEvent {
            parameter_total_length: 2 + payload.len() as u8,
            body: LeMetaEventBody::ExtendedAdvertisingReport(Self { num_reports: 0x1, payload }),
        })
    }
}

#[derive(Debug, Clone, PartialEq, DekuWrite, Deserialize, Serialize, Hash)]
#[deku()]
pub struct LeAdvertisingSetTerminatedEvent {
    pub status: u8,
    pub advertising_handle: u8,
    pub connection_handle: u16,
    pub num_completed_extended_advertising_events: u8,
}

impl LeAdvertisingSetTerminatedEvent {
    pub fn warp(self) -> HciEventPkt {
        HciEventPkt::LeMata(LeMetaEvent {
            parameter_total_length: 6,
            body: LeMetaEventBody::AdvertisingSetTerminated(self),
        })
    }
}

impl From<LeAdvertisingSetTerminatedEvent> for HciEventPkt {
    fn from(value: LeAdvertisingSetTerminatedEvent) -> Self {
        LeAdvertisingSetTerminatedEvent::warp(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ack() {
        println!("{}", hex::encode_upper(CommandCompleteEvent::cmd_ack(0x0c03).to_bytes().unwrap()));
    }
}
