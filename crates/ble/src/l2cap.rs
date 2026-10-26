use crate::hci::{HciAclDataPkt, parameter::Duration};

use deku::prelude::*;
use tracing::error;

#[derive(Debug)]
pub enum L2capError {
    PacketTooShort,
    PacketRemainBytes(usize),
    InvalidLength,
    InvalidCframe(DekuError),
}

#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(id_type = "u8")]
pub enum L2capInformationPayload {
    #[deku(id = 0x01)]
    CommandRejectRsp(L2capCommandRejectRsp),
    #[deku(id = 0x06)]
    DisconnectionReq(L2capDisconnectionReq),
    #[deku(id = 0x07)]
    DisconnectionRsp(L2capDisconnectionRsp),
    #[deku(id = 0x12)]
    ConnectionParameterUpdateReq(L2capConnectionParameterUpdateReq),
    #[deku(id = 0x13)]
    ConnectionParameterUpdateRsp(L2capConnectionParameterUpdateRsp),
    #[deku(id = 0x14)]
    LeCreditBasedConnectionReq(L2capLeCreditBasedConnectionReq),
    #[deku(id = 0x15)]
    LeCreditBasedConnectionRsp(L2capLeCreditBasedConnectionRsp),
    #[deku(id = 0x16)]
    LeFlowControlCreditInd(L2capLeFlowControlCreditInd),
    #[deku(id = 0x17)]
    CreditBasedConnectionReq(L2capCreditBasedConnectionReq),
    #[deku(id = 0x18)]
    CreditBasedConnectionRsp(L2capCreditBasedConnectionRsp),
    #[deku(id = 0x19)]
    CreateBasedReconfigureReq(L2capCreateBasedReconfigureReq),
    #[deku(id = 0x1A)]
    CreateBasedReconfigureRsp(L2capCreateBasedReconfigureRsp),
}

#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku]
pub struct L2capCommandRejectRsp {
    pub identifier: u8,
    #[deku(update = "self.reason_data.len()+0x2")]
    pub data_length: u16,
    pub reason: u16,
    #[deku(count = "data_length-0x2")]
    pub reason_data: Vec<u8>,
}

#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku]
pub struct L2capDisconnectionReq {
    pub identifier: u8,
    #[deku(update = "0x4")]
    pub data_length: u16,
    pub destination_cid: u16,
    pub source_cid: u16,
}

#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku]
pub struct L2capDisconnectionRsp {
    pub identifier: u8,
    #[deku(update = "0x4")]
    pub data_length: u16,
    pub destination_cid: u16,
    pub source_cid: u16,
}

#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku]
pub struct L2capConnectionParameterUpdateReq {
    pub identifier: u8,
    #[deku(update = "0x8")]
    pub data_length: u16,
    pub interval_min: Duration<1_250>,
    pub interval_max: Duration<1_250>,
    pub latency: u16,
    pub timeout: Duration<10_000>,
}

#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku]
pub struct L2capConnectionParameterUpdateRsp {
    pub identifier: u8,
    #[deku(update = "0x2")]
    pub data_length: u16,
    pub result: u16,
}

#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku]
pub struct L2capLeCreditBasedConnectionReq {
    pub identifier: u8,
    #[deku(update = "0x0A")]
    pub data_length: u16,
    pub spsm: u16,
    pub source_cid: u16,
    pub mtu: u16,
    pub mps: u16,
    pub initial_credits: u16,
}

#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku]
pub struct L2capLeCreditBasedConnectionRsp {
    pub identifier: u8,
    #[deku(update = "0x0A")]
    pub data_length: u16,
    pub destination_cid: u16,
    pub mtu: u16,
    pub mps: u16,
    pub initial_credits: u16,
    pub result: u16,
}

#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku]
pub struct L2capLeFlowControlCreditInd {
    pub identifier: u8,
    #[deku(update = "0x04")]
    pub data_length: u16,
    pub cid: u16,
    pub credits: u16,
}

#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku]
pub struct L2capCreditBasedConnectionReq {
    pub identifier: u8,
    #[deku(update = "self.source_cid.len()*0x2+0x8")]
    pub data_length: u16,
    pub spsm: u16,
    pub mtu: u16,
    pub mps: u16,
    pub initial_credits: u16,
    #[deku(count = "(data_length-0x8)/0x2")]
    pub source_cid: Vec<u16>,
}

#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku]
pub struct L2capCreditBasedConnectionRsp {
    pub identifier: u8,
    #[deku(update = "self.destination_cid.len()*0x2+0x8")]
    pub data_length: u16,
    pub mtu: u16,
    pub mps: u16,
    pub initial_credits: u16,
    pub result: u16,
    #[deku(count = "(data_length-0x8)/0x2")]
    pub destination_cid: Vec<u16>,
}

#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku]
pub struct L2capCreateBasedReconfigureReq {
    pub identifier: u8,
    #[deku(update = "self.destination_cid.len()*0x2+0x4")]
    pub data_length: u16,
    pub mtu: u16,
    pub mps: u16,
    #[deku(count = "(data_length-0x4)/0x2")]
    pub destination_cid: Vec<u16>,
}

#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku]
pub struct L2capCreateBasedReconfigureRsp {
    pub identifier: u8,
    #[deku(update = "0x2")]
    pub data_length: u16,
    pub result: u16,
}

/// Decoder for the B-frame on connection-oriented channels in basic L2CAP mode.
pub struct L2capDecoder<'a> {
    pdu_length: u16,
    channel_id: u16,
    payload: &'a [u8],
}

impl<'a> L2capDecoder<'a> {
    /// Creates a L2CAP B-frame packet decoder with given reference to HCI packet.
    pub fn new(acl_packet: &'a HciAclDataPkt) -> Result<Self, L2capError> {
        if acl_packet.data.len() < 4 {
            return Err(L2capError::PacketTooShort);
        }

        let pdu_length = u16::from_le_bytes(acl_packet.data[0..2].try_into().unwrap());
        let channel_id = u16::from_le_bytes(acl_packet.data[2..4].try_into().unwrap());
        let payload = &acl_packet.data[4..];

        if payload.len() != pdu_length as usize {
            return Err(L2capError::InvalidLength);
        }

        Ok(Self {
            pdu_length,
            channel_id,
            payload,
        })
    }

    /// Gets payload size
    pub fn pdu_length(&self) -> u16 {
        self.pdu_length
    }

    /// Gets channel id which identifies the destination channel endpoint of the packet.
    pub fn channel_id(&self) -> u16 {
        self.channel_id
    }

    /// Gets payload received from the upper layer protocol or delivered to the upper layer protocol.
    pub fn payload(&self) -> &[u8] {
        self.payload
    }
}

pub struct L2capEncoder {}

impl L2capEncoder {
    const BFRAME_MAX_PDU_LENGTH: u16 = 65535u16;

    /// Encodes the payload to L2CAP B-frame with given channel id.
    pub fn encode(channel_id: u16, payload: Vec<u8>) -> Result<Vec<u8>, L2capError> {
        let pdu_length = payload.len();
        if pdu_length > Self::BFRAME_MAX_PDU_LENGTH as usize {
            error!("invalid L2CAP packet: invalid length, pdu_length={}", pdu_length);
            return Err(L2capError::InvalidLength);
        }

        Ok((pdu_length as u16)
            .to_le_bytes()
            .into_iter()
            .chain(channel_id.to_le_bytes().into_iter().chain(payload.into_iter()))
            .collect())
    }
}

pub type L2capBframeDecoder<'a> = L2capDecoder<'a>;
pub type L2capBframeEncoder = L2capEncoder;

pub struct L2capCframeDecoder<'a> {
    encoder: L2capDecoder<'a>,
}

impl<'a> L2capCframeDecoder<'a> {
    pub fn new(acl_packet: &'a HciAclDataPkt) -> Result<Self, L2capError> {
        Ok(Self {
            encoder: L2capDecoder::new(acl_packet)?,
        })
    }

    /// Gets payload size
    pub fn pdu_length(&self) -> u16 {
        self.encoder.pdu_length()
    }

    /// Gets channel id which identifies the destination channel endpoint of the packet.
    pub fn channel_id(&self) -> u16 {
        self.encoder.channel_id()
    }

    pub fn information_payload(&self) -> Result<L2capInformationPayload, L2capError> {
        match L2capInformationPayload::from_bytes((self.encoder.payload(), 0)) {
            Ok(((remain, _), payload)) => {
                if remain.len() > 0 {
                    Err(L2capError::PacketRemainBytes(remain.len()))
                } else {
                    Ok(payload)
                }
            }
            Err(err) => {
                error!("failed to parse l2cap packet: {}", err);
                Err(L2capError::InvalidCframe(err))
            }
        }
    }
}

pub struct L2capCframeEncoder {}

impl L2capCframeEncoder {
    pub fn encode(channel_id: u16, mut payload: L2capInformationPayload) -> Result<Vec<u8>, L2capError> {
        payload.update().unwrap();
        L2capEncoder::encode(channel_id, payload.to_bytes().unwrap())
    }
}
