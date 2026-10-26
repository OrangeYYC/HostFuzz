use crate::hci::protocol::ProtocolError;

use super::Protocol;
use super::Transport;
use async_trait::async_trait;
use bytes::Bytes;
use deku::{DekuContainerRead, DekuContainerWrite};
use std::sync::Mutex;
use tracing::{error, trace, warn};

use super::{ControllerToHostPacket, HostToControllerPacket};
use ble::hci::*;

enum H5LinkEstabState {
    Uninitialized,
    Initialized,
    Active,
}

const H5_TYPE_ACK: i32 = 0; // Acknowledgment packets
const H5_TYPE_HCI_CMD: i32 = 1; // HCI Command packet
const H5_TYPE_HCI_ACL: i32 = 2; // HCI ACL Data packet
const H5_TYPE_HCI_SYN: i32 = 3; // HCI Synchronous Data packet
const H5_TYPE_HCI_EVT: i32 = 4; // HCI Event packet
const H5_TYPE_HCI_ISO: i32 = 5; // HCI ISO Data packet
const H5_TYPE_VENDOR: i32 = 14; // Vendor Specific
const H5_TYPE_LINK_CTL: i32 = 15; // Link Control packet

pub struct H5Storage {
    next_ack: i32,
    cur_seq: i32,
    last_reliable: bool,
    link_estab_state: H5LinkEstabState,
}

pub struct H5Protocol {
    transport: Box<dyn Transport>,
    storage: Mutex<H5Storage>,
}

impl H5Protocol {
    pub fn new(transport: Box<dyn Transport>) -> Self {
        Self {
            transport,
            storage: Mutex::new(H5Storage::new()),
        }
    }

    pub async fn handle_link_control_pkt(&self, h5_packet: HciH5Packet) -> Result<(), ProtocolError> {
        trace!("H5 RECV: handle link control packet from host");

        match h5_packet.payload.as_slice() {
            // link control: sync message
            [0x01, 0x7e] => {
                trace!("handle link control packet: sync message");
                let mut resp = HciH5Packet::blank();
                resp.payload = vec![0x02, 0x7d];
                resp.set_pkt_type(H5_TYPE_LINK_CTL);
                resp.update_payload_len();
                resp.update_hdr_chksum();
                self.storage.lock().unwrap().last_reliable = false;
                self.storage.lock().unwrap().link_estab_state = H5LinkEstabState::Initialized;
                self.write_h5_packet(resp).await
            }
            // link control: config message
            [0x03, 0xfc, conf_field] => {
                trace!("handle link control packet: config message");
                let sliding_window_size = conf_field & 0b0000_0111;
                let oof_flow_control = ((conf_field & 0b0000_1000) >> 3) == 1;
                let data_integrity_check_type = ((conf_field & 0b0001_0000) >> 4) == 1;
                let version_number = (conf_field & 0b1110_0000) >> 5;
                trace!("sliding_window_size: {}", sliding_window_size);
                trace!("oof_flow_control: {}", oof_flow_control);
                trace!("data_integrity_check_type: {}", data_integrity_check_type);
                trace!("version_number: {}", version_number);

                let mut resp = HciH5Packet::blank();
                resp.payload = vec![0x04, 0x7b, *conf_field];
                resp.set_pkt_type(H5_TYPE_LINK_CTL);
                resp.update_payload_len();
                resp.update_hdr_chksum();
                self.storage.lock().unwrap().last_reliable = false;
                self.storage.lock().unwrap().link_estab_state = H5LinkEstabState::Active;
                self.write_h5_packet(resp).await
            }
            _ => {
                error!("invalid link control packet");
                Err(ProtocolError::InvalidTransportPacket("invalid link control packet"))
            }
        }
    }

    async fn write_h5_packet(&self, mut pkt: HciH5Packet) -> Result<(), ProtocolError> {
        pkt.set_reliable(self.storage.lock().unwrap().last_reliable);
        pkt.set_ack(self.storage.lock().unwrap().next_ack);
        pkt.set_seq(self.storage.lock().unwrap().cur_seq);
        {
            let mut storage = self.storage.lock().unwrap();
            storage.cur_seq = (storage.cur_seq + 1) % 8;
        }
        pkt.update_payload_len();
        pkt.update_hdr_chksum();
        self.transport.write(Bytes::from(slip_encode(&pkt.to_bytes()))).await?;
        trace!("H5 READ: {}, seq={}, ack={}", hex::encode_upper(pkt.to_bytes()), pkt.seq(), pkt.ack());

        Ok(())
    }
}

#[async_trait]
impl<'a> Protocol for H5Protocol {
    fn transport(&self) -> &dyn Transport {
        &*self.transport
    }

    async fn read(&self) -> Result<HostToControllerPacket, ProtocolError> {
        loop {
            // decode packet
            let slip_pkt = self.transport.read().await?;
            let h5_raw = slip_decode(&slip_pkt)?;
            let h5_packet = HciH5Packet::from_bytes(&h5_raw)?;

            // change internal state
            self.storage.lock().unwrap().next_ack = (h5_packet.seq() + 1) % 8;
            self.storage.lock().unwrap().cur_seq = h5_packet.ack();
            self.storage.lock().unwrap().last_reliable = h5_packet.reliable();
            trace!("H5 RECV: Packet type: {} ack={} seq={}", h5_packet.pkt_type(), h5_packet.ack(), h5_packet.seq());

            match h5_packet.pkt_type() {
                // we should never receive a command packet
                H5_TYPE_HCI_EVT => {
                    error!("H5 RECV: host should never send EVENT packet to controller")
                }
                // ack packet from the host
                H5_TYPE_ACK => {
                    trace!("H5 RECV: ack packet from host")
                }
                // vendor specific packet
                H5_TYPE_VENDOR => {
                    warn!("H5 RECV: vendor sepecific packet from host");
                }
                // link control packet from host
                H5_TYPE_LINK_CTL => {
                    self.handle_link_control_pkt(h5_packet).await?;
                }
                // HCI Command packet
                H5_TYPE_HCI_CMD => {
                    let ((_, _), cmd_pkt) = HciCommandPkt::from_bytes((&h5_packet.payload, 0))?;
                    return Ok(HostToControllerPacket::Command(cmd_pkt));
                }
                // HCI ACL Data packet
                H5_TYPE_HCI_ACL => {
                    let ((_, _), acl_pkt) = HciAclDataPkt::from_bytes((&h5_packet.payload, 0))?;
                    return Ok(HostToControllerPacket::AclData(acl_pkt));
                }
                // HCI Synchronous Data packet
                H5_TYPE_HCI_SYN => {
                    let ((_, _), syn_pkt) = HciSyncDataPkt::from_bytes((&h5_packet.payload, 0))?;
                    return Ok(HostToControllerPacket::SyncData(syn_pkt));
                }
                // HCI ISO Data packet
                H5_TYPE_HCI_ISO => {
                    let ((_, _), iso_pkt) = HciIsoDataPkt::from_bytes((&h5_packet.payload, 0))?;
                    return Ok(HostToControllerPacket::IsoData(iso_pkt));
                }
                // invalid
                x => {
                    error!("H5 RECV: invalid packet id {}", x)
                }
            }
        }
    }

    async fn write(&self, packet: &ControllerToHostPacket) -> Result<(), ProtocolError> {
        self.write_h5_packet(HciH5Packet::from_h4_packet(packet)).await
    }
}

impl H5Storage {
    pub fn new() -> Self {
        Self {
            next_ack: 0,
            cur_seq: 0,
            last_reliable: false,
            link_estab_state: H5LinkEstabState::Uninitialized,
        }
    }
}

fn slip_encode(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0xC0];
    for &b in data {
        match b {
            0xC0 => out.extend_from_slice(&[0xDB, 0xDC]),
            0xDB => out.extend_from_slice(&[0xDB, 0xDD]),
            _ => out.push(b),
        }
    }
    out.push(0xC0);
    out
}

fn slip_decode(data: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    let mut out = Vec::new();
    let mut iter = data.iter().peekable();

    while let Some(&&b) = iter.peek() {
        if b == 0xC0 {
            iter.next();
        } else {
            break;
        }
    }

    while let Some(&b) = iter.next() {
        match b {
            0xC0 => break,
            0xDB => match iter.next() {
                Some(0xDC) => out.push(0xC0),
                Some(0xDD) => out.push(0xDB),
                _ => {
                    return Err(ProtocolError::InvalidTransportPacket("Invalid SLIP escape sequence"));
                }
            },
            _ => out.push(b),
        }
    }

    if out.is_empty() {
        Err(ProtocolError::InvalidTransportPacket("Empty or invalid SLIP frame"))
    } else {
        Ok(out)
    }
}

pub struct HciH5Packet {
    // packet header, 4 octets
    header: Vec<u8>,
    // payload, 0-4095 octets
    payload: Vec<u8>,
    // data integrity check, 2 octets
    integrity: Option<Vec<u8>>,
}

impl HciH5Packet {
    // create blank hci h5 packet
    pub fn blank() -> Self {
        Self {
            header: vec![0x0, 0x0, 0x0, 0x0],
            payload: vec![],
            integrity: None,
        }
    }

    pub fn from_h4_packet(pkt: &ControllerToHostPacket) -> Self {
        let (pkt_type, payload) = match pkt {
            ControllerToHostPacket::Event(p) => (H5_TYPE_HCI_EVT, p.to_bytes()),
            ControllerToHostPacket::AclData(p) => (H5_TYPE_HCI_ACL, p.to_bytes()),
            ControllerToHostPacket::IsoData(p) => (H5_TYPE_HCI_ISO, p.to_bytes()),
            ControllerToHostPacket::SyncData(p) => (H5_TYPE_HCI_SYN, p.to_bytes()),
        };

        let mut ret = Self {
            header: vec![0x0, 0x0, 0x0, 0x0],
            payload: payload.unwrap(),
            integrity: None,
        };
        ret.set_pkt_type(pkt_type);

        ret
    }

    // craft hci h5 packet from raw bytes
    pub fn from_bytes(raw: &[u8]) -> Result<Self, ProtocolError> {
        if raw.len() < 4 {
            return Err(ProtocolError::InvalidTransportPacket("packet length to short"));
        }
        let has_crc = ((raw[0] >> 6) & 0x01) != 0;
        if has_crc && raw.len() < 6 {
            return Err(ProtocolError::InvalidTransportPacket("packet length to short"));
        }
        let pkt = Self {
            header: raw[0..4].to_vec(),
            payload: if has_crc {
                raw[4..raw.len() - 2].to_vec()
            } else {
                raw[4..raw.len()].to_vec()
            },
            integrity: if has_crc { Some(raw[raw.len() - 2..raw.len()].to_vec()) } else { None },
        };
        if pkt.payload_len() as usize != pkt.payload.len() {
            return Err(ProtocolError::InvalidTransportPacket("payload length not equal to length in header"));
        }
        if ![0, 1, 2, 3, 4, 5, 14, 15].contains(&pkt.pkt_type()) {
            return Err(ProtocolError::InvalidTransportPacket("packet type is reserved for future use"));
        }
        Ok(pkt)
    }

    // craft hci h5 packet to raw bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut ret = Vec::new();
        ret.extend(&self.header);
        ret.extend(&self.payload);
        if let Some(integrity) = &self.integrity {
            ret.extend(integrity);
        }
        ret
    }

    // sequence number
    pub fn seq(&self) -> i32 {
        (self.header[0] & 0x07) as i32
    }
    pub fn set_seq(&mut self, seq: i32) {
        assert!(seq < 8);
        let mut tmp = self.header[0] & 0b1111_1000;
        tmp = tmp | (seq as u8 & 0x07);
        self.header[0] = tmp;
    }

    // acknowledgment number
    pub fn ack(&self) -> i32 {
        ((self.header[0] >> 3) & 0x07) as i32
    }
    pub fn set_ack(&mut self, ack: i32) {
        assert!(ack < 8);
        let mut tmp = self.header[0] & 0b1100_0111;
        tmp = tmp | ((ack as u8) << 3);
        self.header[0] = tmp;
    }

    // data integrity check present
    pub fn crc(&self) -> bool {
        ((self.header[0] >> 6) & 0x01) != 0
    }
    pub fn set_crc(&mut self, crc: bool) {
        let mut tmp = self.header[0] & 0b1011_1111;
        if crc {
            tmp = tmp | (1 << 6);
        }
        self.header[0] = tmp;
    }

    // reliable packet
    pub fn reliable(&self) -> bool {
        ((self.header[0] >> 7) & 0x01) != 0
    }
    pub fn set_reliable(&mut self, reliable: bool) {
        let mut tmp = self.header[0] & 0b0111_1111;
        if reliable {
            tmp = tmp | (1 << 7);
        }
        self.header[0] = tmp;
    }

    // packet type
    pub fn pkt_type(&self) -> i32 {
        (self.header[1] & 0xf) as i32
    }
    pub fn set_pkt_type(&mut self, pkt_type: i32) {
        assert!([0, 1, 2, 3, 4, 5, 14, 15].contains(&pkt_type));
        let mut tmp = self.header[1] & 0xf0;
        tmp = tmp | (pkt_type as u8);
        self.header[1] = tmp;
    }

    // payload length
    pub fn payload_len(&self) -> i32 {
        let len_high = self.header[2] as i32;
        let len_low = ((self.header[1] >> 4) & 0x0f) as i32;
        len_low + (len_high << 4)
    }
    pub fn update_payload_len(&mut self) {
        let len_high = (self.payload.len() >> 4) & 0xff;
        let len_low = self.payload.len() & 0x0f;
        self.header[2] = len_high as u8;
        let mut tmp = self.header[1] & 0x0f;
        tmp = tmp | ((len_low as u8) << 4);
        self.header[1] = tmp;
    }

    // header checksum
    pub fn hdr_chksum(&self) -> i32 {
        self.header[3] as i32
    }
    pub fn update_hdr_chksum(&mut self) {
        let sum = self.header[0].wrapping_add(self.header[1]).wrapping_add(self.header[2]);
        self.header[3] = 0xffu8.wrapping_sub(sum)
    }
}

#[cfg(test)]
mod tests {
    use super::HciH5Packet;

    #[test]
    fn test_hci_h5_packet_decode() {
        let packet = HciH5Packet::from_bytes(&[0x28, 0x00, 0x00, 0xD7]).unwrap();
        println!("seq={}, ack={}", packet.seq(), packet.ack());

        assert!(packet.seq() == 0);
        assert!(packet.ack() == 0);
        assert!(packet.crc() == false);
        assert!(packet.reliable() == false);
        assert!(packet.pkt_type() == 15);
        assert!(packet.payload.len() == 2);
        assert!(packet.hdr_chksum() == 0xd0);
    }

    #[test]
    fn test_hci_h5_packet_encode() {
        let mut packet = HciH5Packet::blank();
        packet.set_seq(0);
        packet.set_ack(0);
        packet.set_crc(false);
        packet.set_reliable(false);
        packet.set_pkt_type(15);
        packet.payload = [0x01, 0x7e].to_vec();
        packet.update_payload_len();
        packet.update_hdr_chksum();
        assert!(packet.to_bytes() == [0x00, 0x2f, 0x00, 0xd0, 0x01, 0x7e])
    }
}
