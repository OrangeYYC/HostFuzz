/// Provisiong PDU in advertising report with type 0x29 <PB-ADV>
#[derive(Debug)]
pub struct PbAdvPdu {
    pub link_id: u32,
    pub transaction_number: u8,
    pub generic_prov_pdu: ProvisioningPdu,
}

impl PbAdvPdu {
    pub fn from_bytes(packet: &[u8]) -> Result<PbAdvPdu, &'static str> {
        if packet.len() < 5 {
            return Err("invalid pb-adv header");
        }
        let link_id = u32::from_be_bytes(packet[0..4].try_into().unwrap());
        let transaction_number = packet[4];
        let generic_prov_pdu = ProvisioningPdu::from_bytes(&packet[5..])?;
        return Ok(PbAdvPdu {
            link_id,
            transaction_number,
            generic_prov_pdu,
        });
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut res = Vec::new();
        res.extend_from_slice(&self.link_id.to_be_bytes());
        res.push(self.transaction_number);
        res.extend_from_slice(&self.generic_prov_pdu.to_bytes());
        res
    }
}

#[derive(Debug)]
pub enum ProvisioningPdu {
    TransStart(ProvisioningTransStart),
    TransAck,
    TransCont(ProvisioningTransCont),
    BearerControl(ProvisioningBearerControl),
}

impl ProvisioningPdu {
    /// Convert provisioning pdu from bytes.
    pub fn from_bytes(packet: &[u8]) -> Result<ProvisioningPdu, &'static str> {
        if packet.len() < 1 {
            return Err("packet too short");
        }
        match packet[0] & 0b11 {
            // Transaction Start
            0b00 => {
                if packet.len() < 4 {
                    return Err("transaction start header too short");
                }
                let seg_num = packet[0] >> 2;
                let total_length = ((packet[1] as u16) << 4) + packet[2] as u16;
                let fcs = packet[3];
                let data = packet[4..].to_vec();
                Ok(ProvisioningPdu::TransStart(ProvisioningTransStart {
                    seg_num,
                    total_length,
                    fcs,
                    data,
                }))
            }
            // Transaction Acknowledgment
            0b01 => Ok(ProvisioningPdu::TransAck),
            // Transaction Continuation
            0b10 => {
                let seg_num = packet[0] >> 2;
                let data = packet[1..].to_vec();
                Ok(ProvisioningPdu::TransCont(ProvisioningTransCont { seg_num, data }))
            }
            // Provisioning Bearer Control
            0b11 => {
                let opcode = packet[0] >> 2;
                match opcode {
                    0x00 => {
                        if packet.len() != 17 {
                            return Err("invalid device uuid");
                        }
                        Ok(ProvisioningPdu::BearerControl(ProvisioningBearerControl::LinkOpen(packet[1..17].to_vec())))
                    }
                    0x01 => Ok(ProvisioningPdu::BearerControl(ProvisioningBearerControl::LinkAck)),
                    0x02 => {
                        if packet.len() != 2 {
                            return Err("invalid reason");
                        }
                        Ok(ProvisioningPdu::BearerControl(ProvisioningBearerControl::LinkClose(packet[1])))
                    }
                    _ => Err("invalid bearer control opcode"),
                }
            }
            _ => Err("invalid generic provisioning control field"),
        }
    }

    /// converts provisioning pdu into bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut res = Vec::new();

        match &self {
            Self::TransStart(start) => {
                res.push(start.seg_num << 2);
                res.extend_from_slice(&u16::to_be_bytes(start.total_length));
                res.push(start.fcs);
                res.extend_from_slice(&start.data);
            }
            Self::TransAck => {
                res.push(0b01);
            }
            Self::TransCont(cont) => {
                res.push((cont.seg_num << 2) + 0b10);
                res.extend_from_slice(&cont.data);
            }
            Self::BearerControl(control) => match &control {
                ProvisioningBearerControl::LinkOpen(uuid) => {
                    res.push((0x00 << 2) + 0b11);
                    res.extend_from_slice(uuid);
                }
                ProvisioningBearerControl::LinkAck => {
                    res.push((0x01 << 2) + 0b11);
                }
                ProvisioningBearerControl::LinkClose(reason) => {
                    res.push((0x02 << 2) + 0b11);
                    res.push(*reason);
                }
            },
        };
        res
    }
}

/// Type 0b00: Transaction Start
#[derive(Debug)]
pub struct ProvisioningTransStart {
    pub seg_num: u8,
    pub total_length: u16,
    pub fcs: u8,
    pub data: Vec<u8>,
}

/// Type 0b10: Transaction Continuation
#[derive(Debug)]
pub struct ProvisioningTransCont {
    pub seg_num: u8,
    pub data: Vec<u8>,
}

/// Type 0b11: Provisioning Bearer Control
#[derive(Debug)]
pub enum ProvisioningBearerControl {
    LinkOpen(Vec<u8> /*Device UUID: 16 octets*/), // 0x00
    LinkAck,                                      // 0x01
    LinkClose(u8 /*Reason: 1 octets*/),           // 0x02
}

/// Network PDU in advertising report with type 0x2A <Mesh Message>
#[derive(Debug)]
pub struct NetworkPdu {
    pub ivi: u8,
    pub nid: u8,
    pub ctl: u8,
    pub ttl: u8,
    pub seq: u32,
    pub src: u16,
    pub dst: u16,
    pub data: Vec<u8>,
}

impl NetworkPdu {
    /// Convert network pdu from bytes.
    pub fn from_bytes(packet: &[u8]) -> Result<NetworkPdu, &'static str> {
        if packet.len() < 9 {
            return Err("packet too short");
        }
        let ivi = packet[0] >> 7;
        let nid = packet[0] & 0b01111111;
        let ctl = packet[1] >> 7;
        let ttl = packet[1] & 0b01111111;
        let seq = ((packet[2] as u32) << 16) + ((packet[3] as u32) << 8) + (packet[4] as u32);
        let src = ((packet[5] as u16) << 8) + (packet[6] as u16);
        let dst = ((packet[7] as u16) << 8) + (packet[8] as u16);
        let data = packet[9..].to_vec();
        Ok(NetworkPdu {
            ivi,
            nid,
            ctl,
            ttl,
            seq,
            src,
            dst,
            data,
        })
    }

    /// converts network pdu into bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut packet = Vec::new();

        // byte 0: IVI (1 bit) | NID (7 bits)
        packet.push(((self.ivi & 0x01) << 7) | (self.nid & 0x7F));

        // byte 1: CTL (1 bit) | TTL (7 bits)
        packet.push(((self.ctl & 0x01) << 7) | (self.ttl & 0x7F));

        // byte 2-4: SEQ (24 bits, big-endian)
        packet.push(((self.seq >> 16) & 0xFF) as u8);
        packet.push(((self.seq >> 8) & 0xFF) as u8);
        packet.push((self.seq & 0xFF) as u8);

        // byte 5-6: SRC (big-endian)
        packet.push((self.src >> 8) as u8);
        packet.push((self.src & 0xFF) as u8);

        // byte 7-8: DST (big-endian)
        packet.push((self.dst >> 8) as u8);
        packet.push((self.dst & 0xFF) as u8);

        // byte 9..: payload
        packet.extend_from_slice(&self.data);

        packet
    }
}

/// Mesh Beacon in advertising payload with type 0x2B <Mesh Beacon>
#[derive(Debug)]
pub enum MeshBeacon {
    Unprovisioned(UnprovisionedBeacon),
    Secure(SecureBeacon),
    Private(PrivateBeacon),
}

impl MeshBeacon {
    /// Convert beacon from bytes.
    pub fn from_bytes(packet: &[u8]) -> Result<MeshBeacon, &'static str> {
        if packet.len() < 1 {
            return Err("packet too short");
        }
        match packet[0] {
            0x0 => {
                if packet.len() < 19 {
                    return Err("packet too short");
                }
                let device_uuid = packet[1..17].try_into().unwrap();
                let oob_info = ((packet[17] as u16) << 8) + packet[18] as u16;
                let uri_hash = if packet.len() >= 23 {
                    Some(u32::from_be_bytes([packet[19], packet[20], packet[21], packet[22]]))
                } else {
                    None
                };
                Ok(Self::Unprovisioned(UnprovisionedBeacon {
                    device_uuid,
                    oob_info,
                    uri_hash,
                }))
            }
            0x1 => {
                if packet.len() < 22 {
                    return Err("packet too short");
                }
                let flags = packet[1];
                let mut network_id = [0u8; 8];
                network_id.copy_from_slice(&packet[2..10]);
                let iv_index = u32::from_be_bytes(packet[10..14].try_into().unwrap());
                let auth_value = u64::from_be_bytes(packet[14..22].try_into().unwrap());
                Ok(Self::Secure(SecureBeacon {
                    flags,
                    network_id,
                    iv_index,
                    auth_value,
                }))
            }
            0x2 => {
                if packet.len() < 27 {
                    return Err("packet too short");
                }
                let mut random = [0u8; 13];
                random.copy_from_slice(&packet[1..14]);
                let mut data = [0u8; 5];
                data.copy_from_slice(&packet[14..19]);
                let mut tag = [0u8; 8];
                tag.copy_from_slice(&packet[19..27]);
                Ok(Self::Private(PrivateBeacon { random, data, tag }))
            }
            _ => Err("invalid packet type"),
        }
    }

    /// converts mesh pdu into bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut packet = Vec::new();
        match self {
            MeshBeacon::Unprovisioned(b) => {
                packet.push(0x00);
                // device_uuid (16 bytes)
                packet.extend_from_slice(&b.device_uuid);
                // oob_info (big-endian u16)
                packet.push((b.oob_info >> 8) as u8);
                packet.push((b.oob_info & 0xFF) as u8);
                // optional uri_hash
                if let Some(uri_hash) = b.uri_hash {
                    packet.extend_from_slice(&uri_hash.to_be_bytes());
                }
            }
            MeshBeacon::Secure(b) => {
                packet.push(0x01);
                // flags
                packet.push(b.flags);
                // network_id (8 bytes)
                packet.extend_from_slice(&b.network_id);
                // iv_index (big-endian u32)
                packet.extend_from_slice(&b.iv_index.to_be_bytes());
                // auth_value (big-endian u64)
                packet.extend_from_slice(&b.auth_value.to_be_bytes());
            }

            MeshBeacon::Private(b) => {
                packet.push(0x02);
                // random (13 bytes)
                packet.extend_from_slice(&b.random);
                // data (5 bytes)
                packet.extend_from_slice(&b.data);
                // tag (8 bytes)
                packet.extend_from_slice(&b.tag);
            }
        }
        packet
    }
}

#[derive(Debug)]
pub struct UnprovisionedBeacon {
    pub device_uuid: [u8; 16],
    pub oob_info: u16,
    pub uri_hash: Option<u32>,
}

#[derive(Debug)]
pub struct SecureBeacon {
    pub flags: u8,
    pub network_id: [u8; 8],
    pub iv_index: u32,
    pub auth_value: u64,
}

#[derive(Debug)]
pub struct PrivateBeacon {
    pub random: [u8; 13],
    pub data: [u8; 5],
    pub tag: [u8; 8],
}
