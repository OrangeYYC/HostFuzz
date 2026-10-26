use aes::Aes128;
use ble::hci::{
    ControllerToHostPacket,
    event::LeLongTermKeyRequestEvent,
    parameter::{AddrKind, BdAddr},
};
use cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use tracing::{debug, warn};

use crate::{Simulator, SimulatorError};

/// Simulates Security Manager Protocol state machine for one ACL connection.
pub struct SmpEntity<'a> {
    simulator: &'a Simulator,
    conn_handle: u16,
    peer_addr: BdAddr,
    smp_preq: Option<[u8; 7]>,
    smp_pres: Option<[u8; 7]>,
    smp_responder_confirm: [u8; 16],
    smp_responder_random: [u8; 16],
    smp_initiator_addr: [u8; 6],
    smp_initiator_addr_type: u8,
    smp_responder_addr: [u8; 6],
    smp_responder_addr_type: u8,
    smp_encrypted: bool,
    smp_responder_keys_sent: bool,
    smp_pending_initiator_key_events: u8,
    smp_responder_key_dist: u8,
    responder_sends_first: bool,
    peer_initiates_pairing: bool,
    smp_initiator_confirm: [u8; 16],
    smp_initiator_random: [u8; 16],
    smp_initiator_confirm_sent: bool,
    smp_initiator_random_sent: bool,
    smp_ltk_request_sent: bool,
}

impl<'a> SmpEntity<'a> {
    // Security Manager protocol CID.
    const CID_SM: u16 = 0x0006;

    pub fn new(
        simulator: &'a Simulator,
        conn_handle: u16,
        peer_addr: BdAddr,
        peer_addr_type: AddrKind,
        local_addr: BdAddr,
        local_addr_type: AddrKind,
        host_role_is_central: bool,
    ) -> Self {
        let mut responder_random = [0u8; 16];
        for (idx, byte) in responder_random.iter_mut().enumerate() {
            *byte = (conn_handle as u8).wrapping_add((idx as u8).wrapping_mul(17));
        }
        let mut initiator_random = [0u8; 16];
        for (idx, byte) in initiator_random.iter_mut().enumerate() {
            *byte = (conn_handle as u8).wrapping_add(0x5A).wrapping_add((idx as u8).wrapping_mul(29));
        }

        let (smp_initiator_addr, smp_initiator_addr_type, smp_responder_addr, smp_responder_addr_type) = if host_role_is_central {
            (
                local_addr.addr,
                Self::smp_addr_type(&local_addr_type),
                peer_addr.addr,
                Self::smp_addr_type(&peer_addr_type),
            )
        } else {
            (
                peer_addr.addr,
                Self::smp_addr_type(&peer_addr_type),
                local_addr.addr,
                Self::smp_addr_type(&local_addr_type),
            )
        };

        Self {
            simulator,
            conn_handle,
            peer_addr,
            smp_preq: None,
            smp_pres: None,
            smp_responder_confirm: [0; 16],
            smp_responder_random: responder_random,
            smp_initiator_addr,
            smp_initiator_addr_type: smp_initiator_addr_type,
            smp_responder_addr,
            smp_responder_addr_type: smp_responder_addr_type,
            smp_encrypted: false,
            smp_responder_keys_sent: false,
            smp_pending_initiator_key_events: 0,
            smp_responder_key_dist: 0,
            // Zephyr LE SMP distributes keys with peripheral first.
            // If host role is Central, our simulated peer is Peripheral and should send first.
            responder_sends_first: host_role_is_central,
            peer_initiates_pairing: !host_role_is_central,
            smp_initiator_confirm: [0; 16],
            smp_initiator_random: initiator_random,
            smp_initiator_confirm_sent: false,
            smp_initiator_random_sent: false,
            smp_ltk_request_sent: false,
        }
    }

    /// Triggers peer-initiated pairing (used when host is Peripheral).
    pub fn initiate_interact(&mut self) {
        if !self.peer_initiates_pairing || self.smp_preq.is_some() {
            return;
        }
        self.send_pairing_request_if_idle(false);
    }

    /// Forces one peer-initiated pairing request regardless of role.
    pub fn force_pairing_request(&mut self) {
        self.send_pairing_request_if_idle(true);
    }

    fn send_pairing_request_if_idle(&mut self, rich_key_dist: bool) {
        if self.smp_preq.is_some() {
            return;
        }

        // Legacy Just Works pairing. For forced pairing paths we enable bonding/key dist
        // to exercise additional host-side SMP branches.
        let (auth_req, initiator_key_dist, responder_key_dist) = if rich_key_dist { (0x01, 0x07, 0x07) } else { (0x00, 0x00, 0x00) };
        let preq = [0x01, 0x03, 0x00, auth_req, 0x10, initiator_key_dist, responder_key_dist];
        self.smp_preq = Some(preq);
        self.smp_pres = None;
        self.smp_encrypted = false;
        self.smp_responder_keys_sent = false;
        self.smp_pending_initiator_key_events = 0;
        self.smp_responder_key_dist = 0;
        self.smp_initiator_confirm_sent = false;
        self.smp_initiator_random_sent = false;
        self.smp_ltk_request_sent = false;
        self.simulator.telemetry_mark_pairing_started();

        if let Err(err) = self.simulator.send_l2cap_bframe(self.conn_handle, Self::CID_SM, preq.to_vec()) {
            warn!("Peer[{}]: failed to send SMP Pairing Request: {:?}", self.peer_addr, err);
        }
    }

    pub fn on_sm_packet(&mut self, payload: &[u8]) -> Result<(), SimulatorError> {
        if payload.is_empty() {
            return Ok(());
        }

        debug!(
            "Peer[{}]: handle Security Manager protocol packet: {}",
            self.peer_addr,
            hex::encode_upper(payload)
        );

        match payload[0] {
            // SMP Pairing Request
            0x01 => {
                if payload.len() >= 7 {
                    self.simulator.telemetry_mark_pairing_started();
                    self.peer_initiates_pairing = false;
                    self.smp_initiator_confirm_sent = false;
                    self.smp_initiator_random_sent = false;
                    self.smp_ltk_request_sent = false;
                    let mut preq = [0u8; 7];
                    preq.copy_from_slice(&payload[..7]);
                    self.smp_preq = Some(preq);

                    // Reply with a legacy Pairing Response (clear SC bit).
                    let mut pres = [0u8; 7];
                    pres[0] = 0x02;
                    pres[1] = payload[1];
                    pres[2] = payload[2];
                    pres[3] = payload[3] & !0x08;
                    pres[4] = payload[4];
                    pres[5] = payload[5];
                    pres[6] = payload[6];
                    self.smp_pres = Some(pres);

                    self.smp_encrypted = false;
                    self.smp_responder_keys_sent = false;

                    let initiator_key_dist = preq[5] & pres[5];
                    let responder_key_dist = preq[6] & pres[6];
                    self.smp_pending_initiator_key_events = Self::smp_key_dist_to_event_mask(initiator_key_dist);
                    self.smp_responder_key_dist = responder_key_dist;

                    self.smp_responder_confirm = self.smp_c1_zero_tk(preq, pres, self.smp_responder_random);
                    self.simulator.send_l2cap_bframe(self.conn_handle, Self::CID_SM, pres.to_vec())?;
                }
            }
            // SMP Pairing Response
            0x02 => {
                if self.peer_initiates_pairing && payload.len() >= 7 {
                    let Some(preq) = self.smp_preq else {
                        return Ok(());
                    };
                    let mut pres = [0u8; 7];
                    pres.copy_from_slice(&payload[..7]);
                    self.smp_pres = Some(pres);

                    self.smp_encrypted = false;
                    self.smp_responder_keys_sent = false;
                    let initiator_key_dist = preq[5] & pres[5];
                    let responder_key_dist = preq[6] & pres[6];
                    self.smp_pending_initiator_key_events = Self::smp_key_dist_to_event_mask(initiator_key_dist);
                    self.smp_responder_key_dist = responder_key_dist;
                    self.smp_ltk_request_sent = false;

                    self.smp_initiator_confirm = self.smp_c1_zero_tk(preq, pres, self.smp_initiator_random);
                    let mut confirm = vec![0x03];
                    confirm.extend_from_slice(&self.smp_initiator_confirm);
                    self.simulator.send_l2cap_bframe(self.conn_handle, Self::CID_SM, confirm)?;
                    self.smp_initiator_confirm_sent = true;
                }
            }
            // SMP Pairing Confirm
            0x03 => {
                if self.peer_initiates_pairing {
                    if self.smp_initiator_confirm_sent && !self.smp_initiator_random_sent {
                        let mut random = vec![0x04];
                        random.extend_from_slice(&self.smp_initiator_random);
                        self.simulator.send_l2cap_bframe(self.conn_handle, Self::CID_SM, random)?;
                        self.smp_initiator_random_sent = true;
                    }
                } else {
                    let mut confirm = vec![0x03];
                    confirm.extend_from_slice(&self.smp_responder_confirm);
                    self.simulator.send_l2cap_bframe(self.conn_handle, Self::CID_SM, confirm)?;
                }
            }
            // SMP Pairing Random
            0x04 => {
                if self.peer_initiates_pairing {
                    if self.smp_initiator_confirm_sent && !self.smp_initiator_random_sent {
                        let mut random = vec![0x04];
                        random.extend_from_slice(&self.smp_initiator_random);
                        self.simulator.send_l2cap_bframe(self.conn_handle, Self::CID_SM, random)?;
                        self.smp_initiator_random_sent = true;
                    }
                    // Trigger LE LTK request only after receiving responder random.
                    // BTstack responder path expects this event in SM_RESPONDER_PH2_W4_LTK_REQUEST.
                    self.try_request_link_encryption();
                } else {
                    let mut random = vec![0x04];
                    random.extend_from_slice(&self.smp_responder_random);
                    self.simulator.send_l2cap_bframe(self.conn_handle, Self::CID_SM, random)?;
                }
            }
            // SMP Pairing Failed
            0x05 => {
                let reason = payload.get(1).copied().unwrap_or(0xff);
                self.smp_initiator_confirm_sent = false;
                self.smp_initiator_random_sent = false;
                self.smp_ltk_request_sent = false;
                warn!("Peer[{}]: host reported SMP Pairing Failed, reason=0x{:02x}", self.peer_addr, reason);
            }
            // SMP Encryption Information (initiator phase-3 distribution)
            0x06 => {
                self.smp_pending_initiator_key_events &= !0x01;
                self.try_send_responder_key_distribution();
            }
            // SMP Master Identification
            0x07 => {
                self.smp_pending_initiator_key_events &= !0x02;
                self.try_send_responder_key_distribution();
            }
            // SMP Identity Information
            0x08 => {
                self.smp_pending_initiator_key_events &= !0x04;
                self.try_send_responder_key_distribution();
            }
            // SMP Identity Address Information
            0x09 => {
                self.smp_pending_initiator_key_events &= !0x08;
                self.try_send_responder_key_distribution();
            }
            // SMP Signing Information
            0x0A => {
                self.smp_pending_initiator_key_events &= !0x10;
                self.try_send_responder_key_distribution();
            }
            _ => {}
        }

        Ok(())
    }

    /// Trigger responder key distribution once link encryption is enabled.
    pub fn on_link_encrypted(&mut self) {
        self.smp_encrypted = true;
        self.simulator.telemetry_mark_pairing_completed();
        if self.responder_sends_first {
            self.smp_pending_initiator_key_events = 0;
        }
        self.try_send_responder_key_distribution();
    }

    #[inline]
    fn smp_addr_type(kind: &AddrKind) -> u8 {
        match kind {
            AddrKind::Public | AddrKind::ResolvablePrivateOrPublic => 0x00,
            _ => 0x01,
        }
    }

    #[inline]
    fn smp_encrypt_le(key: &[u8; 16], plaintext: &[u8; 16]) -> [u8; 16] {
        let mut key_be = *key;
        key_be.reverse();

        let mut pt_be = *plaintext;
        pt_be.reverse();

        let cipher = Aes128::new(GenericArray::from_slice(&key_be));
        let mut block = GenericArray::clone_from_slice(&pt_be);
        cipher.encrypt_block(&mut block);

        let mut out = [0u8; 16];
        out.copy_from_slice(&block);
        out.reverse();
        out
    }

    #[inline]
    fn xor_16(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
        let mut out = [0u8; 16];
        for i in 0..16 {
            out[i] = a[i] ^ b[i];
        }
        out
    }

    fn smp_c1_zero_tk(&self, preq: [u8; 7], pres: [u8; 7], random: [u8; 16]) -> [u8; 16] {
        let key = [0u8; 16];
        let mut p1 = [0u8; 16];
        p1[0] = self.smp_initiator_addr_type;
        p1[1] = self.smp_responder_addr_type;
        p1[2..9].copy_from_slice(&preq);
        p1[9..16].copy_from_slice(&pres);

        let mut p2 = [0u8; 16];
        p2[0..6].copy_from_slice(&self.smp_responder_addr);
        p2[6..12].copy_from_slice(&self.smp_initiator_addr);
        // p2[12..16] is zero padding.

        let x = Self::xor_16(&random, &p1);
        let y = Self::smp_encrypt_le(&key, &x);
        let z = Self::xor_16(&y, &p2);
        Self::smp_encrypt_le(&key, &z)
    }

    #[inline]
    fn smp_key_dist_to_event_mask(key_dist: u8) -> u8 {
        let mut mask = 0u8;
        // Encryption key distribution uses two PDUs: 0x06 + 0x07.
        if (key_dist & 0x01) != 0 {
            mask |= 0x01 | 0x02;
        }
        // Identity key distribution uses two PDUs: 0x08 + 0x09.
        if (key_dist & 0x02) != 0 {
            mask |= 0x04 | 0x08;
        }
        // Signing key distribution uses one PDU: 0x0A.
        if (key_dist & 0x04) != 0 {
            mask |= 0x10;
        }
        mask
    }

    fn try_send_responder_key_distribution(&mut self) {
        if !self.smp_encrypted || self.smp_responder_keys_sent {
            return;
        }
        // The initiator must finish its configured key distribution before responder sends keys.
        if self.smp_pending_initiator_key_events != 0 {
            return;
        }
        if self.smp_responder_key_dist == 0 {
            self.smp_responder_keys_sent = true;
            return;
        }

        // SMP Encryption Information
        if (self.smp_responder_key_dist & 0x01) != 0 {
            let mut enc_info = vec![0x06];
            enc_info.extend_from_slice(&[0x21, 0x43, 0x65, 0x87, 0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE, 0x11, 0x22, 0x33, 0x44]);
            if let Err(err) = self.simulator.send_l2cap_bframe(self.conn_handle, Self::CID_SM, enc_info) {
                warn!("Peer[{}]: failed to send SMP Encryption Information: {:?}", self.peer_addr, err);
                return;
            }

            // SMP Master Identification
            let mut master_ident = vec![0x07];
            master_ident.extend_from_slice(&0x1234u16.to_le_bytes()); // EDIV
            master_ident.extend_from_slice(&[
                0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE, // RAND
            ]);
            if let Err(err) = self.simulator.send_l2cap_bframe(self.conn_handle, Self::CID_SM, master_ident) {
                warn!("Peer[{}]: failed to send SMP Master Identification: {:?}", self.peer_addr, err);
                return;
            }
        }

        // SMP Identity Information
        if (self.smp_responder_key_dist & 0x02) != 0 {
            let mut identity_info = vec![0x08];
            identity_info.extend_from_slice(&[0x44, 0x33, 0x22, 0x11, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xF0, 0x0F]);
            if let Err(err) = self.simulator.send_l2cap_bframe(self.conn_handle, Self::CID_SM, identity_info) {
                warn!("Peer[{}]: failed to send SMP Identity Information: {:?}", self.peer_addr, err);
                return;
            }

            // SMP Identity Address Information
            let mut identity_addr = vec![0x09, self.smp_responder_addr_type];
            identity_addr.extend_from_slice(&self.smp_responder_addr);
            if let Err(err) = self.simulator.send_l2cap_bframe(self.conn_handle, Self::CID_SM, identity_addr) {
                warn!("Peer[{}]: failed to send SMP Identity Address Information: {:?}", self.peer_addr, err);
                return;
            }
        }

        // SMP Signing Information
        if (self.smp_responder_key_dist & 0x04) != 0 {
            let mut signing_info = vec![0x0A];
            signing_info.extend_from_slice(&[0x01, 0x10, 0x23, 0x32, 0x45, 0x54, 0x67, 0x76, 0x89, 0x98, 0xAB, 0xBA, 0xCD, 0xDC, 0xEF, 0xFE]);
            if let Err(err) = self.simulator.send_l2cap_bframe(self.conn_handle, Self::CID_SM, signing_info) {
                warn!("Peer[{}]: failed to send SMP Signing Information: {:?}", self.peer_addr, err);
            }
        }

        self.smp_responder_keys_sent = true;
    }

    fn try_request_link_encryption(&mut self) {
        if !self.peer_initiates_pairing || self.smp_ltk_request_sent {
            return;
        }
        if !self.smp_initiator_confirm_sent || !self.smp_initiator_random_sent {
            return;
        }

        let evt = LeLongTermKeyRequestEvent::new(self.conn_handle, [0; 8], 0x0000);
        self.simulator.send_hci_packet(ControllerToHostPacket::Event(evt));
        self.smp_ltk_request_sent = true;
    }
}
