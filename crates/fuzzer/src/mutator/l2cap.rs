use super::MetaMutator;
use crate::MetaState;
use ble::{hci::HciAclDataPkt, l2cap::L2capBframeDecoder};
use libafl::{
    inputs::{BytesInput, BytesSubInput, HasMutatorBytes, ResizableMutator},
    mutators::{MutationResult, Mutator},
    state::HasRand,
};
use libafl_bolts::rands::Rand;
use libafl_core::HasLen;
use simulator::entity::l2cap::L2capEntity;
use tracing::info;

#[derive(Debug, PartialEq)]
pub(super) enum UpperLayerType {
    Unknown,
    Sig,
    Att,
    Sm,
    L2cap,
}

impl<'a> MetaMutator<'a> {
    // Keep CID mutation on channels that are actually used by our BLE scenarios.
    const CID_MAPS: [u16; 5] = [0x04, 0x05, 0x06, 0x40, 0x41];

    fn choose_l2cap_cid(&self, state: &mut MetaState, current: u16) -> u16 {
        let mut candidates = Self::CID_MAPS.to_vec();
        if self.profile_aware_mutation_enabled() {
            for cid in self.runtime_profile().host_visible_dynamic_cids {
                if !candidates.contains(&cid) {
                    candidates.push(cid);
                }
            }
            candidates.sort_unstable();
        }

        for _ in 0..8 {
            let candidate = candidates[state.rand_mut().between(0, candidates.len() - 1)];
            if candidate != current {
                return candidate;
            }
        }
        current
    }

    fn write_u16_field(packet: &mut [u8], offset: usize, value: u16) -> bool {
        if packet.len() < offset + 2 {
            return false;
        }
        let old = u16::from_le_bytes(packet[offset..offset + 2].try_into().unwrap());
        if old == value {
            return false;
        }
        packet[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
        true
    }

    fn choose_profile_aware_u16(&self, state: &mut MetaState, current: u16, candidates: &[u16]) -> u16 {
        for _ in 0..8 {
            let candidate = candidates[state.rand_mut().between(0, candidates.len() - 1)];
            if candidate != current {
                return candidate;
            }
        }
        current
    }

    fn choose_credit_value(&self, state: &mut MetaState, current: u16) -> u16 {
        let runtime = self.runtime_profile();
        let le_cfg = self.simulator.le_credit_config();
        let candidates = [
            runtime.last_initial_credits.unwrap_or(le_cfg.initial_credits),
            le_cfg.initial_credits,
            1,
            4,
            8,
            16,
            le_cfg.initial_credits.saturating_mul(2),
            u16::MAX / 4,
        ];
        self.choose_profile_aware_u16(state, current, &candidates)
    }

    /// decodes and finds the top layer type of the HCI ACL packet.
    pub(super) fn get_upper_layer_type(acl_packet: &HciAclDataPkt) -> UpperLayerType {
        if let Ok(decoder) = L2capBframeDecoder::new(acl_packet) {
            match decoder.channel_id() {
                L2capEntity::CID_ATT => UpperLayerType::Att,
                L2capEntity::CID_SIG => UpperLayerType::Sig,
                L2capEntity::CID_SM => UpperLayerType::Sm,
                _ => UpperLayerType::L2cap,
            }
        } else {
            UpperLayerType::Unknown
        }
    }

    /// mutates the L2CAP packet
    pub(super) fn mutate_l2cap_packet(&mut self, state: &mut MetaState, l2cap_packet: &mut BytesInput) -> Result<MutationResult, libafl::Error> {
        info!("Mutating L2CAP Packet");
        let mut has_mutate = MutationResult::Skipped;
        let profile_aware = self.profile_aware_mutation_enabled();
        let has_semantic_context = profile_aware && self.has_runtime_semantic_context();
        if l2cap_packet.len() < 4 {
            return Ok(MutationResult::Skipped);
        }

        // (10%) mutate cid
        let mut cid = u16::from_le_bytes(l2cap_packet.mutator_bytes()[2..4].try_into().unwrap());
        let is_dynamic_cid = (L2capEntity::CID_DYN_START..=L2capEntity::CID_DYN_END).contains(&cid);
        let cid_mutation_prob = if has_semantic_context {
            if is_dynamic_cid { 8 } else { 30 }
        } else if profile_aware {
            25
        } else {
            10
        };
        // if !credit_sig_stress_target && self.prob(state, cid_mutation_prob) {
        if self.prob(state, cid_mutation_prob) {
            let new_cid = self.choose_l2cap_cid(state, cid);
            if cid != new_cid {
                cid = new_cid;
                has_mutate = MutationResult::Mutated;
            }
        }
        // mutate body
        let mut payload_mutation_res = match cid {
            L2capEntity::CID_SIG => self.mutate_l2cap_sig_packet(state, &mut l2cap_packet.sub_input(4..))?,
            L2capEntity::CID_DYN_START..=L2capEntity::CID_DYN_END => self.mutate_l2cap_coc_packet(state, l2cap_packet)?,
            _ => MutationResult::Skipped,
        };

        let mut payload = l2cap_packet.sub_input(4..);
        let do_havoc = !profile_aware || !has_semantic_context || self.prob(state, 25);
        if do_havoc && MutationResult::Mutated == self.havoc_mutator.mutate(state, &mut payload)? {
            payload_mutation_res = MutationResult::Mutated;
        }

        let length = payload.mutator_bytes().len() as u16;
        if self.prob(state, 80) {
            l2cap_packet.mutator_bytes_mut()[0..2].copy_from_slice(&length.to_le_bytes());
            l2cap_packet.mutator_bytes_mut()[2..4].copy_from_slice(&cid.to_le_bytes());
        } else {
            l2cap_packet.mutator_bytes_mut()[0..2].copy_from_slice(&(length - 1).to_le_bytes());
            l2cap_packet.mutator_bytes_mut()[2..4].copy_from_slice(&cid.to_le_bytes());
            payload_mutation_res = MutationResult::Mutated;
        }

        Ok(if has_mutate == MutationResult::Mutated || payload_mutation_res == MutationResult::Mutated {
            MutationResult::Mutated
        } else {
            MutationResult::Skipped
        })
    }

    fn mutate_l2cap_coc_packet(&mut self, state: &mut MetaState, l2cap_packet: &mut BytesInput) -> Result<MutationResult, libafl::Error> {
        info!("Mutating L2CAP Credit-orientied Channel Packet");
        let mut payload = l2cap_packet.sub_input(4..);
        if payload.len() < 2 {
            return Ok(MutationResult::Skipped);
        }
        let has_semantic_context = self.profile_aware_mutation_enabled() && self.has_runtime_semantic_context();
        let learned_mtu_cap = self.runtime_profile().last_le_credit_mtu.unwrap_or(u16::MAX).max(23);

        let sdu_len = (payload.len() - 2).min(u16::MAX as usize) as u16;
        let tuned_sdu_len = if has_semantic_context && self.prob(state, 8) {
            // Rarely push declared SDU length close to u16 max to pressure reassembly.
            let tail = state.rand_mut().between(0, 1023) as u16;
            u16::MAX.saturating_sub(tail)
        } else if has_semantic_context && self.prob(state, 55) {
            // Keep mutations protocol-shaped but inflate declared SDU length aggressively
            // to stress generic CoC append/reassembly logic.
            let delta_candidates = [1u16, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096];
            let delta = delta_candidates[state.rand_mut().between(0, delta_candidates.len() - 1)];
            sdu_len.saturating_add(delta)
        } else {
            sdu_len
        };
        let tuned_sdu_len = if has_semantic_context && self.prob(state, 85) {
            // Usually stay within negotiated MTU so deep CoC receive paths remain reachable.
            tuned_sdu_len.min(learned_mtu_cap)
        } else {
            tuned_sdu_len
        };
        let current_sdu_len = u16::from_le_bytes(payload.mutator_bytes()[0..2].try_into().unwrap());
        if current_sdu_len != tuned_sdu_len {
            payload.mutator_bytes_mut()[0..2].copy_from_slice(&tuned_sdu_len.to_le_bytes());
        }
        return Ok(MutationResult::Mutated);
    }

    /// mutate L2CAP Signaling packet
    /// `packet` is the information payload in the L2CAP packet (without PDU Length and Channel ID)
    fn mutate_l2cap_sig_packet(&mut self, state: &mut MetaState, sig_packet: &mut BytesSubInput<BytesInput>) -> Result<MutationResult, libafl::Error> {
        info!("Mutating L2CAP signaling packet");
        // packet should be more than 4 bytes long.
        if sig_packet.len() < 4 {
            return Ok(MutationResult::Skipped);
        }

        if !self.profile_aware_mutation_enabled() {
            return Ok(MutationResult::Skipped);
        }

        let runtime = self.runtime_profile();
        let le_cfg = self.simulator.le_credit_config();
        let learned_psm = runtime.le_credit_psms.first().copied();
        let preferred_cid = runtime.host_visible_dynamic_cids.first().copied().unwrap_or(L2capEntity::CID_DYN_START);
        let preferred_mtu = runtime.last_le_credit_mtu.unwrap_or_else(|| if le_cfg.enabled { le_cfg.mtu } else { 128 });
        let preferred_mps = runtime.last_le_credit_mps.unwrap_or_else(|| if le_cfg.enabled { le_cfg.mps } else { 64 });
        let mtu_candidates = [
            preferred_mtu.saturating_sub(1).max(23),
            preferred_mtu,
            preferred_mtu.saturating_add(1),
            le_cfg.mtu,
            64,
            128,
            247,
            512,
            1024,
        ];
        let mps_candidates = [
            preferred_mps.saturating_sub(1).max(23),
            preferred_mps,
            preferred_mps.saturating_add(1),
            23,
            31,
            47,
            le_cfg.mps,
            64,
            96,
            128,
            247,
        ];

        let mut changed = match sig_packet.mutator_bytes()[0] {
            // LE Credit Based Connection Request
            0x14 if sig_packet.len() >= 14 => {
                let mut changed = false;
                let current_psm = u16::from_le_bytes(sig_packet.mutator_bytes()[4..6].try_into().unwrap());
                if let Some(psm) = learned_psm {
                    // Once we learn runtime SPSM, bias requests to that value.
                    changed |= Self::write_u16_field(sig_packet.mutator_bytes_mut(), 4, psm);
                } else if le_cfg.enabled && self.prob(state, 20) {
                    // Keep exploration wide before SPSM is learned.
                    changed |= Self::write_u16_field(sig_packet.mutator_bytes_mut(), 4, le_cfg.psm);
                } else {
                    changed |= Self::write_u16_field(sig_packet.mutator_bytes_mut(), 4, current_psm);
                }
                changed |= Self::write_u16_field(sig_packet.mutator_bytes_mut(), 6, preferred_cid);
                let current_mtu = u16::from_le_bytes(sig_packet.mutator_bytes()[8..10].try_into().unwrap());
                let current_mps = u16::from_le_bytes(sig_packet.mutator_bytes()[10..12].try_into().unwrap());
                changed |= Self::write_u16_field(
                    sig_packet.mutator_bytes_mut(),
                    8,
                    self.choose_profile_aware_u16(state, current_mtu, &mtu_candidates),
                );
                changed |= Self::write_u16_field(
                    sig_packet.mutator_bytes_mut(),
                    10,
                    self.choose_profile_aware_u16(state, current_mps, &mps_candidates),
                );
                let current_credits = u16::from_le_bytes(sig_packet.mutator_bytes()[12..14].try_into().unwrap());
                let new_credits = self.choose_credit_value(state, current_credits);
                changed |= Self::write_u16_field(sig_packet.mutator_bytes_mut(), 12, new_credits);
                changed
            }
            // LE Credit Based Connection Response
            0x15 if sig_packet.len() >= 14 => {
                let mut changed = false;
                changed |= Self::write_u16_field(sig_packet.mutator_bytes_mut(), 4, preferred_cid);
                let current_mtu = u16::from_le_bytes(sig_packet.mutator_bytes()[6..8].try_into().unwrap());
                let current_mps = u16::from_le_bytes(sig_packet.mutator_bytes()[8..10].try_into().unwrap());
                changed |= Self::write_u16_field(
                    sig_packet.mutator_bytes_mut(),
                    6,
                    self.choose_profile_aware_u16(state, current_mtu, &mtu_candidates),
                );
                changed |= Self::write_u16_field(
                    sig_packet.mutator_bytes_mut(),
                    8,
                    self.choose_profile_aware_u16(state, current_mps, &mps_candidates),
                );
                let current_credits = u16::from_le_bytes(sig_packet.mutator_bytes()[10..12].try_into().unwrap());
                let new_credits = self.choose_credit_value(state, current_credits);
                changed |= Self::write_u16_field(sig_packet.mutator_bytes_mut(), 10, new_credits);
                // Keep result on success more often so CoC state can continue deeper.
                if self.prob(state, 80) {
                    changed |= Self::write_u16_field(sig_packet.mutator_bytes_mut(), 12, 0x0000);
                }
                changed
            }
            // LE Flow Control Credit Indication
            0x16 if sig_packet.len() >= 8 => {
                let mut changed = false;
                changed |= Self::write_u16_field(sig_packet.mutator_bytes_mut(), 4, preferred_cid);
                let current_credits = u16::from_le_bytes(sig_packet.mutator_bytes()[6..8].try_into().unwrap());
                let new_credits = self.choose_credit_value(state, current_credits);
                changed |= Self::write_u16_field(sig_packet.mutator_bytes_mut(), 6, new_credits);
                changed
            }
            // Disconnection req/rsp
            0x06 | 0x07 if sig_packet.len() >= 8 => {
                let mut changed = false;
                changed |= Self::write_u16_field(sig_packet.mutator_bytes_mut(), 4, preferred_cid);
                changed |= Self::write_u16_field(sig_packet.mutator_bytes_mut(), 6, preferred_cid);
                changed
            }
            _ => false,
        };

        // mutate the CID of the packet
        if self.prob(state, 20) {
            let cid_list = [0x01, 0x09, 0x0B, 0x08, 0x0A, 0x12, 0x13, 0x14, 0x06];
            let old_cid = sig_packet.mutator_bytes()[0];
            let new_cid = cid_list[state.rand_mut().between(0, cid_list.len() - 1)];
            if new_cid != old_cid {
                changed = true;
                info!("-> L2CAP signaling packet cid mutated");
                sig_packet.mutator_bytes_mut()[0] = new_cid;
            }
        }

        // mutate the cmd length of the packet
        if self.prob(state, 20) && sig_packet.len() > 4 {
            let old_cmd_length = sig_packet.len() - 4;
            let new_cmd_length = state.rand_mut().between(0, old_cmd_length);
            if new_cmd_length != old_cmd_length {
                changed = true;
                info!("-> L2CAP signaling packet cmd length mutated");
                Self::write_u16_field(sig_packet.mutator_bytes_mut(), 2, new_cmd_length as u16);
                sig_packet.resize(4 + new_cmd_length, 0x0);
            }
        }

        // mutate the header of the packet, generates invalid L2CAP signaling header
        if self.prob(state, 20) {
            let old_length = sig_packet.len();
            let new_length = state.rand_mut().between(0, 0x4);
            if old_length != new_length {
                changed = true;
                info!("-> L2CAP signaling packet header mutated");
                sig_packet.resize(new_length, 0x0);
            }
        }

        if changed { Ok(MutationResult::Mutated) } else { Ok(MutationResult::Skipped) }
    }
}
