use super::MetaMutator;
use crate::MetaState;
use libafl::inputs::{BytesInput, BytesSubInput, HasMutatorBytes, ResizableMutator};
use libafl::state::HasRand;
use libafl_bolts::HasLen;
use libafl_bolts::rands::Rand;

impl<'a> MetaMutator<'a> {
    const PBADV_OVERSIZE_PAYLOAD_MIN: usize = 205;
    const PBADV_OVERSIZE_PAYLOAD_MAX: usize = Self::EXT_ADV_STRESS_PAYLOAD_MAX;
    const MESH_MSG_AD_TYPE: u8 = 0x2A;
    const MESH_PBADV_AD_TYPE: u8 = 0x29;
    const MESH_BEACON_AD_TYPE: u8 = 0x2B;
    const MESH_UUID16_SOME_AD_TYPE: u8 = 0x02;
    const MESH_UUID16_ALL_AD_TYPE: u8 = 0x03;
    const MESH_PROXY_SOL_UUID16: u16 = 0x1859;

    pub(super) fn mutate_mesh_extended_adv_payload_length_stress(&self, state: &mut MetaState, adv_data: &mut Vec<u8>) -> bool {
        let (stress_min, stress_max) = (Self::PBADV_OVERSIZE_PAYLOAD_MIN, Self::PBADV_OVERSIZE_PAYLOAD_MAX);

        let mut target_payload_len = if self.prob(state, 85) {
            state.rand_mut().between(stress_min, stress_max)
        } else {
            state.rand_mut().between(Self::EXT_ADV_REPORT_FIXED_PREFIX_LEN, stress_max)
        };
        target_payload_len = target_payload_len.clamp(Self::EXT_ADV_REPORT_FIXED_PREFIX_LEN, Self::EXT_ADV_STRESS_PAYLOAD_MAX);

        let target_adv_len = target_payload_len
            .saturating_sub(Self::EXT_ADV_REPORT_FIXED_PREFIX_LEN)
            .min(Self::MAX_LE_EXT_ADV_REPORT_DATA_LEN);
        let old_len = adv_data.len();

        if old_len < target_adv_len {
            adv_data.reserve(target_adv_len - old_len);
            while adv_data.len() < target_adv_len {
                adv_data.push(state.rand_mut().between(0, 255) as u8);
            }
        } else if old_len > target_adv_len {
            adv_data.truncate(target_adv_len);
        }

        old_len != adv_data.len()
    }

    fn write_underflow_network_payload(&self, state: &mut MetaState, payload: &mut [u8]) {
        if payload.len() < 9 {
            return;
        }

        payload.fill(0);
        payload[0] = state.rand_mut().between(0, 0x7f) as u8; // IVI | NID
        let ttl = (1 + state.rand_mut().between(0, 0x1f)) as u8;
        let ctl_mask = if payload.len() <= 12 || self.prob(state, 80) { 0x80 } else { 0x00 };
        payload[1] = ctl_mask | (ttl & 0x7f);
        payload[2] = state.rand_mut().between(0, 255) as u8;
        payload[3] = state.rand_mut().between(0, 255) as u8;
        payload[4] = state.rand_mut().between(0, 255) as u8;
        payload[5] = 0x12;
        payload[6] = 0x34;
        payload[7] = 0x00;
        payload[8] = (1 + state.rand_mut().between(0, 0xfe)) as u8;
        for idx in 9..payload.len() {
            payload[idx] = state.rand_mut().between(0, 255) as u8;
        }
    }

    pub(super) fn mutate_mesh_solicitation_underflow_adv_payload(&self, state: &mut MetaState, adv_data: &mut Vec<u8>) -> bool {
        let uuid_ad_type = if self.prob(state, 75) {
            Self::MESH_UUID16_ALL_AD_TYPE
        } else {
            Self::MESH_UUID16_SOME_AD_TYPE
        };

        let mut rebuilt = Vec::with_capacity(64);
        rebuilt.push(0x03);
        rebuilt.push(uuid_ad_type);
        rebuilt.extend_from_slice(&Self::MESH_PROXY_SOL_UUID16.to_le_bytes());

        const TINY_NEXT_AD_LEN: [u8; 3] = [0, 1, 2];
        const NORMAL_NEXT_AD_LEN: [u8; 4] = [3, 4, 5, 0x15];
        let next_ad_len = if self.prob(state, 92) {
            TINY_NEXT_AD_LEN[state.rand_mut().between(0, TINY_NEXT_AD_LEN.len() - 1)]
        } else {
            NORMAL_NEXT_AD_LEN[state.rand_mut().between(0, NORMAL_NEXT_AD_LEN.len() - 1)]
        };
        rebuilt.push(next_ad_len);

        let next_ad_type = if self.prob(state, 70) { Self::MESH_BEACON_AD_TYPE } else { 0x16 };
        rebuilt.push(next_ad_type);

        let pulled_u16 = if self.prob(state, 85) {
            Self::MESH_PROXY_SOL_UUID16 ^ 0x00FF
        } else {
            Self::MESH_PROXY_SOL_UUID16
        };
        rebuilt.extend_from_slice(&pulled_u16.to_le_bytes());

        const TRAILING_LEN_CHOICES: [usize; 8] = [22, 23, 24, 25, 26, 28, 30, 32];
        let trailing_len = TRAILING_LEN_CHOICES[state.rand_mut().between(0, TRAILING_LEN_CHOICES.len() - 1)];
        for _ in 0..trailing_len {
            rebuilt.push(state.rand_mut().between(0, 255) as u8);
        }

        if self.prob(state, 25) {
            // Keep one trailing AD item so parser can keep walking after the crafted layout.
            rebuilt.extend_from_slice(&[0x02, 0x01, 0x06]);
        }

        if *adv_data == rebuilt {
            return false;
        }
        *adv_data = rebuilt;
        true
    }

    pub(super) fn mutate_mesh_network_underflow_adv_payload(&self, state: &mut MetaState, adv_data: &mut Vec<u8>) -> bool {
        if self.prob(state, 5) {
            return self.mutate_mesh_solicitation_underflow_adv_payload(state, adv_data);
        }

        if adv_data.len() < 11 {
            return false;
        }

        let mut offset = 0usize;
        let mut target: Option<(usize, usize, usize)> = None;
        let mut fallback: Option<(usize, usize, usize)> = None;
        while offset < adv_data.len() {
            let ad_len = adv_data[offset] as usize;
            if ad_len == 0 {
                break;
            }
            let ad_end = offset + 1 + ad_len;
            if ad_end > adv_data.len() {
                break;
            }
            let ad_type = adv_data[offset + 1];
            let payload_off = offset + 2;
            let payload_len = ad_len.saturating_sub(1);
            if payload_len >= 9 {
                if ad_type == Self::MESH_MSG_AD_TYPE {
                    target = Some((offset, payload_off, payload_len));
                    break;
                }
                if ad_type == Self::MESH_PBADV_AD_TYPE && fallback.is_none() {
                    fallback = Some((offset, payload_off, payload_len));
                }
            }
            offset = ad_end;
        }

        let (elem_off, payload_off, payload_cap) = match target.or(fallback) {
            Some(v) => v,
            None => return false,
        };

        let remain = adv_data.len().saturating_sub(payload_off);
        let max_payload_len = payload_cap.min(remain);
        if max_payload_len < 9 {
            return false;
        }

        const TARGET_LENS: [usize; 6] = [9, 10, 11, 12, 13, 14];
        let mut desired_payload_len = TARGET_LENS[state.rand_mut().between(0, TARGET_LENS.len() - 1)];
        desired_payload_len = desired_payload_len.clamp(9, max_payload_len);

        let mut changed = false;
        let new_ad_len = (desired_payload_len + 1).min(usize::from(u8::MAX)) as u8;
        if adv_data[elem_off] != new_ad_len {
            adv_data[elem_off] = new_ad_len;
            changed = true;
        }
        if adv_data[elem_off + 1] != Self::MESH_MSG_AD_TYPE {
            adv_data[elem_off + 1] = Self::MESH_MSG_AD_TYPE;
            changed = true;
        }

        let payload_end = payload_off + desired_payload_len;
        self.write_underflow_network_payload(state, &mut adv_data[payload_off..payload_end]);
        changed || desired_payload_len >= 9
    }

    pub(super) fn mutate_mesh_proxy_underflow_att_packet<'b>(
        &self,
        state: &mut MetaState,
        att_packet: &mut BytesSubInput<'b, BytesInput>,
        mesh_proxy_handles: &[u16],
        mesh_prov_handles: &[u16],
    ) -> bool {
        if att_packet.len() < 1 {
            return false;
        }

        let mut changed = false;

        {
            let bytes = att_packet.mutator_bytes_mut();
            let opcode = bytes[0];
            if opcode != 0x12 && opcode != 0x52 && opcode != 0xD2 {
                bytes[0] = 0x52; // ATT_WRITE_CMD
                changed = true;
            }
        }

        if att_packet.len() < 4 {
            att_packet.resize(4, 0x00);
            changed = true;
        }

        let current_handle = {
            let bytes = att_packet.mutator_bytes();
            if bytes.len() >= 3 { u16::from_le_bytes([bytes[1], bytes[2]]) } else { 0 }
        };

        let target_handle = if !mesh_proxy_handles.is_empty() {
            mesh_proxy_handles[state.rand_mut().between(0, mesh_proxy_handles.len() - 1)]
        } else if !mesh_prov_handles.is_empty() {
            mesh_prov_handles[state.rand_mut().between(0, mesh_prov_handles.len() - 1)]
        } else {
            current_handle
        };

        {
            let bytes = att_packet.mutator_bytes_mut();
            if bytes.len() >= 3 && target_handle != current_handle {
                bytes[1..3].copy_from_slice(&target_handle.to_le_bytes());
                changed = true;
            }
        }

        // Payload layout: [mesh_proxy_header][short body...]
        // Keep body tiny so gatt bearer forwards very short Network PDU length.
        const SHORT_PAYLOAD_LENS: [usize; 5] = [1, 2, 3, 4, 5];
        let payload_len = SHORT_PAYLOAD_LENS[state.rand_mut().between(0, SHORT_PAYLOAD_LENS.len() - 1)];
        let new_total_len = 3 + payload_len;
        if att_packet.len() != new_total_len {
            att_packet.resize(new_total_len, 0x00);
            changed = true;
        }

        let msg_type = if mesh_proxy_handles.contains(&target_handle) {
            0x00 // Network PDU -> mesh_network_received_message
        } else if mesh_prov_handles.contains(&target_handle) {
            // Provisioning service only accepts type 0x03.
            0x03
        } else {
            0x00
        };
        // Bias to complete message for immediate dispatch.
        let sar = if self.prob(state, 90) {
            0x00
        } else {
            [0x01, 0x02, 0x03][state.rand_mut().between(0, 2)]
        };
        let mesh_header = ((sar & 0x03) << 6) | (msg_type & 0x3f);

        {
            let bytes = att_packet.mutator_bytes_mut();
            if bytes.len() >= 4 && bytes[3] != mesh_header {
                bytes[3] = mesh_header;
                changed = true;
            }
            for idx in 4..bytes.len() {
                let v = state.rand_mut().between(0, 255) as u8;
                if bytes[idx] != v {
                    bytes[idx] = v;
                    changed = true;
                }
            }
        }

        changed
    }
}
