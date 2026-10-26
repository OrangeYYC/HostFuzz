use super::{MetaMutator, vec_to_input_mut};
use crate::MetaState;
use ble::hci::event::{LeAdvertisingReportEvent, LeExtendedAdvertisingReportEvent, LePeriodicAdvertisingReportEvent};
use libafl::{
    mutators::{MutationResult, Mutator},
    state::HasRand,
};
use libafl_bolts::rands::Rand;
use libafl_core::HasLen;
use tracing::info;

impl<'a> MetaMutator<'a> {
    const MAX_LE_ADV_REPORT_DATA_LEN: usize = 31;
    pub(super) const MAX_LE_EXT_ADV_REPORT_DATA_LEN: usize = 191;
    pub(super) const EXT_ADV_REPORT_FIXED_PREFIX_LEN: usize = 24;
    pub(super) const EXT_ADV_STRESS_PAYLOAD_MAX: usize = Self::EXT_ADV_REPORT_FIXED_PREFIX_LEN + Self::MAX_LE_EXT_ADV_REPORT_DATA_LEN;
    const PERIODIC_ADV_REPORT_FIXED_PREFIX_LEN: usize = 7;
    const MAX_PERIODIC_ADV_REPORT_DATA_LEN: usize = 224;

    #[inline]
    fn mibeacon_obj_id_for_len(&self, state: &mut MetaState, len: usize, current: u16) -> u16 {
        match len {
            1 => 0x100A, // battery
            2 => {
                let candidates = [0x1004u16, 0x1006u16, current];
                candidates[state.rand_mut().between(0, candidates.len() - 1)]
            }
            4 => 0x100D, // temp+humidity
            _ => current,
        }
    }

    fn write_mibeacon_object_payload(&self, state: &mut MetaState, obj_id: u16, dst: &mut [u8]) {
        dst.fill(0);
        match (obj_id, dst.len()) {
            // Battery (%)
            (0x100A, 1) => {
                dst[0] = state.rand_mut().between(0, 100) as u8;
            }
            // Temperature (0.1 C)
            (0x1004, 2) => {
                let temp = (state.rand_mut().between(0, 700) as i16) - 100;
                dst.copy_from_slice(&(temp as u16).to_le_bytes());
            }
            // Humidity (0.1 %)
            (0x1006, 2) => {
                let hum = state.rand_mut().between(0, 1000) as u16;
                dst.copy_from_slice(&hum.to_le_bytes());
            }
            // Door / contact style boolean payload
            (0x1019, 1) => {
                dst[0] = state.rand_mut().between(0, 1) as u8;
            }
            // Temperature + humidity
            (0x100D, 4) => {
                let temp = (state.rand_mut().between(0, 700) as i16) - 100;
                let hum = state.rand_mut().between(0, 1000) as u16;
                dst[0..2].copy_from_slice(&(temp as u16).to_le_bytes());
                dst[2..4].copy_from_slice(&hum.to_le_bytes());
            }
            _ if !dst.is_empty() => {
                let idx = state.rand_mut().between(0, dst.len() - 1);
                dst[idx] ^= 1u8 << state.rand_mut().between(0, 7);
            }
            _ => {}
        }
    }

    fn rewrite_mibeacon_object(&self, state: &mut MetaState, service_data: &mut [u8]) -> bool {
        if service_data.len() < 16 {
            return false;
        }

        let payload_cap = service_data.len().saturating_sub(16);
        if payload_cap == 0 {
            return false;
        }

        let mut templates = vec![
            (0x100Au16, 1usize),
            (0x1004u16, 2usize),
            (0x1006u16, 2usize),
            (0x1019u16, 1usize),
            (0x100Du16, 4usize),
        ];
        templates.retain(|(_, len)| *len <= payload_cap);
        if templates.is_empty() {
            return false;
        }

        let (obj_id, obj_len) = templates[state.rand_mut().between(0, templates.len() - 1)];
        service_data[13..15].copy_from_slice(&obj_id.to_le_bytes());
        service_data[15] = obj_len as u8;
        self.write_mibeacon_object_payload(state, obj_id, &mut service_data[16..(16 + obj_len)]);
        if 16 + obj_len < service_data.len() {
            service_data[(16 + obj_len)..].fill(0);
        }
        true
    }

    fn mutate_mibeacon_service_data(&mut self, state: &mut MetaState, service_data: &mut [u8]) -> bool {
        // Service Data layout:
        // [UUID(2)=0xFE95][FrameCtrl(2)][ProductID(2)][FrameCnt(1)][MAC(6)][ObjID(2)][ObjLen(1)][ObjData...]
        if service_data.len() < 16 {
            return false;
        }
        if service_data[0] != 0x95 || service_data[1] != 0xFE {
            return false;
        }

        let mut mutated = false;

        if self.prob(state, 90) {
            service_data[6] = service_data[6].wrapping_add((1 + state.rand_mut().between(0, 7)) as u8);
            mutated = true;
        }

        if self.prob(state, 55) {
            // Keep common MiBeacon capability bits stable while varying frame semantics.
            let frame_low = service_data[2];
            let frame_high = service_data[3];
            let mut frame = u16::from_le_bytes([frame_low, frame_high]);
            frame &= !0x001F;
            frame |= [0x0000u16, 0x0008, 0x0010, 0x0018][state.rand_mut().between(0, 3)];
            service_data[2..4].copy_from_slice(&frame.to_le_bytes());
            mutated = true;
        }

        let mut obj_id = u16::from_le_bytes([service_data[13], service_data[14]]);
        let obj_len = service_data[15] as usize;
        let obj_start: usize = 16;
        let obj_end = obj_start.saturating_add(obj_len);
        if obj_end > service_data.len() {
            return mutated;
        }

        if self.prob(state, 45) && self.rewrite_mibeacon_object(state, service_data) {
            return true;
        }

        if self.prob(state, 45) {
            let new_obj_id = self.mibeacon_obj_id_for_len(state, obj_len, obj_id);
            if new_obj_id != obj_id {
                service_data[13..15].copy_from_slice(&new_obj_id.to_le_bytes());
                obj_id = new_obj_id;
                mutated = true;
            }
        }

        if obj_len > 0 && self.prob(state, 90) {
            let obj = &mut service_data[obj_start..obj_end];
            match (obj_id, obj_len) {
                // Temperature & humidity (0.1 units, little-endian)
                (0x100D, 4) => {
                    let temp = (state.rand_mut().between(0, 700) as i16) - 100; // -10.0..60.0 C
                    let hum = state.rand_mut().between(0, 1000) as u16; // 0.0..100.0 %
                    obj[0..2].copy_from_slice(&(temp as u16).to_le_bytes());
                    obj[2..4].copy_from_slice(&hum.to_le_bytes());
                }
                // Temperature (0.1 C)
                (0x1004, 2) => {
                    let temp = (state.rand_mut().between(0, 700) as i16) - 100;
                    obj.copy_from_slice(&(temp as u16).to_le_bytes());
                }
                // Humidity (0.1 %)
                (0x1006, 2) => {
                    let hum = state.rand_mut().between(0, 1000) as u16;
                    obj.copy_from_slice(&hum.to_le_bytes());
                }
                // Battery (%)
                (0x100A, 1) => {
                    obj[0] = state.rand_mut().between(0, 100) as u8;
                }
                _ => {
                    let idx = state.rand_mut().between(0, obj.len() - 1);
                    obj[idx] ^= 1u8 << state.rand_mut().between(0, 7);
                }
            }
            mutated = true;
        }

        mutated
    }

    fn mutate_xiaomi_mibeacon_in_adv_data(&mut self, state: &mut MetaState, adv_data: &mut [u8]) -> bool {
        let mut offset = 0usize;
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
            // AD type 0x16: Service Data - 16-bit UUID
            if ad_type == 0x16 {
                let service_data = &mut adv_data[(offset + 2)..ad_end];
                if self.mutate_mibeacon_service_data(state, service_data) {
                    return true;
                }
            }
            offset = ad_end;
        }
        false
    }

    fn mutate_adv_ad_length_stress(&self, state: &mut MetaState, adv_data: &mut [u8]) -> bool {
        if adv_data.len() < 4 {
            return false;
        }

        let mut elems: Vec<(usize, u8, usize)> = Vec::new();
        let mut offset = 0usize;
        while offset < adv_data.len() {
            let ad_len = adv_data[offset] as usize;
            if ad_len == 0 {
                break;
            }
            let ad_end = offset + 1 + ad_len;
            if ad_end > adv_data.len() {
                break;
            }
            elems.push((offset, adv_data[offset + 1], ad_len));
            offset = ad_end;
        }
        if elems.is_empty() {
            return false;
        }

        // Generic AD element length perturbation: probe source-bound checks in host parsers.
        if self.prob(state, 75) {
            let idx = state.rand_mut().between(0, elems.len() - 1);
            let (elem_off, _, _) = elems[idx];
            let remain = adv_data.len().saturating_sub(elem_off + 1);
            let mut candidates = vec![0usize, 1, 2, 3];
            if remain > 0 {
                candidates.push(remain.saturating_sub(1));
                candidates.push(remain.min(31));
            }
            let next = candidates[state.rand_mut().between(0, candidates.len() - 1)].min(255) as u8;
            if adv_data[elem_off] != next {
                adv_data[elem_off] = next;
                return true;
            }
        }

        // If we have UUID16 list AD, stress the following AD length byte with tiny values.
        if elems.len() >= 2 {
            for i in 0..(elems.len() - 1) {
                let (_, ad_type, _) = elems[i];
                if ad_type != 0x02 && ad_type != 0x03 {
                    continue;
                }
                let (next_off, _, _) = elems[i + 1];
                if adv_data.len().saturating_sub(next_off + 1) < 20 {
                    continue;
                }
                let tiny = [0u8, 1u8, 2u8][state.rand_mut().between(0, 2)];
                if adv_data[next_off] != tiny {
                    adv_data[next_off] = tiny;
                    return true;
                }
            }
        }

        false
    }

    pub(super) fn mutate_adv_report_packet(&mut self, state: &mut MetaState, packet: &mut LeAdvertisingReportEvent) -> Result<MutationResult, libafl::Error> {
        info!("Mutating adv report packet");

        let (mut ret, mut new_len) = {
            let input = vec_to_input_mut(&mut packet.reports[0].data);
            let ret = self.havoc_mutator.mutate(state, input)?;
            let len = input.len().min(Self::MAX_LE_ADV_REPORT_DATA_LEN);
            (ret, len)
        };
        if self.prob(state, 5) {
            if self.mutate_mesh_network_underflow_adv_payload(state, &mut packet.reports[0].data) {
                ret = MutationResult::Mutated;
                new_len = packet.reports[0].data.len().min(Self::MAX_LE_ADV_REPORT_DATA_LEN);
            }
        }
        if self.prob(state, 20) {
            if self.mutate_adv_ad_length_stress(state, &mut packet.reports[0].data) {
                ret = MutationResult::Mutated;
                new_len = packet.reports[0].data.len().min(Self::MAX_LE_ADV_REPORT_DATA_LEN);
            }
        }
        packet.reports[0].data.truncate(new_len);
        packet.reports[0].data_length = new_len as u8;
        Ok(ret)
    }

    pub(super) fn mutate_extended_adv_report_packet(
        &mut self,
        state: &mut MetaState,
        packet: &mut LeExtendedAdvertisingReportEvent,
    ) -> Result<MutationResult, libafl::Error> {
        info!("Mutating extended adv report packet");
        if packet.payload.len() < Self::EXT_ADV_REPORT_FIXED_PREFIX_LEN {
            return Ok(MutationResult::Skipped);
        }

        let data_len_idx = Self::EXT_ADV_REPORT_FIXED_PREFIX_LEN - 1;
        let declared_len = packet.payload[data_len_idx] as usize;
        let available_len = packet.payload.len() - Self::EXT_ADV_REPORT_FIXED_PREFIX_LEN;
        let adv_len = declared_len.min(available_len);

        let mut adv_data = packet.payload[Self::EXT_ADV_REPORT_FIXED_PREFIX_LEN..(Self::EXT_ADV_REPORT_FIXED_PREFIX_LEN + adv_len)].to_vec();

        let mut mutated = false;
        let has_semantic_context = self.has_runtime_semantic_context();
        let profile_aware_prob = if has_semantic_context { 90 } else { 25 };
        if self.simulator.ablation_flags().enable_profile_aware_mutation && self.prob(state, profile_aware_prob) {
            mutated = self.mutate_xiaomi_mibeacon_in_adv_data(state, &mut adv_data);
            if !mutated && self.prob(state, 90) {
                mutated = self.mutate_adv_ad_length_stress(state, &mut adv_data);
            }
        }
        if !mutated && self.prob(state, 30) {
            mutated = self.mutate_adv_ad_length_stress(state, &mut adv_data);
        }
        if self.prob(state, 5) {
            if self.mutate_mesh_network_underflow_adv_payload(state, &mut adv_data) {
                mutated = true;
            }
        }

        if self.prob(state, 20) && self.mutate_mesh_extended_adv_payload_length_stress(state, &mut adv_data) {
            mutated = true;
        }

        if !mutated {
            let (ret, new_len) = {
                let input = vec_to_input_mut(&mut adv_data);
                let ret = self.havoc_mutator.mutate(state, input)?;
                let len = input.len().min(Self::MAX_LE_EXT_ADV_REPORT_DATA_LEN);
                (ret, len)
            };
            adv_data.truncate(new_len);
            if ret == MutationResult::Mutated {
                mutated = true;
            }
        } else {
            adv_data.truncate(adv_data.len().min(Self::MAX_LE_EXT_ADV_REPORT_DATA_LEN));
        }

        packet.payload.truncate(Self::EXT_ADV_REPORT_FIXED_PREFIX_LEN);
        packet.payload[data_len_idx] = adv_data.len() as u8;
        packet.payload.extend_from_slice(&adv_data);

        if mutated { Ok(MutationResult::Mutated) } else { Ok(MutationResult::Skipped) }
    }

    pub(super) fn mutate_periodic_adv_report_packet(
        &mut self,
        state: &mut MetaState,
        packet: &mut LePeriodicAdvertisingReportEvent,
    ) -> Result<MutationResult, libafl::Error> {
        info!("Mutating periodic adv report packet");
        if packet.payload.len() < Self::PERIODIC_ADV_REPORT_FIXED_PREFIX_LEN {
            return Ok(MutationResult::Skipped);
        }

        let declared_len_idx = Self::PERIODIC_ADV_REPORT_FIXED_PREFIX_LEN - 1;
        let declared_len = packet.payload[declared_len_idx] as usize;
        let available_len = packet.payload.len() - Self::PERIODIC_ADV_REPORT_FIXED_PREFIX_LEN;
        let report_data_len = declared_len.min(available_len);
        let mut report_data =
            packet.payload[Self::PERIODIC_ADV_REPORT_FIXED_PREFIX_LEN..(Self::PERIODIC_ADV_REPORT_FIXED_PREFIX_LEN + report_data_len)].to_vec();

        let (ret, new_len) = {
            let input = vec_to_input_mut(&mut report_data);
            let ret = self.havoc_mutator.mutate(state, input)?;
            let len = input.len().min(Self::MAX_PERIODIC_ADV_REPORT_DATA_LEN);
            (ret, len)
        };
        report_data.truncate(new_len);

        // Keep report shape mostly valid, but only desync declared length with
        // a controlled probability to probe host source-bound checks.
        let mut next_declared_len = report_data.len();
        if self.prob(state, 20) {
            let bias_over = self.prob(state, 85);
            if bias_over {
                let extra = 1 + state.rand_mut().between(0, 63);
                next_declared_len = (report_data.len() + extra).min(255);
            } else {
                // Ensure desync is guaranteed once we enter the 20% branch.
                if report_data.is_empty() {
                    next_declared_len = 1;
                } else {
                    next_declared_len = state.rand_mut().between(0, report_data.len() - 1).min(255);
                }
            }
        }

        packet.payload.truncate(Self::PERIODIC_ADV_REPORT_FIXED_PREFIX_LEN);
        packet.payload[declared_len_idx] = next_declared_len as u8;
        packet.payload.extend_from_slice(&report_data);

        if ret == MutationResult::Mutated || next_declared_len != report_data.len() {
            Ok(MutationResult::Mutated)
        } else {
            Ok(MutationResult::Skipped)
        }
    }
}
