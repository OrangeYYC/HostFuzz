use super::MetaMutator;
use crate::MetaState;
use ble::gatt::{self, GattProfileEntry};
use libafl::{
    inputs::{BytesInput, BytesSubInput, HasMutatorBytes, ResizableMutator},
    mutators::MutationResult,
    state::HasRand,
};
use libafl_bolts::rands::Rand;
use libafl_core::HasLen;
use tracing::info;

impl<'a> MetaMutator<'a> {
    const ATT_OP_MAPS: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x16, 0x17, 0x18, 0x19, 0x1b, 0x1d,
        0x1e, 0x20, 0x21, 0x23, 0x52, 0xd2, 0xff,
    ];
    const UUID_MESH_PROV_DATA_IN: u16 = 0x2ADB;
    const UUID_MESH_PROXY_DATA_IN: u16 = 0x2ADD;
    const MESH_PROXY_MSG_TYPE_NET_PDU: u8 = 0x00;
    const MESH_PROXY_MSG_TYPE_PROV: u8 = 0x03;
    const NO_PROFILE_WRITE_HANDLE_POOL: [u16; 16] = [
        0x0003, 0x0005, 0x0007, 0x0009, 0x000B, 0x000D, 0x0011, 0x0015, 0x0019, 0x0021, 0x0025, 0x0031, 0x0035, 0x0041, 0x0045, 0x0051,
    ];
    const NO_PROFILE_MSG_TYPE_POOL: [u8; 8] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x3F];

    #[inline]
    fn push_unique_handle(handles: &mut Vec<u16>, handle: u16) {
        if handles.contains(&handle) {
            return;
        }
        handles.push(handle);
        handles.sort_unstable();
    }

    fn collect_mesh_data_in_handles(&self) -> (Vec<u16>, Vec<u16>) {
        let profile = self.simulator.target_gatt_profile();
        let mut mesh_proxy_handles = Vec::new();
        let mut mesh_prov_handles = Vec::new();

        for handle in profile.known_handles() {
            let GattProfileEntry::CharacteristicDeclaration(decl) = profile.entry(handle) else {
                continue;
            };
            if (decl.property & gatt::GATT_PROP_WRITE_WITHOUT_RESP) == 0 {
                continue;
            }

            let uuid = decl.uuid.as_le_slice();
            if uuid.len() != 2 {
                continue;
            }
            let uuid16 = u16::from_le_bytes([uuid[0], uuid[1]]);
            if uuid16 == Self::UUID_MESH_PROXY_DATA_IN {
                Self::push_unique_handle(&mut mesh_proxy_handles, decl.value_handle);
            } else if uuid16 == Self::UUID_MESH_PROV_DATA_IN {
                Self::push_unique_handle(&mut mesh_prov_handles, decl.value_handle);
            }
        }

        (mesh_proxy_handles, mesh_prov_handles)
    }

    #[inline]
    fn choose_mesh_write_handle(
        &self,
        state: &mut MetaState,
        mesh_proxy_handles: &[u16],
        mesh_prov_handles: &[u16],
        fallback_handles: &[u16],
        old: u16,
    ) -> u16 {
        let mesh_total = mesh_proxy_handles.len().saturating_add(mesh_prov_handles.len());
        if mesh_total > 0 && self.prob(state, 95) {
            for _ in 0..4 {
                let idx = state.rand_mut().between(0, mesh_total - 1);
                let candidate = if idx < mesh_proxy_handles.len() {
                    mesh_proxy_handles[idx]
                } else {
                    mesh_prov_handles[idx - mesh_proxy_handles.len()]
                };
                if candidate != old {
                    return candidate;
                }
            }
        }
        self.choose_att_handle(state, fallback_handles, old)
    }

    #[inline]
    fn mutate_mesh_proxy_header(&self, state: &mut MetaState, packet: &mut [u8], handle: u16, mesh_proxy_handles: &[u16], mesh_prov_handles: &[u16]) -> bool {
        // ATT Write* payload layout: [opcode][handle_lo][handle_hi][mesh_hdr]...
        if packet.len() < 4 {
            return false;
        }

        let msg_type = if mesh_prov_handles.contains(&handle) {
            Self::MESH_PROXY_MSG_TYPE_PROV
        } else if mesh_proxy_handles.contains(&handle) {
            let proxy_types = [Self::MESH_PROXY_MSG_TYPE_NET_PDU, 0x01, 0x02];
            proxy_types[state.rand_mut().between(0, proxy_types.len() - 1)]
        } else {
            return false;
        };

        const SAR_POOL: [u8; 4] = [0x00, 0x01, 0x02, 0x03];
        let sar = SAR_POOL[state.rand_mut().between(0, SAR_POOL.len() - 1)];
        let new_header = ((sar & 0x03) << 6) | (msg_type & 0x3f);

        let old_header = packet[3];
        if old_header == new_header {
            return false;
        }
        packet[3] = new_header;
        true
    }

    #[inline]
    fn choose_att_handle(&self, state: &mut MetaState, known_handles: &[u16], old: u16) -> u16 {
        if !known_handles.is_empty() && self.prob(state, 90) {
            for _ in 0..4 {
                let idx = state.rand_mut().between(0, known_handles.len() - 1);
                let candidate = known_handles[idx];
                if candidate != old {
                    return candidate;
                }
            }
        }

        let mut candidate = state.rand_mut().between(1, 0xffff) as u16;
        if candidate == old {
            candidate = if candidate == 0xffff { 1 } else { candidate + 1 };
        }
        candidate
    }

    #[inline]
    fn choose_no_profile_write_handle(&self, state: &mut MetaState, old: u16) -> u16 {
        if self.prob(state, 85) {
            for _ in 0..4 {
                let idx = state.rand_mut().between(0, Self::NO_PROFILE_WRITE_HANDLE_POOL.len() - 1);
                let candidate = Self::NO_PROFILE_WRITE_HANDLE_POOL[idx];
                if candidate != old {
                    return candidate;
                }
            }
        }

        let mut candidate = if self.prob(state, 80) {
            state.rand_mut().between(1, 0x0060) as u16
        } else {
            state.rand_mut().between(1, 0xffff) as u16
        };
        if candidate == old {
            candidate = if candidate == 0xffff { 1 } else { candidate + 1 };
        }
        candidate
    }

    fn mutate_att_no_profile_context<'b>(&self, state: &mut MetaState, att_packet: &mut BytesSubInput<'b, BytesInput>) -> MutationResult {
        let bytes = att_packet.mutator_bytes_mut();
        if bytes.is_empty() {
            return MutationResult::Skipped;
        }

        let mut changed = false;
        match bytes[0] {
            // ATT write packets (including write cmd): aggressively explore low-handle ingress
            // paths even before runtime profile handles are discovered.
            0x12 | 0x52 | 0xD2 => {
                if bytes.len() >= 3 && self.prob(state, 95) {
                    let old = u16::from_le_bytes([bytes[1], bytes[2]]);
                    let new = self.choose_no_profile_write_handle(state, old);
                    if old != new {
                        bytes[1..3].copy_from_slice(&new.to_le_bytes());
                        changed = true;
                    }
                }
                if bytes.len() >= 4 && self.prob(state, 85) {
                    const SAR_POOL: [u8; 4] = [0x00, 0x01, 0x02, 0x03];
                    let sar = SAR_POOL[state.rand_mut().between(0, SAR_POOL.len() - 1)];
                    let msg_type = Self::NO_PROFILE_MSG_TYPE_POOL[state.rand_mut().between(0, Self::NO_PROFILE_MSG_TYPE_POOL.len() - 1)];
                    let new_header = ((sar & 0x03) << 6) | (msg_type & 0x3f);
                    if bytes[3] != new_header {
                        bytes[3] = new_header;
                        changed = true;
                    }
                }
                if bytes.len() >= 5 && self.prob(state, 60) {
                    let idx = state.rand_mut().between(4, bytes.len() - 1);
                    let bit = 1u8 << state.rand_mut().between(0, 7);
                    bytes[idx] ^= bit;
                    changed = true;
                }
            }
            // Range-based requests: keep them in low-handle regions to accelerate bootstrap.
            0x04 | 0x06 | 0x08 | 0x10 => {
                if bytes.len() >= 5 {
                    let old_start = u16::from_le_bytes([bytes[1], bytes[2]]);
                    let old_end = u16::from_le_bytes([bytes[3], bytes[4]]);
                    let new_start = self.choose_no_profile_write_handle(state, old_start);
                    let mut new_end = self.choose_no_profile_write_handle(state, old_end);
                    if new_end < new_start {
                        new_end = new_start;
                    }
                    if old_start != new_start {
                        bytes[1..3].copy_from_slice(&new_start.to_le_bytes());
                        changed = true;
                    }
                    if old_end != new_end {
                        bytes[3..5].copy_from_slice(&new_end.to_le_bytes());
                        changed = true;
                    }
                }
            }
            _ => {}
        }

        if changed { MutationResult::Mutated } else { MutationResult::Skipped }
    }

    #[inline]
    fn mutate_att_handle_field(&self, state: &mut MetaState, packet: &mut [u8], offset: usize, known_handles: &[u16]) -> bool {
        if packet.len() < offset + 2 {
            return false;
        }

        let old = u16::from_le_bytes([packet[offset], packet[offset + 1]]);
        let new = self.choose_att_handle(state, known_handles, old);
        if old == new {
            return false;
        }
        packet[offset..(offset + 2)].copy_from_slice(&new.to_le_bytes());
        true
    }

    #[inline]
    fn mutate_att_handle_range_fields(&self, state: &mut MetaState, packet: &mut [u8], start_offset: usize, end_offset: usize, known_handles: &[u16]) -> bool {
        if packet.len() < end_offset + 2 {
            return false;
        }

        let old_start = u16::from_le_bytes([packet[start_offset], packet[start_offset + 1]]);
        let old_end = u16::from_le_bytes([packet[end_offset], packet[end_offset + 1]]);

        let (new_start, new_end) = if known_handles.len() >= 2 && self.prob(state, 90) {
            let start_idx = state.rand_mut().between(0, known_handles.len() - 1);
            let end_idx = state.rand_mut().between(start_idx, known_handles.len() - 1);
            (known_handles[start_idx], known_handles[end_idx])
        } else {
            let start = self.choose_att_handle(state, known_handles, old_start);
            let mut end = self.choose_att_handle(state, known_handles, old_end);
            if end < start {
                end = start;
            }
            (start, end)
        };

        let mut changed = false;
        if old_start != new_start {
            packet[start_offset..(start_offset + 2)].copy_from_slice(&new_start.to_le_bytes());
            changed = true;
        }
        if old_end != new_end {
            packet[end_offset..(end_offset + 2)].copy_from_slice(&new_end.to_le_bytes());
            changed = true;
        }
        changed
    }

    #[inline]
    fn mutate_att_handle_list_field(
        &self,
        state: &mut MetaState,
        packet: &mut [u8],
        start_offset: usize,
        entry_size: usize,
        handle_offset: usize,
        known_handles: &[u16],
    ) -> bool {
        if entry_size < handle_offset + 2 || packet.len() <= start_offset {
            return false;
        }
        let available = packet.len() - start_offset;
        let count = available / entry_size;
        if count == 0 {
            return false;
        }

        let idx = state.rand_mut().between(0, count - 1);
        let handle_pos = start_offset + idx * entry_size + handle_offset;
        self.mutate_att_handle_field(state, packet, handle_pos, known_handles)
    }

    fn mutate_att_profile_aware<'b>(&self, state: &mut MetaState, att_packet: &mut BytesSubInput<'b, BytesInput>) -> MutationResult {
        if att_packet.len() < 2 {
            return MutationResult::Skipped;
        }

        let known_handles = self.simulator.target_gatt_profile().known_handles();
        if known_handles.is_empty() {
            return MutationResult::Skipped;
        }
        let (mesh_proxy_handles, mesh_prov_handles) = self.collect_mesh_data_in_handles();
        let bytes = att_packet.mutator_bytes_mut();

        let mut has_mutate = false;
        match bytes[0] {
            // ErrorRsp
            0x01 => {
                has_mutate |= self.mutate_att_handle_field(state, bytes, 2, &known_handles);
            }
            // Handle range req packets
            0x04 | 0x06 | 0x08 | 0x10 => {
                has_mutate |= self.mutate_att_handle_range_fields(state, bytes, 1, 3, &known_handles);
            }
            // FindInformationRsp
            0x05 => {
                if bytes.len() >= 3 {
                    let entry_size = match bytes[1] {
                        0x01 => 4,
                        0x02 => 18,
                        _ => 0,
                    };
                    if entry_size > 0 {
                        has_mutate |= self.mutate_att_handle_list_field(state, bytes, 2, entry_size, 0, &known_handles);
                    }
                }
            }
            // FindByTypeValueRsp: (found_handle, group_end_handle) list
            0x07 => {
                if self.prob(state, 50) {
                    has_mutate |= self.mutate_att_handle_list_field(state, bytes, 1, 4, 0, &known_handles);
                } else {
                    has_mutate |= self.mutate_att_handle_list_field(state, bytes, 1, 4, 2, &known_handles);
                }
            }
            // ReadByTypeRsp
            0x09 => {
                if bytes.len() >= 3 && bytes[1] >= 2 {
                    has_mutate |= self.mutate_att_handle_list_field(state, bytes, 2, bytes[1] as usize, 0, &known_handles);
                }
            }
            // ATT write packets: prioritize write-no-rsp mesh data ingress handles when present.
            0x12 | 0x52 | 0xD2 => {
                if bytes.len() >= 3 {
                    let old = u16::from_le_bytes([bytes[1], bytes[2]]);
                    let new = self.choose_mesh_write_handle(state, &mesh_proxy_handles, &mesh_prov_handles, &known_handles, old);
                    if old != new {
                        bytes[1..3].copy_from_slice(&new.to_le_bytes());
                        has_mutate = true;
                    }
                    let handle = u16::from_le_bytes([bytes[1], bytes[2]]);
                    if self.mutate_mesh_proxy_header(state, bytes, handle, &mesh_proxy_handles, &mesh_prov_handles) {
                        has_mutate = true;
                    }
                }
            }
            // Single handle packets
            0x0A | 0x0C | 0x16 | 0x17 | 0x1B | 0x1D => {
                has_mutate |= self.mutate_att_handle_field(state, bytes, 1, &known_handles);
            }
            // Multi-handle req packets
            0x0E | 0x20 => {
                has_mutate |= self.mutate_att_handle_list_field(state, bytes, 1, 2, 0, &known_handles);
            }
            // ReadByGroupTypeRsp
            0x11 => {
                if bytes.len() >= 3 && bytes[1] >= 4 {
                    if self.prob(state, 50) {
                        has_mutate |= self.mutate_att_handle_list_field(state, bytes, 2, bytes[1] as usize, 0, &known_handles);
                    } else {
                        has_mutate |= self.mutate_att_handle_list_field(state, bytes, 2, bytes[1] as usize, 2, &known_handles);
                    }
                }
            }
            _ => {}
        }

        if has_mutate { MutationResult::Mutated } else { MutationResult::Skipped }
    }

    /// mutates the ATT packet
    pub(super) fn mutate_att_packet<'b>(
        &mut self,
        state: &mut MetaState,
        att_packet: &mut BytesSubInput<'b, BytesInput>,
    ) -> Result<MutationResult, libafl::Error> {
        info!("Mutating ATT packet");
        if att_packet.len() == 0 {
            return Ok(MutationResult::Skipped);
        }

        let mut has_mutate = MutationResult::Skipped;
        let profile_aware = self.profile_aware_mutation_enabled();
        let att_profile_aware = profile_aware && self.simulator.max_att_profile_guided_probe_steps() > 0;
        let known_handles = self.simulator.target_gatt_profile().known_handles();
        // let runtime = self.runtime_profile();
        let no_handle_bootstrap = att_profile_aware && known_handles.is_empty();
        let (mesh_proxy_handles, mesh_prov_handles) = self.collect_mesh_data_in_handles();

        // let discovery_bootstrap = no_handle_bootstrap && runtime.pairing_completed;
        let has_semantic_context = att_profile_aware && self.has_runtime_semantic_context();

        if self.prob(state, 10) {
            let new_att_op = Self::ATT_OP_MAPS[state.rand_mut().between(0, Self::ATT_OP_MAPS.len() - 1)];
            if att_packet.mutator_bytes_mut()[0] != new_att_op {
                att_packet.mutator_bytes_mut()[0] = new_att_op;
                has_mutate = MutationResult::Mutated;
            }
        }
        if att_profile_aware && !known_handles.is_empty() && self.prob(state, if has_semantic_context { 92 } else { 80 }) {
            if MutationResult::Mutated == self.mutate_att_profile_aware(state, att_packet) {
                has_mutate = MutationResult::Mutated;
            }
        }
        if no_handle_bootstrap && self.prob(state, 85) {
            if MutationResult::Mutated == self.mutate_att_no_profile_context(state, att_packet) {
                has_mutate = MutationResult::Mutated;
            }
        }

        if self.prob(state, 5) && self.mutate_mesh_proxy_underflow_att_packet(state, att_packet, &mesh_proxy_handles, &mesh_prov_handles) {
            has_mutate = MutationResult::Mutated;
        }

        // mutate length
        if self.prob(state, 20) {
            match att_packet.mutator_bytes()[0] {
                0x09 => {
                    let old_len = att_packet.mutator_bytes().len() - 0x2;
                    let new_len = state.rand_mut().between(0, old_len);
                    if new_len != old_len {
                        info!("-> Att packet length mutated");
                        has_mutate = MutationResult::Mutated;
                        att_packet.resize(new_len + 0x2, 0x0);
                        att_packet.mutator_bytes_mut()[1] = new_len as u8;
                    }
                }
                _ => {}
            }
        }

        Ok(has_mutate)
    }
}
