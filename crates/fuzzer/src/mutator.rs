/*!
 * Mutator for BLE packets.
 */
mod acl;
mod att;
mod event;
mod iso;
mod l2cap;
mod mesh;
mod sm;

use crate::MetaState;
use ble::{
    hci::{ControllerToHostPacket, HciEventPkt, event::LeMetaEventBody},
    input::MetaInput,
};
use libafl::{
    corpus::CorpusId,
    inputs::BytesInput,
    mutators::{HavocMutationsNoCrossoverType, HavocScheduledMutator, MutationResult, Mutator, havoc_mutations_no_crossover},
    state::HasRand,
};
use libafl_bolts::{Named, rands::Rand};
use simulator::Simulator;
use std::{borrow::Cow, env, num::NonZero};
use tracing::debug;

/// Mutator for BLE HCI packets
pub struct MetaMutator<'a> {
    // immutable simulator reference for profile-aware mutation
    simulator: &'a Simulator,
    // Global cursor for HCI version exploration across inputs in this fuzzer process.
    next_global_hci_version: Option<u8>,
    // Global cursor for subversion exploration across inputs in this fuzzer process.
    next_global_hci_subversion: Option<u16>,
    // mutator used for mutate packet payload bytes
    havoc_mutator: HavocScheduledMutator<HavocMutationsNoCrossoverType>,
    // Preserve SMP handshake packets after target state is reached.
    preserve_sm_pairing_handshake: bool,
    // Global gate for profile-aware mutation in this mutation round.
    profile_aware_active: bool,
    // ACL mutation mode: preserve ACL payloads.
    acl_mutation_preserve_active: bool,
}

impl<'a> MetaMutator<'a> {
    #[inline]
    fn parse_mode_env(var: &str) -> Option<String> {
        env::var(var).ok().map(|v| v.trim().to_ascii_lowercase()).filter(|v| !v.is_empty())
    }

    #[inline]
    fn is_vendor_response_event_packet(packet: &ControllerToHostPacket) -> bool {
        matches!(
            packet,
            ControllerToHostPacket::Event(HciEventPkt::CommandComplete(_)) | ControllerToHostPacket::Event(HciEventPkt::CommandStatus(_))
        )
    }

    #[inline]
    fn choose_hci_status(&self, state: &mut MetaState, old: u8) -> u8 {
        const STATUS_POOL: [u8; 8] = [0x00, 0x05, 0x07, 0x0C, 0x12, 0x1A, 0x29, 0x3B];
        for _ in 0..8 {
            let idx = state.rand_mut().between(0, STATUS_POOL.len() - 1);
            let candidate = STATUS_POOL[idx];
            if candidate != old {
                return candidate;
            }
        }
        old ^ 0x01
    }

    #[inline]
    fn choose_vendor_opcode(&self, state: &mut MetaState, old: u16, prioritize: bool) -> u16 {
        let keep_synthetic = !prioritize && self.prob(state, 70);
        if keep_synthetic {
            // keep in synthetic vendor range
            let suffix = state.rand_mut().between(0, 0x7f);
            let candidate = 0xFC80u16 | (suffix as u16);
            if candidate != old {
                return candidate;
            }
        }

        for _ in 0..8 {
            let candidate = state.rand_mut().between(0, u16::MAX as usize) as u16;
            if candidate != old {
                return candidate;
            }
        }
        old ^ 0x80
    }

    #[inline]
    fn is_startup_vendor_opcode(opcode: u16) -> bool {
        // Keep vendor bootstrap commands stable before reaching meaningful BLE states.
        // 0xFF04 is used by miiot case13 early init and corruption here causes immediate desync.
        matches!(opcode, 0xFC01 | 0xFC02 | 0xFC03 | 0xFF04)
    }

    fn mutate_vendor_response_event_packet(&self, state: &mut MetaState, packet: &mut ControllerToHostPacket, prioritize: bool) -> bool {
        match packet {
            ControllerToHostPacket::Event(HciEventPkt::CommandComplete(evt)) => {
                // Keep Zephyr HCI VS bootstrap responses stable before entering target states.
                // Corrupting these opcodes/lengths causes early init abort and hurts coverage.
                if Self::is_startup_vendor_opcode(evt.command_opcode) {
                    if !evt.return_parameters.is_empty() && (prioritize || self.prob(state, 2)) {
                        let old_status = evt.return_parameters[0];
                        let new_status = self.choose_hci_status(state, old_status);
                        if new_status != old_status {
                            evt.return_parameters[0] = new_status;
                            return true;
                        }
                    }
                    return false;
                }

                if prioritize {
                    // In prioritize mode, keep frame shape stable and only fuzz status.
                    if !evt.return_parameters.is_empty() {
                        let old_status = evt.return_parameters[0];
                        let new_status = self.choose_hci_status(state, old_status);
                        if new_status != old_status {
                            evt.return_parameters[0] = new_status;
                            return true;
                        }
                    }
                    return false;
                }

                let roll = state.rand_mut().between(0, 99);
                if roll < 20 {
                    let old_opcode = evt.command_opcode;
                    let new_opcode = self.choose_vendor_opcode(state, old_opcode, prioritize);
                    if new_opcode != old_opcode {
                        evt.command_opcode = new_opcode;
                        return true;
                    }
                }

                if roll >= 80 {
                    if evt.return_parameters.len() < 8 && self.prob(state, 70) {
                        evt.return_parameters.push(state.rand_mut().between(0, 255) as u8);
                    } else if !evt.return_parameters.is_empty() {
                        let idx = state.rand_mut().between(0, evt.return_parameters.len() - 1);
                        evt.return_parameters[idx] ^= 1u8 << state.rand_mut().between(0, 7);
                    }
                    evt.parameter_total_length = 0x3 + (evt.return_parameters.len().min(usize::from(u8::MAX)) as u8);
                    return true;
                }

                if !evt.return_parameters.is_empty() {
                    let old_status = evt.return_parameters[0];
                    let new_status = self.choose_hci_status(state, old_status);
                    if new_status != old_status {
                        evt.return_parameters[0] = new_status;
                        return true;
                    }
                }
                false
            }
            ControllerToHostPacket::Event(HciEventPkt::CommandStatus(evt)) => {
                if Self::is_startup_vendor_opcode(evt.command_opcode) {
                    if prioritize || self.prob(state, 2) {
                        let old_status = evt.status;
                        let new_status = self.choose_hci_status(state, old_status);
                        if new_status != old_status {
                            evt.status = new_status;
                            return true;
                        }
                    }
                    return false;
                }

                if prioritize {
                    let old_status = evt.status;
                    let new_status = self.choose_hci_status(state, old_status);
                    if new_status != old_status {
                        evt.status = new_status;
                        return true;
                    }
                    return false;
                }

                if self.prob(state, 15) {
                    let old_opcode = evt.command_opcode;
                    let new_opcode = self.choose_vendor_opcode(state, old_opcode, prioritize);
                    if new_opcode != old_opcode {
                        evt.command_opcode = new_opcode;
                        return true;
                    }
                }

                let old_status = evt.status;
                let new_status = self.choose_hci_status(state, old_status);
                if new_status != old_status {
                    evt.status = new_status;
                    return true;
                }
                false
            }
            _ => false,
        }
    }

    /// Mutates vendor response events marked in input.
    fn mutate_vendor_response_event(&self, state: &mut MetaState, input: &mut MetaInput) -> MutationResult {
        if !self.simulator.ablation_flags().enable_vendor_response_marking {
            return MutationResult::Skipped;
        }
        input.normalize_vendor_response_marks();

        if input.vendor_response_mutation_state().freeze || input.last_execution_feedback().entered_target_state() {
            return MutationResult::Skipped;
        }

        let prioritize = input.vendor_response_mutation_state().prioritize;
        let mutate_prob = if prioritize { 70 } else { 2 };
        if !self.prob(state, mutate_prob) {
            return MutationResult::Skipped;
        }

        let mut packet_bank = Vec::new();
        for (phase_idx, phase) in input.phases().iter().enumerate() {
            let marks = &input.vendor_response_marks()[phase_idx];
            let cnt = phase.len().min(marks.len());
            for packet_idx in 0..cnt {
                if marks[packet_idx] && Self::is_vendor_response_event_packet(&phase[packet_idx]) {
                    packet_bank.push((phase_idx, packet_idx));
                }
            }
        }
        if packet_bank.is_empty() {
            return MutationResult::Skipped;
        }

        if prioritize {
            // Focus early packets first: they are much more likely to be executed before timeout.
            let window = packet_bank.len().min(256);
            let mutate_cnt = 1 + state.rand_mut().between(0, 2);
            let mut mutated = false;
            for _ in 0..mutate_cnt {
                let pos = state.rand_mut().between(0, window - 1);
                let (phase_idx, packet_idx) = packet_bank[pos];
                mutated |= self.mutate_vendor_response_event_packet(state, &mut input.phases_mut()[phase_idx][packet_idx], prioritize);
            }
            if mutated { MutationResult::Mutated } else { MutationResult::Skipped }
        } else {
            let pos = state.rand_mut().between(0, packet_bank.len() - 1);
            let (phase_idx, packet_idx) = packet_bank[pos];
            if self.mutate_vendor_response_event_packet(state, &mut input.phases_mut()[phase_idx][packet_idx], prioritize) {
                MutationResult::Mutated
            } else {
                MutationResult::Skipped
            }
        }
    }

    /// Mutates local version fields in input, focusing on incremental exploration of hci_subversion.
    fn mutate_local_version_information(&mut self, state: &mut MetaState, input: &mut MetaInput) -> MutationResult {
        if !self.simulator.ablation_flags().enable_vendor_bootstrap_search {
            return MutationResult::Skipped;
        }
        if input.version_mutation_state().freeze {
            return MutationResult::Skipped;
        }

        let prioritize_hci_version = input.version_mutation_state().prioritize_hci_version;
        let prioritize_hci_subversion = input.version_mutation_state().prioritize_hci_subversion;
        let mutate_prob = if prioritize_hci_version || prioritize_hci_subversion { 100 } else { 10 };
        if !self.prob(state, mutate_prob) {
            return MutationResult::Skipped;
        }

        if prioritize_hci_version {
            let current = input.local_version_information().hci_version;
            let cursor = self.next_global_hci_version.get_or_insert_with(|| current.wrapping_add(1));
            let mut next = *cursor;
            if next == current {
                next = next.wrapping_add(1);
            }

            input.local_version_information_mut().hci_version = next;
            *cursor = next.wrapping_add(1);
            let state = input.version_mutation_state_mut();
            state.next_hci_version = *cursor;
            state.prioritize_hci_version = false;
            state.prioritize_hci_subversion = true;
            debug!(
                "mutate hci_version: current=0x{:02x} -> next=0x{:02x}, global_cursor_next=0x{:02x}, next_search=subversion, freeze={}",
                current,
                next,
                *cursor,
                input.version_mutation_state().freeze
            );
            return MutationResult::Mutated;
        }

        if !prioritize_hci_subversion {
            return MutationResult::Skipped;
        }

        let current = input.local_version_information().hci_subversion;
        let cursor = self.next_global_hci_subversion.get_or_insert_with(|| current.wrapping_add(1));
        let mut next = *cursor;
        if next == current {
            next = next.wrapping_add(1);
        }

        input.local_version_information_mut().hci_subversion = next;
        *cursor = next.wrapping_add(1);
        let state = input.version_mutation_state_mut();
        state.next_hci_subversion = *cursor;
        state.prioritize_hci_version = true;
        state.prioritize_hci_subversion = true;
        debug!(
            "mutate hci_subversion: current=0x{:04x} -> next=0x{:04x}, global_cursor_next=0x{:04x}, next_search=version, freeze={}",
            current,
            next,
            *cursor,
            input.version_mutation_state().freeze
        );
        MutationResult::Mutated
    }

    pub fn new(simulator: &'a Simulator) -> Self {
        // let adv_mutation_mode = Self::parse_mode_env("VIRTBLE_ADV_MUTATION_MODE");
        // let pbadv_oversize_active = adv_mutation_mode.as_deref().map(|mode| mode == "pbadv_oversize").unwrap_or(false);
        // let adv_mutation_preserve_active = adv_mutation_mode.as_deref().map(|mode| mode == "preserve").unwrap_or(false);

        // let event_length_stress_active = Self::parse_bool_env("VIRTBLE_HCI_EVENT_LENGTH_STRESS") || pbadv_oversize_active;
        // if event_length_stress_active {
        //     debug!("HCI event-length stress mutation enabled by VIRTBLE_HCI_EVENT_LENGTH_STRESS");
        // }
        // if pbadv_oversize_active {
        //     debug!("ADV pbadv oversize mutation mode enabled by VIRTBLE_ADV_MUTATION_MODE=pbadv_oversize");
        // }
        // if adv_mutation_preserve_active {
        //     debug!("ADV preserve mutation mode enabled by VIRTBLE_ADV_MUTATION_MODE=preserve");
        // }
        // let read_by_type_rsp_stress_active = env::var("VIRTBLE_ATT_MUTATION_MODE")
        //     .ok()
        //     .map(|v| v.trim().eq_ignore_ascii_case("read_by_type_rsp_stress"))
        //     .unwrap_or(false);
        // if read_by_type_rsp_stress_active {
        //     debug!("ATT read-by-type response stress mutation enabled by VIRTBLE_ATT_MUTATION_MODE");
        // }
        // let credit_sig_stress_active = env::var("VIRTBLE_L2CAP_MUTATION_MODE")
        //     .ok()
        //     .map(|v| v.trim().eq_ignore_ascii_case("credit_sig_stress"))
        //     .unwrap_or(false);
        // if credit_sig_stress_active {
        //     debug!("L2CAP credit signaling stress mutation enabled by VIRTBLE_L2CAP_MUTATION_MODE");
        // }
        let acl_mutation_preserve_active = Self::parse_mode_env("VIRTBLE_ACL_MUTATION_MODE")
            .as_deref()
            .map(|mode| mode == "preserve")
            .unwrap_or(false);
        if acl_mutation_preserve_active {
            debug!("ACL preserve mutation mode enabled by VIRTBLE_ACL_MUTATION_MODE=preserve");
        }
        Self {
            simulator,
            next_global_hci_version: None,
            next_global_hci_subversion: None,
            havoc_mutator: HavocScheduledMutator::new(havoc_mutations_no_crossover()),
            preserve_sm_pairing_handshake: false,
            profile_aware_active: false,
            // event_length_stress_active,
            // read_by_type_rsp_stress_active,
            // credit_sig_stress_active,
            // pbadv_oversize_active,
            // adv_mutation_preserve_active,
            acl_mutation_preserve_active,
        }
    }

    /// return `true` with probability `prob`%.
    #[inline]
    pub fn prob(&self, state: &mut MetaState, prob: usize) -> bool {
        state.rand_mut().below(NonZero::new(100).unwrap()) < prob
    }

    #[inline]
    fn runtime_profile(&self) -> simulator::RuntimeProfileState {
        self.simulator.runtime_profile()
    }

    #[inline]
    fn has_runtime_semantic_context(&self) -> bool {
        let runtime = self.runtime_profile();
        if !runtime.active_connection_handles.is_empty()
            || !runtime.host_visible_dynamic_cids.is_empty()
            || runtime.pairing_started
            || runtime.pairing_completed
        {
            return true;
        }

        let target_profile = self.simulator.target_gatt_profile();
        target_profile.mtu.is_some() || !target_profile.known_handles().is_empty()
    }

    #[inline]
    fn profile_aware_mutation_enabled(&self) -> bool {
        self.profile_aware_active
    }

    #[inline]
    fn is_adv_meta_event_packet(packet: &ControllerToHostPacket) -> bool {
        matches!(
            packet,
            ControllerToHostPacket::Event(HciEventPkt::LeMata(le_meta_event))
                if matches!(
                    le_meta_event.body,
                    LeMetaEventBody::AdvertisingReport(_)
                        | LeMetaEventBody::ExtendedAdvertisingReport(_)
                        | LeMetaEventBody::PeriodicAdvertisingReport(_)
                )
        )
    }

    /// Mutates single HCI packet
    fn mutate_packet(&mut self, state: &mut MetaState, packet: &mut ControllerToHostPacket) -> Result<MutationResult, libafl::Error> {
        let profile_aware = self.profile_aware_mutation_enabled();
        match packet {
            // mutates acl data at different layer
            ControllerToHostPacket::AclData(pkt) => {
                if self.acl_mutation_preserve_active {
                    return Ok(MutationResult::Skipped);
                }
                if profile_aware {
                    let ret = self.mutate_acl_packet(state, pkt);
                    pkt.data_total_length = pkt.data.len() as u16;
                    ret
                } else {
                    let input = vec_to_input_mut(&mut pkt.data);
                    let ret = self.havoc_mutator.mutate(state, input);
                    pkt.data_total_length = pkt.data.len() as u16;
                    ret
                }
            }
            // mutates all iso data payload
            ControllerToHostPacket::IsoData(pkt) => self.mutate_iso_packet(state, pkt),
            // mutates all sync data payload
            ControllerToHostPacket::SyncData(pkt) => {
                let input = vec_to_input_mut(&mut pkt.data);
                let ret = self.havoc_mutator.mutate(state, input);
                pkt.data_total_length = pkt.data.len() as u16;
                ret
            }
            // mutates HCI event packet
            ControllerToHostPacket::Event(HciEventPkt::LeMata(le_meta_event)) => match &mut le_meta_event.body {
                LeMetaEventBody::AdvertisingReport(body) => {
                    let ret = self.mutate_adv_report_packet(state, body);
                    le_meta_event.parameter_total_length = body.parameter_total_length();
                    ret
                }
                LeMetaEventBody::ExtendedAdvertisingReport(body) => {
                    let ret = self.mutate_extended_adv_report_packet(state, body);
                    le_meta_event.parameter_total_length = 2 + body.payload.len().min(usize::from(u8::MAX)) as u8;
                    ret
                }
                LeMetaEventBody::PeriodicAdvertisingReport(body) => {
                    let ret = self.mutate_periodic_adv_report_packet(state, body);
                    le_meta_event.parameter_total_length = 1 + body.payload.len().min(usize::from(u8::MAX - 1)) as u8;
                    ret
                }
                _ => Ok(MutationResult::Skipped),
            },
            _ => Ok(MutationResult::Skipped),
        }
    }

    /// Returns true if the packet is mutatable.
    fn can_mutate_packet(&self, packet: &ControllerToHostPacket) -> bool {
        match packet {
            ControllerToHostPacket::AclData(_) => !self.acl_mutation_preserve_active,
            ControllerToHostPacket::IsoData(_) => true,
            ControllerToHostPacket::SyncData(_) => true,
            ControllerToHostPacket::Event(HciEventPkt::LeMata(_)) => Self::is_adv_meta_event_packet(packet),
            _ => false,
        }
    }

    /// Mutates packets in all interacting phases.
    pub fn mutate_packets(&mut self, state: &mut MetaState, input: &mut MetaInput) -> Result<MutationResult, libafl::Error> {
        let mut result = MutationResult::Skipped;
        // Once a scenario has reached connection/pairing context, keep the SMP 0x01..0x04
        // handshake stable and spend the mutation budget on post-pairing exploration instead.
        let runtime = self.runtime_profile();
        let entered_target_state = input.last_execution_feedback().entered_target_state();
        let has_semantic_context = self.has_runtime_semantic_context();
        let next_profile_aware_active = self.simulator.ablation_flags().enable_profile_aware_mutation && (entered_target_state || has_semantic_context);
        if next_profile_aware_active != self.profile_aware_active {
            debug!(
                "profile-aware gate changed: {} -> {} (entered_target_state={}, has_semantic_context={})",
                self.profile_aware_active, next_profile_aware_active, entered_target_state, has_semantic_context
            );
        }
        self.profile_aware_active = next_profile_aware_active;
        self.preserve_sm_pairing_handshake = self.simulator.ablation_flags().enable_peer_interaction_pipeline
            && (input.last_execution_feedback().entered_advertising_state
                || input.last_execution_feedback().entered_connection_state
                || runtime.pairing_started
                || runtime.pairing_completed);

        if self.mutate_local_version_information(state, input) == MutationResult::Mutated {
            result = MutationResult::Mutated;
            // In prioritize mode, focus the whole round on subversion exploration.
            if input.version_mutation_state().prioritize_hci_subversion {
                return Ok(result);
            }
        }

        if MutationResult::Mutated == self.mutate_vendor_response_event(state, input) {
            result = MutationResult::Mutated;
            if !entered_target_state && self.prob(state, 35) {
                return Ok(result);
            }
        }

        // packet_bank restores all mutatable HCI packets by their ID (phase, packet) in the input
        let mut packet_bank = Vec::new();
        for (phase_id, phase) in input.phases().iter().enumerate() {
            for (packet_id, packet) in phase.iter().enumerate() {
                if self.can_mutate_packet(packet) {
                    packet_bank.push((phase_id, packet_id));
                }
            }
        }

        // if we don't have enough packets, skip the mutation
        if packet_bank.is_empty() {
            return Ok(result);
        }
        if *input.mutate_start() >= packet_bank.len() {
            *input.mutate_start_mut() = 0;
        }
        let pos = state.rand_mut().between(*input.mutate_start(), packet_bank.len() - 1);
        let packet = &mut input.phases_mut()[packet_bank[pos].0][packet_bank[pos].1];

        if self.mutate_packet(state, packet)? == MutationResult::Mutated {
            result = MutationResult::Mutated;
            input.phases_mut().truncate(packet_bank[pos].0 + 1);
            input.phases_mut()[packet_bank[pos].0].truncate(packet_bank[pos].1 + 1);
            input.vendor_response_marks_mut().truncate(packet_bank[pos].0 + 1);
            if packet_bank[pos].0 < input.vendor_response_marks().len() {
                input.vendor_response_marks_mut()[packet_bank[pos].0].truncate(packet_bank[pos].1 + 1);
            }
            *input.mutate_start_mut() = pos + 1;
        }
        Ok(result)
    }

    #[cfg(feature = "fuzzware_input")]
    fn mutate_mmio_bytes(&mut self, state: &mut MetaState, input: &mut MetaInput) -> Result<MutationResult, libafl::Error> {
        input.ensure_mmio_bytes_seed();
        self.havoc_mutator.mutate(state, vec_to_input_mut(input.mmio_bytes_mut()))
    }
}

impl<'a> Named for MetaMutator<'a> {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("meta-mutator");
        &NAME
    }
}

impl<'a> Mutator<MetaInput, MetaState> for MetaMutator<'a> {
    fn mutate(&mut self, state: &mut MetaState, input: &mut MetaInput) -> Result<MutationResult, libafl::Error> {
        #[cfg(feature = "fuzzware_input")]
        let mut result = self.mutate_packets(state, input)?;
        #[cfg(not(feature = "fuzzware_input"))]
        let result = self.mutate_packets(state, input)?;

        #[cfg(feature = "fuzzware_input")]
        {
            let do_mmio_havoc = self.prob(state, 60) || result == MutationResult::Skipped;
            if do_mmio_havoc && self.mutate_mmio_bytes(state, input)? == MutationResult::Mutated {
                result = MutationResult::Mutated;
            }
        }

        Ok(result)
    }

    fn post_exec(&mut self, _state: &mut MetaState, _new_corpus_id: Option<CorpusId>) -> Result<(), libafl::Error> {
        Ok(())
    }
}

pub(super) fn vec_to_input_mut(v: &mut Vec<u8>) -> &mut BytesInput {
    unsafe { &mut *(v as *mut Vec<u8> as *mut BytesInput) }
}

#[cfg(test)]
mod tests {
    use libafl::inputs::HasMutatorBytes;
    use libafl_core::HasLen;

    use super::*;

    #[test]
    fn check_memory_layout() {
        let raw_bytes = vec![0x12u8, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
        let mut input_bytes = raw_bytes.clone();
        let input = vec_to_input_mut(&mut input_bytes);

        assert!(input.len() == raw_bytes.len());
        for i in 0..input.len() {
            assert!(input.mutator_bytes()[i] == raw_bytes[i])
        }

        input.mutator_bytes_mut()[3] = 0x77;
        assert!(input_bytes[3] == 0x77);
    }
}
