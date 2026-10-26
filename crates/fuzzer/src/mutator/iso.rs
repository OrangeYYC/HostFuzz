use super::{MetaMutator, vec_to_input_mut};
use crate::MetaState;
use ble::hci::{HciIsoDataPkt, parameter::IsoPacketBoundaryFlag};
use libafl::{
    mutators::{MutationResult, Mutator},
    state::HasRand,
};
use libafl_bolts::rands::Rand;

impl<'a> MetaMutator<'a> {
    pub(super) fn mutate_iso_packet(&mut self, state: &mut MetaState, pkt: &mut HciIsoDataPkt) -> Result<MutationResult, libafl::Error> {
        let mut mutated = false;

        if self.prob(state, 40) {
            const PB_CANDIDATES: [IsoPacketBoundaryFlag; 4] = [
                IsoPacketBoundaryFlag::FirstFragment,
                IsoPacketBoundaryFlag::ContinuationFragment,
                IsoPacketBoundaryFlag::Complete,
                IsoPacketBoundaryFlag::LastFragment,
            ];
            let candidate = PB_CANDIDATES[state.rand_mut().between(0, PB_CANDIDATES.len() - 1)].clone();
            if candidate != pkt.packet_boundary_flag {
                pkt.packet_boundary_flag = candidate;
                mutated = true;
            }
        }

        if self.prob(state, 20) {
            let candidate = if pkt.time_stamp_flag == 0 { 1 } else { 0 };
            if candidate != pkt.time_stamp_flag {
                pkt.time_stamp_flag = candidate;
                mutated = true;
            }
        }

        if self.prob(state, 55) {
            let original_len = pkt.data.len();
            let target_len = if self.prob(state, 70) {
                // Bias toward short frames to stress header parsing states.
                state.rand_mut().between(0, 8)
            } else {
                state.rand_mut().between(0, 96)
            };
            pkt.data.truncate(target_len);
            while pkt.data.len() < target_len {
                pkt.data.push(state.rand_mut().between(0, 255) as u8);
            }
            if pkt.data.len() != original_len {
                mutated = true;
            }
        }

        if self.prob(state, 65) || !mutated {
            let input = vec_to_input_mut(&mut pkt.data);
            if MutationResult::Mutated == self.havoc_mutator.mutate(state, input)? {
                mutated = true;
            }
        }

        pkt.data_total_length = pkt.data.len() as u16;
        Ok(if mutated { MutationResult::Mutated } else { MutationResult::Skipped })
    }
}
