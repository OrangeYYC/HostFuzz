use super::MetaMutator;
use crate::MetaState;
use libafl::{
    inputs::{BytesInput, BytesSubInput, HasMutatorBytes},
    mutators::{MutationResult, Mutator},
    state::HasRand,
};
use libafl_bolts::rands::Rand;
use libafl_core::HasLen;

impl<'a> MetaMutator<'a> {
    const SM_OP_MAPS: [u8; 15] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x10];

    #[inline]
    fn is_pairing_handshake_opcode(op: u8) -> bool {
        matches!(op, 0x01 | 0x02 | 0x03 | 0x04)
    }

    fn sm_expected_payload_len(opcode: u8) -> Option<usize> {
        match opcode {
            0x01 | 0x02 => Some(6),
            0x03 | 0x04 | 0x06 | 0x08 | 0x0A => Some(16),
            0x05 => Some(1),
            0x07 => Some(10),
            0x09 => Some(7),
            _ => None,
        }
    }

    fn mutate_sm_profile_aware<'b>(&mut self, state: &mut MetaState, sm_packet: &mut BytesSubInput<'b, BytesInput>) -> Result<MutationResult, libafl::Error> {
        if sm_packet.is_empty() {
            return Ok(MutationResult::Skipped);
        }

        let runtime = self.runtime_profile();
        let opcode_candidates: &[u8] = if runtime.pairing_completed {
            &[0x05, 0x06, 0x07, 0x08, 0x09, 0x0A]
        } else if runtime.pairing_started {
            &[0x01, 0x02, 0x03, 0x04, 0x05]
        } else {
            &[0x01, 0x02, 0x03, 0x04]
        };

        let mut mutated = false;
        if self.prob(state, 65) {
            let new_opcode = opcode_candidates[state.rand_mut().between(0, opcode_candidates.len() - 1)];
            if sm_packet.mutator_bytes()[0] != new_opcode {
                sm_packet.mutator_bytes_mut()[0] = new_opcode;
                mutated = true;
            }
        }

        let opcode = sm_packet.mutator_bytes()[0];
        if let Some(expected_payload_len) = Self::sm_expected_payload_len(opcode) {
            let current_payload_len = sm_packet.len().saturating_sub(1);
            if current_payload_len > expected_payload_len {
                for byte in sm_packet.mutator_bytes_mut()[(expected_payload_len + 1)..].iter_mut() {
                    if *byte != 0 {
                        *byte = 0;
                        mutated = true;
                    }
                }
            }
        }

        if sm_packet.len() > 1 {
            match sm_packet.mutator_bytes()[0] {
                0x01 | 0x02 => {
                    let bytes = sm_packet.mutator_bytes_mut();
                    bytes[1] = 0x03;
                    bytes[2] = 0x00;
                    if runtime.pairing_completed {
                        bytes[3] = 0x01;
                    } else if runtime.pairing_started {
                        bytes[3] |= 0x01;
                    }
                    bytes[4] = 0x10;
                    mutated = true;
                }
                0x05 => {
                    let reasons = [0x03u8, 0x05, 0x08, 0x0A];
                    let next = reasons[state.rand_mut().between(0, reasons.len() - 1)];
                    if sm_packet.mutator_bytes()[1] != next {
                        sm_packet.mutator_bytes_mut()[1] = next;
                        mutated = true;
                    }
                }
                _ => {
                    let mut sm_payload = sm_packet.sub_input(1..);
                    if MutationResult::Mutated == self.havoc_mutator.mutate(state, &mut sm_payload)? {
                        mutated = true;
                    }
                }
            }
        }

        if mutated { Ok(MutationResult::Mutated) } else { Ok(MutationResult::Skipped) }
    }

    /// mutates the SM packet
    pub(super) fn mutate_sm_packet<'b>(
        &mut self,
        state: &mut MetaState,
        sm_packet: &mut BytesSubInput<'b, BytesInput>,
    ) -> Result<MutationResult, libafl::Error> {
        if sm_packet.is_empty() {
            return Ok(MutationResult::Skipped);
        }

        let sm_opcode = sm_packet.mutator_bytes()[0];
        // Keep SMP pairing handshake stable after the run has already entered
        // scan/advertising/connection states, otherwise many runs stop at pairing.
        if self.preserve_sm_pairing_handshake && Self::is_pairing_handshake_opcode(sm_opcode) {
            // Rarely perturb one payload bit to keep slight exploration.
            if sm_packet.len() > 1 && self.prob(state, 3) {
                let idx = state.rand_mut().between(1, sm_packet.len() - 1);
                let bit = state.rand_mut().between(0, 7);
                sm_packet.mutator_bytes_mut()[idx] ^= 1u8 << bit;
                return Ok(MutationResult::Mutated);
            }
            return Ok(MutationResult::Skipped);
        }

        let mut has_mutate = MutationResult::Skipped;
        let runtime = self.runtime_profile();
        let has_semantic_context = self.has_runtime_semantic_context();
        let profile_aware_prob = if runtime.pairing_completed {
            55
        } else if runtime.pairing_started || has_semantic_context {
            75
        } else {
            25
        };
        if self.profile_aware_mutation_enabled()
            && self.prob(state, profile_aware_prob)
            && MutationResult::Mutated == self.mutate_sm_profile_aware(state, sm_packet)?
        {
            has_mutate = MutationResult::Mutated;
            let profile_only_prob = if runtime.pairing_completed {
                0
            } else if runtime.pairing_started {
                35
            } else {
                20
            };
            if has_semantic_context && self.prob(state, profile_only_prob) {
                return Ok(has_mutate);
            }
        }
        // (30%) mutate SM opcode
        if self.prob(state, 30) {
            let new_sm_op = Self::SM_OP_MAPS[state.rand_mut().between(0, Self::SM_OP_MAPS.len() - 1)];
            if sm_packet.mutator_bytes()[0] != new_sm_op {
                sm_packet.mutator_bytes_mut()[0] = new_sm_op;
                has_mutate = MutationResult::Mutated;
            }
        }
        // mutate SM payload
        let mut sm_payload = sm_packet.sub_input(1..);
        if MutationResult::Mutated == self.havoc_mutator.mutate(state, &mut sm_payload)? {
            has_mutate = MutationResult::Mutated;
        }
        Ok(has_mutate)
    }
}
