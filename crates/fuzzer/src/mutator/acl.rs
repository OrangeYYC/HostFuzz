use super::{MetaMutator, l2cap::UpperLayerType, vec_to_input_mut};
use crate::MetaState;
use ble::hci::HciAclDataPkt;
use libafl::{inputs::HasMutatorBytes, mutators::MutationResult};
use libafl_core::HasLen;

impl<'a> MetaMutator<'a> {
    /// Mutates HCI ACL packets
    pub(super) fn mutate_acl_packet(&mut self, state: &mut MetaState, pkt: &mut HciAclDataPkt) -> Result<MutationResult, libafl::Error> {
        match Self::get_upper_layer_type(pkt) {
            UpperLayerType::Att => {
                // let read_by_type_rsp_stress_pkt = self.read_by_type_rsp_stress_active && Self::is_read_by_type_rsp_acl(pkt);
                let mut result = MutationResult::Skipped;
                {
                    let input = vec_to_input_mut(&mut pkt.data);
                    let ret = if self.prob(state, 80) {
                        self.mutate_att_packet(state, &mut input.sub_input(4..))?
                    } else {
                        self.mutate_l2cap_packet(state, input)?
                    };
                    if ret == MutationResult::Mutated {
                        result = MutationResult::Mutated;
                    }
                    let new_length: u16 = input.len().saturating_sub(4) as u16;
                    input.mutator_bytes_mut()[0..2].copy_from_slice(&new_length.to_le_bytes());
                    pkt.data_total_length = input.len() as u16;
                }
                Ok(result)
            }
            UpperLayerType::Sm => {
                let input = vec_to_input_mut(&mut pkt.data);
                if self.prob(state, 20) {
                    self.mutate_l2cap_packet(state, input)
                } else {
                    self.mutate_sm_packet(state, &mut input.sub_input(4..))
                }
            }
            UpperLayerType::L2cap | UpperLayerType::Sig => {
                let input = vec_to_input_mut(&mut pkt.data);
                self.mutate_l2cap_packet(state, input)
            }
            UpperLayerType::Unknown => Ok(MutationResult::Skipped),
        }
    }
}
