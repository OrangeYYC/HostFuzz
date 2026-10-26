use tracing::{debug, warn};

use crate::{
    LeCreditSemanticAction, Simulator, SimulatorError,
    entity::{att::AttEntity, ots, smp::SmpEntity},
};
use ble::{
    hci::{
        HciAclDataPkt,
        parameter::{AddrKind, BdAddr, Duration},
    },
    l2cap::{
        L2capBframeDecoder, L2capCframeDecoder, L2capConnectionParameterUpdateReq, L2capConnectionParameterUpdateRsp, L2capDisconnectionReq,
        L2capDisconnectionRsp, L2capInformationPayload, L2capLeCreditBasedConnectionReq, L2capLeCreditBasedConnectionRsp, L2capLeFlowControlCreditInd,
    },
};

#[derive(Debug, Clone)]
struct LeCocChannel {
    /// Local endpoint CID allocated by simulator and used as destination CID by peer.
    local_cid: u16,
    /// Remote endpoint CID announced by peer in LE Credit Based Connection Request.
    peer_cid: u16,
    /// True when this channel should be handled as OTS CoC.
    is_ots: bool,
    /// Remaining peer->local credits (credits we granted to peer).
    local_credits: u16,
    /// Remaining local->peer credits (credits peer granted to us).
    peer_credits: u16,
    /// Peer Maximum PDU Size from connection request.
    mps: u16,
    /// Peer MTU from connection request/response.
    mtu: u16,
    /// Rolling sequence used to synthesize stream payloads.
    stream_tx_seq: u32,
    /// Current position inside the configured semantic probe sequence.
    semantic_probe_stage: usize,
    /// Tracks whether a P3-only semantic probe has been sent on this channel and is waiting
    /// for a peer-side follow-up signal (data or credit update).
    semantic_probe_inflight: bool,
    /// Pending inbound SDU length when the peer fragmented a CoC SDU across LE frames.
    rx_expected_sdu_len: Option<usize>,
    /// Reassembly buffer for inbound CoC SDU fragments.
    rx_sdu_buf: Vec<u8>,
}

/// Simulates a BLE device with L2CAP layer.
pub struct L2capEntity<'a> {
    simulator: &'a Simulator,
    pub addr: BdAddr,
    pub addr_type: AddrKind,
    conn_handle: u16,
    att_entity: AttEntity<'a>,
    smp_entity: SmpEntity<'a>,
    host_role_is_central: bool,
    mirror_gatt_write_cmd: bool,
    pending_att_bootstrap: bool,
    post_pairing_att_refresh_done: bool,
    idle_probe_ticks: u8,
    le_coc_channels: Vec<LeCocChannel>,
    next_signal_identifier: u8,
    pending_le_coc_local: Option<(u16, u16)>,
}

impl<'a> L2capEntity<'a> {
    // Attribute Protocol
    pub const CID_ATT: u16 = 0x0004;
    // L2CAP LE Signaling channel
    pub const CID_SIG: u16 = 0x0005;
    // Security Manager protocol
    pub const CID_SM: u16 = 0x0006;
    // Start of dynamically allocated channel
    pub const CID_DYN_START: u16 = 0x0040;
    // End of the dynamically allocated channel
    pub const CID_DYN_END: u16 = 0x007F;
    pub fn new(
        simulator: &'a Simulator,
        addr: BdAddr,
        addr_type: AddrKind,
        conn_handle: u16,
        local_addr: BdAddr,
        local_addr_type: AddrKind,
        host_role_is_central: bool,
    ) -> Self {
        Self {
            simulator,
            addr: addr.clone(),
            addr_type: addr_type.clone(),
            conn_handle,
            att_entity: AttEntity::new(simulator, conn_handle),
            smp_entity: SmpEntity::new(simulator, conn_handle, addr, addr_type, local_addr, local_addr_type, host_role_is_central),
            host_role_is_central,
            // In the central_gatt_write/peripheral_gatt_write pair, the peer continuously sends
            // ATT Write Command(handle=0x0001). We mirror that behavior when host is central.
            mirror_gatt_write_cmd: host_role_is_central,
            pending_att_bootstrap: false,
            post_pairing_att_refresh_done: false,
            idle_probe_ticks: 0,
            le_coc_channels: Vec::new(),
            next_signal_identifier: 1,
            pending_le_coc_local: None,
        }
    }

    pub fn handle_acl_data_pkt(&mut self, packet: &HciAclDataPkt) -> Result<(), SimulatorError> {
        let decoder = L2capBframeDecoder::new(packet)?;
        let channel_id = decoder.channel_id();
        let ret = match channel_id {
            Self::CID_ATT => {
                self.att_entity.on_att_raw(decoder.payload())?;
                self.try_send_pending_oacp_read_data()
            }
            Self::CID_SIG => self.on_l2cap_cframe(packet),
            Self::CID_SM => self.smp_entity.on_sm_packet(decoder.payload()),
            Self::CID_DYN_START..=Self::CID_DYN_END => self.on_le_coc_data(decoder.channel_id(), decoder.payload()),
            _ => {
                debug!("Peer[{}]: handle acl data packet: {:?}", self.addr, packet);
                warn!("Peer[{}]: invalid channel ID: {}", self.addr, decoder.channel_id());
                Ok(())
            }
        };

        if ret.is_ok() && self.pending_att_bootstrap {
            if matches!(
                channel_id,
                Self::CID_ATT | Self::CID_SIG | Self::CID_SM | Self::CID_DYN_START..=Self::CID_DYN_END
            ) {
                self.pending_att_bootstrap = false;
                self.att_entity.initiate_interact();
            }
        }

        if ret.is_ok() && channel_id == Self::CID_ATT {
            self.idle_probe_ticks = 0;
        }

        if ret.is_ok()
            && channel_id == Self::CID_ATT
            && self.mirror_gatt_write_cmd
            && self.simulator.ablation_flags().enable_peer_interaction_pipeline
            && !self.simulator.le_credit_config().suppress_att_interact
        {
            self.att_entity.send_stream_write_cmd()?;
        }

        ret
    }

    /// Initiates the interaction with the target.
    pub fn initiate_interact(&mut self) {
        if !self.simulator.ablation_flags().enable_peer_interaction_pipeline {
            self.pending_att_bootstrap = false;
            return;
        }
        self.idle_probe_ticks = 0;
        self.smp_entity.initiate_interact();
        let le_cfg = self.simulator.le_credit_config();
        if le_cfg.enabled && self.host_role_is_central {
            // LE Credit client demos initialize SM but won't actively start pairing.
            // Request pairing from the peer side to drive additional SM/HCI branches.
            self.smp_entity.force_pairing_request();
            if let Err(err) = self.send_connection_parameter_update_req() {
                warn!("Peer[{}]: failed to send connection parameter update req: {:?}", self.addr, err);
            }
        }
        if le_cfg.enabled && le_cfg.auto_open_as_client && !self.host_role_is_central {
            if let Err(err) = self.send_le_credit_connection_req() {
                warn!("Peer[{}]: failed to bootstrap LE CoC: {:?}", self.addr, err);
            }
        }
        if !(le_cfg.enabled && le_cfg.suppress_att_interact) {
            if self.host_role_is_central {
                self.pending_att_bootstrap = false;
                self.att_entity.initiate_interact();
            } else if self.simulator.ablation_flags().enable_semantic_probe_generation {
                self.pending_att_bootstrap = false;
                self.att_entity.initiate_interact();
            } else {
                self.pending_att_bootstrap = true;
            }
        } else {
            self.pending_att_bootstrap = false;
        }
    }

    /// Keep peer-side ATT ingress exploration alive on idle timeouts for server-style targets.
    pub fn on_idle_tick(&mut self) -> bool {
        const MAX_IDLE_PROBE_TICKS: u8 = 2;

        if self.host_role_is_central {
            return false;
        }
        if !self.simulator.ablation_flags().enable_peer_interaction_pipeline {
            return false;
        }
        if self.idle_probe_ticks >= MAX_IDLE_PROBE_TICKS {
            return false;
        }

        match self.att_entity.on_idle_tick() {
            Ok(sent) => {
                if sent {
                    self.idle_probe_ticks = self.idle_probe_ticks.saturating_add(1);
                }
                sent
            }
            Err(err) => {
                warn!("Peer[{}]: idle ATT probe failed: {:?}", self.addr, err);
                false
            }
        }
    }

    /// Sends responder key distribution packets after link encryption is enabled.
    pub fn on_smp_encrypted(&mut self) {
        self.smp_entity.on_link_encrypted();
        if self.post_pairing_att_refresh_done {
            return;
        }
        if self.simulator.le_credit_config().suppress_att_interact {
            return;
        }
        if !self.simulator.ablation_flags().enable_semantic_probe_generation {
            return;
        }

        self.post_pairing_att_refresh_done = true;
        self.pending_att_bootstrap = false;
        if let Err(err) = self.att_entity.restart_after_security_refresh() {
            warn!("Peer[{}]: failed to restart ATT discovery after pairing completed: {:?}", self.addr, err);
        }
    }

    fn on_l2cap_cframe(&mut self, packet: &HciAclDataPkt) -> Result<(), SimulatorError> {
        let cframe_decoder = L2capCframeDecoder::new(packet)?;
        let info = match cframe_decoder.information_payload() {
            Ok(info) => info,
            Err(err) => {
                warn!("Peer[{}]: failed to parse L2CAP signaling packet: {:?}", self.addr, err);
                return Ok(());
            }
        };
        match &info {
            L2capInformationPayload::ConnectionParameterUpdateReq(req) => self.on_l2cap_connection_parameter_update_req(req),
            L2capInformationPayload::LeCreditBasedConnectionReq(req) => self.on_l2cap_le_credit_based_connection_req(req),
            L2capInformationPayload::LeCreditBasedConnectionRsp(rsp) => self.on_l2cap_le_credit_based_connection_rsp(rsp),
            L2capInformationPayload::LeFlowControlCreditInd(ind) => self.on_l2cap_le_flow_control_credit_ind(ind),
            L2capInformationPayload::DisconnectionReq(req) => self.on_l2cap_disconnection_req(req),
            L2capInformationPayload::DisconnectionRsp(_)
            | L2capInformationPayload::ConnectionParameterUpdateRsp(_)
            | L2capInformationPayload::CommandRejectRsp(_) => Ok(()),
            pkt => {
                warn!("Peer[{}]: unhandled L2CAP LE Signaling channel packet: {:?}", self.addr, pkt);
                Ok(())
            }
        }
    }

    fn on_l2cap_connection_parameter_update_req(&self, req: &L2capConnectionParameterUpdateReq) -> Result<(), SimulatorError> {
        debug!("[L2CAP REQ] connection parameter update request (L2CAP_CONNECTION_PARAMETER_UPDATE_REQ)",);
        debug!(
            "   in: id={:02x} interval_min={} interval_max={} lantency={} timeout={}",
            req.identifier, req.interval_min, req.interval_max, req.latency, req.timeout
        );
        debug!("  out: id={:02x} result={}", req.identifier, 0x0000);

        let rsp = L2capInformationPayload::ConnectionParameterUpdateRsp(L2capConnectionParameterUpdateRsp {
            identifier: req.identifier,
            data_length: 0x0002,
            result: 0x0000,
        });
        self.simulator.send_l2cap_cframe(self.conn_handle, Self::CID_SIG, rsp)?;
        Ok(())
    }

    fn send_connection_parameter_update_req(&mut self) -> Result<(), SimulatorError> {
        let req = L2capInformationPayload::ConnectionParameterUpdateReq(L2capConnectionParameterUpdateReq {
            identifier: self.next_signal_identifier(),
            data_length: 0x0008,
            interval_min: Duration::<1_250>(12),
            interval_max: Duration::<1_250>(24),
            latency: 0,
            timeout: Duration::<10_000>(200),
        });
        self.simulator.send_l2cap_cframe(self.conn_handle, Self::CID_SIG, req)?;
        Ok(())
    }

    fn on_l2cap_le_credit_based_connection_req(&mut self, req: &L2capLeCreditBasedConnectionReq) -> Result<(), SimulatorError> {
        debug!("[L2CAP REQ] LE credit based connection request (L2CAP_LE_CREDIT_BASED_CONNECTION_REQ)");
        debug!(
            "   in: id={:02x} spsm=0x{:04x} source_cid=0x{:04x} mtu={} mps={} initial_credits={}",
            req.identifier, req.spsm, req.source_cid, req.mtu, req.mps, req.initial_credits
        );

        let le_cfg = self.simulator.le_credit_config();
        let mut destination_cid = 0x0000;
        let mut result = 0x0002; // SPSM not supported
        let mut rsp_mtu = req.mtu;
        let mut rsp_mps = req.mps;
        let is_le_credit_profile = le_cfg.enabled && req.spsm == le_cfg.psm;
        let is_ots_channel = self.is_ots_channel(req.spsm);
        let is_generic_dynamic_psm = self.is_generic_dynamic_psm(req.spsm);
        let mut local_initial_credits = if is_le_credit_profile {
            le_cfg.initial_credits
        } else {
            ots::LE_COC_INITIAL_CREDITS
        };
        let supported_spsm = is_ots_channel || is_le_credit_profile || is_generic_dynamic_psm;
        if supported_spsm {
            if is_le_credit_profile {
                rsp_mtu = req.mtu.min(le_cfg.mtu);
                rsp_mps = req.mps.min(le_cfg.mps);
                local_initial_credits = le_cfg.initial_credits;
            } else if is_generic_dynamic_psm {
                // Keep dynamic CoC profiles interoperable even without explicit SPSM config.
                // Clamp ranges to avoid unrealistic values while preserving host intent.
                rsp_mtu = req.mtu.clamp(64, 1024);
                // Prefer minimum valid MPS for generic stress so RX reassembly paths use
                // many continuation fragments without violating MTU constraints.
                rsp_mps = 23;
                local_initial_credits = ots::LE_COC_INITIAL_CREDITS.max(8);
            }
            if let Some(local_cid) = self.allocate_dynamic_cid(req.source_cid) {
                destination_cid = local_cid;
                result = 0x0000; // success
                self.le_coc_channels.push(LeCocChannel {
                    local_cid,
                    peer_cid: req.source_cid,
                    is_ots: is_ots_channel,
                    local_credits: local_initial_credits,
                    peer_credits: req.initial_credits,
                    mps: rsp_mps,
                    mtu: rsp_mtu,
                    stream_tx_seq: 0,
                    semantic_probe_stage: 0,
                    semantic_probe_inflight: false,
                    rx_expected_sdu_len: None,
                    rx_sdu_buf: Vec::new(),
                });
                self.simulator
                    .note_le_credit_context(req.spsm, rsp_mtu, rsp_mps, local_initial_credits, Some(req.source_cid));
            } else {
                result = 0x0004; // no resources available
            }
        }

        debug!(
            "  out: id={:02x} destination_cid=0x{:04x} result=0x{:04x}",
            req.identifier, destination_cid, result
        );
        let rsp = L2capInformationPayload::LeCreditBasedConnectionRsp(L2capLeCreditBasedConnectionRsp {
            identifier: req.identifier,
            data_length: 0x000A,
            destination_cid,
            mtu: rsp_mtu,
            mps: rsp_mps,
            initial_credits: local_initial_credits,
            result,
        });
        self.simulator.send_l2cap_cframe(self.conn_handle, Self::CID_SIG, rsp)?;
        if result == 0x0000 && self.simulator.le_credit_config().auto_stream_after_open {
            // Proactively top up peer credits right after channel open so client-side
            // request_can_send_now paths can progress immediately.
            let ind = L2capInformationPayload::LeFlowControlCreditInd(L2capLeFlowControlCreditInd {
                identifier: self.next_signal_identifier(),
                data_length: 0x0004,
                cid: req.source_cid,
                credits: 8,
            });
            self.simulator.send_l2cap_cframe(self.conn_handle, Self::CID_SIG, ind)?;
            self.try_send_le_credit_stream_data()?;
        }
        if result == 0x0000 && self.simulator.ablation_flags().enable_semantic_probe_generation {
            // In full mode, keep non-OTS CoC channels active with controller->host traffic.
            self.try_send_le_credit_stream_data()?;
            // Opportunistically open a reverse CoC channel on the same SPSM to increase
            // bidirectional coverage pressure without relying on case-specific profiles.
            let active_non_ots = self.le_coc_channels.iter().filter(|chan| !chan.is_ots).count();
            if !is_ots_channel && active_non_ots < 2 && self.pending_le_coc_local.is_none() {
                let reverse_mtu = rsp_mtu.clamp(64, 512);
                let reverse_mps = rsp_mps.clamp(23, 64);
                let reverse_credits = local_initial_credits.clamp(4, 32);
                if let Err(err) = self.send_le_credit_connection_req_with_params(req.spsm, reverse_mtu, reverse_mps, reverse_credits) {
                    warn!("Peer[{}]: failed to bootstrap reverse LE CoC req: {:?}", self.addr, err);
                }
            }
        }
        self.try_send_le_credit_semantic_probe()?;
        Ok(())
    }

    fn on_l2cap_le_credit_based_connection_rsp(&mut self, rsp: &L2capLeCreditBasedConnectionRsp) -> Result<(), SimulatorError> {
        debug!("[L2CAP RSP] LE credit based connection response (L2CAP_LE_CREDIT_BASED_CONNECTION_RSP)");
        debug!(
            "   in: id={:02x} destination_cid=0x{:04x} mtu={} mps={} initial_credits={} result=0x{:04x}",
            rsp.identifier, rsp.destination_cid, rsp.mtu, rsp.mps, rsp.initial_credits, rsp.result
        );

        let Some((local_cid, psm)) = self.pending_le_coc_local.take() else {
            return Ok(());
        };

        if rsp.result == 0x0000 && rsp.destination_cid != 0x0000 {
            let is_ots_channel = self.is_ots_channel(psm);
            let local_initial_credits = if is_ots_channel {
                ots::LE_COC_INITIAL_CREDITS
            } else {
                self.simulator.le_credit_config().initial_credits
            };
            self.le_coc_channels.retain(|c| c.local_cid != local_cid);
            self.le_coc_channels.push(LeCocChannel {
                local_cid,
                peer_cid: rsp.destination_cid,
                is_ots: is_ots_channel,
                local_credits: local_initial_credits,
                peer_credits: rsp.initial_credits,
                mps: rsp.mps,
                mtu: rsp.mtu,
                stream_tx_seq: 0,
                semantic_probe_stage: 0,
                semantic_probe_inflight: false,
                rx_expected_sdu_len: None,
                rx_sdu_buf: Vec::new(),
            });
            self.simulator
                .note_le_credit_context(psm, rsp.mtu, rsp.mps, rsp.initial_credits, Some(rsp.destination_cid));
            self.try_send_le_credit_stream_data()?;
            self.try_send_le_credit_semantic_probe()?;
        }
        Ok(())
    }

    fn on_l2cap_le_flow_control_credit_ind(&mut self, ind: &L2capLeFlowControlCreditInd) -> Result<(), SimulatorError> {
        debug!("[L2CAP IND] LE flow control credit indication (L2CAP_LE_FLOW_CONTROL_CREDIT_IND)");
        debug!("   in: id={:02x} cid=0x{:04x} credits={}", ind.identifier, ind.cid, ind.credits);
        // Peer implementations are not always consistent about whether this CID maps to
        // our local endpoint or the peer endpoint. Accept both so credit flow is robust
        // across host/client role combinations.
        if let Some(chan) = self.le_coc_channels.iter_mut().find(|c| c.local_cid == ind.cid || c.peer_cid == ind.cid) {
            chan.peer_credits = chan.peer_credits.saturating_add(ind.credits);
            if chan.semantic_probe_inflight {
                chan.semantic_probe_inflight = false;
                self.simulator.telemetry_mark_semantic_probe_success();
            }
        } else {
            warn!("Peer[{}]: credit indication for unknown CID 0x{:04x}", self.addr, ind.cid);
        }
        self.try_send_le_credit_stream_data()?;
        self.try_send_le_credit_semantic_probe()?;
        Ok(())
    }

    fn on_l2cap_disconnection_req(&mut self, req: &L2capDisconnectionReq) -> Result<(), SimulatorError> {
        debug!("[L2CAP REQ] disconnection request (L2CAP_DISCONNECTION_REQ)");
        debug!(
            "   in: id={:02x} destination_cid=0x{:04x} source_cid=0x{:04x}",
            req.identifier, req.destination_cid, req.source_cid
        );

        let mut removed_ots_channel = false;
        self.le_coc_channels.retain(|chan| {
            let should_remove = (chan.local_cid == req.destination_cid && chan.peer_cid == req.source_cid)
                || (chan.local_cid == req.source_cid && chan.peer_cid == req.destination_cid);
            if should_remove && chan.is_ots {
                removed_ots_channel = true;
            }
            !should_remove
        });
        if removed_ots_channel {
            self.att_entity.on_oacp_coc_disconnected();
        }

        let rsp = L2capInformationPayload::DisconnectionRsp(L2capDisconnectionRsp {
            identifier: req.identifier,
            data_length: 0x0004,
            destination_cid: req.destination_cid,
            source_cid: req.source_cid,
        });
        self.simulator.send_l2cap_cframe(self.conn_handle, Self::CID_SIG, rsp)?;
        Ok(())
    }

    fn send_le_credit_connection_req(&mut self) -> Result<(), SimulatorError> {
        let cfg = self.simulator.le_credit_config();
        if !cfg.enabled || self.pending_le_coc_local.is_some() || self.le_coc_channels.iter().any(|c| c.peer_cid != 0) {
            return Ok(());
        }

        self.send_le_credit_connection_req_with_params(cfg.psm, cfg.mtu, cfg.mps, cfg.initial_credits)
    }

    fn send_le_credit_connection_req_with_params(&mut self, psm: u16, mtu: u16, mps: u16, initial_credits: u16) -> Result<(), SimulatorError> {
        if self.pending_le_coc_local.is_some() {
            return Ok(());
        }

        let Some(source_cid) = self.allocate_dynamic_cid(0xFFFF) else {
            return Ok(());
        };
        let identifier = self.next_signal_identifier();
        self.pending_le_coc_local = Some((source_cid, psm));
        let req = L2capInformationPayload::LeCreditBasedConnectionReq(L2capLeCreditBasedConnectionReq {
            identifier,
            data_length: 0x000A,
            spsm: psm,
            source_cid,
            mtu,
            mps,
            initial_credits,
        });
        self.simulator.send_l2cap_cframe(self.conn_handle, Self::CID_SIG, req)?;
        Ok(())
    }

    fn try_send_le_credit_stream_data(&mut self) -> Result<(), SimulatorError> {
        let cfg = self.simulator.le_credit_config();
        let semantic_mode = self.simulator.ablation_flags().enable_semantic_probe_generation;
        let stream_enabled = (cfg.enabled && cfg.auto_stream_after_open) || semantic_mode;
        if !stream_enabled {
            return Ok(());
        }
        let Some(chan_idx) = self.le_coc_channels.iter().position(|c| !c.is_ots && c.peer_credits > 0) else {
            return Ok(());
        };

        let peer_cid = self.le_coc_channels[chan_idx].peer_cid;
        let mut remaining_credits = self.le_coc_channels[chan_idx].peer_credits;
        let mps = self.le_coc_channels[chan_idx].mps.max(3);
        let mtu = self.le_coc_channels[chan_idx].mtu.max(mps);
        let mut seq = self.le_coc_channels[chan_idx].stream_tx_seq;
        let first_payload_limit = usize::from(mps).saturating_sub(2).max(1);
        let desired_payload = usize::from(cfg.stream_payload_len.max(mps));
        // Keep SDU larger than the first-frame payload budget so RX reassembly paths are exercised.
        let max_payload = desired_payload.clamp(first_payload_limit.saturating_add(1), usize::from(mtu));
        let burst_limit = cfg.stream_packets_per_burst.max(1);
        let mut to_send = if semantic_mode {
            burst_limit.saturating_add((burst_limit / 2).max(1))
        } else {
            burst_limit
        };
        while to_send > 0 && remaining_credits > 0 {
            // Keep SDUs MTU-safe but periodically pin to MTU to maximize fragment count.
            let payload_len = if semantic_mode && seq % 3 == 0 { usize::from(mtu) } else { max_payload };
            let mut payload = vec![0u8; payload_len];
            for (i, byte) in payload.iter_mut().enumerate() {
                *byte = seq.wrapping_add(i as u32) as u8;
            }

            let sent_frames = self.send_le_coc_sdu(peer_cid, mps, remaining_credits, &payload, false)?;
            if sent_frames == 0 {
                break;
            }

            seq = seq.wrapping_add(1);
            remaining_credits = remaining_credits.saturating_sub(sent_frames);
            to_send -= 1;
        }
        if let Some(chan_mut) = self.le_coc_channels.get_mut(chan_idx) {
            chan_mut.peer_credits = remaining_credits;
            chan_mut.stream_tx_seq = seq;
        }
        Ok(())
    }

    fn try_send_le_credit_semantic_probe(&mut self) -> Result<(), SimulatorError> {
        if !self.simulator.ablation_flags().enable_semantic_probe_generation {
            return Ok(());
        }

        const DEFAULT_SEMANTIC_SEQUENCE: [LeCreditSemanticAction; 6] = [
            LeCreditSemanticAction::ValidSmallSdu,
            LeCreditSemanticAction::ValidMtuSdu,
            LeCreditSemanticAction::OversizedSdu,
            LeCreditSemanticAction::OversizedFragment,
            LeCreditSemanticAction::CreditRefillSmall,
            LeCreditSemanticAction::CreditOverrun,
        ];

        let burst_limit = usize::from(self.simulator.le_credit_config().semantic_probe_actions_per_trigger.max(1));
        for _ in 0..burst_limit {
            let semantic_sequence = &self.simulator.le_credit_config().semantic_probe_sequence;
            let custom_sequence = !semantic_sequence.is_empty();
            let Some(chan_idx) = self
                .le_coc_channels
                .iter()
                .position(|chan| !chan.is_ots && chan.peer_cid != 0 && !chan.semantic_probe_inflight && (custom_sequence || chan.peer_credits > 0))
            else {
                break;
            };

            let peer_cid = self.le_coc_channels[chan_idx].peer_cid;
            let peer_credits = self.le_coc_channels[chan_idx].peer_credits;
            let mps = self.le_coc_channels[chan_idx].mps.max(3);
            let semantic_stage = self.le_coc_channels[chan_idx].semantic_probe_stage;
            let action = if custom_sequence {
                semantic_sequence[semantic_stage % semantic_sequence.len()].clone()
            } else {
                DEFAULT_SEMANTIC_SEQUENCE[semantic_stage % DEFAULT_SEMANTIC_SEQUENCE.len()].clone()
            };

            let mut probe_waits_for_ack = false;
            let sent_probe = match action {
                LeCreditSemanticAction::ValidSmallSdu | LeCreditSemanticAction::ValidMtuSdu => {
                    if peer_credits == 0 {
                        false
                    } else {
                        let mtu = self.le_coc_channels[chan_idx].mtu.max(1);
                        let seq = self.le_coc_channels[chan_idx].stream_tx_seq;
                        let payload_len = match action {
                            LeCreditSemanticAction::ValidSmallSdu => usize::from(mps).saturating_sub(2).clamp(8, 32),
                            LeCreditSemanticAction::ValidMtuSdu => usize::from(mtu),
                            _ => unreachable!(),
                        };
                        let payload = self.build_semantic_probe_payload(payload_len, seq);
                        let sent_frames = self.send_le_coc_sdu(peer_cid, mps, peer_credits, &payload, true)?;
                        if sent_frames == 0 {
                            false
                        } else {
                            if let Some(chan) = self.le_coc_channels.get_mut(chan_idx) {
                                chan.peer_credits = chan.peer_credits.saturating_sub(sent_frames);
                                chan.stream_tx_seq = chan.stream_tx_seq.wrapping_add(1);
                                chan.semantic_probe_inflight = true;
                            }
                            probe_waits_for_ack = true;
                            true
                        }
                    }
                }
                LeCreditSemanticAction::OversizedSdu => {
                    if peer_credits == 0 {
                        false
                    } else {
                        let mtu = self.le_coc_channels[chan_idx].mtu.max(1);
                        let seq = self.le_coc_channels[chan_idx].stream_tx_seq;
                        // Keep this probe MTU-safe while allowing partial delivery under tight
                        // credits to extend reassembly lifetime.
                        let payload_len = usize::from(mtu).max(usize::from(mps).saturating_add(1));
                        let payload = self.build_semantic_probe_payload(payload_len, seq);
                        let sent_frames = self.send_le_coc_sdu(peer_cid, mps, peer_credits, &payload, false)?;
                        if sent_frames == 0 {
                            false
                        } else {
                            if let Some(chan) = self.le_coc_channels.get_mut(chan_idx) {
                                chan.peer_credits = chan.peer_credits.saturating_sub(sent_frames);
                                chan.stream_tx_seq = chan.stream_tx_seq.wrapping_add(1);
                            }
                            true
                        }
                    }
                }
                LeCreditSemanticAction::OversizedFragment => {
                    if peer_credits == 0 {
                        false
                    } else {
                        let seq = self.le_coc_channels[chan_idx].stream_tx_seq;
                        let mtu = self.le_coc_channels[chan_idx].mtu.max(1);
                        let first_payload_len = usize::from(mps).saturating_sub(2).max(1);
                        let declared_len = usize::from(mtu);
                        let mut first_frame = self.build_semantic_probe_payload(first_payload_len + 2, seq);
                        first_frame[0..2].copy_from_slice(&(declared_len as u16).to_le_bytes());
                        self.simulator.send_l2cap_bframe(self.conn_handle, peer_cid, first_frame)?;

                        let mut sent_frames = 1u16;
                        let mut remaining_credits = peer_credits.saturating_sub(1);
                        let continuation_budget = remaining_credits.min(6);
                        for frag_idx in 0..continuation_budget {
                            let frag_len = usize::from(mps).max(1);
                            let frag_seq = seq.wrapping_add(frag_idx as u32 + 1);
                            let frag = self.build_semantic_probe_payload(frag_len, frag_seq);
                            self.simulator.send_l2cap_bframe(self.conn_handle, peer_cid, frag)?;
                            sent_frames = sent_frames.saturating_add(1);
                            remaining_credits = remaining_credits.saturating_sub(1);
                            if remaining_credits == 0 {
                                break;
                            }
                        }
                        if let Some(chan) = self.le_coc_channels.get_mut(chan_idx) {
                            chan.peer_credits = chan.peer_credits.saturating_sub(sent_frames);
                            chan.stream_tx_seq = chan.stream_tx_seq.wrapping_add(1);
                        }
                        self.simulator.telemetry_mark_semantic_probe_success();
                        true
                    }
                }
                LeCreditSemanticAction::CreditRefillSmall | LeCreditSemanticAction::CreditRefillBurst | LeCreditSemanticAction::CreditOverrun => {
                    let credits = match action {
                        LeCreditSemanticAction::CreditRefillSmall => 1,
                        LeCreditSemanticAction::CreditRefillBurst => self.simulator.le_credit_config().initial_credits.max(8),
                        LeCreditSemanticAction::CreditOverrun => u16::MAX / 2,
                        _ => unreachable!(),
                    };
                    let ind = L2capInformationPayload::LeFlowControlCreditInd(L2capLeFlowControlCreditInd {
                        identifier: self.next_signal_identifier(),
                        data_length: 0x0004,
                        cid: peer_cid,
                        credits,
                    });
                    self.simulator.send_l2cap_cframe(self.conn_handle, Self::CID_SIG, ind)?;
                    self.simulator.telemetry_mark_semantic_probe_success();
                    true
                }
            };

            if !sent_probe {
                break;
            }

            if let Some(chan) = self.le_coc_channels.get_mut(chan_idx) {
                chan.semantic_probe_stage = chan.semantic_probe_stage.saturating_add(1);
                if !probe_waits_for_ack {
                    chan.semantic_probe_inflight = false;
                }
            }
            self.simulator.telemetry_mark_semantic_interaction_started();
            self.simulator.telemetry_mark_semantic_probe_sent();

            if probe_waits_for_ack {
                break;
            }
        }
        Ok(())
    }

    fn build_semantic_probe_payload(&self, payload_len: usize, seq: u32) -> Vec<u8> {
        let mut payload = Vec::with_capacity(payload_len.max(4));
        payload.extend_from_slice(b"VBLE");
        while payload.len() < payload_len {
            payload.push(seq.wrapping_add(payload.len() as u32) as u8);
        }
        payload
    }

    fn send_le_coc_sdu(&self, peer_cid: u16, mps: u16, available_credits: u16, sdu: &[u8], require_full_delivery: bool) -> Result<u16, SimulatorError> {
        let frame_payload_limit = usize::from(mps.max(3));
        let first_payload_limit = frame_payload_limit.saturating_sub(2).max(1);
        let remaining_after_first = sdu.len().saturating_sub(first_payload_limit);
        let continuation_frames = if remaining_after_first == 0 {
            0
        } else {
            remaining_after_first.div_ceil(frame_payload_limit)
        };
        let frames_needed = 1usize.saturating_add(continuation_frames);

        if require_full_delivery && usize::from(available_credits) < frames_needed {
            return Ok(0);
        }

        let frames_budget = usize::from(available_credits).min(frames_needed);
        if frames_budget == 0 {
            return Ok(0);
        }

        let first_len = sdu.len().min(first_payload_limit);
        let mut first_frame = Vec::with_capacity(first_len + 2);
        first_frame.extend_from_slice(&(sdu.len() as u16).to_le_bytes());
        first_frame.extend_from_slice(&sdu[..first_len]);
        self.simulator.send_l2cap_bframe(self.conn_handle, peer_cid, first_frame)?;

        let mut sent_frames = 1usize;
        let mut offset = first_len;
        while sent_frames < frames_budget && offset < sdu.len() {
            let chunk_len = (sdu.len() - offset).min(frame_payload_limit);
            self.simulator
                .send_l2cap_bframe(self.conn_handle, peer_cid, sdu[offset..offset + chunk_len].to_vec())?;
            offset += chunk_len;
            sent_frames += 1;
        }

        Ok(sent_frames as u16)
    }

    fn on_complete_le_coc_sdu(&mut self, channel_id: u16, is_ots: bool, sdu: &[u8]) -> Result<(), SimulatorError> {
        debug!("Peer[{}]: completed LE CoC SDU on cid=0x{:04x}, len={}", self.addr, channel_id, sdu.len());
        if is_ots {
            self.att_entity.on_oacp_write_sdu(sdu);
        }
        Ok(())
    }

    fn on_le_coc_data(&mut self, channel_id: u16, payload: &[u8]) -> Result<(), SimulatorError> {
        debug!(
            "Peer[{}]: handle LE CoC data on cid=0x{:04x}: {}",
            self.addr,
            channel_id,
            hex::encode_upper(payload)
        );

        let mut refill_peer_cid: Option<u16> = None;
        let mut channel_is_ots = false;
        let mut completed_sdu: Option<Vec<u8>> = None;
        if let Some(chan) = self.le_coc_channels.iter_mut().find(|c| c.local_cid == channel_id) {
            if chan.semantic_probe_inflight {
                chan.semantic_probe_inflight = false;
                self.simulator.telemetry_mark_semantic_probe_success();
            }
            if chan.local_credits > 0 {
                chan.local_credits -= 1;
            }
            if chan.local_credits <= 1 {
                chan.local_credits = chan.local_credits.saturating_add(ots::LE_COC_REFILL_CREDITS);
                refill_peer_cid = Some(chan.peer_cid);
            }
            channel_is_ots = chan.is_ots;

            if let Some(expected_len) = chan.rx_expected_sdu_len {
                let remaining = expected_len.saturating_sub(chan.rx_sdu_buf.len());
                if payload.len() > remaining {
                    warn!(
                        "Peer[{}]: LE CoC continuation larger than remaining SDU bytes (payload={} remaining={})",
                        self.addr,
                        payload.len(),
                        remaining
                    );
                }
                let take_len = payload.len().min(remaining);
                chan.rx_sdu_buf.extend_from_slice(&payload[..take_len]);
                if chan.rx_sdu_buf.len() == expected_len {
                    completed_sdu = Some(std::mem::take(&mut chan.rx_sdu_buf));
                    chan.rx_expected_sdu_len = None;
                }
            } else if payload.len() >= 2 {
                let declared_sdu_len = usize::from(u16::from_le_bytes([payload[0], payload[1]]));
                let actual_payload_len = payload.len().saturating_sub(2);
                if actual_payload_len > declared_sdu_len {
                    warn!(
                        "Peer[{}]: LE CoC first frame larger than declared SDU length (payload={} declared={})",
                        self.addr, actual_payload_len, declared_sdu_len
                    );
                }
                let take_len = actual_payload_len.min(declared_sdu_len);
                chan.rx_sdu_buf.clear();
                chan.rx_sdu_buf.extend_from_slice(&payload[2..2 + take_len]);
                if take_len == declared_sdu_len {
                    completed_sdu = Some(std::mem::take(&mut chan.rx_sdu_buf));
                    chan.rx_expected_sdu_len = None;
                } else {
                    chan.rx_expected_sdu_len = Some(declared_sdu_len);
                }
            } else {
                warn!(
                    "Peer[{}]: LE CoC fragment too short to start a new SDU on cid=0x{:04x} (len={})",
                    self.addr,
                    channel_id,
                    payload.len()
                );
            }
        } else {
            warn!("Peer[{}]: LE CoC data for unknown local CID 0x{:04x}", self.addr, channel_id);
        }

        if let Some(sdu) = completed_sdu.as_deref() {
            self.on_complete_le_coc_sdu(channel_id, channel_is_ots, sdu)?;
        }

        if let Some(peer_cid) = refill_peer_cid {
            let ind = L2capInformationPayload::LeFlowControlCreditInd(L2capLeFlowControlCreditInd {
                identifier: self.next_signal_identifier(),
                data_length: 0x0004,
                cid: peer_cid,
                credits: ots::LE_COC_REFILL_CREDITS,
            });
            self.simulator.send_l2cap_cframe(self.conn_handle, Self::CID_SIG, ind)?;
        }
        self.try_send_le_credit_stream_data()?;
        self.try_send_le_credit_semantic_probe()?;
        Ok(())
    }

    fn try_send_pending_oacp_read_data(&mut self) -> Result<(), SimulatorError> {
        let Some(chan_idx) = self.le_coc_channels.iter().position(|chan| chan.is_ots) else {
            return Ok(());
        };
        let chan = &self.le_coc_channels[chan_idx];
        let peer_cid = chan.peer_cid;
        let peer_credits = chan.peer_credits;
        let mps = chan.mps;
        if peer_credits == 0 {
            return Ok(());
        }

        let Some((offset, total_len)) = self.att_entity.take_ready_oacp_read() else {
            return Ok(());
        };

        // Mimic OTS read transfer via LE CoC after OACP indication confirmation.
        let max_len = usize::from(mps.max(3)) - 2;
        let data = self.att_entity.read_oacp_object_range(offset, total_len);
        let packets_sent = if data.len() <= max_len {
            self.send_le_coc_sdu(peer_cid, mps, peer_credits, &data, true)?
        } else {
            self.send_le_coc_sdu(peer_cid, mps, peer_credits, &data, true)?
        };
        if let Some(chan_mut) = self.le_coc_channels.get_mut(chan_idx) {
            chan_mut.peer_credits = chan_mut.peer_credits.saturating_sub(packets_sent);
        }
        Ok(())
    }

    fn is_ots_channel(&self, psm: u16) -> bool {
        let le_cfg = self.simulator.le_credit_config();
        psm == ots::OTS_PSM && !(le_cfg.enabled && psm == le_cfg.psm)
    }

    fn is_generic_dynamic_psm(&self, psm: u16) -> bool {
        // Static L2CAP fixed channels are below 0x0040. Accepting dynamic/application
        // SPSMs keeps CoC-based demos reachable without per-target SPSM whitelists.
        psm >= 0x0040
    }

    fn allocate_dynamic_cid(&self, peer_cid: u16) -> Option<u16> {
        (Self::CID_DYN_START..=Self::CID_DYN_END).find(|cid| {
            *cid != peer_cid && !self.le_coc_channels.iter().any(|ch| ch.local_cid == *cid) && !self.le_coc_channels.iter().any(|ch| ch.peer_cid == *cid)
        })
    }

    fn next_signal_identifier(&mut self) -> u8 {
        let id = self.next_signal_identifier;
        self.next_signal_identifier = self.next_signal_identifier.wrapping_add(1).max(1);
        id
    }
}
