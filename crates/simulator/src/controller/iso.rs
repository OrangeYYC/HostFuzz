use super::{Controller, ControllerError};
use ble::hci::{
    ControllerToHostPacket, HciIsoDataPkt,
    command::{LeAcceptCisParam, LeRejectCisParam, LeRemoveIsoPathParam, LeSetupIsoPathParam},
    event::{CommandCompleteEvent, LeCisEstablishedEvent, LeCisRequestEvent},
    parameter::{IsoPacketBoundaryFlag, LeEventMaskBit},
};
use rand::Rng;
use tracing::debug;

impl<'a> Controller<'a> {
    fn next_cis_handle_for_acl(&self, acl_handle: u16) -> u16 {
        let mut handle = (acl_handle.wrapping_add(0x40)) & 0x0FFF;
        if handle == 0 {
            handle = 1;
        }
        if self.connection_manager.get_connection(handle).is_some() {
            handle = (handle.wrapping_add(1)) & 0x0FFF;
            if handle == 0 {
                handle = 2;
            }
        }
        handle
    }

    pub(super) fn maybe_send_cis_request_for_acl(&mut self, acl_handle: u16) {
        if !self.iso_session.can_initiate_request() {
            return;
        }
        let le_mask_allows = self.should_emit_le_event(LeEventMaskBit::LeCisRequest);
        // Some hosts initialize ISO (e.g., via LE Set Host Feature / LE Read Buffer Size v2)
        // but do not explicitly enable LE CIS Request in the LE event mask. Keep CIS
        // progression alive once ISO init has happened.
        if !le_mask_allows && !self.iso_session.host_iso_initialized {
            return;
        }
        if !le_mask_allows {
            debug!("forcing LE CIS request event for acl_handle=0x{:04x} after host ISO init", acl_handle);
        }
        self.send_cis_request_for_acl_now(acl_handle);
    }

    pub(super) fn start_peer_interaction_for_acl(&mut self, acl_handle: u16) {
        if let Some(peer) = self.connection_manager.get_connection_mut(acl_handle) {
            peer.initiate_interact();
        }
    }

    fn send_cis_request_for_acl_now(&mut self, acl_handle: u16) {
        if !self.iso_session.can_initiate_request() {
            return;
        }
        let cis_handle = self.next_cis_handle_for_acl(acl_handle);
        self.iso_session.bind_pending_request(acl_handle, cis_handle);
        self.send_hci_event_packet(
            LeCisRequestEvent {
                acl_handle,
                cis_handle,
                cig_id: 0x00,
                cis_id: 0x00,
            }
            .into(),
        );
        self.start_peer_interaction_for_acl(acl_handle);
    }

    pub(super) fn maybe_send_gated_cis_request_on_acl_rx(&mut self, acl_handle: u16) -> bool {
        if !self.iso_session.can_initiate_request() {
            return false;
        }
        if !self.iso_session.take_gated_request_on_acl_rx(acl_handle) {
            return false;
        }
        debug!("releasing gated LE CIS request after host ACL rx: acl_handle=0x{:04x}", acl_handle);
        self.send_cis_request_for_acl_now(acl_handle);
        true
    }

    pub(super) fn maybe_send_gated_cis_request_on_idle(&mut self) -> bool {
        if !self.iso_session.can_initiate_request() {
            return false;
        }
        let Some(acl_handle) = self.iso_session.take_gated_request_on_idle_fallback(3) else {
            return false;
        };
        debug!("releasing gated LE CIS request via idle fallback: acl_handle=0x{:04x}", acl_handle);
        self.send_cis_request_for_acl_now(acl_handle);
        true
    }

    pub(super) fn maybe_send_iso_rx_probe_packet(&mut self) {
        let Some(stream) = self.iso_session.active_stream else {
            return;
        };
        if !stream.rx_path_ready {
            return;
        }

        // Generic robustness probe: exercise short inbound ISO payloads across
        // START/SINGLE boundaries and TS variants.
        let probe_matrix = [
            (IsoPacketBoundaryFlag::FirstFragment, 0u8),
            (IsoPacketBoundaryFlag::FirstFragment, 1u8),
            (IsoPacketBoundaryFlag::Complete, 0u8),
            (IsoPacketBoundaryFlag::Complete, 1u8),
        ];
        for (idx, (pb, ts)) in probe_matrix.into_iter().enumerate() {
            // Keep payload intentionally tiny to probe parser boundary checks.
            let payload_len = 1 + ((self.rng.r#gen::<u8>() as usize + idx) % 3);
            let mut payload = Vec::with_capacity(payload_len);
            for _ in 0..payload_len {
                payload.push(self.rng.r#gen());
            }
            self.simulator.send_hci_packet(ControllerToHostPacket::IsoData(HciIsoDataPkt {
                handle: stream.cis_handle,
                packet_boundary_flag: pb,
                time_stamp_flag: ts,
                reserved_for_use1: 0,
                data_total_length: payload_len as u16,
                reserved_for_use2: 0,
                data: payload,
            }));
        }
    }

    /// Accepts a pending CIS request.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.8.107 LE Accept CIS Request command
    pub(super) fn on_le_accept_cis(&mut self, cmd: &LeAcceptCisParam) -> Result<(), ControllerError> {
        debug!("[HCI CMD] LE accept CIS command (0x2066)");
        debug!("   in: Connection_Handle=0x{:04x}", cmd.connection_handle);
        self.send_hci_event_packet(CommandCompleteEvent::cmd_ack(0x2066));

        let Some(pending) = self.iso_session.pending_request else {
            return Ok(());
        };
        if pending.cis_handle != cmd.connection_handle {
            return Ok(());
        }

        self.iso_session.mark_established(pending);
        if self.should_emit_le_event(LeEventMaskBit::LeCisEstablished) {
            self.send_hci_event_packet(
                LeCisEstablishedEvent {
                    status: 0x00,
                    connection_handle: pending.cis_handle,
                    cig_sync_delay: [0x30, 0x00, 0x00],
                    cis_sync_delay: [0x30, 0x00, 0x00],
                    c_latency: [0x00, 0x00, 0x00],
                    p_latency: [0x00, 0x00, 0x00],
                    c_phy: 0x01,
                    p_phy: 0x01,
                    nse: 0x02,
                    c_bn: 0x01,
                    p_bn: 0x01,
                    c_ft: 0x01,
                    p_ft: 0x01,
                    c_max_pdu: 0x00fb,
                    p_max_pdu: 0x00fb,
                    interval: 0x0006,
                }
                .into(),
            );
        }
        Ok(())
    }

    /// Rejects a pending CIS request.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.8.108 LE Reject CIS Request command
    pub(super) fn on_le_reject_cis(&mut self, cmd: &LeRejectCisParam) -> Result<(), ControllerError> {
        debug!("[HCI CMD] LE reject CIS command (0x2067)");
        debug!("   in: Connection_Handle=0x{:04x}, Reason=0x{:02x}", cmd.connection_handle, cmd.reason);
        let mut body = Vec::new();
        body.extend_from_slice(&cmd.connection_handle.to_le_bytes());
        self.send_hci_event_packet(CommandCompleteEvent::cmd_ret(0x2067, body));
        if self.iso_session.pending_request.is_some_and(|req| req.cis_handle == cmd.connection_handle) {
            self.iso_session.pending_request = None;
        }
        Ok(())
    }

    /// Configures an ISO data path.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.8.111 LE Setup ISO Data Path command
    pub(super) fn on_le_setup_iso_path(&mut self, cmd: &LeSetupIsoPathParam) -> Result<(), ControllerError> {
        debug!("[HCI CMD] LE setup ISO path command (0x206E)");
        debug!(
            "   in: Connection_Handle=0x{:04x}, Direction=0x{:02x}, Path_ID=0x{:02x}, Codec_Config_Len={}",
            cmd.connection_handle, cmd.data_path_direction, cmd.data_path_id, cmd.codec_configuration_length
        );
        self.iso_session.mark_host_iso_initialized();
        let mut body = Vec::new();
        body.extend_from_slice(&cmd.connection_handle.to_le_bytes());
        self.send_hci_event_packet(CommandCompleteEvent::cmd_ret(0x206E, body));

        if let Some(stream) = self.iso_session.active_stream.as_mut() {
            if stream.cis_handle == cmd.connection_handle {
                // Controller->Host direction, host expects inbound ISO data.
                if cmd.data_path_direction == 0x01 {
                    stream.rx_path_ready = true;
                    self.maybe_send_iso_rx_probe_packet();
                }
            }
        }
        Ok(())
    }

    /// Removes an ISO data path.
    ///
    /// # Reference
    /// Vol 4, Part E, 7.8.112 LE Remove ISO Data Path command
    pub(super) fn on_le_remove_iso_path(&mut self, cmd: &LeRemoveIsoPathParam) -> Result<(), ControllerError> {
        debug!("[HCI CMD] LE remove ISO path command (0x206F)");
        debug!(
            "   in: Connection_Handle=0x{:04x}, Direction=0x{:02x}",
            cmd.connection_handle, cmd.data_path_direction
        );
        let mut body = Vec::new();
        body.extend_from_slice(&cmd.connection_handle.to_le_bytes());
        self.send_hci_event_packet(CommandCompleteEvent::cmd_ret(0x206F, body));
        if let Some(stream) = self.iso_session.active_stream.as_mut() {
            if stream.cis_handle == cmd.connection_handle {
                stream.rx_path_ready = false;
            }
        }
        Ok(())
    }
}
