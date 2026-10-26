use crate::hci::protocol::ProtocolError;

use super::{Protocol, Transport};
use async_trait::async_trait;
use ble::hci::event::CommandStatusEvent;
use bytes::{Bytes, BytesMut};
use deku::{DekuContainerRead, DekuContainerWrite, DekuError};
use std::{boxed::Box, sync::Mutex};
use tracing::{error, trace, warn};

use super::{ControllerToHostPacket, HostToControllerPacket};

/// H4 UART HCI Protocol
pub struct H4Protocol {
    transport: Box<dyn Transport>,
    rx_buffer: Mutex<BytesMut>,
}

impl H4Protocol {
    pub fn new(transport: Box<dyn Transport>) -> Self {
        Self {
            transport,
            rx_buffer: Mutex::new(BytesMut::new()),
        }
    }

    fn buffer_rx_bytes(&self, packet_raw: Bytes) {
        let mut rx_buffer = self.rx_buffer.lock().expect("h4 rx buffer poisoned");
        rx_buffer.extend_from_slice(packet_raw.as_ref());
        trace!(read = packet_raw.len(), buffered = rx_buffer.len(), "buffered H4 bytes");
    }

    fn take_h4_frame(&self) -> Result<Option<Bytes>, ProtocolError> {
        let mut rx_buffer = self.rx_buffer.lock().expect("h4 rx buffer poisoned");
        take_h4_frame_from_buffer(&mut rx_buffer)
    }
}

#[async_trait]
impl<'a> Protocol for H4Protocol {
    fn transport(&self) -> &dyn Transport {
        &*self.transport
    }

    async fn read(&self) -> Result<HostToControllerPacket, ProtocolError> {
        loop {
            if let Some(packet_raw) = self.take_h4_frame()? {
                match HostToControllerPacket::from_bytes((packet_raw.as_ref(), 0)) {
                    Ok(((remain, offset), ret)) => {
                        if !remain.is_empty() {
                            warn!(
                                len = remain.len(),
                                offset = offset,
                                "remain bytes after single-frame H4 decode: {}",
                                hex::encode_upper(remain)
                            );
                        }
                        return Ok(ret);
                    }
                    Err(err) => {
                        error!("packet decode error: {}", err);
                        if let [0x01, opcode_1, opcode_2, param_len, body @ ..] = packet_raw.as_ref() {
                            let opcode = ((*opcode_2 as u16) << 8) + *opcode_1 as u16;
                            let ogf = opcode >> 10;
                            let ocf = opcode & 0b1111111111;
                            let body_len = usize::from(*param_len).min(body.len());
                            error!("unknown opcode: 0x{:04x} OGF=0x{:02x} OCF=0x{:04x}", opcode, ogf, ocf,);
                            error!("packet: {}", hex::encode_upper(&body[..body_len]));

                            self.write(&ControllerToHostPacket::Event(CommandStatusEvent::cmd_status(opcode, 0x01))).await?;
                            continue;
                        }
                        return Err(ProtocolError::InvalidHciPacket(err));
                    }
                }
            }

            self.buffer_rx_bytes(self.transport.read().await?);
        }
    }

    async fn write(&self, packet: &ControllerToHostPacket) -> Result<(), ProtocolError> {
        let packet_raw = packet.to_bytes().map_err(|err| ProtocolError::InvalidHciPacket(err))?;
        trace!("write packet: {}", hex::encode_upper(&packet_raw));
        self.transport.write(Bytes::from(packet_raw)).await?;
        Ok(())
    }
}

fn take_h4_frame_from_buffer(rx_buffer: &mut BytesMut) -> Result<Option<Bytes>, ProtocolError> {
    resync_h4_buffer(rx_buffer);

    let Some(frame_len) = h4_frame_len(rx_buffer.as_ref())? else {
        return Ok(None);
    };

    if rx_buffer.len() < frame_len {
        return Ok(None);
    }

    let frame = rx_buffer.split_to(frame_len).freeze();
    if !rx_buffer.is_empty() {
        trace!(pending = rx_buffer.len(), "buffered additional H4 bytes after frame extraction");
    }
    Ok(Some(frame))
}

fn is_valid_h4_packet_type(packet_type: u8) -> bool {
    matches!(packet_type, 0x01 | 0x02 | 0x03 | 0x05)
}

fn is_plausible_h4_frame(frame: &[u8]) -> bool {
    match frame.first().copied() {
        Some(0x01) => {
            if frame.len() < 4 {
                return false;
            }
            let opcode = u16::from_le_bytes([frame[1], frame[2]]);
            opcode != 0
        }
        Some(0x02 | 0x03 | 0x05) => true,
        _ => false,
    }
}

fn find_h4_sync_index(buf: &[u8]) -> Option<usize> {
    let mut incomplete_candidate = None;

    for idx in 0..buf.len() {
        if !is_valid_h4_packet_type(buf[idx]) {
            continue;
        }

        let candidate = &buf[idx..];
        match h4_frame_len(candidate) {
            Ok(Some(frame_len)) => {
                if candidate.len() < frame_len {
                    incomplete_candidate = Some(idx);
                    break;
                }

                if is_plausible_h4_frame(&candidate[..frame_len]) {
                    return Some(idx);
                }
            }
            Ok(None) => {
                incomplete_candidate = Some(idx);
                break;
            }
            Err(_) => continue,
        }
    }

    incomplete_candidate
}

fn resync_h4_buffer(rx_buffer: &mut BytesMut) {
    if rx_buffer.is_empty() || is_valid_h4_packet_type(rx_buffer[0]) {
        return;
    }

    let Some(sync_idx) = find_h4_sync_index(rx_buffer.as_ref()) else {
        let dropped = rx_buffer.split().freeze();
        warn!(
            dropped = dropped.len(),
            bytes = %hex::encode_upper(dropped),
            "dropping non-H4 noise while waiting for next frame"
        );
        return;
    };

    let dropped = rx_buffer.split_to(sync_idx).freeze();
    warn!(
        dropped = dropped.len(),
        bytes = %hex::encode_upper(&dropped),
        "resynchronized H4 stream after discarding non-H4 prefix"
    );
}

fn h4_frame_len(buf: &[u8]) -> Result<Option<usize>, ProtocolError> {
    if buf.is_empty() {
        return Ok(None);
    }

    let frame_len = match buf[0] {
        0x01 => {
            if buf.len() < 4 {
                return Ok(None);
            }
            4 + usize::from(buf[3])
        }
        0x02 | 0x03 | 0x05 => {
            if buf.len() < 5 {
                return Ok(None);
            }
            let payload_len = usize::from(u16::from_le_bytes([buf[3], buf[4]]));
            5 + payload_len
        }
        packet_type => {
            return Err(ProtocolError::InvalidHciPacket(DekuError::Parse(
                format!("Could not match enum variant: ID {} not found on HostToControllerPacket", packet_type).into(),
            )));
        }
    };

    Ok(Some(frame_len))
}

#[cfg(test)]
mod tests {
    use super::{h4_frame_len, take_h4_frame_from_buffer};
    use bytes::BytesMut;

    #[test]
    fn extracts_back_to_back_h4_frames() {
        let mut rx = BytesMut::from(&b"\x01\x03\x0C\x00\x01\x01\x10\x00"[..]);

        let first = take_h4_frame_from_buffer(&mut rx).unwrap().unwrap();
        assert_eq!(first.as_ref(), b"\x01\x03\x0C\x00");
        assert_eq!(rx.as_ref(), b"\x01\x01\x10\x00");

        let second = take_h4_frame_from_buffer(&mut rx).unwrap().unwrap();
        assert_eq!(second.as_ref(), b"\x01\x01\x10\x00");
        assert!(rx.is_empty());
    }

    #[test]
    fn waits_for_partial_h4_frame() {
        let mut rx = BytesMut::from(&b"\x01\x03\x0C"[..]);
        assert!(take_h4_frame_from_buffer(&mut rx).unwrap().is_none());

        rx.extend_from_slice(b"\x00");
        let frame = take_h4_frame_from_buffer(&mut rx).unwrap().unwrap();
        assert_eq!(frame.as_ref(), b"\x01\x03\x0C\x00");
        assert!(rx.is_empty());
    }

    #[test]
    fn parses_acl_frame_length_from_header() {
        let raw = b"\x02\x40\x00\x03\x00\xAA\xBB\xCC";
        assert_eq!(h4_frame_len(raw).unwrap(), Some(raw.len()));
    }

    #[test]
    fn resynchronizes_after_ascii_noise() {
        let mut rx = BytesMut::from(&b"Trace: booting\n\x01\x03\x0C\x00"[..]);

        let frame = take_h4_frame_from_buffer(&mut rx).unwrap().unwrap();
        assert_eq!(frame.as_ref(), b"\x01\x03\x0C\x00");
        assert!(rx.is_empty());
    }

    #[test]
    fn drops_all_noise_when_no_h4_header_present() {
        let mut rx = BytesMut::from(&b"Target log line"[..]);
        assert!(take_h4_frame_from_buffer(&mut rx).unwrap().is_none());
        assert!(rx.is_empty());
    }

    #[test]
    fn skips_spurious_null_command_headers_while_resynchronizing() {
        let mut rx = BytesMut::from(&b"Trace:\x01\x00\x00\x00\x01\x03\x0C\x00"[..]);

        let frame = take_h4_frame_from_buffer(&mut rx).unwrap().unwrap();
        assert_eq!(frame.as_ref(), b"\x01\x03\x0C\x00");
        assert!(rx.is_empty());
    }
}
