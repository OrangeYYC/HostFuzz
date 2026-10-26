pub mod h4;
pub mod h5;

use crate::hci::transport::TransportError;

use super::transport::Transport;
use async_trait::async_trait;
use ble::hci::{ControllerToHostPacket, HostToControllerPacket};
use deku::DekuError;

#[derive(Debug)]
pub enum ProtocolError {
    InvalidType,
    InvalidTransportPacket(&'static str),
    InvalidHciPacket(DekuError),
    TransportFail(TransportError),
}

impl From<TransportError> for ProtocolError {
    fn from(value: TransportError) -> Self {
        ProtocolError::TransportFail(value)
    }
}

impl From<DekuError> for ProtocolError {
    fn from(value: DekuError) -> Self {
        ProtocolError::InvalidHciPacket(value)
    }
}

/// trait for HCI protocols, encodes and decode HCI packet for the Transport.
#[async_trait]
pub trait Protocol: Send + Sync {
    fn transport(&self) -> &dyn Transport;

    /// async writes HCI packet to the transport.
    async fn write(&self, packet: &ControllerToHostPacket) -> Result<(), ProtocolError>;

    /// async reads HCI packet from the transport.
    async fn read(&self) -> Result<HostToControllerPacket, ProtocolError>;

    /// reset the behavior of the protocol
    async fn reset(&self) {}

    /// finish current phase
    async fn finish_phase(&self) -> Result<(), ProtocolError> {
        self.transport().finish_phase().await?;
        Ok(())
    }
}

/// creates protocol with the given type and the underlyling transport.
pub async fn create_protocol(type_str: &str, trans: Box<dyn Transport>) -> Result<Box<dyn Protocol>, ProtocolError> {
    // HCI H4 protocol
    if type_str == "h4" {
        return Ok(Box::new(h4::H4Protocol::new(trans)));
    }

    // HCI H5 protocol
    if type_str == "h5" {
        return Ok(Box::new(h5::H5Protocol::new(trans)));
    }

    Err(ProtocolError::InvalidType)
}
