pub mod bluez_vhci;
pub mod posix_tcp;
pub mod posix_uart;
pub mod posix_udp;
pub mod zephyr_ipc;

use async_trait::async_trait;
use bytes::Bytes;
use std::io;

#[derive(Debug)]
pub enum TransportError {
    InvalidType,
    InvalidConfig,
    CreateFail(io::Error),
    ReadFail(io::Error),
    WriteFail(io::Error),
}

/// Trait for HCI transport implementations
#[async_trait]
pub trait Transport: Send + Sync {
    /// async writes HCI packet to the host.
    async fn write(&self, packet: Bytes) -> Result<(), TransportError>;

    /// async reads HCI packet from the host.
    async fn read(&self) -> Result<Bytes, TransportError>;

    /// finish current phase
    async fn finish_phase(&self) -> Result<(), TransportError> {
        Ok(())
    }
}

/// creates transport with the given type and config string
pub async fn create_tranport(type_str: &str) -> Result<Box<dyn Transport>, TransportError> {
    // posix uart transport: "uart@/path/to/dev"
    if let Some(config) = type_str.strip_prefix("uart@") {
        let trans = posix_uart::PosixUartTransport::new(config)?;
        return Ok(Box::new(trans));
    }

    // posix udp tranport:
    if let Some(config) = type_str.strip_prefix("udp-async@") {
        return if let Some((host, controller)) = config.split_once('-') {
            let trans = posix_udp::PosixUdpTransport::new(host, controller, false).await?;
            Ok(Box::new(trans))
        } else {
            Err(TransportError::InvalidConfig)
        };
    }

    // posix udp tranport notify the phase end:
    if let Some(config) = type_str.strip_prefix("udp-sync@") {
        return if let Some((host, controller)) = config.split_once('-') {
            let trans = posix_udp::PosixUdpTransport::new(host, controller, true).await?;
            Ok(Box::new(trans))
        } else {
            Err(TransportError::InvalidConfig)
        };
    }

    // posix tcp transport:
    if let Some(config) = type_str.strip_prefix("tcp-async@") {
        let trans = posix_tcp::PosixTcpTransport::new(config, false).await?;
        return Ok(Box::new(trans));
    }

    // posix tcp transport notify the phase end:
    if let Some(config) = type_str.strip_prefix("tcp-sync@") {
        let trans = posix_tcp::PosixTcpTransport::new(config, true).await?;
        return Ok(Box::new(trans));
    }

    if type_str == "vhci" {
        let trans = bluez_vhci::VhciTransport::new()?;
        return Ok(Box::new(trans));
    }

    // zephyr ipc transport (BabbleSim/libPhyCom compatible):
    //   "zephyr_ipc@sim=trial_sim,dev=0"
    //   "zephyr_ipc@sim=trial_sim,dev=0,phy=2G4,user=root"
    //   "zephyr-ipc@trial_sim-0"
    if let Some(config) = type_str.strip_prefix("zephyr_ipc@").or_else(|| type_str.strip_prefix("zephyr-ipc@")) {
        let trans = zephyr_ipc::ZephyrIpcTransport::new(config)?;
        return Ok(Box::new(trans));
    }

    Err(TransportError::InvalidType)
}
