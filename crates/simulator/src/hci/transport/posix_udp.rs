use crate::hci::transport::TransportError;

use super::Transport;
use async_trait::async_trait;
use bytes::BytesMut;
use std::{
    io::ErrorKind,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::net::UdpSocket;
use tracing::trace;

pub struct PosixUdpTransport {
    socket: Arc<UdpSocket>,
    notify_end_phase: AtomicBool,
}

impl PosixUdpTransport {
    pub async fn new(host_addr: &str, controller_addr: &str, notify_end_phase: bool) -> Result<Self, TransportError> {
        trace!("creating posix UDP transport:");
        trace!("  host: {}", host_addr);
        trace!("  controller: {}", controller_addr);

        let socket = Arc::new(UdpSocket::bind(controller_addr).await.map_err(|err| TransportError::CreateFail(err))?);
        socket.connect(host_addr).await.map_err(|err| TransportError::CreateFail(err))?;

        Ok(Self {
            socket,
            notify_end_phase: notify_end_phase.into(),
        })
    }
}

#[async_trait]
impl Transport for PosixUdpTransport {
    async fn read(&self) -> Result<bytes::Bytes, TransportError> {
        let mut buf = BytesMut::with_capacity(2048);
        buf.resize(2048, 0);

        let n = self.socket.recv(&mut buf).await.map_err(|err| TransportError::ReadFail(err))?;

        if n == 1 && buf[0] == 0xff {
            return Err(TransportError::ReadFail(ErrorKind::NotFound.into()));
        }

        buf.truncate(n);

        Ok(buf.freeze())
    }

    async fn write(&self, packet: bytes::Bytes) -> Result<(), TransportError> {
        let _ = self.socket.send(packet.as_ref()).await.map_err(|err| TransportError::WriteFail(err))?;
        Ok(())
    }

    async fn finish_phase(&self) -> Result<(), TransportError> {
        if self.notify_end_phase.load(Ordering::Relaxed) {
            self.socket.send(&[0xff]).await.map_err(|err| TransportError::WriteFail(err))?;
        }
        Ok(())
    }
}
