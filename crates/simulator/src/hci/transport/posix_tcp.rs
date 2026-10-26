use crate::hci::transport::TransportError;

use super::Transport;
use async_trait::async_trait;
use bytes::BytesMut;
use std::{
    io::ErrorKind,
    sync::atomic::{AtomicBool, Ordering},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Mutex,
};
use tracing::trace;

pub struct PosixTcpTransport {
    listener: TcpListener,
    stream: Mutex<Option<TcpStream>>,
    notify_end_phase: AtomicBool,
}

impl PosixTcpTransport {
    pub async fn new(listen_addr: &str, notify_end_phase: bool) -> Result<Self, TransportError> {
        trace!("creating posix TCP transport:");
        trace!("  listen: {}", listen_addr);

        let listener = TcpListener::bind(listen_addr)
            .await
            .map_err(TransportError::CreateFail)?;

        Ok(Self {
            listener,
            stream: Mutex::new(None),
            notify_end_phase: notify_end_phase.into(),
        })
    }

    async fn ensure_stream(&self) -> Result<(), TransportError> {
        {
            let guard = self.stream.lock().await;
            if guard.is_some() {
                return Ok(());
            }
        }

        let (stream, peer_addr) = self
            .listener
            .accept()
            .await
            .map_err(TransportError::CreateFail)?;
        stream.set_nodelay(true).map_err(TransportError::CreateFail)?;
        trace!("tcp transport accepted peer {}", peer_addr);

        let mut guard = self.stream.lock().await;
        if guard.is_none() {
            *guard = Some(stream);
        }

        Ok(())
    }
}

#[async_trait]
impl Transport for PosixTcpTransport {
    async fn read(&self) -> Result<bytes::Bytes, TransportError> {
        loop {
            self.ensure_stream().await?;

            let mut buf = BytesMut::with_capacity(2048);
            buf.resize(2048, 0);

            let mut guard = self.stream.lock().await;
            let Some(stream) = guard.as_mut() else {
                continue;
            };

            match stream.read(&mut buf).await {
                Ok(0) => {
                    trace!("tcp transport peer closed");
                    *guard = None;
                    continue;
                }
                Ok(n) => {
                    if n == 1 && buf[0] == 0xff {
                        return Err(TransportError::ReadFail(ErrorKind::NotFound.into()));
                    }
                    buf.truncate(n);
                    return Ok(buf.freeze());
                }
                Err(err) if matches!(err.kind(), ErrorKind::BrokenPipe | ErrorKind::ConnectionReset) => {
                    trace!("tcp transport read reset: {}", err);
                    *guard = None;
                    continue;
                }
                Err(err) => return Err(TransportError::ReadFail(err)),
            }
        }
    }

    async fn write(&self, packet: bytes::Bytes) -> Result<(), TransportError> {
        loop {
            self.ensure_stream().await?;

            let mut guard = self.stream.lock().await;
            let Some(stream) = guard.as_mut() else {
                continue;
            };

            match stream.write_all(packet.as_ref()).await {
                Ok(()) => return Ok(()),
                Err(err) if matches!(err.kind(), ErrorKind::BrokenPipe | ErrorKind::ConnectionReset) => {
                    trace!("tcp transport write reset: {}", err);
                    *guard = None;
                    continue;
                }
                Err(err) => return Err(TransportError::WriteFail(err)),
            }
        }
    }

    async fn finish_phase(&self) -> Result<(), TransportError> {
        if !self.notify_end_phase.load(Ordering::Relaxed) {
            return Ok(());
        }

        self.write(bytes::Bytes::from_static(&[0xff])).await
    }
}
