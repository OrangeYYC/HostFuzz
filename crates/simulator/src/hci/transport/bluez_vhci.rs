use super::Transport;
use crate::hci::transport::TransportError;

use async_trait::async_trait;
use bytes::BytesMut;
use libc;
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::io::FromRawFd;
use tokio::io::unix::AsyncFd;
use tracing::{error, trace};

pub struct VhciTransport {
    vhci_fd: AsyncFd<File>,
}

#[repr(C)]
struct VhciSetupCmd {
    pkt_type: u8,
    ctrl_type: u8,
}

impl VhciSetupCmd {
    fn exec(&self, fd: i32) -> Result<(), TransportError> {
        let ret = unsafe { libc::write(fd, self as *const _ as *const libc::c_void, std::mem::size_of::<VhciSetupCmd>()) };
        if ret < 0 {
            unsafe { libc::close(fd) };
            error!("failed to setup vhci controller");
            Err(TransportError::CreateFail(std::io::Error::last_os_error()))
        } else {
            trace!("successfully setup vhci controller");
            Ok(())
        }
    }
}

impl VhciTransport {
    pub fn new() -> Result<Self, TransportError> {
        trace!("creating VHCI transport");

        let fd = unsafe { libc::open(b"/dev/vhci\0".as_ptr() as *const _, libc::O_RDWR | libc::O_NONBLOCK) };

        if fd < 0 {
            error!("failed to open /dev/vhci");
            return Err(TransportError::CreateFail(std::io::Error::last_os_error()));
        }

        // setup the controller
        VhciSetupCmd {
            pkt_type: 0xff,
            ctrl_type: 0x00,
        }
        .exec(fd)?;

        let file = unsafe { File::from_raw_fd(fd) };
        let vhci_fd = AsyncFd::new(file).map_err(|e| TransportError::CreateFail(e))?;

        trace!("VHCI controller registered");

        Ok(Self { vhci_fd })
    }
}

#[async_trait]
impl Transport for VhciTransport {
    async fn read(&self) -> Result<bytes::Bytes, TransportError> {
        let mut buf = BytesMut::with_capacity(2048);
        buf.resize(2048, 0);

        loop {
            let mut guard = self.vhci_fd.readable().await.map_err(TransportError::ReadFail)?;

            match guard.try_io(|inner| {
                let mut file = inner.get_ref();
                file.read(&mut buf)
            }) {
                Ok(Ok(n)) => {
                    buf.truncate(n);
                    trace!("VHCI read {} bytes", n);
                    if buf.len() > 1 && buf[0] == 0xff {
                        continue;
                    }
                    return Ok(buf.freeze());
                }
                Ok(Err(e)) => return Err(TransportError::ReadFail(e)),
                Err(_) => continue,
            }
        }
    }

    async fn write(&self, packet: bytes::Bytes) -> Result<(), TransportError> {
        let mut file = self.vhci_fd.get_ref();

        let mut offset = 0;
        while offset < packet.len() {
            match file.write(&packet[offset..]) {
                Ok(n) => offset += n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    tokio::task::yield_now().await;
                }
                Err(e) => return Err(TransportError::WriteFail(e)),
            }
        }

        trace!("VHCI write {} bytes", packet.len());
        Ok(())
    }
}
