use crate::hci::transport::TransportError;

use super::Transport;
use async_trait::async_trait;
use bytes::BytesMut;
use libc;
use std::ffi::CStr;
use std::fs;
use std::fs::File;
use std::io;
use std::io::{Read, Write};
use std::os::unix::fs::symlink;
use std::os::unix::io::{FromRawFd, RawFd};
use std::path::{Path, PathBuf};
use tokio::io::unix::AsyncFd;
use tracing::{error, trace};

pub struct PosixUartTransport {
    dev_path: PathBuf,
    tty_fd: AsyncFd<File>,
}

impl Drop for PosixUartTransport {
    fn drop(&mut self) {
        if let Ok(metadata) = fs::symlink_metadata(&self.dev_path) {
            if metadata.file_type().is_symlink() {
                if let Err(e) = fs::remove_file(&self.dev_path) {
                    error!("Failed to remove {}: {:?}", self.dev_path.display(), e);
                } else {
                    trace!("Removed symlink {}", self.dev_path.display());
                }
            }
        }
    }
}

impl PosixUartTransport {
    pub fn new(tty_path: &str) -> Result<Self, TransportError> {
        trace!("creating posix UART transport:");
        trace!("  dev: {}", tty_path);

        let master_fd = posix_openpt().map_err(|err| TransportError::CreateFail(err))?;
        let slave_path = ptsname(master_fd).map_err(|err| TransportError::CreateFail(err))?;
        trace!("PTY slave: {}", slave_path);

        let dev_path = Path::new(tty_path);
        if let Ok(metadata) = fs::symlink_metadata(dev_path) {
            if metadata.file_type().is_symlink() || metadata.is_file() {
                trace!("{} exists, removing stale file/symlink before PTY bind", tty_path);
                fs::remove_file(dev_path).map_err(|err| TransportError::CreateFail(err))?;
            } else {
                let backup_path = PathBuf::from(format!("{tty_path}.bak"));
                trace!("{} exists, backing up to {}", tty_path, backup_path.display());
                if backup_path.exists() {
                    if backup_path.is_dir() {
                        fs::remove_dir_all(&backup_path).map_err(|err| TransportError::CreateFail(err))?;
                    } else {
                        fs::remove_file(&backup_path).map_err(|err| TransportError::CreateFail(err))?;
                    }
                }
                fs::rename(dev_path, &backup_path).map_err(|err| TransportError::CreateFail(err))?;
            }
        }
        trace!("Creating symlink: {} -> {}", tty_path, slave_path);
        symlink(&slave_path, dev_path).map_err(|err| TransportError::CreateFail(err))?;

        set_nonblocking(master_fd).map_err(|err| TransportError::CreateFail(err))?;

        let std_file = unsafe { std::fs::File::from_raw_fd(master_fd) };
        let tty_fd = AsyncFd::new(std_file).map_err(|err| TransportError::CreateFail(err))?;

        let ret = Self {
            dev_path: tty_path.into(),
            tty_fd,
        };

        Ok(ret)
    }
}

#[async_trait]
impl Transport for PosixUartTransport {
    async fn read(&self) -> Result<bytes::Bytes, TransportError> {
        let mut buf = BytesMut::with_capacity(2048);
        buf.resize(2048, 0);

        loop {
            let mut guard = self.tty_fd.readable().await.map_err(|err| TransportError::ReadFail(err))?;

            match guard.try_io(|inner| {
                let mut file = inner.get_ref();
                file.read(&mut buf)
            }) {
                Ok(Ok(n)) => {
                    buf.truncate(n);
                    return Ok(buf.freeze());
                }
                Ok(Err(e)) => return Err(TransportError::ReadFail(e)),
                Err(_would_block) => continue,
            }
        }
    }

    async fn write(&self, packet: bytes::Bytes) -> Result<(), TransportError> {
        let mut offset = 0;

        loop {
            let mut guard = self.tty_fd.writable().await.map_err(|err| TransportError::WriteFail(err))?;

            match guard.try_io(|inner| {
                let mut file = inner.get_ref();
                file.write(&packet[offset..])
            }) {
                Ok(Ok(n)) => {
                    offset += n;
                    if offset == packet.len() {
                        return Ok(());
                    }
                }

                Ok(Err(e)) => {
                    return Err(TransportError::WriteFail(e));
                }

                Err(_would_block) => continue,
            }
        }
    }
}

fn posix_openpt() -> io::Result<RawFd> {
    let flags = libc::O_RDWR | libc::O_NOCTTY;
    let fd = unsafe { libc::posix_openpt(flags) };
    if fd < 0 {
        error!("error openpt");
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::grantpt(fd) } != 0 {
        unsafe { libc::close(fd) };
        error!("error grantpt");
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::unlockpt(fd) } != 0 {
        unsafe { libc::close(fd) };
        error!("error unlockpt");
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

fn ptsname(fd: RawFd) -> io::Result<String> {
    let mut buf = vec![0u8; 128];
    let r = unsafe { libc::ptsname_r(fd, buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
    if r != 0 {
        error!("error ptsname");
        return Err(io::Error::last_os_error());
    }
    let cstr = unsafe { CStr::from_ptr(buf.as_ptr() as *const libc::c_char) };
    Ok(cstr.to_string_lossy().into_owned())
}

fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        error!("error fcntl F_GETFL");
        return Err(io::Error::last_os_error());
    }
    let new = flags | libc::O_NONBLOCK;
    if unsafe { libc::fcntl(fd, libc::F_SETFL, new) } < 0 {
        error!("error fcntl F_SETFL");
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
