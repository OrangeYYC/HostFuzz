use crate::hci::transport::TransportError;

use super::Transport;
use async_trait::async_trait;
use bytes::Bytes;
use std::{
    // env,
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{FileTypeExt, OpenOptionsExt},
    os::unix::io::AsRawFd,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};
use tokio::task;
use tracing::trace;

const DEFAULT_PHY_ID: &str = "HCIIPC";
const DEFAULT_TIMEOUT_MS: u64 = 3000;
const MAX_FRAME_SIZE: usize = u16::MAX as usize;

#[derive(Clone, Debug)]
struct ZephyrIpcConfig {
    sim_id: String,
    device_id: u32,
    phy_id: String,
    com_dir: PathBuf,
    connect_timeout: Duration,
}

#[derive(Debug, Default)]
struct TransportState {
    dtp_reader: Option<fs::File>,
    ptd_writer: Option<fs::File>,
    seen_peer_data: bool,
}

/// Zephyr IPC transport for HCI IPC testcases.
///
/// This transport is intentionally HCI-only:
/// it forwards framed HCI bytes over FIFOs and does not implement any link-layer/p2G4 behavior.
#[derive(Clone)]
pub struct ZephyrIpcTransport {
    cfg: ZephyrIpcConfig,
    state: Arc<Mutex<TransportState>>,
}

impl ZephyrIpcTransport {
    /// Supported config formats:
    /// - `sim=trial_sim,dev=0`
    /// - `sim=trial_sim,dev=0,phy=HCIIPC,user=root`
    /// - `sim=trial_sim,dev=0,dir=/tmp/bs_root/trial_sim`
    /// - `sim=trial_sim,dev=0,mode=hci_ipc`
    /// - `trial_sim-0`
    pub fn new(config: &str) -> Result<Self, TransportError> {
        let cfg = parse_config(config)?;
        trace!("creating zephyr ipc(hci) transport:");
        trace!("  sim id : {}", cfg.sim_id);
        trace!("  dev id : {}", cfg.device_id);
        trace!("  phy id : {}", cfg.phy_id);
        trace!("  com dir: {}", cfg.com_dir.display());
        Ok(Self {
            cfg,
            state: Arc::new(Mutex::new(TransportState::default())),
        })
    }

    fn dtp_path(&self) -> PathBuf {
        self.cfg.com_dir.join(format!("{}.d{}.dtp", self.cfg.phy_id, self.cfg.device_id))
    }

    fn ptd_path(&self) -> PathBuf {
        self.cfg.com_dir.join(format!("{}.d{}.ptd", self.cfg.phy_id, self.cfg.device_id))
    }

    fn dev_lock_path(&self) -> PathBuf {
        self.cfg.com_dir.join(format!("{}.d{}.lock", self.cfg.phy_id, self.cfg.device_id))
    }

    fn with_state_mut<T, F: FnOnce(&mut TransportState) -> io::Result<T>>(&self, f: F) -> io::Result<T> {
        let mut guard = self.state.lock().map_err(|_| io::Error::other("zephyr_ipc state mutex poisoned"))?;
        f(&mut guard)
    }

    async fn ensure_connected(&self) -> Result<(), TransportError> {
        if self
            .with_state_mut(|state| Ok(state.dtp_reader.is_some() && state.ptd_writer.is_some()))
            .map_err(TransportError::CreateFail)?
        {
            return Ok(());
        }

        let dtp_path = self.dtp_path();
        let ptd_path = self.ptd_path();
        let dev_lock_path = self.dev_lock_path();
        let timeout = self.cfg.connect_timeout;
        let state = self.state.clone();

        task::spawn_blocking(move || -> io::Result<()> {
            cleanup_stale_ipc_files(&dtp_path, &ptd_path, &dev_lock_path)?;
            wait_fifo_pair_ready(&dtp_path, &ptd_path, timeout)?;

            // Open the read side first to avoid deadlock with peers which also open
            // their writer side first (for example Zephyr HCI-IPC bridge on cpu1).
            let mut dtp_reader = open_fifo_reader_nonblock(&dtp_path)?;
            set_blocking(&mut dtp_reader, true)?;
            let mut ptd_writer = open_fifo_writer_nonblock_retry(&ptd_path, timeout)?;
            set_blocking(&mut ptd_writer, true)?;

            let mut guard = state.lock().map_err(|_| io::Error::other("zephyr_ipc state mutex poisoned"))?;
            guard.ptd_writer = Some(ptd_writer);
            guard.dtp_reader = Some(dtp_reader);
            Ok(())
        })
        .await
        .map_err(|err| TransportError::CreateFail(io::Error::other(format!("connect task join error: {err}"))))?
        .map_err(TransportError::CreateFail)
    }

    fn read_hci_frame_blocking(&self) -> Result<Bytes, TransportError> {
        let timeout = self.cfg.connect_timeout;
        self.with_state_mut(|state| {
            let eof_wait_start = Instant::now();
            let reader = state
                .dtp_reader
                .as_mut()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "dtp fifo not connected"))?;

            loop {
                match read_u16(reader) {
                    Ok(frame_len) => {
                        state.seen_peer_data = true;
                        let frame_len = frame_len as usize;
                        if frame_len == 0 {
                            continue;
                        }
                        if frame_len > MAX_FRAME_SIZE {
                            return Err(io::Error::new(io::ErrorKind::InvalidData, format!("hci frame too large: {}", frame_len)));
                        }
                        let frame = read_exact_len(reader, frame_len)?;
                        trace!("zephyr_ipc(hci): recv frame len={}", frame.len());
                        return Ok(Bytes::from(frame));
                    }
                    Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => {
                        if !state.seen_peer_data && eof_wait_start.elapsed() < timeout {
                            thread::sleep(Duration::from_millis(1));
                            continue;
                        }
                        return Err(io::Error::new(io::ErrorKind::BrokenPipe, "target closed dtp fifo"));
                    }
                    Err(err) => return Err(err),
                }
            }
        })
        .map_err(TransportError::ReadFail)
    }
}

#[async_trait]
impl Transport for ZephyrIpcTransport {
    async fn read(&self) -> Result<Bytes, TransportError> {
        self.ensure_connected().await?;
        self.read_hci_frame_blocking()
    }

    async fn write(&self, packet: Bytes) -> Result<(), TransportError> {
        self.ensure_connected().await?;
        self.with_state_mut(|state| {
            let writer = state
                .ptd_writer
                .as_mut()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "ptd fifo not connected"))?;

            if packet.len() > MAX_FRAME_SIZE {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("hci frame too large: {}", packet.len())));
            }

            write_u16(writer, packet.len() as u16)?;
            writer.write_all(&packet)?;
            trace!("zephyr_ipc(hci): send frame len={}", packet.len());
            Ok(())
        })
        .map_err(TransportError::WriteFail)
    }
}

fn parse_config(config: &str) -> Result<ZephyrIpcConfig, TransportError> {
    let cfg = config.trim();
    if cfg.is_empty() {
        return Err(TransportError::InvalidConfig);
    }

    let mut sim_id: Option<String> = None;
    let mut dev_id: Option<u32> = None;
    let mut phy_id = DEFAULT_PHY_ID.to_string();
    // let mut user: Option<String> = None;
    let mut root = PathBuf::from("/tmp");
    let mut com_dir: Option<PathBuf> = None;
    let mut timeout_ms = DEFAULT_TIMEOUT_MS;

    if cfg.contains('=') {
        for entry in cfg.split(',') {
            let (k, v) = entry.split_once('=').ok_or(TransportError::InvalidConfig)?;
            let key = k.trim();
            let val = v.trim();
            if val.is_empty() {
                return Err(TransportError::InvalidConfig);
            }
            match key {
                "sim" | "sim_id" | "s" => sim_id = Some(val.to_string()),
                "dev" | "device" | "device_id" | "d" => dev_id = Some(val.parse::<u32>().map_err(|_| TransportError::InvalidConfig)?),
                "phy" | "phy_id" | "p" => phy_id = val.to_string(),
                "user" => {} //user = Some(val.to_string()),
                "root" => root = PathBuf::from(val),
                "dir" | "com_dir" => com_dir = Some(PathBuf::from(val)),
                "timeout_ms" => timeout_ms = val.parse::<u64>().map_err(|_| TransportError::InvalidConfig)?,
                // accept explicit mode to keep config compatibility
                "mode" => {
                    if !matches!(val, "hci" | "hci_ipc" | "hci-ipc") {
                        return Err(TransportError::InvalidConfig);
                    }
                }
                _ => return Err(TransportError::InvalidConfig),
            }
        }
    } else if let Some((sim, dev)) = cfg.rsplit_once('-') {
        sim_id = Some(sim.trim().to_string());
        dev_id = Some(dev.trim().parse::<u32>().map_err(|_| TransportError::InvalidConfig)?);
    } else {
        return Err(TransportError::InvalidConfig);
    }

    let sim_id = sim_id.filter(|s| !s.is_empty()).ok_or(TransportError::InvalidConfig)?;
    let dev_id = dev_id.ok_or(TransportError::InvalidConfig)?;
    // let user = user.unwrap_or_else(current_user_name);
    let com_dir = match com_dir {
        Some(path) => path,
        None => root.join(format!("bs_root")).join(&sim_id),
    };
    Ok(ZephyrIpcConfig {
        sim_id,
        device_id: dev_id,
        phy_id,
        com_dir,
        connect_timeout: Duration::from_millis(timeout_ms),
    })
}

// fn current_user_name() -> String {
//     env::var("USER")
//         .or_else(|_| env::var("LOGNAME"))
//         .ok()
//         .filter(|s| !s.is_empty())
//         .unwrap_or_else(|| "unknown".to_string())
// }

fn wait_fifo_pair_ready(dtp_path: &Path, ptd_path: &Path, timeout: Duration) -> io::Result<()> {
    let start = Instant::now();
    loop {
        let ready = is_fifo(dtp_path)? && is_fifo(ptd_path)?;
        if ready {
            return Ok(());
        }
        if start.elapsed() > timeout {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("waiting fifo timeout (dtp={}, ptd={})", dtp_path.display(), ptd_path.display()),
            ));
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn is_fifo(path: &Path) -> io::Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    Ok(fs::metadata(path)?.file_type().is_fifo())
}

fn cleanup_stale_ipc_files(dtp_path: &Path, ptd_path: &Path, lock_path: &Path) -> io::Result<()> {
    for path in [dtp_path, ptd_path] {
        if !path.exists() {
            continue;
        }
        let meta = fs::symlink_metadata(path)?;
        // Keep existing FIFOs; only remove unexpected files.
        if !meta.file_type().is_fifo() {
            let _ = fs::remove_file(path);
        }
    }

    if lock_path.exists() {
        let _ = fs::remove_file(lock_path);
    }

    Ok(())
}

fn open_fifo_writer_nonblock_retry(path: &Path, timeout: Duration) -> io::Result<fs::File> {
    let start = Instant::now();
    loop {
        match OpenOptions::new().write(true).custom_flags(libc::O_NONBLOCK).open(path) {
            Ok(file) => return Ok(file),
            Err(err) if err.kind() == io::ErrorKind::NotFound || err.raw_os_error() == Some(libc::ENXIO) => {
                if start.elapsed() > timeout {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("opening fifo writer timeout: {}", path.display()),
                    ));
                }
                thread::sleep(Duration::from_millis(20));
            }
            Err(err) => return Err(err),
        }
    }
}

fn open_fifo_reader_nonblock(path: &Path) -> io::Result<fs::File> {
    OpenOptions::new().read(true).custom_flags(libc::O_NONBLOCK).open(path)
}

fn set_blocking(file: &mut fs::File, enable_blocking: bool) -> io::Result<()> {
    let fd = file.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    let new_flags = if enable_blocking {
        flags & !libc::O_NONBLOCK
    } else {
        flags | libc::O_NONBLOCK
    };
    let ret = unsafe { libc::fcntl(fd, libc::F_SETFL, new_flags) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn read_exact_len(reader: &mut fs::File, n: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

fn read_u16(reader: &mut fs::File) -> io::Result<u16> {
    let mut buf = [0u8; 2];
    reader.read_exact(&mut buf)?;
    Ok(u16::from_le_bytes(buf))
}

fn write_u16(writer: &mut fs::File, val: u16) -> io::Result<()> {
    writer.write_all(&val.to_le_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::ffi::OsStrExt;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn mkfifo(path: &Path) {
        let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).expect("invalid fifo path");
        let ret = unsafe { libc::mkfifo(c_path.as_ptr(), 0o750) };
        assert_eq!(ret, 0, "mkfifo failed for {}", path.display());
    }

    #[tokio::test]
    async fn zephyr_ipc_hci_framed_io() {
        let unique = format!(
            "virtble-zephyr-hci-ipc-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).expect("time drift").as_nanos()
        );
        let dir = std::env::temp_dir().join(unique);
        std::fs::create_dir_all(&dir).expect("create temp dir");

        let dtp_path = dir.join("HCIIPC.d0.dtp");
        let ptd_path = dir.join("HCIIPC.d0.ptd");
        mkfifo(&dtp_path);
        mkfifo(&ptd_path);

        let transport = ZephyrIpcTransport::new(&format!("sim=trial_sim,dev=0,phy=HCIIPC,dir={}", dir.display())).expect("transport create");

        let peer = std::thread::spawn(move || {
            let mut from_transport = OpenOptions::new().read(true).open(&ptd_path).expect("open ptd");
            let mut to_transport = OpenOptions::new().write(true).open(&dtp_path).expect("open dtp");

            // send one framed packet to transport.read()
            to_transport.write_all(&(3u16).to_le_bytes()).expect("write inbound len");
            to_transport.write_all(&[0x01, 0x02, 0x03]).expect("write inbound payload");

            // receive one framed packet from transport.write()
            let mut len = [0u8; 2];
            from_transport.read_exact(&mut len).expect("read outbound len");
            assert_eq!(u16::from_le_bytes(len), 4u16, "unexpected outbound len");
            let mut out = [0u8; 4];
            from_transport.read_exact(&mut out).expect("read outbound payload");
            assert_eq!(out, [0x10, 0x20, 0x30, 0x40], "unexpected outbound payload");
        });

        let inbound = transport.read().await.expect("transport read");
        assert_eq!(inbound.as_ref(), &[0x01, 0x02, 0x03], "unexpected inbound frame");

        transport.write(Bytes::from_static(&[0x10, 0x20, 0x30, 0x40])).await.expect("transport write");

        peer.join().expect("peer thread join");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
