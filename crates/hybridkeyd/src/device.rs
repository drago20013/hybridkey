//! The virtual HID device, either created through the privileged
//! `hybridkey-uhidd` relay (default) or directly on `/dev/uhid` (needs write
//! access to it; for development).

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;
use std::time::Duration;

use hybridkey_uhid::{relay, DeviceInfo, UhidDevice, UhidEvent, REPORT_LEN};
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;

pub enum HidDevice {
    Direct(AsyncFd<UhidDevice>),
    /// The relay socket. It stays in blocking mode so that sends simply wait if
    /// the relay is momentarily behind; reads use MSG_DONTWAIT and readiness
    /// from tokio, so they never block the runtime.
    Relay(AsyncFd<OwnedFd>),
}

impl HidDevice {
    pub fn direct(path: &Path, info: &DeviceInfo) -> io::Result<Self> {
        let device = UhidDevice::create(path, info, true)?;
        // Writes never block (see hybridkey_uhid::write_event), so only readability is polled.
        Ok(Self::Direct(register(device)?))
    }

    pub async fn relay(socket: &Path) -> io::Result<Self> {
        let fd = connect_seqpacket(socket)?;
        let fd = register(fd)?;
        let device = Self::Relay(fd);
        // The relay answers READY once the device exists.
        let ready = tokio::time::timeout(Duration::from_secs(5), device.recv_packet())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "relay did not answer"))??;
        if ready != [relay::READY] {
            return Err(io::Error::other("unexpected first message from relay"));
        }
        Ok(device)
    }

    pub async fn next_event(&self) -> io::Result<UhidEvent> {
        loop {
            match self {
                HidDevice::Direct(fd) => {
                    let mut guard = fd.readable().await?;
                    match guard.try_io(|inner| inner.get_ref().read_event()) {
                        Ok(Ok(Some(event))) => return Ok(event),
                        Ok(Ok(None)) => {}
                        Ok(Err(e)) if e.kind() == io::ErrorKind::Interrupted => {}
                        Ok(Err(e)) => return Err(e),
                        Err(_would_block) => {}
                    }
                }
                HidDevice::Relay(_) => {
                    let packet = self.recv_packet().await?;
                    match relay::decode_event(&packet) {
                        Ok(Some(event)) => return Ok(event),
                        Ok(None) => {}
                        Err(e) => return Err(io::Error::other(e)),
                    }
                }
            }
        }
    }

    pub fn send_input(&self, report: &[u8; REPORT_LEN]) -> io::Result<()> {
        match self {
            HidDevice::Direct(fd) => fd.get_ref().send_input(report),
            HidDevice::Relay(fd) => {
                let packet = relay::encode_input(report);
                // SAFETY: packet is valid for its length; fd is a connected socket.
                let n = unsafe {
                    libc::send(
                        fd.get_ref().as_raw_fd(),
                        packet.as_ptr().cast(),
                        packet.len(),
                        libc::MSG_NOSIGNAL,
                    )
                };
                if n < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            }
        }
    }

    /// One packet from the relay socket. EOF is reported as an error: the
    /// device is gone.
    async fn recv_packet(&self) -> io::Result<Vec<u8>> {
        let HidDevice::Relay(fd) = self else {
            unreachable!("only used in relay mode")
        };
        let mut buf = [0u8; relay::MAX_PACKET + 1];
        loop {
            let mut guard = fd.readable().await?;
            let result = guard.try_io(|inner| {
                // SAFETY: buf is valid for buf.len() bytes.
                let n = unsafe {
                    libc::recv(
                        inner.get_ref().as_raw_fd(),
                        buf.as_mut_ptr().cast(),
                        buf.len(),
                        libc::MSG_DONTWAIT,
                    )
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            });
            match result {
                Ok(Ok(0)) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "relay closed the connection",
                    ))
                }
                Ok(Ok(n)) => return Ok(buf[..n].to_vec()),
                Ok(Err(e)) if e.kind() == io::ErrorKind::Interrupted => {}
                Ok(Err(e)) => return Err(e),
                Err(_would_block) => {}
            }
        }
    }
}

fn register<T: AsRawFd>(inner: T) -> io::Result<AsyncFd<T>> {
    // SAFETY: both callers pass a type that owns its descriptor (OwnedFd or
    // UhidDevice's File), so it stays open and unchanged while the AsyncFd lives.
    unsafe { AsyncFd::register_with_interest(inner, Interest::READABLE) }
        .map_err(|e| io::Error::other(e.to_string()))
}

fn connect_seqpacket(path: &Path) -> io::Result<OwnedFd> {
    // SAFETY: plain socket(2) call.
    let raw = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: socket returned a fresh descriptor.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };

    // SAFETY: sockaddr_un is plain old data; all-zero is a valid value.
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let bytes = path.as_os_str().as_encoded_bytes();
    if bytes.len() >= addr.sun_path.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "socket path too long",
        ));
    }
    for (dst, src) in addr.sun_path.iter_mut().zip(bytes) {
        *dst = *src as libc::c_char;
    }
    // SAFETY: valid fd and sockaddr_un.
    let rc = unsafe {
        libc::connect(
            fd.as_raw_fd(),
            &addr as *const libc::sockaddr_un as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}
