//! hybridkey-uhidd: creates hybridkey's virtual FIDO security key on behalf of
//! an unprivileged `hybridkeyd`, so `/dev/uhid` can stay root-only.
//!
//! Runs as a socket-activated system service. Each connection on the
//! `SOCK_SEQPACKET` socket gets exactly one device, always with the fixed FIDO
//! report descriptor, and can only exchange 64-byte reports with it (see
//! `hybridkey_uhid::relay`). Who may connect is decided by the socket's group
//! (`hybridkey`); on top of that the peer must have an active seat session
//! and may own at most one device at a time.

use std::collections::HashSet;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Mutex;

use hybridkey_uhid::{relay, DeviceInfo, UhidDevice};

/// Users that currently own a device.
static ACTIVE: Mutex<Option<HashSet<u32>>> = Mutex::new(None);

struct Options {
    uhid_path: PathBuf,
    listen: Option<PathBuf>,
    seat_check: bool,
}

fn main() -> ExitCode {
    let options = match parse_args() {
        Ok(options) => options,
        Err(message) => {
            eprintln!("{message}");
            eprintln!("usage: hybridkey-uhidd [--uhid PATH] [--listen SOCKET] [--no-seat-check]");
            return ExitCode::from(2);
        }
    };

    let listener = match listener(&options) {
        Ok(fd) => fd,
        Err(e) => {
            eprintln!("error: no listening socket: {e}");
            return ExitCode::FAILURE;
        }
    };
    eprintln!("ready");

    let options: &'static Options = Box::leak(Box::new(options));
    loop {
        // SAFETY: accept4 on a listening socket we own; the result is a new fd or -1.
        let fd = unsafe {
            libc::accept4(
                listener.as_raw_fd(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                libc::SOCK_CLOEXEC,
            )
        };
        if fd < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            eprintln!("error: accept: {e}");
            return ExitCode::FAILURE;
        }
        // SAFETY: accept4 returned a fresh descriptor that nothing else owns.
        let conn = unsafe { OwnedFd::from_raw_fd(fd) };
        std::thread::spawn(move || serve(conn, options));
    }
}

fn parse_args() -> Result<Options, String> {
    let mut options = Options {
        uhid_path: "/dev/uhid".into(),
        listen: None,
        seat_check: true,
    };
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--uhid" => options.uhid_path = args.next().ok_or("--uhid needs a path")?.into(),
            "--listen" => options.listen = Some(args.next().ok_or("--listen needs a path")?.into()),
            "--no-seat-check" => options.seat_check = false,
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    Ok(options)
}

/// The socket passed by systemd (LISTEN_FDS), or one bound to `--listen`.
fn listener(options: &Options) -> io::Result<OwnedFd> {
    let activated = std::env::var("LISTEN_PID").ok() == Some(std::process::id().to_string())
        && std::env::var("LISTEN_FDS").ok().as_deref() == Some("1");
    if activated {
        // SAFETY: systemd passes the listening socket as fd 3 (SD_LISTEN_FDS_START).
        return Ok(unsafe { OwnedFd::from_raw_fd(3) });
    }
    let Some(path) = &options.listen else {
        return Err(io::Error::other(
            "not socket-activated and no --listen given",
        ));
    };
    let _ = std::fs::remove_file(path);
    let fd = seqpacket_socket()?;
    let addr = sockaddr_un(path)?;
    // SAFETY: valid fd and a properly initialised sockaddr_un.
    let rc = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            &addr as *const libc::sockaddr_un as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: valid listening-capable socket.
    if unsafe { libc::listen(fd.as_raw_fd(), 8) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

fn serve(conn: OwnedFd, options: &Options) {
    let uid = match peer_uid(conn.as_raw_fd()) {
        Ok(uid) => uid,
        Err(e) => {
            eprintln!("rejecting connection: cannot read peer credentials: {e}");
            return;
        }
    };
    if options.seat_check && !has_active_session(uid) {
        eprintln!("rejecting uid {uid}: no active seat session");
        return;
    }
    {
        let mut active = ACTIVE.lock().unwrap();
        if !active.get_or_insert_with(HashSet::new).insert(uid) {
            eprintln!("rejecting uid {uid}: already has a device");
            return;
        }
    }

    match relay_device(&conn, uid, options) {
        Ok(()) => eprintln!("uid {uid}: device removed"),
        Err(e) => eprintln!("uid {uid}: device removed: {e}"),
    }
    ACTIVE.lock().unwrap().as_mut().unwrap().remove(&uid);
}

fn relay_device(conn: &OwnedFd, uid: u32, options: &Options) -> io::Result<()> {
    let uniq = hybridkey_uhid::device_uniq(uid);
    let device = UhidDevice::create(
        &options.uhid_path,
        &DeviceInfo {
            name: hybridkey_uhid::DEFAULT_NAME,
            uniq: &uniq,
            vendor_id: hybridkey_uhid::DEFAULT_VENDOR_ID,
            product_id: hybridkey_uhid::DEFAULT_PRODUCT_ID,
        },
        true,
    )?;
    eprintln!("uid {uid}: device created");
    send(conn.as_raw_fd(), &[relay::READY])?;

    let mut buf = [0u8; relay::MAX_PACKET + 1];
    loop {
        let mut fds = [
            libc::pollfd {
                fd: conn.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: device.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // SAFETY: fds is a valid array of two pollfd structs.
        if unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) } < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }

        if fds[0].revents & libc::POLLIN != 0 {
            // SAFETY: buf is valid for buf.len() bytes.
            let n = unsafe {
                libc::recv(
                    conn.as_raw_fd(),
                    buf.as_mut_ptr().cast(),
                    buf.len(),
                    libc::MSG_DONTWAIT,
                )
            };
            match n {
                0 => return Ok(()),
                n if n < 0 => {
                    let e = io::Error::last_os_error();
                    if e.kind() != io::ErrorKind::WouldBlock {
                        return Err(e);
                    }
                }
                n => match relay::decode_input(&buf[..n as usize]) {
                    Some(report) => device.send_input(&report)?,
                    None => return Err(io::Error::other("client sent a malformed packet")),
                },
            }
        } else if fds[0].revents & (libc::POLLHUP | libc::POLLERR) != 0 {
            return Ok(());
        }

        if fds[1].revents & libc::POLLIN != 0 {
            loop {
                match device.read_event() {
                    Ok(Some(event)) => send(conn.as_raw_fd(), &relay::encode_event(&event))?,
                    Ok(None) => {}
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => return Err(e),
                }
            }
        }
    }
}

fn seqpacket_socket() -> io::Result<OwnedFd> {
    // SAFETY: plain socket(2) call.
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: socket returned a fresh descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn sockaddr_un(path: &Path) -> io::Result<libc::sockaddr_un> {
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
    Ok(addr)
}

fn send(fd: RawFd, packet: &[u8]) -> io::Result<()> {
    // SAFETY: packet is valid for packet.len() bytes.
    let n = unsafe { libc::send(fd, packet.as_ptr().cast(), packet.len(), libc::MSG_NOSIGNAL) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn peer_uid(fd: RawFd) -> io::Result<u32> {
    // SAFETY: ucred is plain old data; getsockopt fills it.
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: cred and len are valid for writing.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(cred.uid)
}

#[link(name = "systemd")]
extern "C" {
    /// Number of seats on which `uid` has an active session (with
    /// `require_active` set); see sd_uid_get_state(3).
    fn sd_uid_get_seats(
        uid: libc::uid_t,
        require_active: libc::c_int,
        seats: *mut *mut *mut libc::c_char,
    ) -> libc::c_int;
}

/// True if `uid` has the foreground session on some seat: the same user that
/// `uaccess` gives the resulting hidraw node to.
fn has_active_session(uid: u32) -> bool {
    // SAFETY: passing NULL for `seats` asks only for the count.
    unsafe { sd_uid_get_seats(uid, 1, std::ptr::null_mut()) > 0 }
}
