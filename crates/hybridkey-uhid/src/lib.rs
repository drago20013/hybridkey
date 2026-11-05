//! Minimal wrapper around the kernel's `/dev/uhid` interface
//! (Documentation/hid/uhid.rst), just enough to expose one FIDO HID device,
//! plus the wire protocol between `hybridkeyd` and the `hybridkey-uhidd` relay.
//!
//! Synchronous on purpose: the relay uses it with `poll(2)`, the daemon wraps the
//! descriptor in tokio's `AsyncFd`.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

pub const REPORT_LEN: usize = 64;

// enum uhid_event_type
const UHID_DESTROY: u32 = 1;
const UHID_START: u32 = 2;
const UHID_STOP: u32 = 3;
const UHID_OPEN: u32 = 4;
const UHID_CLOSE: u32 = 5;
const UHID_OUTPUT: u32 = 6;
const UHID_GET_REPORT: u32 = 9;
const UHID_GET_REPORT_REPLY: u32 = 10;
const UHID_CREATE2: u32 = 11;
const UHID_INPUT2: u32 = 12;
const UHID_SET_REPORT: u32 = 13;
const UHID_SET_REPORT_REPLY: u32 = 14;

const BUS_USB: u16 = 0x03;
const HID_MAX_DESCRIPTOR_SIZE: usize = 4096;
const UHID_DATA_MAX: usize = 4096;
/// sizeof(struct uhid_event): a u32 type plus the largest union member (uhid_create2_req).
const EVENT_SIZE: usize = 4 + 128 + 64 + 64 + 2 + 2 + 4 + 4 + 4 + 4 + HID_MAX_DESCRIPTOR_SIZE;

/// HID report descriptor of a FIDO authenticator: usage page 0xF1D0, 64-byte
/// input and output reports, no report IDs. This is the only descriptor this
/// crate can create a device with.
const FIDO_REPORT_DESCRIPTOR: &[u8] = &[
    0x06, 0xd0, 0xf1, // Usage Page (FIDO Alliance)
    0x09, 0x01, //       Usage (CTAPHID)
    0xa1, 0x01, //       Collection (Application)
    0x09, 0x20, //         Usage (Input Report Data)
    0x15, 0x00, //         Logical Minimum (0)
    0x26, 0xff, 0x00, //   Logical Maximum (255)
    0x75, 0x08, //         Report Size (8)
    0x95, 0x40, //         Report Count (64)
    0x81, 0x02, //         Input (Data, Var, Abs)
    0x09, 0x21, //         Usage (Output Report Data)
    0x15, 0x00, //         Logical Minimum (0)
    0x26, 0xff, 0x00, //   Logical Maximum (255)
    0x75, 0x08, //         Report Size (8)
    0x95, 0x40, //         Report Count (64)
    0x91, 0x02, //         Output (Data, Var, Abs)
    0xc0, //             End Collection
];

pub const DEFAULT_NAME: &str = "hybridkey phone passkey bridge";
/// pid.codes test VID/PID until a real one is assigned.
pub const DEFAULT_VENDOR_ID: u32 = 0x1209;
pub const DEFAULT_PRODUCT_ID: u32 = 0x0001;

/// The `uniq` string of the device created for `uid`. It shows up as
/// `HID_UNIQ` in the hidraw uevent, which is how a daemon finds its own node.
pub fn device_uniq(uid: u32) -> String {
    format!("hybridkey-{uid}")
}

pub struct DeviceInfo<'a> {
    pub name: &'a str,
    pub uniq: &'a str,
    pub vendor_id: u32,
    pub product_id: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub enum UhidEvent {
    /// An output report written by a host application (e.g. the browser).
    Output([u8; REPORT_LEN]),
    /// A host application opened the hidraw node.
    Opened,
    /// The last host application closed the hidraw node.
    Closed,
}

/// A FIDO HID device. Destroyed when dropped.
pub struct UhidDevice {
    file: File,
}

impl UhidDevice {
    /// Creates the device. With `nonblocking`, [`UhidDevice::read_event`]
    /// returns `WouldBlock` instead of waiting.
    pub fn create(path: &Path, info: &DeviceInfo, nonblocking: bool) -> io::Result<Self> {
        let flags = libc::O_CLOEXEC | if nonblocking { libc::O_NONBLOCK } else { 0 };
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(flags)
            .open(path)?;

        let mut ev = vec![0u8; EVENT_SIZE];
        ev[0..4].copy_from_slice(&UHID_CREATE2.to_ne_bytes());
        let body = &mut ev[4..];
        copy_cstr(&mut body[0..128], info.name);
        copy_cstr(&mut body[128..192], "hybridkey");
        copy_cstr(&mut body[192..256], info.uniq);
        body[256..258].copy_from_slice(&(FIDO_REPORT_DESCRIPTOR.len() as u16).to_ne_bytes());
        body[258..260].copy_from_slice(&BUS_USB.to_ne_bytes());
        body[260..264].copy_from_slice(&info.vendor_id.to_ne_bytes());
        body[264..268].copy_from_slice(&info.product_id.to_ne_bytes());
        // version (268..272) and country (272..276) stay zero.
        body[276..276 + FIDO_REPORT_DESCRIPTOR.len()].copy_from_slice(FIDO_REPORT_DESCRIPTOR);
        write_event(&mut file, &ev)?;

        Ok(Self { file })
    }

    /// Reads one kernel event. Returns `Ok(None)` for events handled internally
    /// or not of interest.
    pub fn read_event(&self) -> io::Result<Option<UhidEvent>> {
        let mut buf = vec![0u8; EVENT_SIZE];
        let n = (&self.file).read(&mut buf)?;
        self.decode(&buf[..n])
    }

    fn decode(&self, buf: &[u8]) -> io::Result<Option<UhidEvent>> {
        if buf.len() < 4 {
            return Ok(None);
        }
        let kind = u32::from_ne_bytes(buf[0..4].try_into().unwrap());
        let body = &buf[4..];
        Ok(match kind {
            UHID_OUTPUT => {
                // struct uhid_output_req { u8 data[4096]; u16 size; u8 rtype; }
                if body.len() < UHID_DATA_MAX + 2 {
                    return Ok(None);
                }
                let size =
                    u16::from_ne_bytes([body[UHID_DATA_MAX], body[UHID_DATA_MAX + 1]]) as usize;
                let data = &body[..size.min(UHID_DATA_MAX)];
                // hidraw passes the report number through as the first byte; our
                // device has no numbered reports, so it is always zero.
                let data = match data.len() {
                    n if n == REPORT_LEN + 1 && data[0] == 0 => &data[1..],
                    REPORT_LEN => data,
                    _ => return Ok(None),
                };
                Some(UhidEvent::Output(data.try_into().unwrap()))
            }
            UHID_OPEN => Some(UhidEvent::Opened),
            UHID_CLOSE => Some(UhidEvent::Closed),
            UHID_START | UHID_STOP => None,
            UHID_GET_REPORT | UHID_SET_REPORT => {
                // We have no feature reports. Reply with an error so the caller
                // does not block until the kernel's timeout.
                if body.len() < 4 {
                    return Ok(None);
                }
                let id = u32::from_ne_bytes(body[0..4].try_into().unwrap());
                let reply_kind = if kind == UHID_GET_REPORT {
                    UHID_GET_REPORT_REPLY
                } else {
                    UHID_SET_REPORT_REPLY
                };
                let mut ev = [0u8; 4 + 4 + 2 + 2];
                ev[0..4].copy_from_slice(&reply_kind.to_ne_bytes());
                ev[4..8].copy_from_slice(&id.to_ne_bytes());
                ev[8..10].copy_from_slice(&(libc::EIO as u16).to_ne_bytes());
                write_event(&self.file, &ev)?;
                None
            }
            _ => None,
        })
    }

    /// Sends one input report to the host.
    pub fn send_input(&self, report: &[u8; REPORT_LEN]) -> io::Result<()> {
        // struct uhid_input2_req { u16 size; u8 data[4096]; }
        let mut ev = [0u8; 4 + 2 + REPORT_LEN];
        ev[0..4].copy_from_slice(&UHID_INPUT2.to_ne_bytes());
        ev[4..6].copy_from_slice(&(REPORT_LEN as u16).to_ne_bytes());
        ev[6..].copy_from_slice(report);
        write_event(&self.file, &ev)
    }
}

impl AsRawFd for UhidDevice {
    fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

impl Drop for UhidDevice {
    fn drop(&mut self) {
        let _ = write_event(&self.file, &UHID_DESTROY.to_ne_bytes());
    }
}

/// Writes to /dev/uhid are processed synchronously by the kernel and never return
/// EAGAIN, so a plain write is fine even on a non-blocking descriptor.
fn write_event(mut file: impl Write, ev: &[u8]) -> io::Result<()> {
    let written = file.write(ev)?;
    if written != ev.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "short write to uhid",
        ));
    }
    Ok(())
}

fn copy_cstr(dst: &mut [u8], s: &str) {
    let n = s.len().min(dst.len() - 1);
    dst[..n].copy_from_slice(&s.as_bytes()[..n]);
}

/// Messages on the `SOCK_SEQPACKET` socket between `hybridkeyd` (client) and
/// `hybridkey-uhidd` (relay). One message per packet.
///
/// Client → relay: `INPUT` + 64-byte report. Nothing else is accepted.
/// Relay → client: `READY` once the device exists, then `OUTPUT` + 64-byte
/// report, `OPENED` and `CLOSED` as the kernel reports them.
pub mod relay {
    use super::{UhidEvent, REPORT_LEN};

    pub const DEFAULT_SOCKET: &str = "/run/hybridkey-uhidd.sock";
    /// Largest packet either side sends.
    pub const MAX_PACKET: usize = 1 + REPORT_LEN;

    pub const READY: u8 = 0x00;
    pub const INPUT: u8 = 0x01;
    pub const OUTPUT: u8 = 0x01;
    pub const OPENED: u8 = 0x02;
    pub const CLOSED: u8 = 0x03;

    pub fn encode_event(event: &UhidEvent) -> Vec<u8> {
        match event {
            UhidEvent::Output(report) => {
                let mut packet = Vec::with_capacity(MAX_PACKET);
                packet.push(OUTPUT);
                packet.extend_from_slice(report);
                packet
            }
            UhidEvent::Opened => vec![OPENED],
            UhidEvent::Closed => vec![CLOSED],
        }
    }

    /// Relay → client packets. `Ok(None)` for READY.
    /// A packet that does not match the protocol.
    #[derive(Debug, PartialEq, Eq)]
    pub struct MalformedPacket;

    impl std::fmt::Display for MalformedPacket {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("malformed relay packet")
        }
    }

    impl std::error::Error for MalformedPacket {}

    pub fn decode_event(packet: &[u8]) -> Result<Option<UhidEvent>, MalformedPacket> {
        match packet {
            [READY] => Ok(None),
            [OUTPUT, report @ ..] if report.len() == REPORT_LEN => {
                Ok(Some(UhidEvent::Output(report.try_into().unwrap())))
            }
            [OPENED] => Ok(Some(UhidEvent::Opened)),
            [CLOSED] => Ok(Some(UhidEvent::Closed)),
            _ => Err(MalformedPacket),
        }
    }

    pub fn encode_input(report: &[u8; REPORT_LEN]) -> [u8; MAX_PACKET] {
        let mut packet = [0u8; MAX_PACKET];
        packet[0] = INPUT;
        packet[1..].copy_from_slice(report);
        packet
    }

    /// Client → relay packets: the only accepted form is INPUT + 64 bytes.
    pub fn decode_input(packet: &[u8]) -> Option<[u8; REPORT_LEN]> {
        match packet {
            [INPUT, report @ ..] if report.len() == REPORT_LEN => report.try_into().ok(),
            _ => None,
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn round_trips() {
            let report = [7u8; REPORT_LEN];
            for event in [
                UhidEvent::Output(report),
                UhidEvent::Opened,
                UhidEvent::Closed,
            ] {
                assert_eq!(decode_event(&encode_event(&event)), Ok(Some(event)));
            }
            assert_eq!(decode_event(&[READY]), Ok(None));
            assert_eq!(decode_input(&encode_input(&report)), Some(report));
        }

        #[test]
        fn rejects_malformed_input() {
            assert_eq!(decode_input(&[]), None);
            assert_eq!(decode_input(&[INPUT; 64]), None, "one byte short");
            assert_eq!(decode_input(&[INPUT; 66]), None, "one byte long");
            assert_eq!(decode_input(&[0x99; 65]), None, "unknown type");
            assert!(decode_event(&[0x42]).is_err());
        }
    }
}
