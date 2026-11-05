//! CTAPHID framing: splitting messages into 64-byte HID reports and
//! reassembling them (FIDO CTAP 2.1, section 11.2).
//!
//! This module is pure (no I/O) so it can be unit tested in isolation.

use std::time::{Duration, Instant};

pub const REPORT_LEN: usize = 64;
const INIT_HEADER: usize = 7;
const CONT_HEADER: usize = 5;
const INIT_DATA: usize = REPORT_LEN - INIT_HEADER;
const CONT_DATA: usize = REPORT_LEN - CONT_HEADER;
/// Largest message that fits in one initialization packet plus 128 continuation packets.
pub const MAX_MESSAGE_LEN: usize = INIT_DATA + 128 * CONT_DATA;

pub const BROADCAST_CID: u32 = 0xffff_ffff;

/// How long a partially received message may sit before it is discarded.
const ASSEMBLY_TIMEOUT: Duration = Duration::from_secs(3);

pub mod cmd {
    pub const PING: u8 = 0x01;
    pub const INIT: u8 = 0x06;
    pub const WINK: u8 = 0x08;
    pub const CBOR: u8 = 0x10;
    pub const CANCEL: u8 = 0x11;
    pub const KEEPALIVE: u8 = 0x3b;
    pub const ERROR: u8 = 0x3f;
}

pub mod err {
    pub const INVALID_CMD: u8 = 0x01;
    pub const INVALID_LEN: u8 = 0x03;
    pub const INVALID_SEQ: u8 = 0x04;
    pub const CHANNEL_BUSY: u8 = 0x06;
    pub const INVALID_CHANNEL: u8 = 0x0b;
}

pub mod capability {
    pub const WINK: u8 = 0x01;
    pub const CBOR: u8 = 0x04;
    /// Device does not implement CTAPHID_MSG (no U2F/CTAP1).
    pub const NMSG: u8 = 0x08;
}

pub mod keepalive {
    pub const PROCESSING: u8 = 0x01;
    pub const UP_NEEDED: u8 = 0x02;
}

/// A fully reassembled CTAPHID message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub cid: u32,
    pub cmd: u8,
    pub payload: Vec<u8>,
}

/// Outcome of feeding one report into the [`Assembler`].
#[derive(Debug, PartialEq, Eq)]
pub enum Event {
    /// More packets are needed.
    Pending,
    Complete(Message),
    /// The packet was invalid; reply with CTAPHID_ERROR on `cid`.
    Error {
        cid: u32,
        code: u8,
    },
}

struct Partial {
    cid: u32,
    cmd: u8,
    total: usize,
    payload: Vec<u8>,
    next_seq: u8,
    started: Instant,
}

/// Reassembles messages from incoming reports. Only one message is assembled at a
/// time; packets from other channels in the meantime are answered with CHANNEL_BUSY.
#[derive(Default)]
pub struct Assembler {
    partial: Option<Partial>,
}

impl Assembler {
    pub fn push(&mut self, report: &[u8]) -> Event {
        if report.len() < REPORT_LEN {
            return Event::Pending;
        }
        let cid = u32::from_be_bytes([report[0], report[1], report[2], report[3]]);

        if self
            .partial
            .as_ref()
            .is_some_and(|p| p.started.elapsed() > ASSEMBLY_TIMEOUT)
        {
            self.partial = None;
        }

        if report[4] & 0x80 != 0 {
            let cmd = report[4] & 0x7f;
            let total = u16::from_be_bytes([report[5], report[6]]) as usize;

            if let Some(partial) = &self.partial {
                // A new INIT on the same channel resynchronises; anything else is busy.
                if partial.cid != cid {
                    return Event::Error {
                        cid,
                        code: err::CHANNEL_BUSY,
                    };
                }
                if cmd != cmd::INIT {
                    self.partial = None;
                    return Event::Error {
                        cid,
                        code: err::INVALID_SEQ,
                    };
                }
                self.partial = None;
            }
            if total > MAX_MESSAGE_LEN {
                return Event::Error {
                    cid,
                    code: err::INVALID_LEN,
                };
            }

            let take = total.min(INIT_DATA);
            let payload = report[INIT_HEADER..INIT_HEADER + take].to_vec();
            if payload.len() == total {
                return Event::Complete(Message { cid, cmd, payload });
            }
            self.partial = Some(Partial {
                cid,
                cmd,
                total,
                payload,
                next_seq: 0,
                started: Instant::now(),
            });
            return Event::Pending;
        }

        // Continuation packet.
        let seq = report[4];
        let Some(partial) = self.partial.as_mut() else {
            // Stray continuation packets are ignored, as the spec requires.
            return Event::Pending;
        };
        if partial.cid != cid {
            return Event::Error {
                cid,
                code: err::CHANNEL_BUSY,
            };
        }
        if seq != partial.next_seq {
            self.partial = None;
            return Event::Error {
                cid,
                code: err::INVALID_SEQ,
            };
        }
        partial.next_seq += 1;
        let take = (partial.total - partial.payload.len()).min(CONT_DATA);
        partial
            .payload
            .extend_from_slice(&report[CONT_HEADER..CONT_HEADER + take]);
        if partial.payload.len() == partial.total {
            let p = self.partial.take().expect("partial message present");
            return Event::Complete(Message {
                cid: p.cid,
                cmd: p.cmd,
                payload: p.payload,
            });
        }
        Event::Pending
    }
}

/// Splits a message into reports. `payload` must not exceed [`MAX_MESSAGE_LEN`].
pub fn fragment(cid: u32, cmd: u8, payload: &[u8]) -> Vec<[u8; REPORT_LEN]> {
    debug_assert!(payload.len() <= MAX_MESSAGE_LEN);
    let mut reports = Vec::new();
    let cid = cid.to_be_bytes();

    let mut first = [0u8; REPORT_LEN];
    first[..4].copy_from_slice(&cid);
    first[4] = cmd | 0x80;
    first[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    let take = payload.len().min(INIT_DATA);
    first[INIT_HEADER..INIT_HEADER + take].copy_from_slice(&payload[..take]);
    reports.push(first);

    for (seq, chunk) in payload[take..].chunks(CONT_DATA).enumerate() {
        let mut report = [0u8; REPORT_LEN];
        report[..4].copy_from_slice(&cid);
        report[4] = seq as u8;
        report[CONT_HEADER..CONT_HEADER + chunk.len()].copy_from_slice(chunk);
        reports.push(report);
    }
    reports
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reassemble(reports: &[[u8; REPORT_LEN]]) -> Message {
        let mut assembler = Assembler::default();
        let (last, rest) = reports.split_last().unwrap();
        for report in rest {
            assert_eq!(assembler.push(report), Event::Pending);
        }
        match assembler.push(last) {
            Event::Complete(message) => message,
            other => panic!("expected a complete message, got {other:?}"),
        }
    }

    #[test]
    fn round_trips_short_and_long_messages() {
        for len in [0, 1, INIT_DATA, INIT_DATA + 1, 1000, MAX_MESSAGE_LEN] {
            let payload: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let reports = fragment(0x0102_0304, cmd::CBOR, &payload);
            let message = reassemble(&reports);
            assert_eq!(message.cid, 0x0102_0304);
            assert_eq!(message.cmd, cmd::CBOR);
            assert_eq!(message.payload, payload, "length {len}");
        }
    }

    #[test]
    fn rejects_interleaved_channel() {
        let mut assembler = Assembler::default();
        let long = fragment(1, cmd::CBOR, &[0u8; 100]);
        assert_eq!(assembler.push(&long[0]), Event::Pending);
        let other = fragment(2, cmd::PING, &[1, 2, 3]);
        assert_eq!(
            assembler.push(&other[0]),
            Event::Error {
                cid: 2,
                code: err::CHANNEL_BUSY
            }
        );
        // The original message can still complete.
        assert!(matches!(assembler.push(&long[1]), Event::Complete(_)));
    }

    #[test]
    fn rejects_bad_sequence() {
        let mut assembler = Assembler::default();
        let mut reports = fragment(7, cmd::CBOR, &[0u8; 200]);
        reports[1][4] = 5;
        assembler.push(&reports[0]);
        assert_eq!(
            assembler.push(&reports[1]),
            Event::Error {
                cid: 7,
                code: err::INVALID_SEQ
            }
        );
    }

    #[test]
    fn init_resynchronises_same_channel() {
        let mut assembler = Assembler::default();
        let long = fragment(9, cmd::CBOR, &[0u8; 100]);
        assembler.push(&long[0]);
        let init = fragment(9, cmd::INIT, &[0u8; 8]);
        assert!(matches!(assembler.push(&init[0]), Event::Complete(m) if m.cmd == cmd::INIT));
    }

    #[test]
    fn rejects_oversized_length() {
        let mut report = [0u8; REPORT_LEN];
        report[4] = cmd::CBOR | 0x80;
        report[5..7].copy_from_slice(&((MAX_MESSAGE_LEN + 1) as u16).to_be_bytes());
        assert_eq!(
            Assembler::default().push(&report),
            Event::Error {
                cid: 0,
                code: err::INVALID_LEN
            }
        );
    }
}
