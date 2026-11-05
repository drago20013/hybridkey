//! CTAPHID transport: channel allocation, keepalives, cancellation and busy
//! handling on top of the virtual HID device. CBOR messages go to the [`Authenticator`].

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time::MissedTickBehavior;
use tracing::{debug, info, warn};

use crate::authenticator::{Authenticator, RequestContext};
use crate::ctaphid::{self, capability, cmd, err, Assembler, Event, Message, BROADCAST_CID};
use hybridkey_uhid::UhidEvent;

use crate::device::HidDevice;

const KEEPALIVE_INTERVAL: Duration = Duration::from_millis(100);

struct Transaction {
    id: u64,
    cid: u32,
    ctx: RequestContext,
}

pub struct HidServer {
    device: HidDevice,
    authenticator: Arc<Authenticator>,
    assembler: Assembler,
    next_cid: u32,
    next_txn: u64,
    active: Option<Transaction>,
}

impl HidServer {
    pub fn new(device: HidDevice, authenticator: Arc<Authenticator>) -> Self {
        Self {
            device,
            authenticator,
            assembler: Assembler::default(),
            // Start somewhere unpredictable so a restarted daemon does not hand out
            // channel IDs a browser still remembers from before.
            next_cid: (std::process::id() << 8) | 1,
            next_txn: 0,
            active: None,
        }
    }

    pub async fn run(mut self) -> anyhow::Result<()> {
        let (done_tx, mut done_rx) = mpsc::channel::<(u64, Vec<u8>)>(4);
        let mut keepalive = tokio::time::interval(KEEPALIVE_INTERVAL);
        keepalive.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                event = self.device.next_event() => match event? {
                    UhidEvent::Output(report) => match self.assembler.push(&report) {
                        Event::Pending => {}
                        Event::Complete(message) => self.on_message(message, &done_tx)?,
                        Event::Error { cid, code } => self.send_error(cid, code)?,
                    },
                    UhidEvent::Opened => debug!("hidraw opened"),
                    UhidEvent::Closed => {
                        debug!("hidraw closed");
                        // Nobody is listening for the answer any more.
                        if let Some(txn) = self.active.take() {
                            txn.ctx.cancel.cancel();
                        }
                    }
                },
                Some((id, response)) = done_rx.recv() => {
                    if let Some(txn) = self.active.take_if(|t| t.id == id) {
                        self.send(txn.cid, cmd::CBOR, &response)?;
                    }
                }
                _ = keepalive.tick(), if self.active.is_some() => {
                    let txn = self.active.as_ref().unwrap();
                    self.send(txn.cid, cmd::KEEPALIVE, &[txn.ctx.keepalive_status()])?;
                }
            }
        }
    }

    fn on_message(
        &mut self,
        message: Message,
        done_tx: &mpsc::Sender<(u64, Vec<u8>)>,
    ) -> anyhow::Result<()> {
        let Message {
            cid,
            cmd: command,
            payload,
        } = message;
        if cid == 0 || (cid == BROADCAST_CID && command != cmd::INIT) {
            return self.send_error(cid, err::INVALID_CHANNEL);
        }

        match command {
            cmd::INIT => {
                if payload.len() != 8 {
                    return self.send_error(cid, err::INVALID_LEN);
                }
                let assigned = if cid == BROADCAST_CID {
                    self.allocate_cid()
                } else {
                    // Resynchronisation on an existing channel aborts its transaction.
                    if let Some(txn) = self.active.take_if(|t| t.cid == cid) {
                        txn.ctx.cancel.cancel();
                    }
                    cid
                };
                let mut response = payload; // the 8-byte nonce
                response.extend_from_slice(&assigned.to_be_bytes());
                response.extend_from_slice(&[
                    2, // CTAPHID protocol version
                    0,
                    1,
                    0, // device version major/minor/build
                    capability::WINK | capability::CBOR | capability::NMSG,
                ]);
                self.send(cid, cmd::INIT, &response)
            }
            cmd::PING => self.send(cid, cmd::PING, &payload),
            cmd::WINK => self.send(cid, cmd::WINK, &[]),
            cmd::CANCEL => {
                if let Some(txn) = self.active.as_ref().filter(|t| t.cid == cid) {
                    debug!(cid = format!("{cid:08x}"), "cancel requested");
                    txn.ctx.cancel.cancel();
                }
                Ok(())
            }
            cmd::CBOR => {
                if payload.is_empty() {
                    return self.send_error(cid, err::INVALID_LEN);
                }
                if self.active.is_some() {
                    return self.send_error(cid, err::CHANNEL_BUSY);
                }
                self.next_txn += 1;
                let txn = Transaction {
                    id: self.next_txn,
                    cid,
                    ctx: RequestContext::new(),
                };
                let (id, ctx) = (txn.id, txn.ctx.clone());
                self.active = Some(txn);

                let authenticator = self.authenticator.clone();
                let done_tx = done_tx.clone();
                tokio::spawn(async move {
                    let response = authenticator.handle(&payload, &ctx).await;
                    let _ = done_tx.send((id, response)).await;
                });
                Ok(())
            }
            other => {
                debug!(cmd = format!("{other:#04x}"), "unsupported CTAPHID command");
                self.send_error(cid, err::INVALID_CMD)
            }
        }
    }

    fn allocate_cid(&mut self) -> u32 {
        loop {
            self.next_cid = self.next_cid.wrapping_add(1);
            if self.next_cid != 0 && self.next_cid != BROADCAST_CID {
                info!(cid = format!("{:08x}", self.next_cid), "allocated channel");
                return self.next_cid;
            }
        }
    }

    fn send_error(&self, cid: u32, code: u8) -> anyhow::Result<()> {
        warn!(cid = format!("{cid:08x}"), code, "CTAPHID error");
        self.send(cid, cmd::ERROR, &[code])
    }

    fn send(&self, cid: u32, command: u8, payload: &[u8]) -> anyhow::Result<()> {
        let payload = if payload.len() > ctaphid::MAX_MESSAGE_LEN {
            warn!(len = payload.len(), "response too large for CTAPHID");
            &[crate::ctap2::status::OTHER][..]
        } else {
            payload
        };
        for report in ctaphid::fragment(cid, command, payload) {
            self.device.send_input(&report)?;
        }
        Ok(())
    }
}
