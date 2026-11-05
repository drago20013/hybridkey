//! Presenters show the hybrid QR code (and progress) to the user.
//!
//! * [`command::CommandPresenter`] runs a helper program (by default the
//!   `hybridkey-qr` GTK window) and talks to it over a line protocol on stdin.
//! * [`terminal::TerminalPresenter`] prints the QR code to the log, for headless
//!   debugging.

pub mod command;
pub mod terminal;

use std::sync::Arc;

use async_trait::async_trait;

use crate::backend::Operation;

pub struct Prompt {
    /// The `FIDO:/...` URL encoded in the QR code. It contains the session's
    /// secret, so it must never be logged or passed on a command line.
    pub url: String,
    pub operation: Operation,
    pub rp_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UiStatus {
    ProximityCheck,
    Connecting,
    Authenticating,
    /// The tunnel is up; the user now confirms on the phone.
    Connected,
    Done,
    Failed(String),
}

impl UiStatus {
    /// Line-protocol form, see `docs/qr-helper-protocol.md`.
    pub fn to_line(&self) -> String {
        match self {
            UiStatus::ProximityCheck => "status proximity".into(),
            UiStatus::Connecting => "status connecting".into(),
            UiStatus::Authenticating => "status authenticating".into(),
            UiStatus::Connected => "status connected".into(),
            UiStatus::Done => "status done".into(),
            UiStatus::Failed(reason) => format!("status failed {}", reason.replace('\n', " ")),
        }
    }
}

#[async_trait]
pub trait Presenter: Send + Sync {
    /// Shows the prompt. It stays visible until the returned handle is dropped.
    async fn show(&self, prompt: &Prompt) -> anyhow::Result<Arc<dyn PromptHandle>>;
}

#[async_trait]
pub trait PromptHandle: Send + Sync {
    fn update(&self, status: UiStatus);

    /// Resolves when the user closes the prompt. Never resolves for presenters
    /// that cannot be dismissed.
    async fn dismissed(&self);
}
