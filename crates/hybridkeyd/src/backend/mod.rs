//! Backends complete a WebAuthn ceremony on some other authenticator. The only
//! one today is [`hybrid::HybridBackend`] (a phone over caBLE).

pub mod hybrid;

use async_trait::async_trait;

use crate::authenticator::RequestContext;
use crate::ctap2::status;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    MakeCredential,
    GetAssertion,
}

impl Operation {
    pub fn short(self) -> &'static str {
        match self {
            Operation::MakeCredential => "mc",
            Operation::GetAssertion => "ga",
        }
    }
}

pub struct ForwardRequest {
    /// CTAP2 command byte.
    pub command: u8,
    /// CBOR request body, possibly rewritten by the authenticator.
    pub cbor: Vec<u8>,
    pub operation: Operation,
    pub rp_id: String,
}

#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    #[error("cancelled by the browser")]
    Cancelled,
    #[error("dismissed by the user")]
    Dismissed,
    #[error("timed out waiting for the phone")]
    Timeout,
    #[error("backend unavailable: {0}")]
    Unavailable(String),
    #[error("{0}")]
    Failed(String),
}

impl BackendError {
    pub fn ctap_status(&self) -> u8 {
        match self {
            BackendError::Cancelled => status::KEEPALIVE_CANCEL,
            BackendError::Timeout => status::USER_ACTION_TIMEOUT,
            // Not OPERATION_DENIED: Firefox reads that as "built-in UV failed" and retries.
            BackendError::Dismissed => status::NOT_ALLOWED,
            BackendError::Unavailable(_) | BackendError::Failed(_) => status::OTHER,
        }
    }
}

#[async_trait]
pub trait Backend: Send + Sync {
    fn name(&self) -> &'static str;

    /// Runs the request and returns the raw CTAP2 response (status byte + CBOR).
    /// Implementations must stop promptly when `ctx.cancel` fires.
    async fn forward(
        &self,
        request: ForwardRequest,
        ctx: &RequestContext,
    ) -> Result<Vec<u8>, BackendError>;
}
