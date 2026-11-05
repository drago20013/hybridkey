//! Forwards requests to a phone over the FIDO hybrid transport (caBLE v2),
//! using libwebauthn for the QR code, BLE proximity check and tunnel.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use libwebauthn::proto::ctap2::cbor::CborRequest;
use libwebauthn::proto::ctap2::Ctap2CommandCode;
use libwebauthn::transport::cable::channel::{CableUpdate, CableUxUpdate};
use libwebauthn::transport::cable::qr_code_device::{
    CableQrCodeDevice, CableTransports, QrCodeOperationHint,
};
use libwebauthn::transport::{Channel as _, ChannelSettings, Device as _};
use serde::Deserialize;
use tracing::{debug, info};

use super::{Backend, BackendError, ForwardRequest, Operation};
use crate::authenticator::RequestContext;
use crate::presenter::{Presenter, Prompt, UiStatus};

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum TransportMode {
    /// caBLE v2 through the tunnel server. Works with every current phone.
    #[default]
    Cloud,
    /// Also offer CTAP 2.3's direct BLE L2CAP channel; older phones fall back to the tunnel.
    CloudOrLocal,
}

pub struct HybridBackend {
    presenter: Arc<dyn Presenter>,
    timeout: Duration,
    transports: CableTransports,
}

impl HybridBackend {
    pub fn new(presenter: Arc<dyn Presenter>, timeout: Duration, mode: TransportMode) -> Self {
        let transports = match mode {
            TransportMode::Cloud => CableTransports::CloudAssistedOnly,
            TransportMode::CloudOrLocal => CableTransports::CloudAssistedOrLocal,
        };
        Self {
            presenter,
            timeout,
            transports,
        }
    }

    pub async fn bluetooth_available() -> bool {
        libwebauthn::transport::cable::is_available().await
    }
}

#[async_trait]
impl Backend for HybridBackend {
    fn name(&self) -> &'static str {
        "hybrid"
    }

    async fn forward(
        &self,
        request: ForwardRequest,
        ctx: &RequestContext,
    ) -> Result<Vec<u8>, BackendError> {
        let command = Ctap2CommandCode::try_from(request.command).map_err(|_| {
            BackendError::Failed(format!("unsupported command {:#04x}", request.command))
        })?;
        let hint = match request.operation {
            Operation::MakeCredential => QrCodeOperationHint::MakeCredential,
            Operation::GetAssertion => QrCodeOperationHint::GetAssertionRequest,
        };
        let mut device = CableQrCodeDevice::new_transient(hint, self.transports)
            .map_err(|e| BackendError::Failed(format!("creating QR code: {e}")))?;

        let prompt = Prompt {
            url: device.qr_code.to_string(),
            operation: request.operation,
            rp_id: request.rp_id.clone(),
        };
        let ui = self
            .presenter
            .show(&prompt)
            .await
            .map_err(|e| BackendError::Unavailable(format!("cannot show QR code: {e:#}")))?;

        let exchange = async {
            let mut channel = device
                .channel(ChannelSettings::default())
                .await
                .map_err(|e| BackendError::Failed(format!("opening hybrid channel: {e}")))?;

            let mut updates = channel.get_ux_update_receiver();
            let ui_updates = ui.clone();
            let relay = tokio::spawn(async move {
                while let Ok(update) = updates.recv().await {
                    debug!(?update, "hybrid update");
                    if let CableUxUpdate::CableUpdate(update) = update {
                        ui_updates.update(match update {
                            CableUpdate::ProximityCheck => UiStatus::ProximityCheck,
                            CableUpdate::Connecting => UiStatus::Connecting,
                            CableUpdate::Authenticating => UiStatus::Authenticating,
                            CableUpdate::Connected => UiStatus::Connected,
                            CableUpdate::Error(e) => UiStatus::Failed(e.to_string()),
                        });
                    }
                }
            });

            let cbor = CborRequest {
                command,
                encoded_data: request.cbor,
            };
            // Both calls first wait (without a timeout) for the tunnel to come up;
            // the overall deadline below bounds that.
            let result = async {
                channel.cbor_send(&cbor, self.timeout).await?;
                channel.cbor_recv(self.timeout).await
            }
            .await;
            // Send the caBLE Shutdown message. Without it the phone sees the tunnel
            // drop and shows "Something went wrong" even after a successful ceremony.
            channel.close().await;
            relay.abort();

            let response =
                result.map_err(|e| BackendError::Failed(format!("hybrid exchange: {e}")))?;
            let mut out = vec![u8::from(response.status_code)];
            out.extend(response.data.unwrap_or_default());
            Ok(out)
        };

        let result = tokio::select! {
            result = tokio::time::timeout(self.timeout, exchange) => {
                result.unwrap_or(Err(BackendError::Timeout))
            }
            _ = ctx.cancel.cancelled() => Err(BackendError::Cancelled),
            _ = ui.dismissed() => Err(BackendError::Dismissed),
        };

        match &result {
            Ok(_) => {
                info!("phone answered");
                ui.update(UiStatus::Done);
            }
            // Nothing to explain when the user or the browser gave up.
            Err(BackendError::Cancelled | BackendError::Dismissed) => {}
            Err(error) => ui.update(UiStatus::Failed(error.to_string())),
        }
        result
    }
}
