use std::sync::Arc;

use async_trait::async_trait;
use qrcode::render::unicode;
use qrcode::QrCode;
use tracing::info;

use super::{Presenter, Prompt, PromptHandle, UiStatus};

pub struct TerminalPresenter;

#[async_trait]
impl Presenter for TerminalPresenter {
    async fn show(&self, prompt: &Prompt) -> anyhow::Result<Arc<dyn PromptHandle>> {
        let image = QrCode::new(prompt.url.as_bytes())?
            .render::<unicode::Dense1x2>()
            .dark_color(unicode::Dense1x2::Light)
            .light_color(unicode::Dense1x2::Dark)
            .build();
        eprintln!(
            "\nScan with your phone to {} on {}:\n{image}\n",
            match prompt.operation {
                crate::backend::Operation::MakeCredential => "create a passkey",
                crate::backend::Operation::GetAssertion => "sign in",
            },
            prompt.rp_id
        );
        Ok(Arc::new(TerminalHandle))
    }
}

struct TerminalHandle;

#[async_trait]
impl PromptHandle for TerminalHandle {
    fn update(&self, status: UiStatus) {
        info!(status = status.to_line(), "prompt update");
    }

    async fn dismissed(&self) {
        std::future::pending::<()>().await
    }
}
