//! Runs an external helper to display the QR code. The prompt is written to the
//! helper's stdin (never its argv, which other local users can read via /proc);
//! closing stdin tells the helper to close its window.

use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use async_trait::async_trait;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::sync::{mpsc, watch};
use tracing::{debug, warn};

use super::{Presenter, Prompt, PromptHandle, UiStatus};

pub struct CommandPresenter {
    argv: Vec<String>,
}

impl CommandPresenter {
    pub fn new(argv: Vec<String>) -> anyhow::Result<Self> {
        anyhow::ensure!(!argv.is_empty(), "presenter command is empty");
        Ok(Self { argv })
    }
}

#[async_trait]
impl Presenter for CommandPresenter {
    async fn show(&self, prompt: &Prompt) -> anyhow::Result<Arc<dyn PromptHandle>> {
        let mut child = Command::new(&self.argv[0])
            .args(&self.argv[1..])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .with_context(|| format!("starting {}", self.argv[0]))?;
        let mut stdin = child.stdin.take().expect("stdin is piped");

        // The RP ID comes from the web page; keep it on one line.
        let rp_id: String = prompt.rp_id.chars().filter(|c| !c.is_control()).collect();
        let header = format!(
            "rp {rp_id}\nop {}\nurl {}\nshow\n",
            prompt.operation.short(),
            prompt.url
        );
        stdin
            .write_all(header.as_bytes())
            .await
            .context("writing to presenter")?;

        let (lines_tx, mut lines_rx) = mpsc::unbounded_channel::<String>();
        let (dismissed_tx, dismissed_rx) = watch::channel(false);

        tokio::spawn(async move {
            let mut stdin = Some(stdin);
            loop {
                tokio::select! {
                    line = lines_rx.recv(), if stdin.is_some() => match line {
                        Some(line) => {
                            let w = stdin.as_mut().unwrap();
                            if w.write_all(format!("{line}\n").as_bytes()).await.is_err() {
                                stdin = None;
                            }
                        }
                        // Handle dropped: EOF asks the helper to close.
                        None => {
                            drop(stdin.take());
                            match tokio::time::timeout(Duration::from_secs(5), child.wait()).await {
                                Ok(_) => {}
                                Err(_) => {
                                    warn!("presenter did not exit after EOF, killing it");
                                    let _ = child.kill().await;
                                }
                            }
                            return;
                        }
                    },
                    status = child.wait() => {
                        match status {
                            // Exit status 0 while the prompt is open means the user closed it.
                            Ok(status) if status.success() => {
                                debug!("presenter closed by the user");
                                let _ = dismissed_tx.send(true);
                            }
                            Ok(status) => warn!(%status, "presenter exited with an error"),
                            Err(error) => warn!(%error, "waiting for presenter"),
                        }
                        return;
                    }
                }
            }
        });

        Ok(Arc::new(CommandHandle {
            lines_tx,
            dismissed_rx,
        }))
    }
}

struct CommandHandle {
    lines_tx: mpsc::UnboundedSender<String>,
    dismissed_rx: watch::Receiver<bool>,
}

#[async_trait]
impl PromptHandle for CommandHandle {
    fn update(&self, status: UiStatus) {
        let _ = self.lines_tx.send(status.to_line());
    }

    async fn dismissed(&self) {
        let mut rx = self.dismissed_rx.clone();
        if rx.wait_for(|dismissed| *dismissed).await.is_err() {
            // The helper went away without being dismissed (crash, error):
            // keep waiting for the phone or the browser instead.
            std::future::pending::<()>().await
        }
    }
}
