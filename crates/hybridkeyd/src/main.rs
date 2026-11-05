//! hybridkeyd: a virtual FIDO2 USB security key that forwards WebAuthn
//! ceremonies to a phone over the hybrid (caBLE) transport.

mod authenticator;
mod backend;
mod client;
mod config;
mod ctap2;
mod ctaphid;
mod device;
mod hid;
mod presenter;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};
use tokio::signal::unix::{signal, SignalKind};
use tracing::info;
use tracing_subscriber::EnvFilter;

use crate::authenticator::Authenticator;
use crate::backend::hybrid::HybridBackend;
use crate::backend::Operation;
use crate::config::{Config, DeviceMode, PresenterKind};
use crate::presenter::command::CommandPresenter;
use crate::presenter::terminal::TerminalPresenter;
use crate::presenter::{Presenter, Prompt, UiStatus};

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// Configuration file (default: $XDG_CONFIG_HOME/hybridkey/config.toml).
    #[arg(long, global = true)]
    config: Option<PathBuf>,

    /// Print the QR code to the log instead of running the helper window.
    #[arg(long, global = true)]
    terminal: bool,

    #[command(subcommand)]
    command: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create the virtual security key and serve requests (default).
    Run,
    /// Check that everything the daemon needs is available.
    Check,
    /// Show a dummy QR prompt to test the presenter. The code is not usable.
    TestPrompt,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_env("HYBRIDKEY_LOG").unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();
    let mut config = Config::load(cli.config.as_deref())?;
    if cli.terminal {
        config.ui.presenter = PresenterKind::Terminal;
    }

    match cli.command.unwrap_or(Cmd::Run) {
        Cmd::Run => run(config).await,
        Cmd::Check => check(&config).await,
        Cmd::TestPrompt => test_prompt(&config).await,
    }
}

fn presenter(config: &Config) -> anyhow::Result<Arc<dyn Presenter>> {
    Ok(match config.ui.presenter {
        PresenterKind::Command => Arc::new(CommandPresenter::new(config.ui.command.clone())?),
        PresenterKind::Terminal => Arc::new(TerminalPresenter),
    })
}

/// A fixed AAGUID for this authenticator model. Attestation comes from the
/// phone, so relying parties never see it; only the browser does.
fn aaguid() -> [u8; 16] {
    Sha256::digest(b"hybridkey virtual authenticator")[..16]
        .try_into()
        .unwrap()
}

async fn run(config: Config) -> anyhow::Result<()> {
    let backend = Arc::new(HybridBackend::new(
        presenter(&config)?,
        Duration::from_secs(config.hybrid.timeout_secs),
        config.hybrid.transports,
    ));
    let authenticator = Arc::new(
        Authenticator::new(backend, config.ctap.silent_probes, aaguid())
            .with_allow_list_forwarding(config.ctap.forward_allow_list)
            .deferring_to(config.ctap.defer_to.clone(), None),
    );

    let device = match config.device.mode {
        DeviceMode::Relay => device::HidDevice::relay(&config.device.relay_socket)
            .await
            .with_context(|| {
                format!(
                    "connecting to the hybridkey-uhidd relay at {} \
                     (is hybridkey-uhidd.socket enabled and are you in the hybridkey group?)",
                    config.device.relay_socket.display()
                )
            })?,
        DeviceMode::Direct => {
            let uniq = hybridkey_uhid::device_uniq(client::current_uid());
            device::HidDevice::direct(
                &config.device.uhid_path,
                &hybridkey_uhid::DeviceInfo {
                    name: &config.device.name,
                    uniq: &uniq,
                    vendor_id: config.device.vendor_id,
                    product_id: config.device.product_id,
                },
            )
            .with_context(|| {
                format!(
                    "creating the virtual HID device via {} (direct mode needs write access to it)",
                    config.device.uhid_path.display()
                )
            })?
        }
    };
    info!("virtual security key ready");

    let mut sigterm = signal(SignalKind::terminate())?;
    tokio::select! {
        result = hid::HidServer::new(device, authenticator).run() => result,
        _ = tokio::signal::ctrl_c() => { info!("interrupted, removing device"); Ok(()) }
        _ = sigterm.recv() => { info!("terminated, removing device"); Ok(()) }
    }
}

async fn check(config: &Config) -> anyhow::Result<()> {
    let mut ok = true;
    let mut report = |good: bool, what: &str, detail: String| {
        ok &= good;
        println!("[{}] {what}: {detail}", if good { " ok " } else { "FAIL" });
    };

    match config.device.mode {
        DeviceMode::Relay => {
            let socket = &config.device.relay_socket;
            let writable = std::ffi::CString::new(socket.as_os_str().as_encoded_bytes())
                // SAFETY: valid NUL-terminated path.
                .is_ok_and(|path| unsafe { libc::access(path.as_ptr(), libc::W_OK) } == 0);
            report(
                writable,
                "relay",
                if writable {
                    format!("{} is accessible", socket.display())
                } else if socket.exists() {
                    format!(
                        "{}: permission denied (join the hybridkey group, then log in again)",
                        socket.display()
                    )
                } else {
                    format!(
                        "{} missing (enable hybridkey-uhidd.socket)",
                        socket.display()
                    )
                },
            );
        }
        DeviceMode::Direct => {
            let uhid = &config.device.uhid_path;
            match std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(uhid)
            {
                Ok(_) => report(true, "uhid", format!("{} is writable", uhid.display())),
                Err(e) => report(false, "uhid", format!("{}: {e}", uhid.display())),
            }
        }
    }

    let bt = HybridBackend::bluetooth_available().await;
    report(
        bt,
        "bluetooth",
        if bt {
            "adapter found".into()
        } else {
            "no powered adapter".into()
        },
    );

    match config.ui.presenter {
        PresenterKind::Terminal => report(true, "presenter", "terminal".into()),
        PresenterKind::Command => {
            let program = config.ui.command.first().map(String::as_str).unwrap_or("");
            let found = which(program);
            report(
                found.is_some(),
                "presenter",
                match found {
                    Some(path) => format!("{}", path.display()),
                    None => format!("{program:?} not found in PATH"),
                },
            );
        }
    }

    match Config::default_path() {
        Some(path) if path.exists() => println!("config: {}", path.display()),
        Some(path) => println!("config: {} (not present, using defaults)", path.display()),
        None => println!("config: defaults"),
    }
    anyhow::ensure!(ok, "some checks failed");
    Ok(())
}

async fn test_prompt(config: &Config) -> anyhow::Result<()> {
    let prompt = Prompt {
        url: "FIDO:/hybridkey-test-prompt-not-a-real-code".into(),
        operation: Operation::GetAssertion,
        rp_id: "login.microsoftonline.com".into(),
    };
    let handle = presenter(config)?.show(&prompt).await?;
    let steps = [
        UiStatus::ProximityCheck,
        UiStatus::Connecting,
        UiStatus::Authenticating,
        UiStatus::Connected,
        UiStatus::Done,
    ];
    let walk = async {
        for status in steps {
            tokio::time::sleep(Duration::from_secs(2)).await;
            handle.update(status);
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    };
    tokio::select! {
        _ = walk => println!("prompt test finished"),
        _ = handle.dismissed() => println!("prompt dismissed by the user"),
    }
    Ok(())
}

fn which(program: &str) -> Option<PathBuf> {
    if program.contains('/') {
        let path = PathBuf::from(program);
        return path.is_file().then_some(path);
    }
    std::env::var_os("PATH")?
        .to_str()?
        .split(':')
        .map(|dir| PathBuf::from(dir).join(program))
        .find(|p| p.is_file())
}
