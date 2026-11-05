use std::path::{Path, PathBuf};

use anyhow::Context as _;
use serde::Deserialize;

use crate::authenticator::ProbePolicy;
use crate::backend::hybrid::TransportMode;

#[derive(Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub device: DeviceConfig,
    pub hybrid: HybridConfig,
    pub ui: UiConfig,
    pub ctap: CtapConfig,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DeviceConfig {
    pub mode: DeviceMode,
    /// Socket of the hybridkey-uhidd relay (`relay` mode).
    pub relay_socket: PathBuf,
    /// `direct` mode only; the relay always uses its own fixed values.
    pub uhid_path: PathBuf,
    pub name: String,
    pub vendor_id: u32,
    pub product_id: u32,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum DeviceMode {
    /// Ask the privileged hybridkey-uhidd relay to create the device.
    Relay,
    /// Open /dev/uhid ourselves. Needs write access to it; for development.
    Direct,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HybridConfig {
    /// Overall deadline for one ceremony, from showing the QR code to the phone's answer.
    pub timeout_secs: u64,
    pub transports: TransportMode,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum PresenterKind {
    Command,
    Terminal,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UiConfig {
    pub presenter: PresenterKind,
    /// argv of the helper used by the `command` presenter.
    pub command: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CtapConfig {
    pub silent_probes: ProbePolicy,
    /// Send the site's credential list to the phone on sign-in. When false, the
    /// phone offers all of its passkeys for the site instead.
    pub forward_allow_list: bool,
    /// Programs (executable names) that do hybrid themselves; requests from
    /// them are left alone so only their own QR code shows.
    pub defer_to: Vec<String>,
}

impl Default for CtapConfig {
    fn default() -> Self {
        Self {
            silent_probes: ProbePolicy::default(),
            forward_allow_list: true,
            defer_to: crate::client::DEFAULT_DEFER_TO
                .iter()
                .map(|s| s.to_string())
                .collect(),
        }
    }
}

impl Default for DeviceConfig {
    fn default() -> Self {
        Self {
            mode: DeviceMode::Relay,
            relay_socket: hybridkey_uhid::relay::DEFAULT_SOCKET.into(),
            uhid_path: "/dev/uhid".into(),
            name: hybridkey_uhid::DEFAULT_NAME.into(),
            vendor_id: hybridkey_uhid::DEFAULT_VENDOR_ID,
            product_id: hybridkey_uhid::DEFAULT_PRODUCT_ID,
        }
    }
}

impl Default for HybridConfig {
    fn default() -> Self {
        Self {
            timeout_secs: 180,
            transports: TransportMode::default(),
        }
    }
}

impl Default for UiConfig {
    fn default() -> Self {
        Self {
            presenter: PresenterKind::Command,
            command: vec!["hybridkey-qr".into()],
        }
    }
}

impl Config {
    pub fn default_path() -> Option<PathBuf> {
        let base = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))?;
        Some(base.join("hybridkey").join("config.toml"))
    }

    /// Loads `path`, or the default location. A missing default file means defaults.
    pub fn load(path: Option<&Path>) -> anyhow::Result<Self> {
        let (path, explicit) = match path {
            Some(path) => (path.to_owned(), true),
            None => match Self::default_path() {
                Some(path) => (path, false),
                None => return Ok(Self::default()),
            },
        };
        match std::fs::read_to_string(&path) {
            Ok(text) => {
                toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && !explicit => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_config_parses() {
        let text = include_str!("../../../packaging/config.example.toml");
        let config: Config = toml::from_str(text).unwrap();
        assert_eq!(config.hybrid.timeout_secs, 180);
        assert_eq!(config.ui.presenter, PresenterKind::Command);
    }

    #[test]
    fn empty_config_is_default() {
        let config: Config = toml::from_str("").unwrap();
        assert_eq!(config.device.mode, DeviceMode::Relay);
        assert_eq!(config.device.uhid_path, PathBuf::from("/dev/uhid"));
        assert_eq!(config.ctap.silent_probes, ProbePolicy::Optimistic);
    }
}
