# hybridkey

Use the passkeys on your phone (Microsoft Authenticator, Google Password
Manager, iCloud Keychain, …) from **any** Linux browser or app, including
Firefox, which has no "use a phone" option on Linux.

hybridkey creates a virtual FIDO2 USB security key. When a site asks that key to
sign in, hybridkey shows a QR code. You scan it with your phone, and hybridkey
forwards the request over the FIDO **hybrid** transport (formerly caBLE). That is
the same protocol Chrome, Windows and macOS use for "sign in with a phone".

```
Firefox / any WebAuthn client
        │  CTAP2 over USB HID          (every browser already speaks this)
        ▼
virtual FIDO key  ◄── hybridkey-uhidd (tiny root relay, owns /dev/uhid)
        │  64-byte reports over a socket for the hybridkey group
        ▼
hybridkeyd (your user)
        │  hybrid / caBLE v2: QR code + BLE proximity check + tunnel server
        ▼
Phone → Microsoft Authenticator / Google / iCloud passkey
```

> **Status: experimental.** See [docs/testing.md](docs/testing.md) for what has
> been verified so far.

## Requirements

- Linux with the `uhid` kernel module (every distribution kernel has it).
- A Bluetooth adapter that BlueZ can scan with, on the computer.
- Bluetooth and internet on the phone. Android 9+ with Google Play services, or
  iOS 16+. For Microsoft Authenticator passkeys: Android 14+ or iOS 17+.
- Runtime packages: `bluez`, `dbus`, `gtk4`.

## Install

### Arch / Omarchy (local package)

```sh
cd packaging/arch && makepkg -si
sudo systemctl enable --now hybridkey-uhidd.socket
sudo usermod -aG hybridkey "$USER"     # then log out and back in
hybridkey-toggle on
```

### From source

```sh
make
sudo make install          # PREFIX=/usr by default
sudo make activate         # create the group, start the relay socket
sudo usermod -aG hybridkey "$USER"     # then log out and back in
hybridkey-toggle on        # enable the user service
```

`hybridkey-toggle on` checks these prerequisites and tells you what is missing.

### Omarchy window rule

The QR window should float, be centred, and be hidden from screen shares. To set
that up, copy the rule and load it from your Hyprland config:

```sh
cp /usr/share/hybridkey/hypr/hybridkey.lua ~/.config/hypr/hybridkey.lua
echo 'require("hypr.hybridkey")' >> ~/.config/hypr/hyprland.lua
```

## Use

1. Sign in on a site and choose the security key / passkey option.
2. A window shows a QR code. Scan it with your phone's camera app. (In
   Authenticator itself, use the camera, not the QR scanner for accounts.)
3. Approve on the phone. The browser gets the answer as if a USB key had
   answered.

Close the window or press Esc to cancel.

## Turning it on and off

| What | How |
|---|---|
| Enable for this user (starts at login) | `hybridkey-toggle on` |
| Disable | `hybridkey-toggle off` |
| Status | `hybridkey-toggle status` |
| Check prerequisites | `hybridkeyd check` |
| Stop offering keys to anyone | `sudo systemctl disable --now hybridkey-uhidd.socket` |
| Remove completely | `pacman -R hybridkey`, or `sudo make uninstall` (then `sudo groupdel hybridkey`) |

When the service is stopped, the virtual key disappears, as if unplugged.
Nothing else on the system changes.

## Configuration

Optional: `~/.config/hybridkey/config.toml`. All keys and defaults are in
[packaging/config.example.toml](packaging/config.example.toml).

Logs: `journalctl --user -u hybridkey`. For more detail, set
`HYBRIDKEY_LOG=debug` (for example with `systemctl --user edit hybridkey`).

## Limitations

- Chromium-based browsers (Chrome, Chromium, Brave, Edge, Vivaldi, Opera)
  already do hybrid themselves on Linux. hybridkey recognises them and stays out
  of the way, so you only see their own QR code (`ctap.defer_to`).
- One sign-in per QR scan. The "remember this phone" (state-assisted) mode is
  not implemented yet.
- Firefox probes keys silently before signing in, which a phone cannot answer.
  hybridkey answers optimistically and sends the phone the full credential list,
  so the phone still picks the right passkey. See
  [docs/architecture.md](docs/architecture.md#silent-probes).

## Documentation

- [Architecture](docs/architecture.md): how the pieces fit together
- [Security](docs/security.md): threat model and audit checklist
- [Testing](docs/testing.md): test plan and results
- [QR helper protocol](docs/qr-helper-protocol.md): replacing the GTK window

## License

LGPL-2.1-or-later. hybridkey uses [libwebauthn](https://github.com/linux-credentials/libwebauthn)
from the Credentials for Linux project for the hybrid transport.
