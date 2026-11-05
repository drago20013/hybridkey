# Testing

## Automated

```sh
cargo test --workspace
```

These tests cover CTAPHID framing (round-trips up to the 7609-byte maximum,
busy/sequence/length errors, INIT resync), CTAP2 request inspection, the
silent-probe list restoration for both allow and exclude lists, the deny
policy, device selection waiting for cancel, and config parsing.

## Without a phone

| Test | Command | Expect |
|---|---|---|
| Prerequisites | `hybridkeyd check` | all `ok` |
| QR window | `hybridkeyd test-prompt` | Window with a QR code, status walks through to "Done." |
| Dismissal | `hybridkeyd test-prompt`, press Esc | `prompt dismissed by the user` |
| Relay running | `systemctl status hybridkey-uhidd.socket` | `active (listening)` |
| Device appears | `hybridkeyd run` (or the service), then `fido2-token -L` | Lists `hybridkey phone passkey bridge` |
| getInfo | `fido2-token -I /dev/hidrawN` | `FIDO_2_0`, `rk`, `up`, `uv`, `maxmsgsiz: 7609`, transport `hybrid` |
| Web | <https://webauthn.io> in Firefox, open the security key prompt | A QR window appears |

## With a phone

Run the daemon from the checkout with debug logs (rebuilds first; log in `$XDG_RUNTIME_DIR/hybridkey-dev/daemon.log`):

```sh
systemctl --user stop hybridkey
scripts/dev-run                                # defaults
scripts/dev-run 'forward_allow_list = false'   # extra [ctap] settings
```

| # | Scenario | Client | Phone | Result |
|---|---|---|---|---|
| P1 | Register a passkey on webauthn.io | Firefox | Android / Google Password Manager | |
| P2 | Sign in with it (discoverable, empty allow list) | Firefox | Android | |
| P3 | Sign in with a username (non-empty allow list, exercises silent probes) | Firefox | Android | |
| P4 | Microsoft account / Entra ID sign-in with an Authenticator passkey | Firefox | Android 14+ / iOS 17+ | |
| P5 | Same as P2 with an iPhone (Apple tunnel server) | Firefox | iOS 17+ | |
| P6 | Cancel in the browser while the QR code is showing | Firefox | — | Window closes, browser shows cancelled |
| P7 | Close the QR window | Firefox | — | Browser reports failure |
| P8 | Let it time out (`hybrid.timeout_secs = 20`) | Firefox | — | Browser reports failure |
| P9 | Physical key plugged in as well | Firefox | — | Touching the physical key works; hybridkey does not steal selection |
| P10 | CLI client | `fido2-assert -G` / `fido2-cred -M` | Android | |
| P11 | Chromium (sees both its own hybrid and the virtual key) | Chromium | Android | |

Fill in the results, including phone model, OS version and provider.

## Results so far

| Date | What | Result |
|---|---|---|
| 2026-10-23 | Unit tests (17) | pass |
| 2026-10-23 | `test-prompt`: window, status updates, dismissal via exit status | pass |
| 2026-10-23 | udev `uaccess` rule: `/dev/uhid` and the new hidraw node get a user ACL | pass |
| 2026-10-23 | `fido2-token -L` / `-I` (libfido2 1.17): device listed, getInfo parsed | pass (after fixing canonical CBOR key order) |
| 2026-10-23 | `fido2-assert -G -r`: QR window appears, BLE proximity scan starts, killing the client cancels the ceremony | pass |
| 2026-10-23 | P1/P2 Firefox + Android (Google Play services) + Bitwarden: BLE proximity, tunnel (`cable.ua5v.com`), Noise handshake and phone getInfo all succeed; request reaches the phone | partial |
| 2026-10-23 | Same: tunnel closed by the far end exactly ~30 s after the request was sent, before the phone answered (3 of 3 attempts); phone showed "Something went wrong" | **open** |
| 2026-10-23 | libwebauthn 0.10 never sent caBLE Shutdown (phone shows an error even on success); moved to libwebauthn master with the fix (#310) and call `close()` | fixed (register now ends cleanly) |
| 2026-10-23 | P1 Firefox register on webauthn.io → Android + Bitwarden (phone answered in 13 s, Shutdown sent) | **pass** |
| 2026-10-23 | Chromium's own hybrid on the same phone: register works. Whether it survives >30 s on the phone is not yet confirmed | open |
| 2026-10-23 | P3 Firefox sign-in with username (allow list of 2 restored after probe) → phone shows "Something went wrong", tunnel closed after 30 s | **fail**, investigating (`up: true` normalisation added) |
| 2026-10-23 | Cancel in the QR window made Firefox retry forever (it treats OPERATION_DENIED as a failed built-in UV); now NOT_ALLOWED, and a phone's OPERATION_DENIED is translated too | fixed, needs retest |
| 2026-10-23 | Retest after the Cancel fix: Firefox sign-in on webauthn.io with username → Android + Bitwarden (3 s) | **pass** |
| 2026-10-23 | P4 Firefox sign-in to login.microsoft.com → phone (4 s) | **pass** |
| 2026-10-23 | P11 Chromium shows its own QR code plus ours; ours never connected | fixed by deferring to Chromium-based browsers (`ctap.defer_to`); verified with libfido2 (no QR, no BLE scan) |
| 2026-10-23 | Relay (`hybridkey-uhidd --listen`, unprivileged test run): device created for uid 1000 with `HID_UNIQ=hybridkey-1000`, libfido2 getInfo through the relay | pass |
| 2026-10-23 | Relay refuses a second device for the same uid; malformed packet closes the connection and removes the device; daemon exit removes the device | pass |
| 2026-10-23 | `systemd-analyze verify` on the relay socket/service and the user service | pass |
