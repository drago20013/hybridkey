# QR helper protocol

The `command` presenter runs `ui.command` (default `hybridkey-qr`) once per
ceremony. All data goes over the helper's **stdin**, one command per line. The
QR URL contains the session secret, so it is never put on the command line,
where other local users could read it from `/proc`.

## Daemon → helper (stdin)

| Line | Meaning |
|---|---|
| `rp <rp-id>` | Relying party, e.g. `login.microsoftonline.com`. Control characters are removed. |
| `op ga` / `op mc` | Sign in (getAssertion) or create a passkey (makeCredential). |
| `url FIDO:/<digits>` | Content for the QR code. |
| `show` | Everything is set; show the prompt. |
| `status <state> [detail]` | Progress update; see below. |
| EOF | The ceremony is over; close. |

Status states: `proximity` (scanning for the phone over Bluetooth), `connecting`, `authenticating`, `connected` (the
user now confirms on the phone), `done`, `failed <reason>`.

## Helper → daemon

Only the exit status counts:

- **0** while the prompt is still open: the user dismissed it. The daemon aborts
  the ceremony and the browser gets `CTAP2_ERR_NOT_ALLOWED`.
- **Non-zero**: the helper failed. The daemon logs it and keeps waiting for the
  phone or the browser.

Exiting after EOF is expected, and the status is then ignored.

## Writing your own

Any program that follows this protocol works, e.g. a layer-shell overlay, a
`notify-send` with an image, or a TUI. Set it in the config:

```toml
[ui]
command = ["/path/to/my-helper", "--some-flag"]
```

Test it without a phone using `hybridkeyd test-prompt`.
