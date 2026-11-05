# Architecture

hybridkey is three programs and a library:

- **`hybridkeyd`**: the daemon. It runs as a systemd *user* service.
- **`hybridkey-qr`**: a small GTK 4 window that shows the QR code. The daemon
  starts it for each ceremony.
- **`hybridkey-uhidd`**: a tiny socket-activated *system* service that owns
  `/dev/uhid` and creates the virtual key on the daemon's behalf (see
  [security.md](security.md#the-uhid-relay)).
- **`hybridkey-uhid`**: the shared library for `/dev/uhid` and the relay's wire
  protocol.

## Layers in `hybridkeyd`

| Module | Responsibility |
|---|---|
| `device.rs` | The virtual HID device: through the `hybridkey-uhidd` relay (default), or directly on `/dev/uhid` (`device.mode = "direct"`, development only). The FIDO report descriptor (usage page `0xF1D0`, fixed in `hybridkey-uhid`) makes udev's `fido_id` tag the hidraw node as a security token, so browsers find it and the logged-in user can open it. |
| `ctaphid.rs` | Pure CTAPHID framing: splits messages into 64-byte reports and reassembles them. Unit tested. |
| `hid.rs` | CTAPHID transport: channel IDs (`INIT`), `PING`, `WINK`, `CANCEL`, keepalives every 100 ms, `CHANNEL_BUSY`. Runs one CBOR transaction at a time. |
| `authenticator.rs` | The CTAP2 authenticator: answers `getInfo`, silent probes and selection requests itself, and forwards `makeCredential`/`getAssertion` to the backend. |
| `ctap2.rs` | CTAP2 constants and the minimal CBOR inspection and rewriting the authenticator needs. |
| `backend/` | `Backend` trait. `hybrid.rs` uses libwebauthn's `CableQrCodeDevice` and passes the browser's CTAP2 bytes through unchanged (`cbor_send`/`cbor_recv`). |
| `presenter/` | `Presenter` trait. `command.rs` runs `hybridkey-qr` (or any program that speaks [the protocol](qr-helper-protocol.md)). `terminal.rs` prints the QR code to the log. |
| `client.rs` | Finds which programs hold the hidraw node open (`/proc/*/fd`), so requests from browsers with built-in hybrid can be left alone. |
| `config.rs` | Optional TOML config. |

Each of the three boundaries (device, backend, presenter) is a trait or a
self-contained module. That makes it possible, for example, to add a
"remembered phone" backend or a layer-shell presenter without touching the CTAP
code.

## Ceremony flow

1. The browser opens the hidraw node, sends `CTAPHID_INIT` and then
   `authenticatorGetInfo`. hybridkeyd answers: CTAP 2.0, `uv: true`, `rk: true`,
   no `clientPin`, transport `hybrid`. Because there is no PIN, browsers send
   `uv: true` directly and never try a PIN protocol. The phone does user
   verification itself.
2. The browser sends `makeCredential` or `getAssertion`. The authenticator sets
   the keepalive status to `UPNEEDED`, so the browser shows "touch your key".
   Then it hands the request to the hybrid backend.
3. The backend creates a fresh caBLE QR code (P-256 key and QR secret). The
   presenter shows it, writing the URL to the helper's stdin.
4. The phone scans the code and advertises over BLE (the proximity check).
   libwebauthn finds the advert, connects to the tunnel server the phone chose
   (Google's `cable.ua5v.com` or Apple's `cable.auth.com`), and runs the Noise
   handshake.
5. The browser's CTAP2 bytes go to the phone unchanged. The phone shows its
   passkey UI, the user approves, and the phone's CTAP2 response comes back.
6. The response goes back to the browser in CTAPHID frames. The QR window
   closes.

If the user closes the window, the browser cancels (`CTAPHID_CANCEL`), the
browser closes the device, or `hybrid.timeout_secs` expires, the hybrid
connection is dropped and the browser gets a CTAP error.

## Silent probes

Before a real request, Firefox (authenticator-rs) sends `getAssertion` with
`up: false` to find out which credentials in the allow or exclude list the key
holds. It then sends only those. A phone over hybrid cannot answer silent
requests.

Answering "no credentials" would make Firefox abort with an error. Answering a
real "yes" is impossible. So with `ctap.silent_probes = "optimistic"` (the
default), hybridkey:

1. Answers the probe with a syntactically valid assertion claiming the first
   credential. Browsers only use this to filter the list. It never reaches a
   relying party.
2. Remembers the full list for that RP ID, for 2 minutes.
3. When the real request arrives with the narrowed list, it puts the full list
   back. The phone then picks whichever passkey it actually has.

The WebAuthn API cannot produce `up: false` requests, so this only affects the
browser's own probing.

## Device selection ("blink")

With several keys plugged in, browsers send each key a dummy `makeCredential`
(RP ID `make.me.blink` in Firefox, `.dummy` in Chromium) and use whichever is
touched first. hybridkey never claims to be touched, because that would steal
selection from physical keys. It waits until the browser cancels. So with a
hardware key also plugged in, the hardware key wins unless you remove it.

## Browsers that already do hybrid

Chromium-based browsers have their own "use a phone or tablet" support on
Linux. They also see the virtual key, so both QR codes would appear. Before
forwarding a ceremony, hybridkey looks up which processes have its hidraw node
open. If every one of them is listed in `ctap.defer_to` (by default Chrome,
Chromium, Brave, Edge, Vivaldi and Opera), it does not show a QR code or start a
Bluetooth scan. It waits like an untouched key until the browser cancels.

## Why a virtual USB key and not a browser patch?

Every Linux browser and WebAuthn library already supports USB HID security
keys, sandboxed Flatpak browsers included (through the browser's own device
access). A virtual key needs no browser changes. A D-Bus portal
(`credentialsd`) is the long-term upstream answer, but it needs browser
integration that does not exist yet.
