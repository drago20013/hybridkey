# Security

## What hybridkey can and cannot do

hybridkey holds **no keys and no secrets** that outlive a ceremony. Each QR code
uses a fresh ephemeral P-256 key and QR secret. Passkeys stay on the phone.
Signatures and attestations are produced by the phone and passed through
unchanged. The browser still computes `clientDataHash` and enforces the origin
→ RP ID binding, exactly as it does for a USB key.

## Trust boundaries

| Boundary | Who is on the other side | Notes |
|---|---|---|
| hidraw node | Any process of the logged-in user (via `uaccess`) | Same as a physical FIDO key: any local process of the user can send requests. A ceremony still needs the user to scan a new QR code and approve on the phone, and both screens show the RP ID. |
| Relay socket | Members of the `hybridkey` group with an active seat session | Can only get one FIDO device each, with a fixed descriptor, and exchange 64-byte reports. |
| BLE | Nearby radios | caBLE adverts are encrypted with a key derived from the QR secret. They only prove proximity. |
| Tunnel server | Google or Apple | Relays Noise-encrypted traffic. It cannot read or change CTAP messages. The same infrastructure Chrome, Windows and macOS use. |
| QR helper | Process started by the daemon | Gets the QR URL on stdin, never in argv. The Omarchy window rule hides it from screen sharing. |
| Config file | The user | Selects the helper command. Only the user can write it, and the daemon runs as that user. |

## The uhid relay

`/dev/uhid` can create *any* HID device, keyboards included. Giving a desktop
user write access to it would let any of their processes inject keystrokes,
bypassing Wayland's client isolation. So `/dev/uhid` keeps its default
root-only permissions, and a tiny relay creates the one device hybridkey needs.

`hybridkey-uhidd` (about 250 lines, `std` + `libc` only):

- **Socket-activated:** it listens on `/run/hybridkey-uhidd.sock`
  (`SOCK_SEQPACKET`, `root:hybridkey 0660`). Only users an administrator has put
  in the `hybridkey` group can connect.
- **Per-connection checks:** for each connection it reads the peer's UID
  (`SO_PEERCRED`) and refuses it unless that user has an **active session on a
  seat** (`sd_uid_get_seats`). That is the same user `uaccess` gives the
  resulting hidraw node to. It also refuses a **second device** for the same
  user.
- **Fixed device:** it always creates the device with the fixed FIDO report
  descriptor, name and VID/PID. The client cannot choose any of them.
- **Narrow protocol:** the client can only send `INPUT` + exactly 64 bytes. Any
  other packet closes the connection and removes the device. The device is
  removed when the connection closes.
- **Sandbox:** it runs as root only for DAC access to `/dev/uhid`, with an empty
  capability bounding set, `DevicePolicy=closed` + `DeviceAllow=/dev/uhid`, no
  network, a read-only system, a syscall filter and no namespaces.

Worst case if the relay were compromised by a group member: it can create HID
devices, the same power the rejected udev rule would have given. Hence keeping
it small and auditable.

## Client detection

To leave Chromium-based browsers alone, the daemon reads the `/proc/<pid>/fd`
symlinks and `/proc/<pid>/exe` of the user's own processes. It does this only
while a ceremony starts, and only compares paths. Executable names can be
spoofed by any local program; the worst outcome is that hybridkey ignores that
program's request, which it could cause anyway by not using the key.

## Privacy

- Using hybrid contacts Google's or Apple's tunnel server, depending on the
  phone. Chrome does the same.
- BLE scanning runs only during a ceremony.
- Logs contain RP IDs and CTAP status codes at `info` level. They never contain
  the QR URL, credential IDs or CBOR payloads. At `debug` level, CTAP command
  bytes and lengths are logged, plus libwebauthn's own debug output.

## Audit checklist

| # | Item | Where |
|---|---|---|
| A1 | ~~udev `uaccess` on `/dev/uhid`~~ replaced by `hybridkey-uhidd`; review the relay (peer checks, packet validation, thread-per-connection resource use) | `crates/hybridkey-uhidd`, `crates/hybridkey-uhid` |
| A2 | CTAPHID parser robustness: lengths, sequence numbers, interleaving, oversized messages (unit tests exist; add fuzzing with `cargo fuzz` on `Assembler::push`) | `ctaphid.rs` |
| A3 | CBOR parsing of untrusted requests: `ciborium` limits on nesting and size; messages are capped at 7609 bytes by CTAPHID | `ctap2.rs` |
| A4 | Silent-probe answer cannot reach a relying party: it is only produced for `up: false`, which WebAuthn cannot request | `authenticator.rs` |
| A5 | Probe cache cannot inject credentials across RPs: keyed by RP ID, used only when the real list is a subset, 2-minute TTL | `authenticator.rs` |
| A6 | QR URL never in argv, logs or the environment | `presenter/` |
| A7 | RP ID shown in the UI is sanitised (control characters removed); GTK labels are not markup | `presenter/command.rs`, `hybridkey-qr` |
| A8 | Cancellation: browser cancel, hidraw close, window close and timeout all drop the hybrid connection | `hid.rs`, `backend/hybrid.rs` |
| A9 | libwebauthn version pin and review of its caBLE implementation (Noise handshake, EID decryption, tunnel domain derivation) | `Cargo.lock` |
| A10 | systemd sandboxing of both units; check `systemd-analyze security hybridkey-uhidd.service` | `packaging/systemd` |
| A11 | VID/PID: replace the pid.codes test PID with an assigned one before distribution | `config.rs` |
| A12 | Client detection via `/proc` cannot make hybridkey act on someone else's behalf; it can only suppress the QR code | `client.rs` |
