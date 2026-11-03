# Two-system view-only diagnostic (written, not yet run)

This is an experimental manual check, **not** a finished remote-desktop
application. It sends one to ten separately captured, private compressed VP9
envelopes from an interactive host to a viewer. The default is one. This uses
an explicit non-decoding-sink API, rather than asserting the viewer supports a
VP9 decoder. The viewer only reports metadata and byte count;
it does **not** decode, render, save or validate screen pixels. It does not
send mouse/keyboard input. Completion is not proof of production security,
video interoperability, correct pixels, performance or usable remote control.
The native decoder remains unsafe for untrusted network input, even when a
peer is pinned or password-authenticated; do not decode the received envelope.

Use only two explicitly authorized disposable machines on an isolated trusted
LAN, with a host owner physically present. Do not expose this to the internet,
configure port forwarding, use a shared/public network, or run on a secure
Windows/UAC desktop. Close firewalls again afterward. The shared-password proof
allows offline guessing; host verification depends on a correctly provisioned
public-key pin. The exact socket IP allowlist is not viewer authentication, and
NAT/proxies can conceal or share it. The CLI approval prompt is not a trusted
OS consent UI and does not stop other processes from capturing. There is no
rate limiter, server 2FA, trusted-device policy or production security review.

## Prerequisites on both systems

1. Use the **same committed source snapshot**, including the `libs/hbb_common`
   submodule at the recorded baseline. The exported source candidate includes
   the submodule contents but is not an independently verified build or release.
2. Install Node.js 20, Rust stable, MSVC C++ toolchain and source-native build
   dependencies. The current Windows workflow documents its pinned vcpkg
   revision and installs `libvpx`, `libyuv`, and `aom` using the
   `x64-windows-static` triplet. Native configuration must match the local
   toolchain; these instructions have not been verified on a real desktop.
3. From `remote-core/bindings/node`, run `npm run build` on each machine. This
   builds a native addon for that machine, it does not ship a binary. Stop if
   compilation, linkage or dependency setup fails. No current build is claimed.
4. Pick a unique, high-entropy shared secret of at least 20 UTF-8 bytes. Transfer
   it securely out of band and set `REMOTE_CORE_DEMO_PASSWORD` on each machine
   without placing it in commands, source files, logs or chat. Environment
   variables and JavaScript strings are not secure storage and cannot be erased
   reliably; remove the variable and rotate the secret after the diagnostic.

## Host, then viewer

Use a specific LAN interface address, **not** `0.0.0.0`/`::` or any alternate
spelling of an unspecified address. Scoped IPv6 literals are not supported by
this diagnostic. The host must know
the source IP that the viewer's socket actually presents. Select an unoccupied
port, or use `0` and note the selected port printed by the host. On the host,
from the Node binding directory:

```powershell
node examples/two-system-host.cjs --acknowledge-network-exposure HOST_LAN_IP 0 VIEWER_LAN_IP demo-host host-pin.bin 0
```

`host-pin.bin` must not already exist. Each listener generates a **new** key;
copy its 32-byte public pin to the viewer via an authenticated independent
channel, and verify the printed SHA-256 fingerprint through that channel too.
The pin has no confidentiality requirement, but replacing it breaks identity
verification. A previous run's pin must never be reused for a new listener.
Do not rely on a fingerprint received solely over the connection being tested.

On the viewer, after independently verifying the host identity and fingerprint,
run (replace values with the actual nonzero port and verified lowercase hash):

```powershell
node examples/two-system-viewer.cjs --acknowledge-trusted-host HOST_LAN_IP ACTUAL_PORT demo-host host-pin.bin VERIFIED_64_HEX_SHA256 0
```

The host checks one socket IP, receives the login, then asks its local operator
to type `YES` within 30 seconds. Only after that confirmation does it approve
viewing and attempt the requested bounded captures. The listener's overall accept/login
and approval deadline is 180 seconds from starting `accept`; a connection that
arrives near the deadline may expire before approval. Approval and native
capture can fail on locked/non-interactive desktops, missing permissions,
changed display topology, VPX no-output or `WouldBlock`; the diagnostic ends
rather than claiming success. Its display index is a volatile local index.
Use a disposable visible desktop and avoid displaying sensitive data.

To request more than one frame, append the **same** count (1–10) to both
commands. The host displays that maximum before asking for approval. It waits
for one receipt before each next capture; every capture reopens a capturer and
creates a new encoder, so this is neither a continuous stream nor a performance
test. A mismatch of counts causes timeout/closure, not automatic negotiation.

The viewer reports each expected VP9 wire envelope and sends the existing
connection-wide `VideoReceived` notification. The host waits for that untrusted
claim, which carries no display or sequence identifier and proves neither
decoding nor rendering. Each wait for a video envelope shares a 30-second
receive budget across at most 20 control messages; the subsequent receipt send
has its own 10-second deadline. Each receipt wait shares a 10-second budget
across at most 20 heartbeats, and rejects other control messages. These are
cooperative deadlines, not guarantees against a blocked native operation.
A timeout or uncertain send ends the session; no retry is safe on that connection. Close both sessions, remove temporary pin copies, clear the shared
secret from both environments and revert firewall rules. Never log credentials,
peer claims or frame bytes. If an error occurs, stop and inspect it rather than
retrying uncertain network sends on the same session.

## Validation still required

The scripts and all recent prototype changes are unbuilt and untested. First
run build/unit/Node CI, then use a loopback-only synthetic mock, then an isolated
LAN with two interactive Windows machines. Verify firewall behavior, fresh pin
transfer, simultaneous connect/approval deadlines, cancellation and cleanup,
wrong/expired approvals, changed IP and display, close races, oversized frames,
VPX no-output and privacy. A future renderer/input path needs separate threat
model, native decoder hardening, consent design and real-device validation.

### Optional ACK-paced burst mode (unbuilt/unrun)

After the independent-frame diagnostic and all build/unit validation succeed,
both operators can append the same frame count and `ack-burst` to their
commands, for example `0 3 ack-burst` in place of the final display argument
on both commands. The host uses a single encoder for a bounded five-second
burst and the viewer requests source ACK pacing. The CLI still receives and
acknowledges compressed envelopes only; it does not decode or render. This is
not a test of usable remote desktop video or input. A static screen or source
VPX no-output may yield fewer than the requested frames; a timeout, topology
change, unexpected event, ACK ambiguity or mode mismatch is reported as a
failure, not retried on the same connection. Native calls can exceed five
seconds. Receipt claims remain untrusted and unsequenced, and do not prove the
correct frame was processed. The new mode itself has never been built or run
on either system; the same isolated-LAN and consent restrictions apply.

The current scripts request cooperative shutdown on Ctrl+C. During an active
viewer connection attempt the request handle cancels the pending TCP/login;
after connection the viewer uses `requestClose()`. The host requests listener
and session closure and cancels an outstanding approval prompt. The scripts
then await the active Promise and explicitly close owned objects. This is a
best-effort diagnostic convenience, not guaranteed OS cleanup or proof that
bytes were not delivered: synchronous capture, crypto, blocking I/O, forced
process termination and runtime failures may delay or bypass it. Repeated
Ctrl+C is not a hard-kill mechanism while the handler is installed. If the
owner sees a cleanup error, stop and inspect it. This path is unbuilt/unrun.

The diagnostic does not exercise keyboard input. Separately, the experimental
viewer exposes `sendWindowsTranslateText(text, acknowledgeSourceEffects,
timeoutMs)` for the existing source Translate/Seq wire form. It is rejected
unless the boolean is true; that acknowledgement is **not** host consent or
permission. RustDesk's Windows implementation can release Shift or synthesize
layout modifiers into the focused application, and its pinned rdev code
truncates each non-BMP scalar to its low 16 bits instead of encoding a UTF-16
surrogate pair. The prototype host does not implement this path. Do not use it
against a real desktop without separate owner approval, input arbitration and
Windows validation. The implementation and fixtures have not been run.
