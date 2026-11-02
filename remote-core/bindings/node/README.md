# Experimental Node-API capture binding

This is a partial binding, not a Node remote desktop SDK. It currently exposes
only display enumeration and a single raw capture using RustDesk's existing
capture adapter. It does not expose input injection, a session, networking,
codec negotiation, secure transport or authentication. No binary is shipped.
The API and build have not been tested.

Install the same Rust/native dependencies needed by the Rust workspace, then:

```powershell
cd remote-core/bindings/node
npm run build
node -e "require('./').listDisplays().then(console.log).catch(console.error)"
```

`listDisplays()` and `captureDisplay(index, timeoutMs)` return promises and run
on a libuv worker, but a native backend may block beyond the timeout hint.
Only one capture operation runs at a time; concurrent operations are rejected.
Display indices are snapshots and may refer to different monitors after
hotplug; callers must not use them as stable identifiers. The copied frame is
limited to 64 MiB, but backend allocations, JS-held frames and libuv work queues
are not included in this limit. Frame bytes may include padding; inspect the
format and per-plane strides rather than assuming RGBA. `WouldBlock`, permission
errors, desktop changes and unsupported texture frames reject the promise.

Capture contains private screen data. Invoke only with the local user's
permission and avoid logging or transmitting frame buffers. This binding is not
an OS security boundary and has no trusted-consent UI. Use a disposable
interactive Windows desktop for manual verification.
