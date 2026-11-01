# Observed session lifecycle — partial static analysis

This is not the proposed RemoteCore state machine and does not prove complete cleanup or reconnection semantics.

1. Server initialization (`src/server.rs::new`) registers shared services; rendezvous is initialized separately (`src/rendezvous_mediator.rs::RendezvousMediator::start_all`). Client starts via `src/client.rs::Client::start`; all direct/relay connection paths still need tracing.
2. `src/server/connection.rs::Connection::start` creates `Connection` with `authorized=false`, an unauthorized admission guard, channels and an async `tokio::select!` loop. Desktop input is handled on a separate thread. Admission code specifies an overall cap 64, per-address cap 16; unauthorized login grace is 180s. The comments identify the per-address cap as not a security boundary.
3. `Connection::on_message` handles close reason, login scope, login/2FA and permission/authorized message dispatch; connection-manager IPC can authorize or close. `send_logon_response_and_keep_alive` sets `authorized=true` and releases the unauthorized guard after checks, then prepares response and services. The exact authentication decision tree and owner approval alternatives remain to be mapped.
4. Timer logic sends `TestDelay` and closes on 30s receive inactivity; an independent auto-disconnect policy can close. An owner can close through connection-manager IPC; reconnect behavior differs by close reason. Actual client retry policy must be audited rather than assumed.
5. `Connection::on_close` uses `closed` for idempotence, informs connection manager, optionally locks the screen and closes forwarding. Other resources are released via surrounding loop and RAII; `on_close` alone does not demonstrate every resource or pressed key is released.

Open questions: exact handshake state transitions, session IDs vs connection IDs, multiple viewers and shared resource ownership, cancellation of each background thread, authentication/timeouts, key releases under disconnect, reconnection and failure states. Audit and test before defining API contracts.
