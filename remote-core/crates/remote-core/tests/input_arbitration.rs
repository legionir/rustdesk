//! Fake input backend only; no real Windows desktop interaction.
use remote_core::{input_arbiter::{ArbitrationError, InputArbiter}, HostInputSession};
use remote_input::{InputBackend, MouseButton, VirtualKey};
use remote_security::{password_response, OwnerApproval, PasswordVerifier};
use remote_session::{Credential, Permissions, Principal, SessionId};
use std::{cell::Cell, io, rc::Rc, time::Duration};

#[derive(Clone, Default)]
struct Fake { fail_release: Rc<Cell<bool>> }
impl InputBackend for Fake {
    fn move_to(&mut self, _: i32, _: i32) -> io::Result<()> { Ok(()) }
    fn mouse_down(&mut self, _: MouseButton) -> io::Result<()> { Ok(()) }
    fn mouse_up(&mut self, _: MouseButton) -> io::Result<()> {
        if self.fail_release.get() { Err(io::Error::new(io::ErrorKind::Other, "fake failure")) } else { Ok(()) }
    }
    fn scroll(&mut self, _: i32, _: i32) -> io::Result<()> { Ok(()) }
    fn key_down(&mut self, _: VirtualKey) -> io::Result<()> { Ok(()) }
    fn key_up(&mut self, _: VirtualKey) -> io::Result<()> { Ok(()) }
}
fn host(byte: u8, fake: Fake) -> HostInputSession<Fake> {
    let id = SessionId::new([byte; 16]).unwrap();
    let principal = Principal::new(format!("test-{byte}")).unwrap();
    let permissions = Permissions { control_mouse: true, ..Default::default() };
    let mut verifier = PasswordVerifier::new(id, principal.clone(), "test", "salt", Duration::from_secs(30)).unwrap();
    let response = password_response("test", verifier.challenge()).unwrap();
    let mut approval = OwnerApproval::new(id, principal, Some(permissions));
    let mut host = HostInputSession::new(id, fake);
    host.begin_connect().unwrap(); host.transport_connected().unwrap();
    host.authenticate(Credential::new(response.as_bytes()), permissions, &mut verifier, &mut approval).unwrap();
    host
}
#[test]
fn prevents_a_second_cooperating_controller_until_close() {
    let arbiter = InputArbiter::new();
    let mut first = match arbiter.attach(host(1, Fake::default())) { Ok(value) => value, Err(_) => panic!("first attach") };
    let second = match arbiter.attach(host(2, Fake::default())) {
        Err((ArbitrationError::Busy, host)) => host,
        _ => panic!("expected busy and original session"),
    };
    first.close().unwrap();
    let mut second = match arbiter.attach(second) { Ok(value) => value, Err(_) => panic!("second attach") };
    second.close().unwrap();
    assert_eq!(arbiter.owner().unwrap(), None);
}
#[test]
fn failed_cleanup_quarantines_on_drop_and_requires_explicit_recovery() {
    let arbiter = InputArbiter::new();
    let fake = Fake::default();
    let mut owner = match arbiter.attach(host(1, fake.clone())) { Ok(value) => value, Err(_) => panic!("attach") };
    owner.host_mut().mouse_down(MouseButton::Left).unwrap();
    fake.fail_release.set(true);
    assert!(owner.close().is_err());
    assert_eq!(arbiter.acknowledge_manual_recovery(), Err(ArbitrationError::Busy));
    drop(owner);
    assert!(arbiter.is_quarantined().unwrap());
    let pending = match arbiter.attach(host(2, Fake::default())) {
        Err((ArbitrationError::Quarantined, host)) => host,
        _ => panic!("expected quarantine"),
    };
    // In production a trusted operator must actually inspect/release the OS state.
    arbiter.acknowledge_manual_recovery().unwrap();
    let mut pending = match arbiter.attach(pending) { Ok(value) => value, Err(_) => panic!("attach after recovery") };
    pending.close().unwrap();
}
