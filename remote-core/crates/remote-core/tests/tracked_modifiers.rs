//! Deferred fake-only cases; do not inject operating-system input.
use base::message_proto::{ControlKey, KeyEvent, Message, MouseEvent};
use hbb_common::protobuf::Message as _;
use remote_core::{tracked_modifiers, HostInputSession};
use remote_input::{InputBackend, MouseButton, VirtualKey};
use remote_protocol::Envelope;
use remote_security::{password_response, OwnerApproval, PasswordVerifier};
use remote_session::{Credential, Permissions, Principal, SessionId};
use std::{io, sync::{Arc, Mutex}, time::Duration};
#[derive(Default, Clone)] struct Fake(Arc<Mutex<Vec<String>>>);
impl InputBackend for Fake {
    fn move_to(&mut self, _: i32, _: i32) -> io::Result<()> { Ok(()) }
    fn mouse_down(&mut self, _: MouseButton) -> io::Result<()> { self.0.lock().unwrap().push("mouse-down".into()); Ok(()) }
    fn mouse_up(&mut self, _: MouseButton) -> io::Result<()> { self.0.lock().unwrap().push("mouse-up".into()); Ok(()) }
    fn scroll(&mut self, _: i32, _: i32) -> io::Result<()> { Ok(()) }
    fn key_down(&mut self, k: VirtualKey) -> io::Result<()> { self.0.lock().unwrap().push(format!("down:{}", k.code())); Ok(()) }
    fn key_up(&mut self, k: VirtualKey) -> io::Result<()> { self.0.lock().unwrap().push(format!("up:{}", k.code())); Ok(()) }
}
fn keyboard(key: ControlKey, down: bool, modifiers: &[ControlKey]) -> Envelope {
    let mut event = KeyEvent::new(); event.set_control_key(key); event.down = down;
    event.modifiers = modifiers.iter().copied().map(Into::into).collect();
    let mut message = Message::new(); message.set_key_event(event);
    Envelope::decode(&message.write_to_bytes().unwrap(), 4096).unwrap()
}
fn mouse(modifiers: &[ControlKey]) -> Envelope {
    let mut event = MouseEvent::new(); event.mask = (1 << 3) | 1;
    event.modifiers = modifiers.iter().copied().map(Into::into).collect();
    let mut message = Message::new(); message.set_mouse_event(event);
    Envelope::decode(&message.write_to_bytes().unwrap(), 4096).unwrap()
}
fn authorized(fake: Fake) -> HostInputSession<Fake> {
    let id = SessionId::new([42; 16]).unwrap(); let principal = Principal::new("viewer".into()).unwrap();
    let permissions = Permissions { control_mouse: true, control_keyboard: true, ..Default::default() };
    let mut auth = PasswordVerifier::new(id, principal.clone(), "test", "salt", Duration::from_secs(10)).unwrap();
    let proof = password_response("test", auth.challenge()).unwrap(); let mut policy = OwnerApproval::new(id, principal, Some(permissions));
    let mut host = HostInputSession::new(id, fake); host.begin_connect().unwrap(); host.transport_connected().unwrap();
    host.authenticate(Credential::new(proof.as_bytes()), permissions, &mut auth, &mut policy).unwrap(); host
}
#[test]
fn tracked_control_modifier_is_never_inferred_and_is_released() {
    let fake = Fake::default(); let calls = fake.0.clone(); let mut host = authorized(fake);
    assert!(tracked_modifiers::mouse(&mut host, &mouse(&[ControlKey::Control])).is_err());
    tracked_modifiers::keyboard(&mut host, &keyboard(ControlKey::Control, true, &[])).unwrap();
    assert!(tracked_modifiers::mouse(&mut host, &mouse(&[])).is_err());
    tracked_modifiers::mouse(&mut host, &mouse(&[ControlKey::Control])).unwrap();
    host.restrict_permissions(Permissions::default()).unwrap();
    assert_eq!(&*calls.lock().unwrap(), &["down:162", "mouse-down", "up:162", "mouse-up"]);
}
