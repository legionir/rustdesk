//! Synthetic protobuf and fake backend; no OS keyboard events are injected.
use base::message_proto::{ControlKey, KeyEvent, KeyboardMode, Message};
use hbb_common::protobuf::Message as _;
use remote_core::{windows_keyboard::{dispatch, DispatchError}, HostInputSession};
use remote_input::{InputBackend, MouseButton, VirtualKey};
use remote_protocol::Envelope;
use remote_security::{password_response, OwnerApproval, PasswordVerifier};
use remote_session::{Credential, Permissions, Principal, SessionId};
use std::{cell::RefCell, io, rc::Rc, time::Duration};

#[derive(Clone, Default)]
struct Fake(Rc<RefCell<Vec<String>>>);
impl InputBackend for Fake {
    fn move_to(&mut self, _: i32, _: i32) -> io::Result<()> { Ok(()) }
    fn mouse_down(&mut self, _: MouseButton) -> io::Result<()> { Ok(()) }
    fn mouse_up(&mut self, _: MouseButton) -> io::Result<()> { Ok(()) }
    fn scroll(&mut self, _: i32, _: i32) -> io::Result<()> { Ok(()) }
    fn key_down(&mut self, k: VirtualKey) -> io::Result<()> { self.0.borrow_mut().push(format!("down:{}", k.code())); Ok(()) }
    fn key_up(&mut self, k: VirtualKey) -> io::Result<()> { self.0.borrow_mut().push(format!("up:{}", k.code())); Ok(()) }
    fn type_text(&mut self, text: &str) -> io::Result<()> { self.0.borrow_mut().push(format!("text:{text}")); Ok(()) }
}
fn event(key: ControlKey, down: bool, press: bool, mode: KeyboardMode, modifiers: bool) -> Envelope {
    let mut key_event = KeyEvent::new();
    key_event.set_control_key(key); key_event.down = down; key_event.press = press; key_event.mode = mode.into();
    if modifiers { key_event.modifiers.push(ControlKey::Shift.into()); }
    let mut message = Message::new(); message.set_key_event(key_event);
    Envelope::decode(&message.write_to_bytes().unwrap(), 4096).unwrap()
}
fn authorized(fake: Fake) -> HostInputSession<Fake> {
    let id = SessionId::new([7; 16]).unwrap();
    let principal = Principal::new("test".into()).unwrap();
    let permissions = Permissions { control_keyboard: true, ..Default::default() };
    let mut verifier = PasswordVerifier::new(id, principal.clone(), "test", "salt", Duration::from_secs(30)).unwrap();
    let response = password_response("test", verifier.challenge()).unwrap();
    let mut policy = OwnerApproval::new(id, principal, Some(permissions));
    let mut host = HostInputSession::new(id, fake);
    host.begin_connect().unwrap(); host.transport_connected().unwrap();
    host.authenticate(Credential::new(response.as_bytes()), permissions, &mut verifier, &mut policy).unwrap();
    host
}
#[test]
fn accepts_plain_legacy_controls_and_releases_on_revocation() {
    let fake = Fake::default(); let calls = fake.0.clone(); let mut host = authorized(fake);
    dispatch(&mut host, &event(ControlKey::Return, false, true, KeyboardMode::Legacy, false)).unwrap();
    dispatch(&mut host, &event(ControlKey::F2, true, false, KeyboardMode::Legacy, false)).unwrap();
    host.restrict_permissions(Permissions::default()).unwrap();
    assert!(dispatch(&mut host, &event(ControlKey::Return, true, false, KeyboardMode::Legacy, false)).is_err());
    assert_eq!(&*calls.borrow(), &["down:13", "up:13", "down:113", "up:113"]);
}
#[test]
fn rejects_modifiers_other_modes_and_unauthorized_events() {
    let fake = Fake::default(); let calls = fake.0.clone();
    let mut host = authorized(fake.clone());
    assert!(matches!(dispatch(&mut host, &event(ControlKey::Return, true, false, KeyboardMode::Legacy, true)), Err(DispatchError::Unsupported(_))));
    assert!(matches!(dispatch(&mut host, &event(ControlKey::Shift, true, false, KeyboardMode::Legacy, false)), Err(DispatchError::Unsupported(_))));
    assert!(matches!(dispatch(&mut host, &event(ControlKey::Return, true, false, KeyboardMode::Map, false)), Err(DispatchError::Unsupported(_))));
    let mut denied = HostInputSession::new(SessionId::new([8; 16]).unwrap(), fake);
    assert!(dispatch(&mut denied, &event(ControlKey::Return, true, false, KeyboardMode::Legacy, false)).is_err());
    assert!(calls.borrow().is_empty());
}

fn text_event(text: &str) -> Envelope {
    let mut key = KeyEvent::new(); key.set_seq(text.to_owned());
    let mut message = Message::new(); message.set_key_event(key);
    Envelope::decode(&message.write_to_bytes().unwrap(), 8192).unwrap()
}
#[test]
fn permits_bounded_bmp_text_but_not_while_a_key_is_held() {
    let fake = Fake::default(); let calls = fake.0.clone(); let mut host = authorized(fake);
    dispatch(&mut host, &text_event("سلام" )).unwrap();
    dispatch(&mut host, &event(ControlKey::F2, true, false, KeyboardMode::Legacy, false)).unwrap();
    assert!(dispatch(&mut host, &text_event("blocked" )).is_err());
    dispatch(&mut host, &event(ControlKey::F2, false, false, KeyboardMode::Legacy, false)).unwrap();
    assert!(dispatch(&mut host, &text_event("😀" )).is_err());
    assert_eq!(&*calls.borrow(), &["text:سلام", "down:113", "up:113"]);
}
