//! Synthetic protobuf and fake backend; no OS keyboard events are injected.
use base::message_proto::{ControlKey, KeyEvent, KeyboardMode, Message};
use hbb_common::protobuf::Message as _;
use remote_core::{windows_keyboard::{dispatch, DispatchError}, HostInputSession};
use remote_input::{InputBackend, MouseButton, ScanCode, VirtualKey};
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
    fn scan_down(&mut self, key: ScanCode) -> io::Result<()> { self.0.borrow_mut().push(format!("scan-down:{}", key.code())); Ok(()) }
    fn scan_up(&mut self, key: ScanCode) -> io::Result<()> { self.0.borrow_mut().push(format!("scan-up:{}", key.code())); Ok(()) }
    fn raw_virtual_down(&mut self, key: VirtualKey) -> io::Result<()> { self.0.borrow_mut().push(format!("raw-down:{}", key.code())); Ok(()) }
    fn raw_virtual_up(&mut self, key: VirtualKey) -> io::Result<()> { self.0.borrow_mut().push(format!("raw-up:{}", key.code())); Ok(()) }
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

#[test]
fn restricted_map_mode_tracks_scan_keys_and_releases_on_revoke() {
    let fake = Fake::default(); let calls = fake.0.clone(); let mut host = authorized(fake);
    let down = Envelope::windows_scan_event(0xe01d, true).unwrap();
    let up = Envelope::windows_scan_event(0xe01d, false).unwrap();
    remote_core::windows_keyboard::dispatch_map(&mut host, &down).unwrap();
    // Physical and virtual representations must not be tracked simultaneously.
    assert!(dispatch(&mut host, &event(ControlKey::F2, true, false, KeyboardMode::Legacy, false)).is_err());
    remote_core::windows_keyboard::dispatch_map(&mut host, &up).unwrap();
    remote_core::windows_keyboard::dispatch_map(&mut host, &down).unwrap();
    host.restrict_permissions(Permissions::default()).unwrap();
    assert_eq!(&*calls.borrow(), &["scan-down:57373", "scan-up:57373", "scan-down:57373", "scan-up:57373"]);
    assert!(Envelope::windows_scan_event(0x12345, true).is_err());
}

#[test]
fn restricted_translate_mode_dispatches_source_code_and_releases_on_revoke() {
    let fake = Fake::default(); let calls = fake.0.clone(); let mut host = authorized(fake);
    let vk_down = Envelope::windows_translate_event(0x0041_1234, true).unwrap();
    let vk_up = Envelope::windows_translate_event(0x0041_ffff, false).unwrap();
    remote_core::windows_keyboard::dispatch_translate(&mut host, &vk_down).unwrap();
    let scan = Envelope::windows_translate_event(0xe01d, true).unwrap();
    assert!(remote_core::windows_keyboard::dispatch_translate(&mut host, &scan).is_err());
    remote_core::windows_keyboard::dispatch_translate(&mut host, &vk_up).unwrap();
    remote_core::windows_keyboard::dispatch_translate(&mut host, &scan).unwrap();
    host.restrict_permissions(Permissions::default()).unwrap();
    assert_eq!(&*calls.borrow(), &["raw-down:65", "raw-up:65", "scan-down:57373", "scan-up:57373"]);
    assert!(Envelope::windows_translate_event(0xffff_0000, true).is_err());
}

#[test]
fn source_supplementary_unicode_is_explicit_and_permission_checked() {
    use remote_core::windows_keyboard::dispatch_source_unicode;
    use remote_input::SourceWindowsUnicodeOptIn;
    use remote_protocol::input::LegacyKey;
    let token = SourceWindowsUnicodeOptIn::acknowledge_source_surrogate_and_delivery_risks;
    let fake = Fake::default(); let calls = fake.0.clone(); let mut host = authorized(fake);
    let unicode = Envelope::legacy_keyboard_event(LegacyKey::Unicode(0x1f600), false, false, &[]).unwrap();
    assert!(dispatch(&mut host, &unicode).is_err());
    dispatch_source_unicode(&mut host, &unicode, token()).unwrap();
    dispatch_source_unicode(&mut host, &text_event("A😀"), token()).unwrap();
    assert!(dispatch_source_unicode(&mut host, &event(ControlKey::F2, true, false, KeyboardMode::Legacy, false), token()).is_err());
    let modifiers = Envelope::legacy_keyboard_event(LegacyKey::Sequence("😀"), true, false, &[4]).unwrap();
    assert!(dispatch_source_unicode(&mut host, &modifiers, token()).is_err());
    host.restrict_permissions(Permissions::default()).unwrap();
    assert!(dispatch_source_unicode(&mut host, &unicode, token()).is_err());
    assert_eq!(&*calls.borrow(), &["text:😀", "text:A😀"]);
}
