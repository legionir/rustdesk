//! Synthetic only. Does not inject into the operating system.
use remote_core::{windows_touch::{TouchError, TouchScale}, HostInputSession};
use remote_input::{InputBackend, MouseButton, VirtualKey};
use remote_protocol::{pointer::Touch, Envelope};
use remote_security::{password_response, OwnerApproval, PasswordVerifier};
use remote_session::{Credential, Permissions, Principal, SessionId};
use std::{cell::{Cell, RefCell}, io, rc::Rc, time::Duration};

#[derive(Clone, Default)]
struct Fake { events: Rc<RefCell<Vec<String>>>, fail_up: Rc<Cell<bool>> }
impl InputBackend for Fake {
    fn move_to(&mut self, _: i32, _: i32) -> io::Result<()> { Ok(()) }
    fn mouse_down(&mut self, _: MouseButton) -> io::Result<()> { Ok(()) }
    fn mouse_up(&mut self, _: MouseButton) -> io::Result<()> { Ok(()) }
    fn scroll(&mut self, x: i32, y: i32) -> io::Result<()> { self.events.borrow_mut().push(format!("scroll:{x}:{y}")); Ok(()) }
    fn key_down(&mut self, k: VirtualKey) -> io::Result<()> { self.events.borrow_mut().push(format!("down:{}", k.code())); Ok(()) }
    fn key_up(&mut self, k: VirtualKey) -> io::Result<()> {
        self.events.borrow_mut().push(format!("up:{}", k.code()));
        if self.fail_up.get() { Err(io::Error::new(io::ErrorKind::Other, "fake release failure")) } else { Ok(()) }
    }
}
fn host(fake: Fake, perms: Permissions) -> HostInputSession<Fake> {
    let id = SessionId::new([42; 16]).unwrap(); let principal = Principal::new("test".into()).unwrap();
    let mut verifier = PasswordVerifier::new(id, principal.clone(), "test", "salt", Duration::from_secs(30)).unwrap();
    let proof = password_response("test", verifier.challenge()).unwrap();
    let mut approval = OwnerApproval::new(id, principal, Some(perms));
    let mut host = HostInputSession::new(id, fake);
    host.begin_connect().unwrap(); host.transport_connected().unwrap();
    host.authenticate(Credential::new(proof.as_bytes()), perms, &mut verifier, &mut approval).unwrap(); host
}
fn scale(n: i32) -> Envelope { Envelope::touch_event(Touch::Scale(n)) }
#[test]
fn scale_tracks_control_once_and_explicit_end_releases_it() {
    let fake = Fake::default(); let events = fake.events.clone();
    let mut host = host(fake, Permissions { control_mouse: true, control_keyboard: true, ..Default::default() });
    let mut touch = TouchScale::new();
    touch.dispatch(&mut host, &scale(100)).unwrap(); touch.dispatch(&mut host, &scale(-120)).unwrap();
    assert!(touch.active()); touch.dispatch(&mut host, &scale(0)).unwrap(); assert!(!touch.active());
    assert_eq!(&*events.borrow(), &["down:162", "scroll:0:100", "scroll:0:-120", "up:162"]);
}
#[test]
fn denies_missing_permissions_other_keys_pan_and_unbounded_scale() {
    let fake = Fake::default(); let events = fake.events.clone();
    let mut denied = host(fake.clone(), Permissions { control_mouse: true, ..Default::default() });
    assert!(TouchScale::new().dispatch(&mut denied, &scale(1)).is_err());
    let mut host = host(fake, Permissions { control_mouse: true, control_keyboard: true, ..Default::default() });
    let mut touch = TouchScale::new();
    assert!(matches!(touch.dispatch(&mut host, &scale(12_001)), Err(TouchError::InvalidScale)));
    assert!(matches!(touch.dispatch(&mut host, &Envelope::touch_event(Touch::PanEnd { x: 1, y: 2 })), Err(TouchError::Unsupported)));
    let key = VirtualKey::new(65).unwrap(); host.key_down(key).unwrap();
    assert!(matches!(touch.dispatch(&mut host, &scale(1)), Err(TouchError::ConflictingInput)));
    host.key_up(key).unwrap(); assert_eq!(&*events.borrow(), &["down:65", "up:65"]);
}
#[test]
fn failed_end_is_retryable_and_controller_close_retries_release() {
    let fake = Fake::default(); let events = fake.events.clone(); let failure = fake.fail_up.clone();
    let mut host = host(fake, Permissions { control_mouse: true, control_keyboard: true, ..Default::default() });
    let mut touch = TouchScale::new(); touch.dispatch(&mut host, &scale(1)).unwrap();
    failure.set(true); assert!(touch.end(&mut host).is_err()); assert!(touch.active());
    assert!(host.close().is_err()); failure.set(false); host.close().unwrap();
    assert_eq!(&*events.borrow(), &["down:162", "scroll:0:1", "up:162", "up:162", "up:162"]);
}
