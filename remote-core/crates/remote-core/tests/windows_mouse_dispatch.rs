//! Fake-backend tests; they do not inject real OS input.
use remote_core::{windows_mouse::{dispatch, DispatchError}, HostInputSession};
use remote_input::{InputBackend, MouseButton, VirtualKey};
use remote_protocol::{Envelope, MouseEvent};
use remote_security::{password_response, OwnerApproval, PasswordVerifier};
use remote_session::{Credential, Permissions, Principal, SessionId};
use std::{cell::RefCell, io, rc::Rc, time::Duration};

#[derive(Clone, Default)]
struct Fake(Rc<RefCell<Vec<String>>>);
impl InputBackend for Fake {
    fn move_to(&mut self, x: i32, y: i32) -> io::Result<()> { self.0.borrow_mut().push(format!("abs:{x}:{y}")); Ok(()) }
    fn move_relative(&mut self, x: i32, y: i32) -> io::Result<()> { self.0.borrow_mut().push(format!("rel:{x}:{y}")); Ok(()) }
    fn mouse_down(&mut self, b: MouseButton) -> io::Result<()> { self.0.borrow_mut().push(format!("down:{b:?}")); Ok(()) }
    fn mouse_up(&mut self, b: MouseButton) -> io::Result<()> { self.0.borrow_mut().push(format!("up:{b:?}")); Ok(()) }
    fn scroll(&mut self, x: i32, y: i32) -> io::Result<()> { self.0.borrow_mut().push(format!("scroll:{x}:{y}")); Ok(()) }
    fn key_down(&mut self, _: VirtualKey) -> io::Result<()> { Ok(()) }
    fn key_up(&mut self, _: VirtualKey) -> io::Result<()> { Ok(()) }
}
fn event(mask: i32, x: i32, y: i32) -> Envelope { Envelope::mouse_event(MouseEvent { mask, x, y }) }
fn authorized(fake: Fake) -> HostInputSession<Fake> {
    let id = SessionId::new([7; 16]).unwrap();
    let principal = Principal::new("test".into()).unwrap();
    let permissions = Permissions { control_mouse: true, ..Default::default() };
    let mut verifier = PasswordVerifier::new(id, principal.clone(), "test", "salt", Duration::from_secs(30)).unwrap();
    let response = password_response("test", verifier.challenge()).unwrap();
    let mut policy = OwnerApproval::new(id, principal, Some(permissions));
    let mut host = HostInputSession::new(id, fake);
    host.begin_connect().unwrap(); host.transport_connected().unwrap();
    host.authenticate(Credential::new(response.as_bytes()), permissions, &mut verifier, &mut policy).unwrap();
    host
}
#[test]
fn authorizes_and_maps_windows_mouse_subset() {
    let fake = Fake::default(); let events = fake.0.clone();
    let mut host = authorized(fake);
    dispatch(&mut host, &event(0, -40, 50)).unwrap();
    dispatch(&mut host, &event(5, i32::MAX, i32::MIN)).unwrap();
    dispatch(&mut host, &event((8 << 3) | 1, 0, 0)).unwrap();
    dispatch(&mut host, &event((8 << 3) | 2, 0, 0)).unwrap();
    dispatch(&mut host, &event(3, 2, -3)).unwrap();
    assert_eq!(&*events.borrow(), &["abs:-40:50", "rel:10000:-10000", "down:Back", "up:Back", "scroll:-240:-360"]);
    dispatch(&mut host, &event(4, 15, -25)).unwrap();
    assert_eq!(events.borrow().last().unwrap(), "scroll:-15:-25");
    assert!(matches!(dispatch(&mut host, &event(4, i32::MIN, 0)), Err(DispatchError::InvalidWheelDelta)));
    assert!(matches!(dispatch(&mut host, &event(3, i32::MIN, 0)), Err(DispatchError::InvalidWheelDelta)));
}
#[test]
fn denies_before_auth_and_releases_on_revocation() {
    let fake = Fake::default(); let events = fake.0.clone();
    let mut unauthorized = HostInputSession::new(SessionId::new([9; 16]).unwrap(), fake.clone());
    assert!(dispatch(&mut unauthorized, &event(0, 1, 2)).is_err());
    assert!(events.borrow().is_empty());
    let mut host = authorized(fake);
    dispatch(&mut host, &event((1 << 3) | 1, 0, 0)).unwrap();
    host.restrict_permissions(Permissions::default()).unwrap();
    assert!(dispatch(&mut host, &event(0, 1, 2)).is_err());
    assert_eq!(&*events.borrow(), &["down:Left", "up:Left"]);
}
