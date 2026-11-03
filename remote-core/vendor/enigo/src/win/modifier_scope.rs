//! Source-style modifier setup with best-effort rollback on failed setup.

/// Execute one layout-key operation, releasing successfully pressed temporary
/// modifiers in reverse order even if a later press or the main action fails.
/// Release is infallible in Enigo's interface, so success here never proves
/// that Windows accepted a release or that it was safe to release a key the
/// user had already held. Concurrent controllers remain the caller's problem.
pub(crate) fn with_modifiers<C, E>(
    context: &mut C,
    flags: u16,
    mut press: impl FnMut(&mut C, usize) -> Result<(), E>,
    mut release: impl FnMut(&mut C, usize),
    action: impl FnOnce(&mut C) -> Result<(), E>,
) -> Result<(), E> {
    let mut pressed = [false; 3];
    for index in 0..pressed.len() {
        if flags & (1 << index) != 0 {
            if let Err(error) = press(context, index) {
                for old in (0..index).rev() {
                    if pressed[old] { release(context, old); }
                }
                return Err(error);
            }
            pressed[index] = true;
        }
    }
    let result = action(context);
    for index in (0..pressed.len()).rev() {
        if pressed[index] { release(context, index); }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::with_modifiers;

    #[derive(Default)]
    struct Fake { events: Vec<String>, fail_at: Option<usize>, fail_action: bool }
    fn run(fake: &mut Fake, flags: u16) -> Result<(), &'static str> {
        with_modifiers(fake, flags,
            |f, key| { f.events.push(format!("down{key}")); if f.fail_at == Some(key) { Err("press") } else { Ok(()) } },
            |f, key| f.events.push(format!("up{key}")),
            |f| { f.events.push("action".into()); if f.fail_action { Err("action") } else { Ok(()) } })
    }

    #[test]
    fn failed_modifier_setup_unwinds_only_successful_prior_presses() {
        let mut f = Fake { fail_at: Some(2), ..Fake::default() };
        assert_eq!(run(&mut f, 7), Err("press"));
        assert_eq!(f.events, ["down0", "down1", "down2", "up1", "up0"]);
        let mut f = Fake { fail_at: Some(1), ..Fake::default() };
        assert_eq!(run(&mut f, 6), Err("press"));
        assert_eq!(f.events, ["down1"]);
    }

    #[test]
    fn action_failure_still_releases_in_reverse_order() {
        let mut f = Fake { fail_action: true, ..Fake::default() };
        assert_eq!(run(&mut f, 5), Err("action"));
        assert_eq!(f.events, ["down0", "down2", "action", "up2", "up0"]);
    }

    #[test]
    fn success_and_no_modifier_paths_preserve_order() {
        let mut f = Fake::default();
        assert_eq!(run(&mut f, 7), Ok(()));
        assert_eq!(f.events, ["down0", "down1", "down2", "action", "up2", "up1", "up0"]);
        let mut f = Fake::default();
        assert_eq!(run(&mut f, 0), Ok(()));
        assert_eq!(f.events, ["action"]);
    }
}
