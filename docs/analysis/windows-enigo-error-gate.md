# Windows Enigo error-formatting gate — static finding, unverified

## Scope and evidence

The pinned source at `23e5bb471a040d62f0a6ad52591fb30784265b73`,
`libs/enigo/src/win/win_impl.rs::get_error`, initializes a `Vec<u16>` to 256
units and passes `buff_size + 1` as `FormatMessageW`'s buffer capacity. It then
uses `chars_copied` as an index before trimming. A successful 256-unit result
would index at the vector's length and panic; the declared 257-unit capacity
can also allow the OS to write beyond the advertised Rust buffer/allocation.
The RustDesk source calls this helper on a failed `SendInput` in `mouse_down`
and `key_down`; the experimental `remote_input::windows::WindowsInput` used
to call that original backend and now calls the candidate fork described below. Error delivery can already be partial, and other Enigo input operations
can also hide native failures. This analysis has not reproduced an actual
Windows error message of that length or measured a memory corruption.

## Required disposition before Windows input use

Do not deploy or enable the experimental Windows input backend. Preserve the
original RustDesk tree; use a reviewed independently maintained fork/extracted
copy, or an explicitly reviewed safe Windows adapter, without silently
removing input functionality. Pin its provenance and licensing, review its
public API and source compatibility, and retain a clear migration/patch record.
An experimental independent fork is now present, but it is not yet reviewed or approved for input use.

The fix must supply the **actual** initialized buffer capacity to Windows,
check the returned count before slicing/indexing, handle zero and boundary
results without reading the terminator as data, and never trust a count greater
than the real buffer. Preserve meaningful error reporting and capture the
native error code before subsequent OS calls can overwrite it. A reviewed
alternative is to report the numeric OS error directly and avoid hand-written
message formatting; either choice needs compatibility review. The helper is not
the only unsafe/native input code, so audit its callers and cleanup semantics.

## Validation after a reviewed fix

- Unit-test count 0, ordinary message, largest fitting message, rejected or
  malformed count equal to/greater than capacity, UTF-16 decode behavior and
  trailing whitespace/control handling using a mock that never writes outside
  its test buffer. Test exact error propagation on each call site.
- Run Windows-specific synthetic and real SendInput failure scenarios on an
  explicitly authorized disposable desktop; inspect returned results, partial
  input, held-key/button release, UAC/UIPI and denied-desktop behavior.
- Use appropriate Windows memory-safety tooling to exercise actual
  `FormatMessageW`; a mock, Rust parser or successful CI compilation alone does
  not establish memory safety. Review debug/release overflow behavior.
- Rebuild and rerun the complete Rust workspace, Node addon, affected features
  and real two-system validation only after extraction and toolchain setup.
  Record test commands, platform/toolchain, skips and results accurately.

## Related process-wide keyboard-layout race

The same pinned file declares mutable process-global `static mut LAYOUT`.
`keybd_event` reads/writes it without synchronization when deriving a scan code,
and `get_layoutdependent_keycode` resets and rewrites it. The adapter's raw
virtual-key path invokes `keybd_event` with a zero scan code; the source Enigo
Unicode sequence path also passes zero, so the concern is not confined to
`Key::Layout` events. RustDesk's input
service ordinarily uses its shared `ENIGO` mutex for its own paths, but the
extracted `WindowsInput::new` can create separate backends and the provisional
`InputArbiter` is optional and only coordinates callers that share it. If two
threads reach these source accesses concurrently without a common lock, a
read/write or write/write data race is possible. The prototype does not prove
that all uses of the source Enigo instance are serialized, and external source
users inside the same process can bypass the optional arbiter. This is a static
risk analysis; a race has not been reproduced.

The independent fix/review must remove or synchronize the process-global mutable
layout state across **all** relevant Enigo paths, while also preserving or
explicitly documenting foreground-layout semantics. A local controller mutex or
an OS-wide ownership assertion alone does not protect uncooperative callers.
Review whether per-operation layout lookup can replace shared mutable state;
validate concurrent clients and layout/focus changes with appropriate tooling
and an authorized Windows desktop. The candidate fork is described below.

The pinned `libs/enigo/Cargo.toml` declares `MIT` and its tree contains
`libs/enigo/LICENSE`; any independent copy must retain notices and source
provenance. This observation is not legal clearance for the full RustDesk
extraction or its transitive dependencies (the repository root is AGPL-3.0).

Dependency provenance is also unresolved: the baseline Enigo manifest names a
Git `rdev` without an explicit revision and a `tfc` Git branch, while the
candidate's inherited lockfile has not been resolved for the extracted
workspace. A fork must retain required functionality and pin/review its actual
resolved graph; the current static path audit does not check those Git sources.

## Additional read-only native test plan (2026-11-03)

The fork now contains Windows-only tests that call its actual bounded system
error formatter after setting a controlled thread-local Windows error, and
call `FormatMessageW` with guarded buffers and test strings at the capacity
boundary. Concurrent threads also call the fork's actual synchronized native
layout lookup helpers; they do not call `SendInput`. They passed as part of
[CI run 41593701213](https://github.com/legionir/rustdesk/actions/runs/41593701213)
on `39ff8773fdb651f73f2a2c2752976a29f7112747`, which also passed Linux,
Windows, Node addon, exported-candidate and local transport jobs. The fake
modifier rollback fixtures were included in the workspace tests. The native
fixtures do not simulate focus changes, prove delivery, test UIPI or exercise
intentional SendInput failure, and are not a substitute for memory-safety
tooling or independent review.

## Candidate fork (not a gate clearance)

`remote-core/vendor/enigo` was copied from the exact RustDesk baseline above,
retaining the MIT LICENSE and source tree. The initial copy also normalized
trailing whitespace in README and .travis.yml. The original `libs/enigo` is
unchanged. The manifest's sibling path dependencies were adjusted to the
export tree, and Windows `remote-input` now resolves to this fork.

The fork captures `GetLastError` before allocating, supplies the actual
initialized 256-unit buffer length, checks the returned length before slicing,
and returns a numeric fallback even when formatting fails or the code is zero.
Errors now include a numeric code and a SendInput prefix; unlike the original,
a failed SendInput no longer becomes success solely because formatting failed.
The original process-global cached layout is retained behind a single mutex,
including both update and mapping paths. This preserves a shared cache but
does not make focus changes atomic across an entire key sequence; unrelated
input callers and OS processes can still interfere. Mutex poisoning is
recovered because the protected value is just an opaque handle.

The pure formatting tests are compiled into `remote-input` without Windows
input side effects, covering zero, maximal-fitting and invalid counts, trimming
and malformed UTF-16. Separate synthetic threaded tests exercise the exact
layout-cache mutex and poison recovery without input injection. The earlier CI run did not exercise the real `FormatMessageW`, native layout
APIs or OS input concurrency. See the additional test plan above. The original
Enigo still exists in the candidate source for provenance;
other consumers must not accidentally depend on it. The copy retains unpinned
upstream Git declarations, and no lockfile or license clearance is implied.
CI run [41572283211](https://github.com/legionir/rustdesk/actions/runs/41572283211)
on `e1bcee65d66e88d22b3ae840d530c1f393444c40` built and tested the Windows
workspace, Node addon and exported source candidate, and passed the Linux job.
The pure formatter and synthetic mutex fixtures were part of workspace tests.
It did not exercise native Windows input, a deliberate SendInput failure,
memory-safety instrumentation or real focus/layout concurrency. Independent
review and those native tests are still required before closing this gate.

## Additional modifier cleanup concern

Static review of the copied `win_impl.rs::key_down(Key::Layout(_))` found that
it presses required Shift/Control/Alt modifiers in a loop using `?`. If a
later modifier press fails, the function returns before its reverse release
loop, so modifiers pressed earlier in that operation may remain held. The
fork's improved error reporting can make this failure path observable in cases
where the original returned an empty error. This has not been reproduced on a
Windows desktop. The current `remote-input::WindowsInput` virtual-key adapter
uses `Key::Raw`, not this `Key::Layout` branch, but the copied Enigo crate
still exposes it and other consumers could call it. Further review must cover
rollback on partial modifier setup, pre-existing physical/remote key state,
concurrent senders, and the fact that source `key_up` is infallible and may
silently fail. A best-effort release is not evidence that the OS released the
key; do not enable the backend on this analysis alone.

The candidate fork now attempts reverse-order release of successfully pressed
modifiers when later setup or the main layout-key operation returns an error.
The extracted `modifier_scope` is tested using a fake backend without injecting
input. This is not a general ownership or OS-state solution: a failed press
could have uncertain effects, `key_up` cannot report failure, pre-existing key
state is not reconciled, and unwinding/panic or process termination can still
interrupt cleanup. Its tests and native validation must be reported separately;
the Windows input safety gate remains open.

## Controller cleanup on detectable release failures

The per-session `InputController` previously closed on an explicit key/button
release failure without immediately attempting to release other tracked inputs.
It now attempts the other tracked releases once while retaining the failing
record, and a failed permission-revocation pass also cleans categories that
were previously still allowed. Failed cleanup records remain for `close` or
best-effort `Drop`; the first error is returned. This is an explicit local
fail-closed policy, not exact RustDesk compatibility, and it assumes the owner
has authority over the tracked inputs. It cannot protect against concurrent
human/other-process input and can itself affect those keys. In particular,
Windows Enigo release calls still hide some native failures, so this policy
cannot establish that the OS released anything. New tests use fake backends;
real Windows validation and review remain required before use.

The no-immediate-retry rule above is limited to `InputController`'s failing
release call. The enclosing `HostConnection` aborts on detected dispatch
failure and calls host `close`, which may retry the retained release immediately;
`Drop` can also retry. Neither retry is proof of safety when OS state is
uncertain, and consumers must review this composition before using input.

## Candidate detectable-release extension

The independent fork now exposes fallible raw virtual-key and mouse-button
release methods; the `WindowsInput` adapter uses them instead of the source's
void-returning release methods. Each checks the single-event `SendInput` return
once and captures the error immediately on zero. Source Enigo's original
trait methods remain available and unchanged. Pure fake tests cover call count
and stale-error avoidance; this is not native failure injection. A nonzero
return is not proof that the intended application processed the event, and
other input operations such as mouse movement, scroll and text may still hide
native failures. Releases can affect physically held inputs or other processes.
The extension is not approved for use until Windows review and real tests.

CI [41615318903](https://github.com/legionir/rustdesk/actions/runs/41615318903)
at `623b9b5639a9b641d440c97d585885d84d464a83` passed Linux and Windows
workspace checks/tests, Node addon, exported-candidate checks and local
transport. The new cleanup and result-classification fixtures used fake
backends; no real SendInput release or interactive Windows desktop was tested.
This is not a two-system, OS input safety or security review, and the gate
remains open.
