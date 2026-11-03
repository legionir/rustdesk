# Limited validation results — 2026-11-03

These checks were performed in the Linux sandbox on the restored experimental
workspace. They do not validate a standalone build, the native addon, a real
Windows desktop, security, or two-system interoperability.

- `python3 -m unittest discover -s remote-core/tools/tests -v`: **9 passed**.
  These exercise synthetic export-manifest and local Cargo-path-auditor fixtures;
  they do not resolve dependencies or build code. Python 3.11.2.
- From `remote-core/bindings/node`, `node --test test/two-system-common.test.cjs
  test/two-system-exchange.test.cjs`: **14 passed**. These are JavaScript-only
  mocked orchestration/argument tests, not a network or native-addon test.
  Node v22.22.3 (the workflow targets Node 20).
- `cargo test --manifest-path remote-core/Cargo.toml --workspace`: **not run**;
  shell exited 127 because `cargo` is not installed. `rustc` is also absent.
- From `remote-core/bindings/node`, `npm run build`: **failed** with
  `spawnSync cargo ENOENT`; no native addon was built, so addon tests were not
  run. No claims about Rust compilation can be made from these results.

The Windows Enigo safety gate remains unresolved; see
`windows-enigo-error-gate.md`. Do not exercise Windows input before a reviewed
fix and dedicated validation. Extraction remains incomplete.

## GitHub Actions follow-up

[Run 41559651038](https://github.com/legionir/rustdesk/actions/runs/41559651038)
on commit `7f71f42dd77a700ca887c2b6f0cf0ab255002057` completed successfully:
Linux workspace checks/tests, Node addon, exported candidate and Xvfb capture;
Windows workspace checks/tests, Node addon and exported candidate; and local
transport on both platforms. The workflow also exercises the optional
`source-totp` feature. Earlier runs exposed compile errors and Windows timer
fixture assumptions, which were corrected before this successful run.

Hosted CI does not exercise a real interactive Windows desktop, input injection,
real GPU capture, two physical systems, or all feature combinations. It is not
security, protocol or license validation. The unresolved Windows Enigo safety
gate remains in force and extraction remains incomplete.

## Windows movement and Unicode candidate

GitHub Actions [run 41642242860](https://github.com/legionir/rustdesk/actions/runs/41642242860)
completed successfully for commit `4509399d0b7e0d87ffc83e7c28b5c362870bbe3b`:
Linux capture/codec, Windows capture/codec, and local transport on Linux and
Windows passed, including the Node addon and exported-source candidate steps.
The added wheel and Unicode sequencing tests use fake senders; they do not
inject Windows input or prove delivery. No interactive desktop, deliberate
native SendInput failure, independent security review, or two-system test was
performed. The Windows input gate remains open.

The committed candidate exported to `/home/user/remote-core-mouse-unicode-20261103`
with 471 hashed files; manifest verification and the limited path auditor
accepted 16 manifests and 44 edges. These checks do not establish authenticity,
license clearance, dependency closure, or independent-product readiness. Eleven
Python exporter/auditor tests passed locally; Cargo was unavailable locally.
