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
