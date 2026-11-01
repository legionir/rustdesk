# ADR 0001: Stop before extraction (provisional)

## Problem
A standalone library must preserve RustDesk behavior, security and licensing, but the supplied environment cannot run the baseline and the application graph has not been fully traced.

## Evidence
See `docs/analysis/build-baseline.md`, `dependencies.md`, and `extraction-report.md`. `scrap` depends on application protocol types; input uses global state and clipboard-assisted paths; WebSocket depends on shared config and encryption.

## Options
1. Move crates immediately: quick, but risks silently losing behavior/security.
2. Invent independent protocol and transport now: potentially simpler public surface, but compatibility and security unproven.
3. Preserve source and finish baseline and analysis before choosing boundaries.

## Decision
Choose option 3. No protocol change, dependency removal, extraction, production code change, or final crate layout is authorized by this ADR. This is an execution safeguard, not approval of the final architecture.

## Consequences and risks
Slower initial progress; preserves reviewability and avoids false claims. Blocked on Rust tooling/native prerequisites, detailed analysis, real platform tests and human review of security, protocol, API and distribution/license decisions.
