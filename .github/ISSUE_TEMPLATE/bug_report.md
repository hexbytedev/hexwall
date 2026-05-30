---
name: Bug report
about: Report a problem with pihole-guard
title: '[bug] '
labels: ''
assignees: ''

---

## Describe the bug

Describe what happened and why it is incorrect.

## To Reproduce

Provide the exact steps to reproduce the issue.

1. Run `...`
2. Start pihole-guard with `...`
3. Trigger traffic or state with `...`
4. Observe `...`

## Expected behavior

A clear description of what you expected instead.

## Logs or output

Paste relevant logs, terminal output, stack traces, or error messages.

## Runtime details

- OS: [e.g. Ubuntu 24.04, Debian 12, macOS 25]
- Go version: [e.g. go1.26.3]
- pihole-guard version or commit: [e.g. v0.0.1 or abc1234]
- Mode: [e.g. watch or enforce]
- Flags used: [e.g. `--db ... --guard-db ... --mode enforce --debug`]

## Environment details

- Pi-hole DB source: [e.g. `/etc/pihole/pihole-FTL.db`, Docker-mounted DB, custom `--db` path]
- `somo` availability: [e.g. installed in `$PATH`, version if known]
- Guard DB path: [e.g. `./pihole-guard.db`]
- Network context: [e.g. direct-IP connection, Pi-hole history refresh, Docker, VM, bare metal]

## Additional context

Include anything else that helps explain the issue, such as whether it affects trusted IP refresh, fraud lookups, connection monitoring, or process killing.
