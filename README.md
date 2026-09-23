# hexwall

[![Go Reference][1]][2]
[![CodeQL Advanced][3]][4]
[![golangci-lint][5]][6]
[![Dependency Review][7]][8]
[![Dependency Graph][9]][10]
[![Dependabot Updates][11]][12]
[![Go][13]][14]

`hexwall` is an outbound exfiltration brake for servers already protected by Pi-hole. When a supply-chain attack, malware implant, or compromised package is already running inside the machine, it can skip DNS entirely and send stolen data straight to a hard-coded IP. Pi-hole does not see that hop. `ss` (falling back to `somo` when unavailable) can see the live connection. `hexwall` uses that visibility to flag and, in `enforce` mode, kill suspicious direct-IP connections before data leaves the server.

It monitors active network connections and kills any that connect to IPs that are not trusted by Pi-hole history, the built-in local allowlist, or recent already-established traffic — closing the gap that Pi-hole leaves open for direct-IP connections.

In short: `Pi-hole + hexwall` gives you a practical containment layer for post-compromise outbound traffic, especially the kind of direct-IP exfiltration occasionally used in supply-chain attacks.

## At a glance

| Situation                                    | Server without Pi-hole DNS | Server with only Pi-hole              | Server with Pi-hole + hexwall                  |
| -------------------------------------------- | -------------------------- | ------------------------------------- | --------------------------------------------- |
| Malicious domain resolved over DNS           | ❌ Exposed                  | ✅ Can block at DNS layer              | ✅ Can block at DNS layer                      |
| Malware connects to a hard-coded IP directly | ❌ Exposed                  | ❌ Pi-hole does not see it             | ✅ Direct-IP connection is visible and checked |
| Identify which process owns the connection   | ❌ No built-in visibility   | ❌ No process visibility               | ✅ `ss`/`somo` shows PID/program               |
| Stop outbound exfiltration after compromise  | ❌ No containment layer     | ⚠️ Only if the attacker still uses DNS | ✅ Can kill suspicious established connections |
| Supply-chain malware bypassing DNS           | ❌ High risk                | ❌ Still exposed                       | ✅ Stronger containment                        |
| Overall outbound protection posture          | ❌ Weak                     | ⚠️ Partial                             | 🛡️ Strongest of the three                      |

---

## The problem

Pi-hole operates at the DNS layer. It can block a domain, but it has no visibility into connections that bypass DNS entirely — processes that dial a hard-coded IP address directly. Malware and compromised packages commonly use this technique to phone home without triggering any DNS-based block.

hexwall works from the inverse assumption: **if a connection is not trusted, it is suspicious by default.** Trust is granted when the IP matches the built-in CIDR allowlist, was refreshed from Pi-hole query history within the last hour, or was already observed as an established connection within the last 60 seconds. On startup it immediately refreshes trusted IPs from Pi-hole, then refreshes them every 30 seconds while scanning connections every 10 seconds.

When Zeek is enabled (`--zeek-log`), hexwall also captures the TLS SNI for each connection and checks that exact domain against Pi-hole's own allow/deny lists before ever falling back to third-party reputation — this is what lets it tell apart a blocked site from a harmless one even when both happen to share the same IP, as is common behind a CDN. Anything that still falls outside every trust check is optionally escalated to an external reputation API, with results cached locally for 6 hours. Confirmed threats are either logged (watch mode) or killed (enforce mode).

---

## Dependencies

| Dependency                                                   | Role                                                                         | Required                                                                  |
| ------------------------------------------------------------ | ---------------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| [`ss`](https://wiki.linuxfoundation.org/networking/iproute2) | Lists established TCP connections; kills a single connection via `ss -K`     | Default — part of iproute2, present on virtually all Linux systems        |
| [`somo`](https://github.com/theopfr/somo)                    | Fallback connection lister when `ss` is unavailable; kills by PID            | Fallback — only required if `ss` (iproute2) is unavailable, e.g. on macOS |
| Pi-hole FTL database                                         | Source of trusted DNS history and allow/deny policy lists                    | Auto-detected or via `--db`                                               |
| `deghostapi.hexbyte.dev`                                     | Fraud/threat classification for unrecognized IPs and domains                 | Optional — see `--enable-deghost-*` below                                 |
| Zeek                                                         | Passive capture of TLS SNI (`ssl.log`) and DNS-bypass notices (`notice.log`) | Optional — see `--zeek-*`/`--enable-zeek` below                           |

**Build dependency:** `modernc.org/sqlite` (pure-Go SQLite, no CGo or system libsqlite3 required).

## Binaries and deployment

CI publishes lightweight Linux binaries for:

- `linux/amd64`
- `linux/arm64`

You can download them from the project's GitHub Releases page:

- [GitHub Releases](https://github.com/hexbytedev/hexwall/releases)

For production Linux servers, download the matching binary from Releases, place it where your deployment expects `./app/hexwall`, and use the included demo Docker Compose file at [`docker-compose.yml`](./docker-compose.yml) to launch it on the server.

hexwall targets Linux, where prebuilt binaries are published by CI. macOS is best-effort: clone the repository and build the binary manually, and install `somo` as a fallback since `ss` (Linux's iproute2) isn't available there. Windows is not supported.

### Connection backend

At startup, hexwall picks a connection-listing backend by availability, not by OS: `ss` first if it's on `PATH`, then `somo`, then it exits with an install message if neither is found. This means `ss` is used by default on real Linux boxes (iproute2 ships with virtually every distro) and `somo` only comes into play as a fallback — on macOS, where `ss` doesn't exist, or on a stripped-down Linux system without iproute2 installed. The connection-kill path already tries `ss -K` first and falls back to a process-level signal kill regardless of which lister found the connection, so no behavior changes based on which backend is selected.

### Install `somo`

The steps below are only needed on the fallback path described above (macOS, or a Linux box without `ss`).

If `somo` is not already in your `$PATH`, this is the quickest way to install and verify it on Ubuntu or Debian:

```sh
curl https://sh.rustup.rs -sSf | sh
sudo apt install build-essential
cargo install somo
sudo ln -s "$HOME/.cargo/bin/somo" /usr/local/bin/somo
sudo somo
```

What these steps do:

- install Rust tooling with `rustup`
- install the compiler toolchain needed to build `somo`
- build and install `somo` with Cargo
- expose `somo` system-wide through `/usr/local/bin`
- run `sudo somo` once to confirm it can see live connections and PIDs

---

## Pi-hole database locations

Auto-detection checks in this order:

1. `/etc/pihole/pihole-FTL.db` — bare-metal / package install
2. A running Docker container whose name or image contains `pihole`, inspecting its `/etc/pihole` mount

If neither is found, start fails. Use `--db` to specify the path manually.

---

## CLI flags

| Flag                      | Default                             | Description                                                                                       |
| ------------------------- | ----------------------------------- | ------------------------------------------------------------------------------------------------- |
| `--db`                    | _(auto-detected)_                   | Path to `pihole-FTL.db`                                                                           |
| `--hexwall-db`            | `./hexwall.db`                      | Path to the local hexwall database (created on first run)                                         |
| `--mode`                  | `watch`                             | `watch` — detect and log only; `enforce` — detect, log, and kill                                  |
| `--debug`                 | `false`                             | Enable verbose per-connection scan logging                                                        |
| `--enable-zeek`           | `false`                             | Enable the Zeek `notice.log` DNS-bypass alert path (independent of `--zeek-log`)                  |
| `--zeek-log`              | _(unset — SNI matching skipped)_    | Path to Zeek's `ssl.log`, used to match a connection's TLS SNI against Pi-hole's allow/deny lists |
| `--zeek-notice-log`       | `/opt/zeek/logs/current/notice.log` | Path to Zeek's `notice.log`; only read when `--enable-zeek` is set                                |
| `--enable-deghost-ip`     | `true`                              | Enable third-party IP reputation checks for unrecognized connections with no SNI                  |
| `--enable-deghost-domain` | `true`                              | Enable third-party domain reputation checks for unrecognized SNI domains                          |
| `--version`               | `false`                             | Print version and exit                                                                            |

`--mode` accepts `watch` or `enforce` (case-insensitive). Any other value exits with an error.

`--enable-zeek` and `--zeek-log` are independent switches for two unrelated Zeek consumers: `--zeek-log` feeds SNI-based domain matching into the main decision ladder, while `--enable-zeek` (plus `--zeek-notice-log`) turns on a separate, standalone DNS-bypass alert path. Either, both, or neither can be set.

### Zeek setup

hexwall tails `ssl.log` directly, in whichever of Zeek's two output formats it's actually producing — no Zeek-side configuration is required:

- **TSV** (Zeek's default `LogAscii` output, used by a stock install with no extra config) — the column order is learned from the log file's own `#fields` header the first time it's read, rather than assumed, so it keeps working across Zeek versions or configurations that add extra columns.
- **JSON** (`redef LogAscii::use_json = T;`) — also supported, parsed line by line.

Tested against Zeek 9.0.0. Point `--zeek-log` at the running instance's `ssl.log`: for a plain `zeek -i <interface>` invocation, that's a file in the working directory Zeek was started from; under `zeekctl`, it's `<logdir>/current/ssl.log`.

### Debug logging

When `--debug` is enabled, hexwall also logs intermediate, non-actionable outcomes it would otherwise stay quiet about — a domain or IP coming back clean from a reputation check, or a check being skipped because its flag is disabled. Warnings, blocks, and kills are always logged regardless of `--debug`.

Every scan tick prints a one-line summary regardless of `--debug` — connection count, and how many were trusted, blocked, unknown, or errored — and an empty scan (the connection-listing tool returning zero connections) is always logged too.

---

## When a connection is killed

A connection is only ever killed in `--mode enforce`, for a connection the active connection-listing tool (`ss` or `somo`) reports as currently established. Three independent checks can trigger it:

1. **Pi-hole domain denylist match** — Zeek captured the connection's TLS SNI (via `--zeek-log`) and that domain is on Pi-hole's own denylist or gravity blocklist. Requires only Pi-hole; no third-party service is involved, and this check runs regardless of the `--enable-deghost-*` flags.
2. **Third-party domain reputation match** — an SNI was captured, the domain is on neither Pi-hole list and isn't already known-trusted for this IP, and the reputation API's verdict (fetched live or reused from a 6-hour cache) says to block it. Requires `--enable-deghost-domain` (default `true`).
3. **Third-party IP reputation match** — no SNI was available at all (non-TLS traffic, ECH, or a connection predating startup), the IP is not trusted, and the reputation API's verdict on the bare IP (live or 6-hour cached) marks it `is_abuser`, `is_attacker`, or `is_threat`. Requires `--enable-deghost-ip` (default `true`).

With both `--enable-deghost-ip` and `--enable-deghost-domain` set to `false`, only the first check — Pi-hole's own denylist — can ever trigger a kill.

A connection is treated as trusted, and skipped entirely, when any of these are true:

- Its IP matches the built-in CIDR allowlist.
- Its domain is explicitly on Pi-hole's allowlist.
- Its IP was refreshed from Pi-hole query history within the last hour, or was already seen as an established connection within the last 60 seconds.
- Its domain has already been seen for this exact IP in hexwall's own history.

Connections are not killed in these cases:

- `--mode watch` is active — a would-be kill is only logged as `would kill`.
- The relevant reputation check is disabled via its flag.
- A cached reputation verdict from the last 6 hours says clean.
- The IP reputation API returns HTTP `403`, treated as clean/private/reserved.
- The reputation lookup itself fails — a failed lookup is never treated as a block.

When a kill does happen, hexwall first records the event in the local `killed_connections` audit table, then signals the owning PID: `SIGTERM` first, escalating to `SIGKILL` after a 2-second grace period if the process is still alive. A hardcoded set of protected system processes (`systemd`, `sshd`, `dockerd`, and similar) can never be killed this way, whichever check triggered the match.

### Reputation API cache behavior

Both IP and domain reputation lookups are cached in the local SQLite database for 6 hours, keyed by IP or by domain respectively.

- If a cached decision is newer than 6 hours, hexwall reuses it and does not call the reputation API again.
- If the cached decision is older than 6 hours, the next scan calls the API again and refreshes the cache timestamp.
- Both clean and block-worthy decisions are cached.
- HTTP `403` responses (IP checks only) are treated as clean/private/reserved and cached as a non-kill result.
- A failed lookup is not cached, so it will be retried on the next scan.

This cache lives in the local hexwall database as Unix timestamps (`INTEGER` / int64-style seconds) and survives restarts.

---

## How Pi-hole history becomes trusted IPs

Pi-hole trust is built from recent DNS history, not by directly trusting every current connection. The refresh flow is:

1. Read the `queries` table from `pihole-FTL.db`.
2. Select distinct non-empty domains seen within the last hour.
3. Normalize them to lowercase and trim whitespace.
4. Resolve each domain through the system DNS resolver, with bounded concurrency and a 1 second lookup timeout per domain.
5. Ignore domains that do not resolve. This is normal for blocked domains, expired records, and similar cases.
6. Deduplicate resolved IPs. If multiple domains resolve to the same IP, the first domain in sorted order is stored for that IP.
7. Upsert each resolved IP into the local `allowed_ips` table, setting or refreshing `last_refreshed`.

Important details:

- Startup performs this refresh immediately before the first monitoring scan, so normal traffic seen in recent Pi-hole history is trusted before enforcement begins.
- The refresh repeats every 30 seconds.
- Trust from Pi-hole refresh lasts for 1 hour from the most recent successful upsert.
- Existing rows keep their original `first_approved` and `last_established` values when refreshed; only the stored domain and `last_refreshed` timestamp are updated.
- The monitor also extends trust for long-lived allowed connections by updating `last_established` whenever an already-trusted connection is seen still established.

This means an IP becomes trusted from Pi-hole history only after all of these happen:

1. Pi-hole recorded a domain query for it within the last hour.
2. That domain still resolves during a refresh cycle.
3. One of the resolved IPs is written into the local `allowed_ips` cache.

If a domain was seen in Pi-hole history but no longer resolves during refresh, no IP is added for it, so there is nothing to trust from that domain alone.

---

[1]: https://pkg.go.dev/badge/github.com/hexbytedev/hexwall
[2]: https://pkg.go.dev/github.com/hexbytedev/hexwall
[3]: https://github.com/hexbytedev/hexwall/actions/workflows/codeql.yml/badge.svg
[4]: https://github.com/hexbytedev/hexwall/actions/workflows/codeql.yml
[5]: https://github.com/hexbytedev/hexwall/actions/workflows/golangci-lint.yml/badge.svg
[6]: https://github.com/hexbytedev/hexwall/actions/workflows/golangci-lint.yml
[7]: https://github.com/hexbytedev/hexwall/actions/workflows/dependency-review.yml/badge.svg
[8]: https://github.com/hexbytedev/hexwall/actions/workflows/dependency-review.yml
[9]: https://github.com/hexbytedev/hexwall/actions/workflows/dependabot/update-graph/badge.svg
[10]: https://github.com/hexbytedev/hexwall/actions/workflows/dependabot/update-graph
[11]: https://github.com/hexbytedev/hexwall/actions/workflows/dependabot/dependabot-updates/badge.svg
[12]: https://github.com/hexbytedev/hexwall/actions/workflows/dependabot/dependabot-updates
[13]: https://github.com/hexbytedev/hexwall/actions/workflows/go.yml/badge.svg
[14]: https://github.com/hexbytedev/hexwall/actions/workflows/go.yml
