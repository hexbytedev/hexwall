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

hexwall works from the inverse assumption: **if a connection is not trusted, it is suspicious by default.** Trust is granted when the IP matches the built-in CIDR allowlist, was resolved from a domain a client asked Pi-hole for within the last hour, or was already observed as an established connection within the last 60 seconds. On startup it immediately reads the last hour of Pi-hole history, then picks up new queries every 30 seconds while scanning connections every 10 seconds.

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

To run hexwall directly on the host instead, so that it starts at boot and restarts if it crashes, use [`hexwall install-service`](#run-as-a-systemd-service).

hexwall targets Linux, where prebuilt binaries are published by CI. macOS is best-effort: clone the repository and build the binary manually, and install `somo` as a fallback since `ss` (Linux's iproute2) isn't available there. Windows is not supported.

### Connection backend

At startup, hexwall picks a connection-listing backend and prints which one it chose. On Linux, `ss` is used if it's on `PATH`, otherwise `somo`; hexwall exits with an install message if neither is found. `ss` is therefore the default on real Linux boxes (iproute2 ships with virtually every distro), and `somo` only comes into play on a stripped-down system without iproute2. On macOS, `ss` is never probed: its single-connection kill relies on a Linux kernel feature (`CONFIG_INET_DIAG_DESTROY`), so hexwall goes straight to `somo` and every kill there is process-level. The kill path works the same whichever lister found the connection (see [When a connection is killed](#when-a-connection-is-killed)).

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
| `--enable-deghost-ip`     | `false`                             | Send unrecognized IPs (connections with no SNI) to the third-party reputation API                 |
| `--enable-deghost-domain` | `false`                             | Send unrecognized SNI domains to the third-party reputation API                                   |
| `--version`               | `false`                             | Print version and exit                                                                            |

`--mode` accepts `watch` or `enforce` (case-insensitive). Any other value exits with an error.

`--enable-zeek` and `--zeek-log` are independent switches for two unrelated Zeek consumers: `--zeek-log` feeds SNI-based domain matching into the main decision ladder, while `--enable-zeek` (plus `--zeek-notice-log`) turns on a separate, standalone DNS-bypass alert path. Either, both, or neither can be set.

### Zeek setup

hexwall reads two Zeek logs, in whichever of Zeek's two output formats Zeek is producing:

- **TSV** (Zeek's default `LogAscii` output, used by a stock install with no extra config) — the column order is learned from the log file's own `#fields` header rather than assumed, so it keeps working across Zeek versions or configurations that add extra columns.
- **JSON** (`redef LogAscii::use_json = T;`) — also supported, parsed line by line.

Tested against Zeek 9.0.0.

`ssl.log` (for `--zeek-log`) is written by every Zeek install; nothing needs configuring. `notice.log` alerts (for `--enable-zeek`) come from a DNS-bypass detection script that ships inside the hexwall binary. Install it with:

```sh
sudo hexwall zeek-setup
```

`zeek-setup` finds Zeek through `zeek-config` (on `PATH`, or `/opt/zeek/bin/zeek-config`), then:

1. writes `dns-bypass.zeek` into Zeek's site directory, replacing an older copy so the script always matches the hexwall binary that reads its alerts;
2. adds `@load dns-bypass` to `local.zeek` once, leaving the rest of the file alone;
3. checks that every `interface=` in `node.cfg` exists on this machine, and lists the real interfaces if one doesn't (Zeek can't start on a missing interface; the stock `node.cfg` says `eth0`);
4. prints the next steps: `sudo zeekctl deploy` to restart Zeek with the script, and the exact `--zeek-log`/`--zeek-notice-log` flags for the configured log directory.

It does not edit `node.cfg` or restart Zeek itself. Re-running it is safe.

Under `zeekctl`, both logs are in `<logdir>/current/` (`/opt/zeek/logs/current/` by default). For a plain `zeek -i <interface>` invocation, they're written to the directory Zeek was started from.

Both logs are read from the moment hexwall starts: alerts already in `notice.log` are skipped, so a restart can't act on old ones, and SNI is only known for TLS handshakes made after startup.

### DNS-bypass alerts

The script raises a `DNSBypass::PossibleBypass` notice when a TLS connection's SNI names a domain that the client never looked up through DNS, a sign that it bypassed Pi-hole. For each alert hexwall checks the domain against Pi-hole's lists and records it in the `zeek_alerts` table. If the domain is blocked:

- in `--mode watch`, the alert is logged;
- in `--mode enforce`, hexwall looks for the alerted connection among **this machine's** sockets and kills it through the same guarded path as every other kill (see [When a connection is killed](#when-a-connection-is-killed)).

Zeek sees the whole network it listens on, but a socket can only be closed on the machine that owns it. An alert about another device is recorded as `not_on_this_host` with a warning; to block that device's connection, run hexwall on it too.

### Debug logging

When `--debug` is enabled, hexwall also logs intermediate, non-actionable outcomes it would otherwise stay quiet about — a domain or IP coming back clean from a reputation check, or a check being skipped because its flag is disabled. Warnings, blocks, and kills are always logged regardless of `--debug`.

Every scan tick prints a one-line summary regardless of `--debug` — connection count, and how many were trusted, blocked, unknown, or errored — and an empty scan (the connection-listing tool returning zero connections) is always logged too.

### Run as a systemd service

```sh
sudo hexwall install-service [hexwall flags...]
# e.g.
sudo /usr/local/bin/hexwall install-service --zeek-log /opt/zeek/logs/current/ssl.log --enable-zeek
```

This makes hexwall start at boot and restart if it crashes. The flags after `install-service` are the ones the service runs with, and they're checked first, so a typo fails here instead of making the service crash at every boot. Then it:

1. writes `/etc/systemd/system/hexwall.service`, running this binary (by its absolute path) with those flags from `/var/lib/hexwall`, where the default `./hexwall.db` is created;
2. if the flags use Zeek (`--zeek-log` or `--enable-zeek`), writes a `zeek.service` that runs `zeekctl deploy` at boot and `zeekctl stop` on shutdown, and orders hexwall after it. A `zeek.service` that hexwall didn't write (from a package, or written by hand) is left untouched and used as is;
3. runs `systemctl daemon-reload`, enables both units, and (re)starts hexwall.

**The service runs in `--mode watch` unless you pass `--mode` yourself.** A service starts before anyone is watching, so killing has to be switched on deliberately: check the logs first, then re-run `install-service` with `--mode enforce`.

Re-running `install-service` updates the units. Build hexwall before you run it: the binary that `go run` makes is deleted when it exits, so it's refused.

```sh
systemctl status hexwall             # is it running?
journalctl -u hexwall -f             # follow its logs
sudo systemctl disable --now hexwall # stop it and remove it from boot
```

Linux with systemd only.

### Uninstall

```sh
sudo hexwall uninstall
```

Undoes `install-service` and `zeek-setup`: it stops, disables and deletes the units hexwall wrote, removes the `@load dns-bypass` lines from `local.zeek`, and deletes the script. Only files carrying hexwall's signature are touched, so a `zeek.service` or `dns-bypass.zeek` someone else wrote is left in place. Changes you made yourself, such as the interface in `node.cfg`, stay.

Two things are kept on purpose: `/var/lib/hexwall` (the database with the kill and alert history; delete it with `sudo rm -r /var/lib/hexwall`) and the hexwall binary, which you installed.

---

## When a connection is killed

A connection is only ever killed in `--mode enforce`, for a connection the active connection-listing tool (`ss` or `somo`) reports as currently established. Four independent checks can trigger it:

1. **Pi-hole domain denylist match** — Zeek captured the connection's TLS SNI (via `--zeek-log`) and that domain is on Pi-hole's own denylist, a regex denylist entry, or the gravity blocklist. Requires only Pi-hole; no third-party service is involved, and this check runs regardless of the `--enable-deghost-*` flags.
2. **Third-party domain reputation match** — an SNI was captured, the domain is on neither Pi-hole list and isn't already known-trusted for this IP, and the reputation API's verdict (fetched live or reused from a 6-hour cache) says to block it. Requires `--enable-deghost-domain` (default `false`).
3. **Third-party IP reputation match** — no SNI was available at all (non-TLS traffic, ECH, or a connection predating startup), the IP is not trusted, and the reputation API's verdict on the bare IP (live or 6-hour cached) marks it `is_abuser`, `is_attacker`, or `is_threat`. Requires `--enable-deghost-ip` (default `false`).

4. **Zeek DNS-bypass alert for a blocked domain** — Zeek raised a bypass alert (`--enable-zeek`), the domain is blocked by Pi-hole's lists, and the alerted connection is on this machine. See [DNS-bypass alerts](#dns-bypass-alerts).

Both `--enable-deghost-*` flags default to `false`, because they send connection data off the machine. With the defaults, only the Pi-hole checks (1 and 4) can trigger a kill, and both need Zeek. So `--mode enforce` without `--zeek-log` kills nothing unless you opt in to `--enable-deghost-ip`; hexwall warns about this at startup.

Pi-hole regex entries are matched the way Pi-hole matches them: case-insensitive, with `;invert` honoured. Options hexwall can't evaluate for a connection (`;querytype=`, `;reply=`, unknown ones) resolve toward not killing: an allow rule with them still applies, and a deny rule with them is skipped. Regex lists are reloaded on the 30-second refresh, so edits in Pi-hole take effect without a restart.

A connection is treated as trusted, and skipped entirely, when any of these are true:

- Its IP matches the built-in CIDR allowlist.
- Its domain is on Pi-hole's allowlist (exact or regex).
- Its IP was resolved from a domain a client asked Pi-hole for within the last hour, or was already seen as an established connection within the last 60 seconds.
- Its domain has already been seen for this exact IP in hexwall's own history.

Connections are not killed in these cases:

- `--mode watch` is active — a would-be kill is only logged as `would kill`.
- The relevant reputation check is disabled via its flag.
- A cached reputation verdict from the last 6 hours says clean.
- The IP reputation API returns HTTP `403`, treated as clean/private/reserved.
- The reputation lookup itself fails — a failed lookup is never treated as a block.

When a kill does happen, hexwall first records it in the local `killed_connections` audit table with the outcome `attempting`, so the record exists even if hexwall dies mid-kill. It then runs its guardrails: it refuses PID 1, its own PID, invalid PIDs, and a hardcoded set of protected system processes (`systemd`, `sshd`, `dockerd`, and similar), whichever check triggered the match. Once the attempt ends, the row's `outcome` says what happened: `killed`, `refused` (a guardrail declined it), or `failed` (no usable PID, or the kill itself errored). Rows written before this column existed say `unknown`. A kill the guardrails allow closes the connection in one of two ways:

1. **Just that connection**: `ss -K` asks the kernel to destroy the single socket, leaving every other connection the process holds untouched. This needs `CAP_NET_ADMIN` (e.g. running as root) and a kernel built with `CONFIG_INET_DIAG_DESTROY`. Because `ss -K` can exit successfully even when the kernel refused, hexwall re-lists the socket afterwards and only counts the kill if the connection is actually gone.
2. **The whole process** (fallback): if the connection is still there, or `ss` is unavailable (always the case on macOS), hexwall signals the owning PID: `SIGTERM` first, escalating to `SIGKILL` after a 2-second grace period if the process is still alive. This also drops every other connection that process holds.

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

1. Read the queries logged in `pihole-FTL.db` since the previous refresh (the last hour, on the first refresh). Each query is read once, tracked by its id.
2. Keep the non-empty domains **that Pi-hole answered**. Queries Pi-hole blocked are skipped, so a blocked domain's IP never becomes trusted, even if the host's resolver could look it up through another nameserver. Only the FTL statuses known to mean "answered" (forwarded, cached, retried, and their variants) count; a status hexwall doesn't recognise counts as not answered.
3. Normalize them to lowercase and trim whitespace.
4. Resolve each domain through the system DNS resolver, with bounded concurrency and a 1 second lookup timeout per domain.
5. Ignore domains that do not resolve, such as expired records.
   If the host's resolver is Pi-hole itself, these lookups are logged as queries too. hexwall remembers when it looked up each domain and skips the logged query that matches, so its own lookups never count as a client asking again. Without that, every domain would stay "recently seen", and trusted, forever.
6. Deduplicate resolved IPs. If multiple domains resolve to the same IP, the first domain in sorted order is stored for that IP.
7. Upsert each resolved IP into the local `allowed_ips` table, setting or refreshing `last_refreshed`.

Important details:

- Startup performs this refresh immediately before the first monitoring scan, so normal traffic seen in recent Pi-hole history is trusted before enforcement begins.
- The refresh repeats every 30 seconds, and only resolves domains clients asked for since the previous one.
- Trust from Pi-hole lasts for 1 hour from the most recent successful upsert, which is shortly after a client last asked for one of the IP's domains.
- If Pi-hole's query log is flushed or recreated (its ids restart), hexwall notices and re-reads the last hour.
- Existing rows keep their original `first_approved` and `last_established` values when refreshed; only the stored domain and `last_refreshed` timestamp are updated.
- The monitor also extends trust for long-lived allowed connections by updating `last_established` whenever an already-trusted connection is seen still established.

This means an IP becomes trusted from Pi-hole history only after all of these happen:

1. A client asked Pi-hole for one of its domains, and Pi-hole answered.
2. That domain still resolves at the next refresh.
3. One of the resolved IPs is written into the local `allowed_ips` cache.

If a domain was seen in Pi-hole history but doesn't resolve at the refresh, no IP is added for it, so there is nothing to trust from that domain alone.

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
