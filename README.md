# hexwall

[![Go Reference][1]][2]
[![CodeQL Advanced][3]][4]
[![golangci-lint][5]][6]
[![Dependency Review][7]][8]
[![Dependency Graph][9]][10]
[![Dependabot Updates][11]][12]
[![Go][13]][14]

`hexwall` is an outbound exfiltration brake for servers already protected by Pi-hole. When a supply-chain attack, malware implant, or compromised package is already running inside the machine, it can skip DNS entirely and send stolen data straight to a hard-coded IP. Pi-hole does not see that hop. `somo` can see the live connection. `hexwall` uses that visibility to flag and, in `enforce` mode, kill suspicious direct-IP connections before data leaves the server.

It monitors active network connections and kills any that connect to IPs that are not trusted by Pi-hole history, the built-in local allowlist, or recent already-established traffic — closing the gap that Pi-hole leaves open for direct-IP connections.

In short: `Pi-hole + somo + hexwall` gives you a practical containment layer for post-compromise outbound traffic, especially the kind of direct-IP exfiltration occasionally used in supply-chain attacks.

## At a glance

| Situation | Server without Pi-hole DNS | Server with only Pi-hole | Server with Pi-hole + somo + hexwall |
| --- | --- | --- | --- |
| Malicious domain resolved over DNS | ❌ Exposed | ✅ Can block at DNS layer | ✅ Can block at DNS layer |
| Malware connects to a hard-coded IP directly | ❌ Exposed | ❌ Pi-hole does not see it | ✅ Direct-IP connection is visible and checked |
| Identify which process owns the connection | ❌ No built-in visibility | ❌ No process visibility | ✅ `somo` shows PID/program |
| Stop outbound exfiltration after compromise | ❌ No containment layer | ⚠️ Only if the attacker still uses DNS | ✅ Can kill suspicious established connections |
| Supply-chain malware bypassing DNS | ❌ High risk | ❌ Still exposed | ✅ Stronger containment |
| Overall outbound protection posture | ❌ Weak | ⚠️ Partial | 🛡️ Strongest of the three |

---

## The problem

Pi-hole operates at the DNS layer. It can block a domain, but it has no visibility into connections that bypass DNS entirely — processes that dial a hard-coded IP address directly. Malware and compromised packages commonly use this technique to phone home without triggering any DNS-based block.

hexwall works from the inverse assumption: **if an IP is not trusted, the connection is suspicious by default.** Trust is granted when the IP matches the built-in CIDR allowlist, was refreshed from Pi-hole query history within the last hour, or was already observed as an established connection within the last 60 seconds. On startup it immediately refreshes trusted IPs from Pi-hole, then refreshes them every 30 seconds while scanning connections every 10 seconds. Anything that falls outside that trust set is checked against an external fraud API, with results cached locally for 6 hours per IP. Confirmed threats are either logged (watch mode) or killed (enforce mode).

---

## Dependencies

| Dependency                                | Role                                                | Required                    |
| ----------------------------------------- | --------------------------------------------------- | --------------------------- |
| [`somo`](https://github.com/theopfr/somo) | Lists established TCP/UDP connections; kills by PID | Must be in `$PATH`          |
| Pi-hole FTL database                      | Source of trusted DNS history                       | Auto-detected or via `--db` |
| `deghostapi.hexbyte.dev`                  | Fraud/threat classification for unknown IPs         | Network access required     |

**Build dependency:** `modernc.org/sqlite` (pure-Go SQLite, no CGo or system libsqlite3 required).

## Binaries and deployment

CI publishes lightweight Linux binaries for:

- `linux/amd64`
- `linux/arm64`

You can download them from the project's GitHub Releases page:

- [GitHub Releases](https://github.com/hexbytedev/hexwall/releases)

For production Linux servers, download the matching binary from Releases, place it where your deployment expects `./app/hexwall`, and use the included demo Docker Compose file at [`docker-compose.yml`](./docker-compose.yml) to launch it on the server.

For macOS and Windows, prebuilt binaries are not published by CI. Clone the repository and build the binary manually before deployment.

### Install `somo`

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

| Flag         | Default             | Description                                                      |
| ------------ | ------------------- | ---------------------------------------------------------------- |
| `--db`       | _(auto-detected)_   | Path to `pihole-FTL.db`                                          |
|`--hexwall-db`| `./hexwall.db`      | Path to the local hexwall database (created on first run)        |
| `--mode`     | `watch`             | `watch` — detect and log only; `enforce` — detect, log, and kill |
| `--debug`    | `false`             | Enable verbose per-connection scan logging                       |

`--mode` accepts `watch` or `enforce` (case-insensitive). Any other value exits with an error.

### Debug logging

When `--debug` is enabled, each scan cycle logs every connection it encounters with its status:

- **allowed** — IP is in the local trust cache or allowlist
- **unrecognized-clean** — IP is not in cache, but the fraud API returned a clean verdict (or 403 for private/reserved ranges)
- **vulnerable** — IP is not in cache, fraud API flagged it as abuser/attacker/threat

When debug is disabled (default), only non-allowed results are logged. Additionally, empty scans (somo returning zero connections) are always logged regardless of debug mode.

---

## When a connection is killed

A connection is killed only when all of the following are true:

1. `--mode enforce` is active.
2. `somo` reports the connection as currently established.
3. The remote IP is not trusted.
4. The remote IP's current fraud decision, either fetched live or reused from the local 6-hour cache, marks it as `is_abuser`, `is_attacker`, or `is_threat`.

An IP is considered trusted when any of these are true:

- It matches the built-in CIDR allowlist.
- It was refreshed from Pi-hole history within the last hour.
- It was already seen as an established allowed connection within the last 60 seconds.

Connections are not killed in these cases:

- `--mode watch` is active. The connection is only logged as `would kill`.
- The IP is on the built-in allowlist.
- The IP is still trusted from a recent Pi-hole refresh or recent established-connection activity.
- The IP already has a cached clean fraud verdict from the last 6 hours.
- The fraud API returns HTTP `403`, which is treated as clean/private/reserved.
- The fraud API returns a report but none of `is_abuser`, `is_attacker`, or `is_threat` are true.
- The fraud lookup itself fails.

When a kill does happen, hexwall first records the event in the local `killed_connections` audit table and then asks `somo` to kill the owning PID.

### Fraud API cache behavior

Fraud lookups are cached in the local SQLite database for 6 hours per IP.

- If an untrusted IP has a cached fraud decision newer than 6 hours, hexwall reuses that cached result and does not call the fraud API again.
- If the cached decision is older than 6 hours, the next scan calls the fraud API again and refreshes the cache timestamp.
- Both clean and kill-worthy fraud decisions are cached.
- HTTP `403` responses are treated as clean/private/reserved and cached as a non-kill result.
- Fraud lookup failures are not cached.

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
