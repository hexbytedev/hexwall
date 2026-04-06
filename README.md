# pihole-guard

Monitors active network connections and kills any that connect to IPs not previously seen through Pi-hole's DNS resolver — closing the gap that Pi-hole leaves open for direct-IP connections.

---

## The problem

Pi-hole operates at the DNS layer. It can block a domain, but it has no visibility into connections that bypass DNS entirely — processes that dial a hard-coded IP address directly. Malware and compromised packages commonly use this technique to phone home without triggering any DNS-based block.

pihole-guard works from the inverse assumption: **if an IP was never resolved through Pi-hole, the connection is suspicious by default.** Every 30 seconds it reads Pi-hole's own query history, resolves those domains forward, and builds a local allow-set of trusted IPs. Anything that falls outside that set is checked against an external fraud API. Confirmed threats are either logged (watch mode) or killed (enforce mode).


---

## Dependencies

| Dependency                                | Role                                                | Required                    |
| ----------------------------------------- | --------------------------------------------------- | --------------------------- |
| [`somo`](https://github.com/theopfr/somo) | Lists established TCP/UDP connections; kills by PID | Must be in `$PATH`          |
| Pi-hole FTL database                      | Source of trusted DNS history                       | Auto-detected or via `--db` |
| `fraudcheckapi.hexbyte.dev`               | Fraud/threat classification for unknown IPs         | Network access required     |

**Build dependency:** `modernc.org/sqlite` (pure-Go SQLite, no CGo or system libsqlite3 required).

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
| `--guard-db` | `./pihole-guard.db` | Path to the local guard database (created on first run)          |
| `--mode`     | `watch`             | `watch` — detect and log only; `enforce` — detect, log, and kill |

`--mode` accepts `watch` or `enforce` (case-insensitive). Any other value exits with an error.
