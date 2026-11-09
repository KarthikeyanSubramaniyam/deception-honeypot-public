# Deception Honeypot

A multi-service **deception honeypot** in Python that impersonates a sloppy
production box (`prod-db-01`), lets attackers in, and turns everything they do
into defender-grade intelligence — captured credentials, full shell sessions,
extracted IOCs, per-attacker threat scores, honeytoken trip-wires, and a live
operator console with session replay.

One process, one SQLite file, one `docker compose up`.

```
         SSH 2222      HTTP 8080      Telnet 2323      Redis 6379
       fake shell     fake admin    BusyBox login    RESP responder
       + fake FS      + scanner      (Mirai bait)    (RDB-takeover
       + HASSH        bait + API                      detector)
           \              \              /              /
            \              \            /              /
             ─────────────  EventBus  ─────────────────
                          /    |     \
         honeytoken  IOC extract  enrichment    sinks (JSONL,
          detector    + scoring   (rDNS/GeoIP)   Slack webhook)
                          |
                    SQLite store
                          |
              Operator console :9000
     overview · attackers · sessions (replay) · IOCs · live feed
```

## What it captures

| Layer | Impersonates | Intelligence produced |
|---|---|---|
| **SSH** (`asyncssh`) | OpenSSH 8.9 / Ubuntu 22.04, weak passwords | every credential, every command, files read, offered pubkeys, **HASSH** client fingerprint |
| **Telnet** | BusyBox login (what Mirai-class IoT bots hit) | default-cred attempts, the bot's full command playbook, next-stage payload URL |
| **Redis** | unauthenticated Redis 5.0 (RESP protocol) | the `CONFIG SET dir … / SAVE` **takeover chain** — fires critical and captures the SSH key or cron line being planted |
| **HTTP** (`aiohttp`) | nginx "Admin Console" + scanner bait (`/.env`, `/.git/config`, `/actuator/env`, …) | request forensics, web logins, API-token probes |
| **Honeytokens** | fake AWS keys, API tokens, DB passwords, canary URLs | **confirmed-malicious** signal the instant a planted secret is used anywhere |

## Intelligence layer

* **IOC extraction** — pulls payload URLs, C2 IPs, crypto-wallet addresses,
  hashes, pasted SSH keys and base64 blobs out of attacker input, de-duplicated
  with first/last-seen and source IPs. Exportable as JSONL.
* **Threat scoring** — each source IP gets a 0–100 score and explainable tags
  (`brute-force`, `download`, `execution`, `persistence`, `malware`,
  `honeytoken-triggered`, `multi-service`) from its behaviour.
* **Session replay** — any SSH/Telnet session renders to an
  [asciinema](https://asciinema.org) cast; replay it in the browser or
  `asciinema play session.cast` in your terminal.
* **Bot vs human** — inter-command timing classifies each session as
  bot / scripted / human.
* **Enrichment** — reverse DNS always; GeoIP/ASN opt-in (`HP_GEOIP=1`).

## Quick start

```bash
cp .env.example .env            # change the dashboard password at least
docker compose up --build -d
docker compose logs -f
```

Throw a scripted multi-service attack at it (brute-force → recon → steal &
use a token → Mirai telnet → Redis takeover):

```bash
pip install -r requirements.txt
python scripts/simulate_attack.py
```

Open the console at **http://localhost:9000** (basic auth: `admin` / `changeme`).

By hand:

```bash
ssh root@localhost -p 2222              # any password works on the 2nd try
curl -i localhost:8080/.env             # scanner bait, seeded with a honeytoken
redis-cli -p 6379 INFO                  # fake Redis
```

### Without Docker

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
make run        # or: python -m honeypot
make test       # 50 tests
make lint       # ruff
```

## Console

Five tabs over a JSON/SSE API:

* **Overview** — counts, events/hour, top IPs / credentials / commands
* **Attackers** — IP table ranked by threat score with tags and geo/rDNS
* **Sessions** — captured sessions with bot/human class; click any row to replay
* **IOCs** — extracted indicators with a type filter and JSONL export
* **Live feed** — real-time event stream with severity/service filters

### API

```
GET /healthz                         unauthenticated liveness probe
GET /api/stats                       aggregate counters
GET /api/events?limit=&service=&ip=&severity=&kind=
GET /api/attackers                   per-IP threat scores + tags
GET /api/attackers/{ip}              one attacker: score, info, recent events
GET /api/sessions                    sessions + bot/human classification
GET /api/sessions/{id}               one session's events
GET /api/sessions/{id}/replay.cast   asciinema v2 cast
GET /api/iocs?type=                  extracted indicators of compromise
GET /api/tokens                      active honeytokens (values truncated)
GET /api/export.jsonl                every event as JSON lines
GET /api/stream                      Server-Sent Events live feed
```

Everything also lives in `data/events.sqlite` — point any SQL tool at it.

## Configuration (`.env`)

| Var | Default | Meaning |
|---|---|---|
| `HP_SERVICES` | `ssh,http,telnet,redis` | which listeners to start |
| `HP_HOSTNAME` | `prod-db-01` | hostname in prompts, MOTD, pages |
| `HP_DASH_USER` / `HP_DASH_PASS` | `admin` / `changeme` | console basic auth — **change it** (a warning is logged while it's the default) |
| `HP_DASH_BIND` | `127.0.0.1` | console listen address (the Docker image sets `0.0.0.0`; compose publishes it on loopback only) |
| `HP_TRUST_PROXY` | `0` | honour `X-Forwarded-For` only behind a trusted proxy |
| `HP_MAX_CONN_PER_IP` / `HP_MAX_TOTAL_CONN` / `HP_CONN_PER_MIN_PER_IP` | 8 / 400 / 60 | self-protection limits |
| `HP_HTTP_REQ_PER_MIN_PER_IP` | 600 | HTTP per-IP request rate; excess gets a 503 and isn't logged |
| `HP_SESSION_IDLE_TIMEOUT` / `HP_SESSION_MAX_COMMANDS` | 300 / 500 | per-session caps |
| `HP_RDNS` / `HP_GEOIP` | 1 / 0 | enrichment (GeoIP makes outbound calls) |
| `HP_JSONL_LOG` | unset | append every event to a JSONL file |
| `HP_ALERT_WEBHOOK` / `HP_ALERT_FORMAT` / `HP_ALERT_MIN_SEVERITY` | unset / slack / high | webhook alerting (sent from a background queue, never blocks capture) |
| `HP_ALERT_MAX_PER_MIN` | 30 | cap on webhook posts per minute during floods |

To catch real internet scanners, map host ports `22`, `80`, `23` in
`docker-compose.yml`, keep the dashboard on `127.0.0.1`, and reach it over an
SSH tunnel.

## Layout

```
honeypot/
  config.py        env-driven settings
  events.py        Event model, SQLite store (events/ip_info/iocs), pub/sub bus
  fakefs.py        in-memory Linux filesystem + ~40-command shell emulator
  ssh_service.py   asyncssh: auth capture, HASSH, interactive/exec shell
  telnet_service.py BusyBox-style Telnet for IoT-botnet capture
  redis_service.py  RESP responder + RDB-takeover detection
  http_service.py  fake admin site, scanner bait, canary endpoint
  honeytokens.py   token minting, persistence, matching, decoy files
  analysis.py      IOC extraction, threat scoring, bot/human, asciicast replay
  enrichment.py    rDNS + opt-in GeoIP/ASN
  sinks.py         JSONL + webhook alerting
  guard.py         per-IP / global / rate-limit connection guard
  dashboard.py     basic-auth console + JSON/SSE API
  main.py          wires it all together
scripts/simulate_attack.py   scripted attacker across all four services
tests/                       50 tests incl. live SSH/Telnet/Redis integration
```

## Safety

* The container runs read-only, unprivileged, all caps dropped, memory/pid
  capped. The fake shell never executes anything; payload downloaders always
  "fail" with network-unreachable, so nothing is fetched or run.
* A honeypot invites hostile traffic. Run it on an isolated host/VLAN, never on
  a box with real data, and change the dashboard password.
* Session replays strip terminal escape sequences, so playing an attacker's
  `.cast` with `asciinema play` can't hijack your terminal.
* Captured credentials are attacker-supplied and stored in plaintext **by
  design** — that's the intel. Treat `data/` and `honeytokens/` as sensitive.

## Extending it

The `EventBus` + `start_<service>` pattern makes new services a single file:
SMTP, FTP, MySQL-banner, SMB. Other natural additions: GeoIP-enriched attack
map, ship JSONL to Elastic/Loki with a Grafana board, Suricata/Zeek correlation,
or a notebook that clusters sessions by HASSH + command sequence.
