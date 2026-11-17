# Central log collector

The README approved this layout on 2026-11-13: VictoriaLogs on Dell and a Vector shipper on each host, both native under systemd, with logs kept for 30 days.

## Dell (installed 2026-11-18 02:15 ICT, owner's order "ติดตั้ง collector บน Dell เลย")

| Item | Value |
|---|---|
| VictoriaLogs | `v1.54.0` (`victoria-logs-linux-amd64-v1.54.0.tar.gz`, sha256 checked against the release checksums) |
| Vector | `0.62.0` (`vector-0.62.0-x86_64-unknown-linux-gnu.tar.gz`, sha256 checked against `vector-0.62.0-SHA256SUMS`) |
| Root | `/data/yuth/logging`: `bin/`, `etc/vector.yaml`, `vlogs-data/`, `vector-data/` |
| Units | `systemd --user` (user `yuth`, linger on): `victoria-logs.service`, `vector.service` in `~/.config/systemd/user/`. Dell has no passwordless sudo, so these are user units like `tq.service`. |
| Listen | `127.0.0.1:9428` only. No public address yet. |
| Retention | `-retentionPeriod=30d`, plus a disk cap of `-retention.maxDiskSpaceUsageBytes=200GiB` |
| Source | Dell's whole journald, from install time on (`since_now`). User `yuth` is in `adm`, so it reads system units as well as user units. Measured before install: about 63k lines/hour, about half of them from `service-ibrowe`. |

The files in this folder are the installed copies.

### How a line is shaped

- A journald message that is a JSON object (a `log108` line) is unpacked, so `level`, `service`, `target`, `request_id` and event fields become searchable fields. Any other line is kept as `message`.
- `service` falls back to the systemd unit name without `.service`. A command run from an ssh login (`session-<n>.scope`) is named by its syslog tag instead.
- `level` always uses the log108 words `error` | `warn` | `info` | `debug` | `trace`, so `level:error` finds errors from every unit. A line with no `level` gets one from journald `PRIORITY`: 0–3 → `error`, 4 → `warn`, 5–6 → `info`, 7 → `debug`. A JSON `level` is lowercased, and `warning`/`crit`/`fatal`/`notice` are folded into those words. The raw journald number stays in `priority`. Lines stored before 2026-11-18 02:21 ICT still carry the number in `level`.
- On Dell, the config before this change is kept at `/data/yuth/logging/etc/vector.yaml.prev`.
- The stream key is `host,service`.

### Query

```bash
ssh Dell-server 'curl -s 127.0.0.1:9428/select/logsql/query --data-urlencode "query=_time:1h service:tq level:error"'
```

The web UI is at `http://127.0.0.1:9428/select/vmui/`, through an ssh tunnel: `ssh -L 9428:127.0.0.1:9428 Dell-server`.

### Operate

```bash
systemctl --user status victoria-logs vector
journalctl --user -u vector -n 50
```

## Not done yet

- **`https://logs.108plaza.net`**: the Cloudflare tunnel and its access policy. They need the owner's Cloudflare account, and there must be an access policy before any public hostname exists. Log lines carry internal hostnames and error text.
- **Shippers on other hosts** (the DO droplet running bank-bot, line-bot and tg-bot). They need a reachable endpoint first: the tunnel, or a Tailscale address with auth in front.
- `/data/yuth/logging/dl/` (252M) holds the downloaded tarballs. They are left in place because the rules forbid deleting on Dell without the owner.
