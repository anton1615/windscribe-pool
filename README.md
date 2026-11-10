# windscribe-pool

**One shared Windscribe free-account pool, many clients.** `windscribe-pool`
turns Windscribe's free OpenVPN nodes into a small **multi-client service for
your trusted network**: every client gets its own exit behind a stable port,
delivered as 🧾 mihomo subscription nodes and controlled over a ⚙️ HTTP API.
Unofficial community software. Not affiliated with or endorsed by Windscribe.
> Only use it with accounts you are authorized to use, in accordance with
> Windscribe's terms of service.

Design borrowed heavily from
[foxyvpn-pool](https://github.com/anton1615/foxyvpn-pool) and
[urn-pool](https://github.com/anton1615/urn-pool) — same byte-relay swap
choreography, adapted to OpenVPN tunnels on Windscribe free nodes.

## ✨ Highlights

- 🖥 **One pool, N clients** — every client draws from the same
  pre-provisioned free-account pool on the host
- 🚪 **A stable port per client** — public ports come from a monotonic
  counter persisted in the state file, so subscription URLs never go stale
- 🌍 **Region switching / rotation nobody notices** — `/country` and
  `/rotate` warm up the replacement tunnel first; streams keep flowing on
  the old tunnel while it drains, and idle keep-alive connections are cut
  within seconds so every *new* request rides the new exit IP
- 🔋 **Quota self-management** — every free account has a hard 2 GiB/month
  cap; the wrapper meters bytes locally, reconciles against the API, and
  swaps a node to the next account in its batch *before* the current one
  runs dry — without dropping a single client connection
- 🧾 mihomo subscription endpoints (`/sub`, `/sub?uid=…`) plus plain SOCKS5
- ⚙️ Full instance lifecycle from the API: register, delete, list nodes,
  switch country, rotate, status

## 🧠 How it works

```
client ──socks5──> <bind-host>:2300x   🚪 front (pure byte relay, no protocol)
                                         │
             old tunnel keeps serving its connections ◄── 🔁 flip
                                         │              (drain, then retire)
                                 <inner>:3300x  socks5 backend (SO_BINDTODEVICE → tunX)
                                         │
                             tunX (OpenVPN, node IP:443/udp) ──► 🌍 exit
```

Every client (a `uid` of its choosing) gets a **public port** (`23000+`,
stable for its lifetime) served by a byte-relay, and an **OpenVPN tunnel** to
one free Windscribe node, fronted by a loopback SOCKS5 backend bound to the
tunnel device.

The key trick (inherited from foxyvpn-pool): SOCKS5 carries exactly **one
tunnel per TCP connection**, so the relay in front needs to understand no
protocol at all — it just moves bytes. A swap warms up the new tunnel, flips
the relay, then retires the old one once its connections have drained; the
public port never changes.

## 🔑 The account pool

- Free accounts land as JSON files in `inbox/` (pushed by whatever
  registration tooling you use — **registration is not part of this repo,
  bring your own accounts**). The pool ingests them every cycle:

  ```bash
  ssh user@pool-host "cat > ~/windscribe-pool/inbox/<username>.json"
  ```

  ```json
  {"username": "…", "password": "…", "ovpn_user": "…", "ovpn_pass": "…",
   "traffic_max": 2147483648}
  ```

- One account can hold exactly **one tunnel** (a second is silently
  blackholed), so each account serves one node at a time; nodes draw a small
  batch (`ACCOUNTS_PER_NODE`, default 3) and rotate within it.
- Only **free nodes** are ever used (`serverlist/openvpn/0/0`, all
  `pro_only` entries excluded).

### One-time provisioning

`template.udp` is the base OpenVPN profile (CA/cert/tls-auth, no `remote`),
fetched from any account's session and kept out of the checkout:

```bash
curl -s -H "authorization: Bearer <session-token>" \
     "https://api.windscribe.com/ServerConfigs?ovpn_version=2.5" \
  | base64 -d > ~/windscribe-pool/template.udp
```

`serverlist.json` (free-node list) is refreshed by the pool itself.

## 🚀 Install

stdlib-only Python 3.11+, plus `openvpn` on `PATH`.

```bash
git clone <this repo> ~/windscribe-pool
cd ~/windscribe-pool
```

Foreground test run:

```bash
python3 wspool.py
```

As a system service (see `examples/`):

```bash
cp examples/windscribe-pool.service.example /etc/systemd/system/windscribe-pool.service
systemctl daemon-reload && systemctl enable --now windscribe-pool
journalctl -u windscribe-pool -f
```

By default the API binds to the host's Tailscale address (port 8094); front
ports start at 23000, inner backends at 33000. Override with
`BIND_HOST` / `API_PORT` / `FRONT_BASE` / `INNER_BASE`.

## ⚙️ HTTP API

| Endpoint | Meaning |
|---|---|
| `GET /register?uid=<name>[&country=CC][&node=…]` | 🚪 Reserve a client: allocate accounts, start a tunnel, return its stable port. Idempotent per name |
| `GET /delete?uid=<name>` | 🗑 Tear the node down, release accounts and port |
| `GET /country?uid=<name>&country=CC` | 🔁 Seamless switch to another free node of that country (port unchanged) |
| `GET /rotate?uid=<name>[&country=CC]` | ♻️ Re-pick a random free node (no repeats), exit IP changes; retry-safe |
| `GET /status` | 📊 Per-node state + pool accounting (quota / in-use / bad / exhausted) |
| `GET /accounts` | 🪙 Account pool with quota and health |
| `GET /accounts/reset?label=<L>` | ↩ Clear an account's bad/exhausted flag (manual) |
| `GET /nodes[?country=CC]` | 🌍 Free-node list (paid nodes never appear) |
| `GET /sub[?uid=<name>]` | 🧾 mihomo YAML (one node or all) |

Register a client and use it:

```bash
curl 'http://<host>:8094/register?uid=laptop'
# → {"uid":"laptop","public_port":23000,"socks":"socks5://<host>:23000",...}
curl --socks5-hostname <host>:23000 https://ipinfo.io/json
```

mihomo consumes the subscription URL instead:

```
http://<host>:8094/sub?uid=laptop
```

DNS must resolve on the exit side (`socks5h` semantics).

## 🛡 Security & trust model

**Built for a trusted network — a tailnet, a VPN, or a LAN that you
control.** The SOCKS5 ports and the bare API paths carry no authentication:
the trust boundary is your network's egress, not this service. Do not expose
the bind address to the public internet.

- Nothing enforces a client↔node mapping: any client on the network can
  reach any node the host has created and steer it via a known `uid`.
- `accounts/`, `inbox/`, `state.json`, `template.udp` and `conf/` contain
  account credentials and per-account certificates — keep them `0600` and
  out of any public checkout (they are in `.gitignore`).

## 🧩 Layout

```
wspool.py        pool wrapper + HTTP API + byte relay (standalone, stdlib only)
examples/        example data formats + systemd units
```

## 🙏 Credits

- [foxyvpn-pool](https://github.com/anton1615/foxyvpn-pool) — the
  byte-relay/warm-up/swap design, README voice, and the public-repo split
  (registration tooling stays out of the repo).
- [urn-pool](https://github.com/anton1615/urn-pool) — the rotate/no-repeat
  and quota self-management patterns.
