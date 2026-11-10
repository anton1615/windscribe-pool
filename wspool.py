#!/usr/bin/env python3
"""windscribe-pool — 一個客戶端一個穩定 port,背後是 Windscribe 免費節點的 OpenVPN 出口。

架構(仿 foxyvpn-pool / urn-pool 的 byte-relay 設計):
    client ──socks5──> <BIND_HOST>:2300x   前層 byte relay(不解協議,只搬位元組)
                          │ flip
                  <inner>:3300x     socks5 後端(SO_BINDTODEVICE → tunX)
                          │
                     tunX (openvpn, 免費節點 IP:443/udp) ──> Windscribe

- 一個 port = 一個節點 + 一批 Windscribe 帳號(batch)。免費帳號額度 2 GiB/月,用完換批內下一顆:
  先起新隧道暖機 → relay 翻轉 → 舊的等連線排空退休,對外 port 全程不變。
- 只用免費節點(`serverlist/openvpn/0/0` 過濾 `pro_only`);付費節點永不使用。
- 一顆帳號同時只能有一條隧道(Windscribe 實測:同帳號第二條會被靜默丟包),所以每顆帳號只配一個節點。
- 帳號來源:註冊工具(不在本 repo)把帳號 JSON push 進 `inbox/`,池每輪 ingest:

      ssh user@pool-host "cat > ~/windscribe-pool/inbox/<username>.json"

  格式:{"username","password","ovpn_user","ovpn_pass","traffic_max","node_ip","node","datacenter"}

API(無認證,信任網段):
  GET  /status                     → 節點 + 額度 + 帳號池狀態
  GET  /register?uid=N&(country=|node=)  → 建節點,回 public port(無 country/node 則隨機挑免費節點)
  GET  /country?uid=N&country=CC   → 無縫換節點(同國、port 不變)
  GET  /rotate?uid=N[&country=CC][&key=K] → 不重複隨機挑免費節點並切過去
  GET  /accounts                   → 帳號池(額度 / 使用中 / bad / exhausted)
  GET  /accounts/reset?label=L     → 解除 bad / exhausted(手動)
  GET  /nodes[?country=CC]         → 免費節點清單(付費節點不出現)
  GET  /sub[?uid=N]                → mihomo 訂閱(socks5 節點)
  GET  /delete?uid=N               → 刪節點
"""
import json
import os
import random
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

BASE = os.path.dirname(os.path.abspath(__file__))
STATE_PATH = os.path.join(BASE, "state.json")
INBOX = os.path.join(BASE, "inbox")
ACCDIR = os.path.join(BASE, "accounts")
SERVERLIST = os.path.join(BASE, "serverlist.json")
TEMPLATE = os.path.join(BASE, "template.udp")
LOGDIR = os.path.join(BASE, "logs")
CONFDIR = os.path.join(BASE, "conf")

FRONT_BASE = int(os.environ.get("FRONT_BASE", 23000))
INNER_BASE = int(os.environ.get("INNER_BASE", 33000))
API_PORT = int(os.environ.get("API_PORT", 8094))
def default_bind_host():
    """比照家族專案:預設綁本機 Tailscale 位址;抓不到退回 loopback。"""
    try:
        out = subprocess.run(["ip", "-4", "addr", "show", "tailscale0"],
                             capture_output=True, text=True, timeout=10).stdout
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("inet "):
                return line.split()[1].split("/")[0]
    except Exception:
        pass
    return "127.0.0.1"

BIND_HOST = os.environ.get("BIND_HOST") or default_bind_host()
PUBLIC_HOST = os.environ.get("PUBLIC_HOST", "")
API = "https://api.windscribe.com"
WS_PORT = int(os.environ.get("WS_PORT", 443))
WS_PROTO = os.environ.get("WS_PROTO", "udp")

ACCOUNTS_PER_NODE = int(os.environ.get("ACCOUNTS_PER_NODE", 3))  # 每個 port 先配幾顆帳號(一批)
POLL = int(os.environ.get("POLL", 120))                          # 監督/額度檢查週期(秒)
QUOTA_SOFT = float(os.environ.get("QUOTA_SOFT", 0.92))           # 本地計量到此比例就換帳號
QUOTA_PROBE_AT = float(os.environ.get("QUOTA_PROBE_AT", 0.75))   # 超過此比例才向 API 對帳
PROBE_GAP = int(os.environ.get("PROBE_GAP", 600))                # 同一顆帳號兩次對帳最短間隔(秒)

LOCK = threading.RLock()
STATE = {"nodes": {}, "next_slot": 0, "accts": {}, "rotate": {}}
OVPN = shutil.which("openvpn") or "/usr/sbin/openvpn"


def log(msg):
    print(f"[pool] {msg}", flush=True)


# ---------------- 狀態 ----------------
def load_state():
    global STATE
    if os.path.exists(STATE_PATH):
        try:
            STATE = json.load(open(STATE_PATH))
        except Exception:
            pass
    for k, v in (("nodes", {}), ("accts", {}), ("rotate", {})):
        STATE.setdefault(k, {})
    STATE.setdefault("next_slot", 0)


def save_state():
    tmp = STATE_PATH + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(STATE, fh, indent=1)
    os.replace(tmp, STATE_PATH)


def alloc_slot():
    with LOCK:
        idx = STATE["next_slot"]
        STATE["next_slot"] = idx + 1
        save_state()
        return idx


def tun_name(slot):
    return f"tun{200 + slot}"


def month_key():
    return time.strftime("%Y-%m", time.gmtime())


# ---------------- 帳號池 ----------------
def ingest_inbox():
    """把 inbox/*.json 收進 accounts/,回傳新收幾顆。"""
    os.makedirs(INBOX, exist_ok=True)
    os.makedirs(ACCDIR, exist_ok=True)
    n = 0
    for name in sorted(os.listdir(INBOX)):
        if not name.endswith(".json"):
            continue
        src, dst = os.path.join(INBOX, name), os.path.join(ACCDIR, name)
        try:
            with open(src) as fh:
                d = json.load(fh)
            if not (d.get("username") and d.get("ovpn_user") and d.get("ovpn_pass")):
                raise ValueError("missing username/ovpn_user/ovpn_pass")
            os.replace(src, dst)
            os.chmod(dst, 0o600)
            n += 1
        except Exception as exc:
            log(f"inbox {name} rejected: {exc}")
            bad = src + ".bad"
            try:
                os.replace(src, bad)
            except Exception:
                pass
    return n


def load_accounts():
    out = []
    if not os.path.isdir(ACCDIR):
        return out
    for name in sorted(os.listdir(ACCDIR)):
        if not name.endswith(".json"):
            continue
        try:
            d = json.load(open(os.path.join(ACCDIR, name)))
        except Exception as exc:
            log(f"accounts/{name} unreadable: {exc}")
            continue
        if not (d.get("username") and d.get("ovpn_user") and d.get("ovpn_pass")):
            continue
        out.append(d)
    return out


def label_of(acct):
    return acct["username"]


def acct_state(label):
    with LOCK:
        st = STATE["accts"].setdefault(label, {})
        st.setdefault("used_bytes", 0)
        st.setdefault("month", month_key())
        st.setdefault("bad", False)
        st.setdefault("exhausted", False)
        st.setdefault("reported", None)
        st.setdefault("probed_at", 0)
        return st


def roll_month():
    """Windscribe 免費額度按月給;跨月就把本地計量歸零(exhausted 也一起解)。"""
    cur = month_key()
    dirty = False
    with LOCK:
        for label, st in STATE["accts"].items():
            if st.get("month") != cur:
                st["month"] = cur
                st["used_bytes"] = 0
                st["reported"] = None
                st["exhausted"] = False
                dirty = True
        if dirty:
            save_state()


def live_slots():
    """(label, dev) 目前還掛著的 slot(含已退休但欄位未清的,以 STATE 為準)。"""
    out = []
    for node in STATE["nodes"].values():
        for s in (node.get("slots") or {}).values():
            if s.get("cred") and s.get("dev"):
                out.append((s["cred"], s["dev"]))
    return out


def in_use_labels():
    """目前真的有一條活隧道在跑的帳號(死掉的隧道不算,帳號立刻可被下一個節點接手)。

    draining 中(已翻 target、等排空)的舊隧道也算在內:openvpn 還掛著、
    帳號額度還在燒,不該讓別的節點同時抓同一顆帳號。
    """
    counts = {}
    for uid, n in NODES.items():
        tun = n.get("cur")
        if tun and tun.up:
            counts[tun.label] = counts.get(tun.label, 0) + 1
        for old in n.get("draining", []):
            if old.up:
                counts[old.label] = counts.get(old.label, 0) + 1
    return counts


def dev_bytes(dev):
    try:
        p = subprocess.run(["ip", "-s", "link", "show", "dev", dev],
                           capture_output=True, text=True, timeout=5)
        rx = tx = 0
        for line in p.stdout.splitlines():
            f = line.split()
            if len(f) >= 4 and f[0].isdigit():
                rx, tx = int(f[0]), int(f[2])
        return rx, tx
    except Exception:
        return 0, 0


def acct_used(label):
    st = acct_state(label)
    total = int(st.get("used_bytes") or 0)
    for lab, dev in live_slots():
        if lab == label:
            rx, tx = dev_bytes(dev)
            total += rx + tx
    return total


def acct_limit(acct):
    st = acct_state(label_of(acct))
    rep = st.get("reported") or {}
    return int(rep.get("max") or acct.get("traffic_max") or 2 * 1024**3)


def acct_available(label):
    st = acct_state(label)
    return not st.get("bad") and not st.get("exhausted")


def other_batch_labels(uid=""):
    """其他節點的 batch 成員(挑帳號時優先避開,免得所有節點搶同一批)。"""
    out = set()
    for u, meta in STATE["nodes"].items():
        if u == uid:
            continue
        out |= {l for l in (meta.get("batch") or []) if l}
    return out


def pick_account(exclude=()):
    """挑一顆可用、且目前沒有任何節點正在用的帳號。"""
    with LOCK:
        used = in_use_labels()
        for a in load_accounts():
            lab = label_of(a)
            if lab in exclude or used.get(lab, 0):
                continue
            if not acct_available(lab):
                continue
            return a
    return None


def mark_account(label, bad=None, exhausted=None, error=""):
    with LOCK:
        st = acct_state(label)
        if bad is not None:
            st["bad"] = bool(bad)
            if bad:
                st["fails"] = int(st.get("fails") or 0) + 1
            else:
                st["fails"] = 0
        if exhausted is not None:
            st["exhausted"] = bool(exhausted)
        if error:
            st["last_error"] = error[:200]
        st["updated_at"] = time.time()
        save_state()


def settle_slot(meta, slot_key):
    """slot 退休:把 tun 介面累計位元組記到該帳號的用量,再清掉 slot。"""
    s = (meta.get("slots") or {}).pop(str(slot_key), None)
    if not s:
        return
    lab = s.get("cred")
    if lab and s.get("dev"):
        rx, tx = dev_bytes(s["dev"])
        with LOCK:
            st = acct_state(lab)
            st["used_bytes"] = int(st.get("used_bytes") or 0) + rx + tx
            save_state()


def probe_quota(acct):
    """向 Windscribe 對帳(只在使用量接近上限時呼叫)。429/707 就跳過,等下一輪。"""
    lab = label_of(acct)
    st = acct_state(lab)
    if time.time() - float(st.get("probed_at") or 0) < PROBE_GAP:
        return
    with LOCK:
        st["probed_at"] = time.time()
        save_state()
    body = json.dumps({"username": lab, "password": acct.get("password"),
                       "platform": "legacy-web", "session_type_id": 1}).encode()
    req = urllib.request.Request(API + "/Session", data=body, method="POST",
                                 headers={"Content-Type": "application/json",
                                          "Origin": "https://windscribe.com",
                                          "Referer": "https://windscribe.com/",
                                          "authorization": "Bearer anonymous"})
    try:
        d = json.load(urllib.request.urlopen(req, timeout=30))["data"]
    except urllib.error.HTTPError as exc:
        if exc.code == 429:
            log(f"quota probe {lab}: rate limited, skip")
        else:
            log(f"quota probe {lab}: HTTP {exc.code}")
        return
    except Exception as exc:
        log(f"quota probe {lab}: {exc}")
        return
    used, mx = int(d.get("traffic_used") or 0), int(d.get("traffic_max") or 0)
    with LOCK:
        st = acct_state(lab)
        st["reported"] = {"used": used, "max": mx, "at": time.time(),
                          "reset": d.get("last_reset"), "status": d.get("status")}
        if mx and used >= mx:
            st["exhausted"] = True
            log(f"quota probe {lab}: API says exhausted ({used}/{mx})")
        save_state()
    return st.get("reported")


# ---------------- 免費節點 ----------------
def free_nodes(refresh=False):
    """只在 serverlist 裡的免費節點(pro_only 全排除)。"""
    if refresh or not os.path.exists(SERVERLIST):
        try:
            req = urllib.request.Request(
                "https://assets.windscribe.com/serverlist/openvpn/0/0",
                headers={"User-Agent": "curl/8"})
            data = urllib.request.urlopen(req, timeout=40).read()
            tmp = SERVERLIST + ".tmp"
            with open(tmp, "wb") as fh:
                fh.write(data)
            os.replace(tmp, SERVERLIST)
        except Exception as exc:
            log(f"serverlist refresh failed: {exc}")
    d = json.load(open(SERVERLIST))
    out = []
    for region in d.get("data", []):
        for n in region.get("nodes", []):
            if n.get("pro_only") or not n.get("ip"):
                continue
            out.append({"country": region.get("short_name", ""),
                        "hostname": n.get("hostname", ""), "ip": n["ip"]})
    return out


def node_country(node):
    return (node.get("country") or "").split("-")[0].upper()


def pick_node(country=None):
    pool = free_nodes()
    if country:
        cc = country.upper()
        hits = [n for n in pool if node_country(n) == cc]
        if not hits:
            return None
        return random.choice(hits)
    return random.choice(pool) if pool else None


def rotate_node(country=None, key=None):
    """不重複隨機:一輪洗牌用完才重洗。"""
    pool = free_nodes()
    if country:
        cc = country.upper()
        pool = [n for n in pool if node_country(n) == cc]
    if not pool:
        return None
    ips = [n["ip"] for n in pool]
    with LOCK:
        rot = STATE.setdefault("rotate", {})
        k = key or (country.upper() if country else "ALL")
        st = rot.get(k) or {}
        order, pos = st.get("order") or [], int(st.get("pos") or 0)
        if not order or set(order) != set(ips) or pos >= len(order):
            order = random.sample(ips, len(ips))
            pos = 0
            log(f"rotate {k}: new shuffle over {len(order)} free nodes")
        ip = order[pos]
        rot[k] = {"order": order, "pos": pos + 1, "size": len(order), "updated_at": time.time()}
        save_state()
    return next((n for n in pool if n["ip"] == ip), None)


# ---------------- SOCKS5 後端(綁 tun 裝置) ----------------
def handle_socks_client(client, dev):
    upstream = None
    try:
        head = client.recv(2)
        if len(head) < 2 or head[0] != 5:
            return
        client.recv(head[1])
        client.sendall(b"\x05\x00")
        req = client.recv(4)
        if len(req) < 4 or req[1] != 1:
            client.sendall(b"\x05\x07\x00\x01" + b"\x00" * 6)
            return
        atyp = req[3]
        if atyp == 1:
            host = socket.inet_ntoa(client.recv(4))
        elif atyp == 3:
            host = client.recv(client.recv(1)[0]).decode()
        else:
            host = socket.inet_ntop(socket.AF_INET6, client.recv(16))
        port = struct.unpack("!H", client.recv(2))[0]

        upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        upstream.settimeout(25)
        upstream.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, dev.encode() + b"\0")
        upstream.connect((host, port))
        upstream.settimeout(None)
        client.sendall(b"\x05\x00\x00\x01" + socket.inet_aton("0.0.0.0") + struct.pack("!H", 0))

        def pump(a, b):
            try:
                while True:
                    data = a.recv(65536)
                    if not data:
                        break
                    b.sendall(data)
            except Exception:
                pass

        t = threading.Thread(target=pump, args=(upstream, client), daemon=True)
        t.start()
        pump(client, upstream)
        t.join(timeout=1)
    except Exception:
        pass
    finally:
        for s in (client, upstream):
            try:
                s.close()
            except Exception:
                pass


def start_socks(port, dev, stop_flag):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(64)
    srv.settimeout(1.0)

    def loop():
        while not stop_flag.is_set():
            try:
                c, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=handle_socks_client, args=(c, dev), daemon=True).start()
        try:
            srv.close()
        except Exception:
            pass

    threading.Thread(target=loop, daemon=True).start()
    return srv


# ---------------- 前層 byte relay ----------------
class Relay:
    def __init__(self, port):
        self.port = port
        self.target = None
        self.active = 0
        self.active_by_port = {}   # inner_port -> 這條隧道目前背著的連線數
        self.stop = threading.Event()
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind((BIND_HOST, port))
        self.srv.listen(128)
        self.srv.settimeout(1.0)
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while not self.stop.is_set():
            try:
                c, _ = self.srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            target = self.target
            if not target:
                c.close()
                continue
            try:
                u = socket.create_connection(("127.0.0.1", target), timeout=10)
            except Exception:
                c.close()
                continue
            self.active += 1
            self.active_by_port[target] = self.active_by_port.get(target, 0) + 1
            threading.Thread(target=self._pipe, args=(c, u, target), daemon=True).start()

    def _pipe(self, a, b, target_port):
        def one(x, y):
            try:
                while True:
                    d = x.recv(65536)
                    if not d:
                        break
                    y.sendall(d)
            except Exception:
                pass
            try:
                y.shutdown(socket.SHUT_WR)
            except Exception:
                pass

        t = threading.Thread(target=one, args=(b, a), daemon=True)
        t.start()
        one(a, b)
        t.join(timeout=1)
        for s in (a, b):
            try:
                s.close()
            except Exception:
                pass
        self.active = max(0, self.active - 1)
        self.active_by_port[target_port] = max(0, self.active_by_port.get(target_port, 0) - 1)

    def close(self):
        self.stop.set()
        try:
            self.srv.close()
        except Exception:
            pass


# ---------------- OpenVPN 後端 ----------------
def write_ovpn(slot, node_ip):
    """伺服器回的基礎檔(CA / tls-auth,無 remote)+ 免費節點 IP。"""
    os.makedirs(CONFDIR, exist_ok=True)
    path = os.path.join(CONFDIR, f"slot{slot}.ovpn")
    body = open(TEMPLATE).read().rstrip("\n")
    body += (f"\nremote {node_ip}\nport {WS_PORT}\nproto {WS_PROTO}\n"
             "tun-mtu 1400\nmssfix 1300\nresolv-retry infinite\n")
    with open(path, "w") as fh:
        fh.write(body)
    os.chmod(path, 0o600)
    return path


class Tunnel:
    def __init__(self, slot, node_ip, acct):
        self.slot = slot
        self.node_ip = node_ip
        self.acct = acct
        self.label = label_of(acct)
        self.dev = tun_name(slot)
        self.inner_port = INNER_BASE + slot
        self.proc = None
        self.stop_flag = threading.Event()
        self.socks = None
        self.up = False
        self.error = None
        os.makedirs(LOGDIR, exist_ok=True)
        self.log_path = os.path.join(LOGDIR, f"slot{slot}.log")

    def start(self, timeout=50):
        conf = write_ovpn(self.slot, self.node_ip)
        auth = os.path.join(CONFDIR, f"slot{self.slot}.auth")
        with open(auth, "w") as fh:
            fh.write(f"{self.acct['ovpn_user']}\n{self.acct['ovpn_pass']}\n")
        os.chmod(auth, 0o600)
        cmd = [OVPN, "--config", conf, "--dev", self.dev, "--dev-type", "tun",
               "--auth-user-pass", auth, "--route-nopull",
               "--pull-filter", "ignore", "route",
               "--pull-filter", "ignore", "route-ipv6",
               "--pull-filter", "ignore", "dhcp-option",
               "--pull-filter", "ignore", "redirect-gateway",
               "--script-security", "0", "--nobind", "--verb", "3",
               "--log", self.log_path,
               "--connect-timeout", "15", "--connect-retry-max", "2"]
        try:
            self.proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as exc:
            self.error = f"openvpn spawn failed: {exc}"
            return False
        deadline = time.time() + timeout
        while time.time() < deadline:
            time.sleep(1)
            txt = open(self.log_path, errors="ignore").read() if os.path.exists(self.log_path) else ""
            if "Initialization Sequence Completed" in txt:
                self.up = True
                break
            if "AUTH_FAILED" in txt:
                self.error = "AUTH_FAILED"
                break
            if self.proc.poll() is not None:
                time.sleep(0.5)
                txt = open(self.log_path, errors="ignore").read() if os.path.exists(self.log_path) else ""
                if "AUTH_FAILED" in txt:
                    self.error = "AUTH_FAILED"
                elif "Initialization Sequence Completed" in txt:
                    self.up = True
                else:
                    self.error = "tunnel failed"
                break
        if not self.up:
            self.stop()
            return False
        self.socks = start_socks(self.inner_port, self.dev, self.stop_flag)
        return True

    def alive(self):
        return bool(self.up and self.proc and self.proc.poll() is None)

    def stop(self):
        self.stop_flag.set()
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=8)
            except Exception:
                try:
                    self.proc.kill()
                except Exception:
                    pass
        self.up = False


# ---------------- 節點 ----------------
NODES = {}   # uid -> {"relay": Relay, "cur": Tunnel}


def node_public_port(slot):
    return FRONT_BASE + slot


def node_meta(uid):
    return STATE["nodes"].get(uid)


def node_json(uid):
    meta = node_meta(uid) or {}
    n = NODES.get(uid)
    return {"uid": uid, "public_port": meta.get("public_port"),
            "socks": f"socks5://{PUBLIC_HOST}:{meta.get('public_port')}",
            "country": meta.get("country"), "node": meta.get("node"),
            "node_ip": meta.get("node_ip"), "cred": meta.get("cred"),
            "batch": meta.get("batch") or [],
            "quota": quota_view(meta), "created_at": meta.get("created_at"),
            "up": bool(n and n["cur"].alive()),
            "active": n["relay"].active if n else 0}


def quota_view(meta):
    if not meta or not meta.get("cred"):
        return None
    label = meta["cred"]
    acct = next((a for a in load_accounts() if label_of(a) == label), None)
    if not acct:
        return None
    st = acct_state(label)
    used, limit = acct_used(label), acct_limit(acct)
    return {"label": label, "used_bytes": used, "limit_bytes": limit,
            "pct": round(used / limit * 100, 1) if limit else None,
            "exhausted": bool(st.get("exhausted")), "bad": bool(st.get("bad")),
            "reported": st.get("reported")}


def start_tunnel(slot, node_ip, acct):
    tun = Tunnel(slot, node_ip, acct)
    return tun if tun.start() else tun


def provision(uid, meta, node, batch, slot=None):
    """起一條隧道並讓 relay 指向它(relay 已存在就只翻轉)。"""
    tried = set()
    used_now = in_use_labels()
    for label in list(batch):
        acct = next((a for a in load_accounts() if label_of(a) == label), None)
        if not acct:
            batch.remove(label)
            continue
        if used_now.get(label):            # 這顆帳號已經有別的活隧道 → 一帳一隧道,跳過
            continue
        tried.add(label)
        tun = start_tunnel(slot, node["ip"], acct)
        if tun.up:
            rel = NODES[uid]["relay"] if uid in NODES else None
            if rel is None:
                rel = Relay(node_public_port(meta["primary_slot"]))
                NODES[uid] = {"relay": rel, "cur": tun}
            old = NODES[uid]["cur"]
            rel.target = tun.inner_port
            NODES[uid]["cur"] = tun
            old_slot = old.slot if old is not tun else None
            meta["slots"][str(slot)] = {"slot": slot, "cred": tun.label, "dev": tun.dev,
                                        "inner_port": tun.inner_port, "node_ip": node["ip"]}
            meta["cred"], meta["node_ip"] = tun.label, node["ip"]
            meta["node"], meta["country"] = node["hostname"], node["country"]
            save_state()
            if old_slot is not None and old_slot != slot:
                NODES[uid].setdefault("draining", []).append(old)
                retire_tunnel(uid, old, old_slot)
            return meta, None
        err = tun.error or "tunnel failed"
        if err == "AUTH_FAILED":
            mark_account(tun.label, bad=True, error="AUTH_FAILED")
            log(f"account {tun.label} AUTH_FAILED → bad, try next")
            batch.remove(tun.label)
            continue
        return None, err
    meta["cred"] = ""
    meta["slots"] = {}
    save_state()
    return meta, "no usable account in batch"


def retire_tunnel(uid, tun, slot):
    """舊隧道等「它自己背的連線」排空後退休,並結算該 slot 的流量。

    呼叫時 relay.target 已翻到新隧道,所以只能看 per-tunnel 計數
    (active_by_port),不能用 rel.target 比較。上限 300s 防 hang 死
    的 keep-alive 連線把舊隧道永久釘住;連線歸零就當秒退休。
    """
    def run():
        meta = node_meta(uid)
        rel = NODES.get(uid, {}).get("relay")
        deadline = time.time() + 300
        while rel and time.time() < deadline:
            if rel.active_by_port.get(tun.inner_port, 0) == 0:
                break
            time.sleep(2)
        tun.stop()
        if meta:
            settle_slot(meta, slot)
        try:
            NODES.get(uid, {}).get("draining", []).remove(tun)
        except ValueError:
            pass
        log(f"{uid}: slot{slot} retired ({tun.label})")
    threading.Thread(target=run, daemon=True).start()


def refill_batch(meta, n):
    """補這個節點的帳號批:先挑別的節點沒配到的,不夠才共用(共用只影響挑選順序,
    真正上場時由 in_use 保證一顆帳號同時只有一條隧道)。"""
    have = set(meta.get("batch") or [])
    others = other_batch_labels(meta.get("uid", ""))
    used = in_use_labels()
    cands = [a for a in load_accounts()
             if label_of(a) not in have and acct_available(label_of(a))]
    cands.sort(key=lambda a: (label_of(a) in used, label_of(a) in others))
    for a in cands:
        have.add(label_of(a))
        if len(have) >= n:      # 批滿了仍要收到一顆空閒的,否則 provision 整批跳過 → no usable account
            if any(l not in used for l in have) or not any(label_of(x) not in used for x in cands):
                break
    meta["batch"] = list(have)
    return meta["batch"]


def rotate_account(uid, reason=""):
    """額度用完 / 帳號壞掉:同一個 port、同一個節點,換批內下一顆帳號。"""
    meta = node_meta(uid)
    if not meta:
        return None, "no such node"
    bad = meta.get("cred")
    used_now = in_use_labels()
    batch = [l for l in (meta.get("batch") or [])
             if l != bad and acct_available(l) and not used_now.get(l)]
    if not batch:
        refill_batch(meta, max(ACCOUNTS_PER_NODE, len(meta.get("batch") or []) + 1))
        batch = [l for l in (meta.get("batch") or [])
                 if l != bad and acct_available(l) and not used_now.get(l)]
        if not batch:                     # 批內全在用/全壞 → 直接從全池找一顆空的
            a = pick_account(exclude={bad})
            if a:
                batch = [label_of(a)]
                meta.setdefault("batch", []).append(label_of(a))
        if not batch:
            meta["cred"] = ""
            save_state()
            return meta, "account pool exhausted"
    node = {"ip": meta["node_ip"], "hostname": meta.get("node"), "country": meta.get("country")}
    slot = alloc_slot()
    meta, err = provision(uid, meta, node, batch, slot=slot)
    if err:
        return None, err
    log(f"{uid}: account rotated → {meta['cred']} ({reason})")
    return meta, None


def switch_node(uid, node):
    """無縫換節點:新 slot 暖機 → relay 翻轉 → 舊的排空退休。"""
    meta = node_meta(uid)
    if not meta:
        return None, "no such node"
    if not meta.get("cred") or not acct_available(meta["cred"]):
        return rotate_account(uid, "cred unavailable" if meta.get("cred") else "no cred")
    slot = alloc_slot()
    # shortcut: 舊隧道正佔用 cred → provision 跳過它,須補 idle 帳號才能換節點
    batch = [meta["cred"]] + sorted({l for l in (meta.get("batch") or []) if l and l != meta["cred"]})
    return provision(uid, meta, node, batch, slot=slot)


def ensure_node(uid, node=None):
    with LOCK:
        meta = STATE["nodes"].get(uid)
        if meta and not meta.get("_restore"):
            if uid in NODES:
                return meta, None
        if meta and meta.get("_restore"):
            meta.pop("_restore", None)
            node = node or {"ip": meta.get("node_ip"), "hostname": meta.get("node"),
                            "country": meta.get("country")}
        if node is None:
            return None, "no free node available"
        if not meta:
            slot = alloc_slot()
            meta = {"uid": uid, "primary_slot": slot, "public_port": node_public_port(slot),
                    "slots": {}, "created_at": time.time()}
            STATE["nodes"][uid] = meta
            save_state()
        else:
            STATE["nodes"][uid] = meta
            slot = meta["primary_slot"]
        batch = refill_batch(meta, ACCOUNTS_PER_NODE)
        batch = [l for l in batch if acct_available(l)]
        if not batch:
            return None, "account pool empty (wait for register to push accounts)"
        meta, err = provision(uid, meta, node, batch, slot=slot)
        if err:
            STATE["nodes"].pop(uid, None)
            save_state()
            return None, err
        save_state()
        return meta, None


def delete_node(uid):
    meta = STATE["nodes"].pop(uid, None)
    n = NODES.pop(uid, None)
    if n:
        n["relay"].close()
        n["cur"].stop()
    if meta:
        for key in list((meta.get("slots") or {}).keys()):
            settle_slot(meta, key)
    save_state()
    return bool(n or meta)


# ---------------- 監督 / 額度 ----------------
def supervise():
    while True:
        time.sleep(POLL)
        try:
            roll_month()
            if ingest_inbox():
                log("inbox ingested")
            for uid, meta in list(STATE["nodes"].items()):
                n = NODES.get(uid)
                if not n or not n["cur"].alive():
                    node = {"ip": meta["node_ip"], "hostname": meta.get("node"),
                            "country": meta.get("country")}
                    slot = alloc_slot()
                    meta, err = provision(uid, meta, node, [meta["cred"]] if meta.get("cred") else [], slot=slot)
                    if err:
                        log(f"{uid}: reprovision failed ({err}) → rotating account")
                        meta, err2 = rotate_account(uid, "tunnel dead")
                        if err2:
                            log(f"{uid}: rotate failed ({err2})")
                    else:
                        log(f"{uid}: tunnel re-provisioned")
                    continue
                label = meta.get("cred")
                acct = next((a for a in load_accounts() if label_of(a) == label), None)
                if not acct:
                    continue
                used, limit = acct_used(label), acct_limit(acct)
                if limit and used >= limit * QUOTA_PROBE_AT:
                    rep = probe_quota(acct)
                    if rep and rep.get("max") and rep["used"] >= rep["max"] * QUOTA_SOFT:
                        meta, err = rotate_account(uid, f"api quota {rep['used']}/{rep['max']}")
                        if err:
                            log(f"{uid}: rotate failed ({err})")
                        continue
                    if rep and rep.get("max"):
                        used, limit = rep["used"], rep["max"]
                if limit and used >= limit * QUOTA_SOFT:
                    meta, err = rotate_account(uid, f"quota {used}/{limit}")
                    if err:
                        log(f"{uid}: rotate failed ({err})")
        except Exception as exc:  # noqa: BLE001 — 一輪失敗不該停整個監督
            log(f"supervise cycle failed: {exc}")


# ---------------- HTTP API ----------------
class Handler(BaseHTTPRequestHandler):
    def _send(self, code, obj, ctype="application/json"):
        body = (json.dumps(obj, ensure_ascii=False, indent=1) if ctype == "application/json"
                else obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *a):
        print("[http] " + fmt % a, flush=True)

    def _q(self):
        u = urlparse(self.path)
        return u.path, {k: v[0] for k, v in parse_qs(u.query).items()}

    def do_GET(self):
        path, q = self._q()
        if path in ("/", "/ui"):
            return self._send(200, {"service": "windscribe-pool", "front_base": FRONT_BASE,
                                    "public_host": PUBLIC_HOST,
                                    "endpoints": ["/status", "/register", "/country", "/rotate",
                                                  "/accounts", "/nodes", "/sub", "/delete"]})
        if path == "/status":
            return self._send(200, {"nodes": [node_json(u) for u in STATE["nodes"]],
                                    "accounts": self._accounts(),
                                    "free_nodes": len(free_nodes()),
                                    "serverlist_age": (time.time() - os.path.getmtime(SERVERLIST)
                                                       if os.path.exists(SERVERLIST) else None)})
        if path == "/accounts":
            return self._send(200, {"accounts": self._accounts()})
        if path == "/accounts/reset":
            label = q.get("label", "")
            mark_account(label, bad=False, exhausted=False, error="manual reset")
            return self._send(200, {"ok": True, "label": label})
        if path == "/nodes":
            pool = free_nodes()
            cc = (q.get("country") or "").upper()
            if cc:
                pool = [n for n in pool if node_country(n) == cc]
            counts = {}
            for n in free_nodes():
                counts[n["country"]] = counts.get(n["country"], 0) + 1
            return self._send(200, {"country": cc or None, "countries": counts,
                                    "free_nodes": pool})
        if path == "/sub":
            return self._send(200, self._sub(q.get("uid")), ctype="text/yaml")
        if path == "/rotate":
            cc = q.get("country")
            node = rotate_node(cc, key=q.get("key"))
            if not node:
                return self._send(404, {"ok": False, "error": "no free node for that country"})
            uid = q.get("uid")
            if uid:
                meta, err = switch_node(uid, node)
                if err:
                    return self._send(500, {"ok": False, "error": err, "node_ip": node["ip"]})
                rot = STATE.get("rotate", {}).get(cc.upper() if cc else "ALL", {})
                return self._send(200, {"ok": True, "uid": uid, "node": node["hostname"],
                                        "node_ip": node["ip"], "country": node["country"],
                                        "public_port": meta["public_port"],
                                        "progress": f"{rot.get('pos',0)}/{rot.get('size',0)}"})
            rot = STATE.get("rotate", {}).get(cc.upper() if cc else "ALL", {})
            return self._send(200, {"ok": True, "node": node["hostname"], "node_ip": node["ip"],
                                    "country": node["country"],
                                    "progress": f"{rot.get('pos',0)}/{rot.get('size',0)}"})
        if path == "/country":
            uid = q.get("uid")
            if not uid:
                return self._send(400, {"error": "uid required"})
            node = None
            if q.get("node"):
                node = {"ip": q["node"], "hostname": q.get("node"), "country": q.get("cc", "")}
            else:
                node = pick_node(q.get("country"))
            if not node:
                return self._send(400, {"error": "no free node for that country"})
            meta, err = switch_node(uid, node)
            if err:
                return self._send(500, {"error": err})
            return self._send(200, {"ok": True, "uid": uid, "node": node["hostname"],
                                    "node_ip": node["ip"], "public_port": meta["public_port"]})
        if path == "/delete":
            return self._send(200, {"deleted": delete_node(q.get("uid", ""))})
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        path, q = self._q()
        if path == "/register":
            uid = q.get("uid")
            if not uid:
                return self._send(400, {"error": "uid required"})
            meta = node_meta(uid)
            if meta and meta.get("cred") and uid in NODES:
                return self._send(200, {"ok": True, **node_json(uid)})
            node = None
            if q.get("node"):
                node = {"ip": q["node"], "hostname": q.get("node"), "country": q.get("cc", "")}
            else:
                node = pick_node(q.get("country"))
            if not node:
                return self._send(400, {"ok": False,
                                        "error": "no free node (country has none?)"})
            meta, err = ensure_node(uid, node)
            if err:
                return self._send(500, {"ok": False, "error": err})
            return self._send(200, {"ok": True, **node_json(uid)})
        if path == "/delete":
            return self._send(200, {"deleted": delete_node(q.get("uid", ""))})
        return self._send(404, {"error": "not found"})

    def _accounts(self):
        used = in_use_labels()
        out = []
        for a in load_accounts():
            lab = label_of(a)
            st = acct_state(lab)
            u, lim = acct_used(lab), acct_limit(a)
            out.append({"label": lab, "in_use": used.get(lab, 0), "used_bytes": u,
                        "limit_bytes": lim, "pct": round(u / lim * 100, 1) if lim else None,
                        "bad": bool(st.get("bad")), "exhausted": bool(st.get("exhausted")),
                        "datacenter": a.get("datacenter", ""), "node": a.get("node", ""),
                        "last_error": st.get("last_error", ""),
                        "reported": st.get("reported")})
        return out

    def _sub(self, only_uid=None):
        lines = ["proxies:"]
        picked = [u for u in STATE["nodes"] if not only_uid or u == only_uid]
        for uid in picked:
            meta = STATE["nodes"][uid]
            lines += [f"  - name: ws-{uid}",
                      "    type: socks5",
                      f"    server: {PUBLIC_HOST}",
                      f"    port: {meta['public_port']}",
                      "    udp: false"]
        if not picked:
            lines.append("  []")
        lines += ["proxy-groups:", "  - name: WS", "    type: select",
                  "    proxies: [" + ", ".join(f"ws-{u}" for u in picked) + "]"
                  if picked else "    proxies: [DIRECT]",
                  "rules:", "  - MATCH,WS"]
        return "\n".join(lines) + "\n"


def main():
    load_state()
    os.makedirs(INBOX, exist_ok=True)
    ingest_inbox()
    roll_month()
    log(f"API on {BIND_HOST}:{API_PORT} front {FRONT_BASE}+ inner {INNER_BASE}+ "
        f"public {PUBLIC_HOST} accounts={len(load_accounts())} free_nodes={len(free_nodes())}")
    for uid, meta in list(STATE["nodes"].items()):
        try:
            meta["_restore"] = True
            m, err = ensure_node(uid, None)
            log(f"restore {uid}: {'ok' if not err else err}")
        except Exception as exc:  # noqa: BLE001
            log(f"restore {uid} failed: {exc}")
    threading.Thread(target=supervise, daemon=True).start()
    ThreadingHTTPServer((BIND_HOST, API_PORT), Handler).serve_forever()


if __name__ == "__main__":
    sys.exit(main())
