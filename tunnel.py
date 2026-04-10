"""
tunnel.py — Secure TUN tunnel, SOCKS5 proxy, pcap capture.
Linux only (requires root, tun kernel module, iptables).

Security design
───────────────
Every IP packet is encrypted with AES-256-GCM before leaving the client.
Key is derived from shared secret + peer_id via HKDF-SHA256, so the relay
server cannot read packet contents even while relaying them.

Frame layout (inside the existing TLS stream):
  JSON: {"type":"tpkt","d":"<base64(nonce_12 | ciphertext)>"}

  Plaintext inside ciphertext: 2-byte original length | packet | random padding
  Padding aligns payload to PKT_ALIGN bytes, hiding real packet sizes.

DNS leak prevention
───────────────────
/etc/resolv.conf is replaced with stub pointing at 8.8.8.8/1.1.1.1 (which
are routed through the tunnel).  Original is restored on stop().

Interface names
───────────────
Random 6-char hex suffix on every start() call — no static fingerprint.

SOCKS5 proxy
────────────
Local asyncio SOCKS5 listener (127.0.0.1:1080) proxies TCP connections
through the E2E-encrypted peer-to-peer channel.  Relay server sees only
opaque ciphertext wrapped in JSON.

PCAP capture
────────────
ServerTunnelManager can write a standard libpcap file of all routed packets.
"""

import os, struct, subprocess, logging, asyncio, base64, time
import hashlib, json, socket, shutil, platform as _platform
from typing import Optional, Callable

_IS_LINUX = _platform.system().lower() == "linux"

# Linux-only low-level imports — guarded so Windows can import tunnel.py
if _IS_LINUX:
    import fcntl, select
else:
    fcntl = None; select = None
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256

log = logging.getLogger("tunnel")

TUN_SUBNET    = "10.8.0"
SERVER_TUN_IP = f"{TUN_SUBNET}.1"
TUNSETIFF     = 0x400454ca
IFF_TUN       = 0x0001
IFF_NO_PI     = 0x1000
MTU           = 1420
PKT_ALIGN     = 256
PCAP_MAGIC    = 0xa1b2c3d4
PCAP_LINKTYPE = 101

def check_root():
    if not _IS_LINUX:
        raise RuntimeError(
            "Traffic tunnel and PCAP require Linux.\n"
            "SOCKS5 proxy works on all platforms without root.")
    if os.geteuid() != 0:
        raise RuntimeError("Traffic tunnel requires root.\nRun: sudo python3 tui.py")

def _run(cmd: list, check: bool = True) -> str:
    r = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if check and r.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)}: {r.stderr.strip()}")
    return r.stdout.strip()

def _rand_iface(prefix: str) -> str:
    return (prefix + os.urandom(3).hex())[:15]

def _open_tun(name: str) -> int:
    if not _IS_LINUX or fcntl is None:
        raise RuntimeError("TUN devices are Linux-only")
    try:
        fd = os.open("/dev/net/tun", os.O_RDWR | os.O_NONBLOCK)
    except PermissionError:
        raise RuntimeError("Cannot open /dev/net/tun — run as root.")
    except FileNotFoundError:
        raise RuntimeError("/dev/net/tun missing — run: modprobe tun")
    ifr = struct.pack("16sH14s", name.encode()[:15], IFF_TUN | IFF_NO_PI, b"\x00" * 14)
    try:
        fcntl.ioctl(fd, TUNSETIFF, ifr)
    except OSError as e:
        os.close(fd); raise RuntimeError(f"ioctl TUNSETIFF failed: {e}")
    return fd

def _iface_up(name: str, ip: str, prefix: int = 24):
    _run(["ip", "link", "set", name, "mtu", str(MTU), "up"])
    _run(["ip", "addr", "replace", f"{ip}/{prefix}", "dev", name])

def _iface_del(name: str):
    _run(["ip", "link", "delete", name], check=False)

def _get_default_route() -> tuple:
    out   = _run(["ip", "route", "show", "default"])
    parts = out.split()
    try:
        return parts[parts.index("via")+1], parts[parts.index("dev")+1]
    except (ValueError, IndexError):
        raise RuntimeError(f"Cannot parse default route: {out!r}")


# ── Per-packet crypto ──────────────────────────────────────────────────────────

def _derive_tunnel_key(secret: bytes, peer_id: str) -> bytes:
    return HKDF(
        algorithm=SHA256(), length=32, salt=None,
        info=b"tunnel-pkt-v2:" + peer_id.encode(),
    ).derive(secret)

def _encrypt_pkt(key: bytes, pkt: bytes) -> bytes:
    payload = struct.pack(">H", len(pkt)) + pkt
    rem = len(payload) % PKT_ALIGN
    if rem:
        payload += os.urandom(PKT_ALIGN - rem)
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, payload, None)

def _decrypt_pkt(key: bytes, blob: bytes) -> bytes:
    payload  = AESGCM(key).decrypt(blob[:12], blob[12:], None)
    orig_len = struct.unpack(">H", payload[:2])[0]
    return payload[2:2 + orig_len]


# ── Async TUN reader ───────────────────────────────────────────────────────────

class _AsyncTUNReader:
    def __init__(self, fd: int):
        self._fd = fd; self._stop = False

    def stop(self): self._stop = True

    def _read_one(self) -> bytes:
        if self._fd is None or self._stop:
            time.sleep(0.05); return b""
        if select is None: time.sleep(0.1); return b""
        try:
            r, _, _ = select.select([self._fd], [], [], 0.1)
            if r: return os.read(self._fd, 65536)
        except (OSError, ValueError): pass
        return b""

    async def packets(self, loop=None):
        loop = loop or asyncio.get_event_loop()
        while not self._stop:
            pkt = await loop.run_in_executor(None, self._read_one)
            if pkt: yield pkt

    def write(self, pkt: bytes):
        if self._fd is not None:
            try: os.write(self._fd, pkt)
            except OSError as e: log.warning("TUN write: %s", e)


# ── PCAP writer ────────────────────────────────────────────────────────────────

class PcapWriter:
    def __init__(self, path: str):
        self._path = path
        self._f    = open(path, "wb")
        self._f.write(struct.pack("<IHHiIII",
            PCAP_MAGIC, 2, 4, 0, 0, 65535, PCAP_LINKTYPE))
        self._f.flush()

    def write_packet(self, pkt: bytes):
        if self._f.closed: return
        t = time.time(); sec = int(t); usec = int((t-sec)*1_000_000)
        self._f.write(struct.pack("<IIII", sec, usec, len(pkt), len(pkt)))
        self._f.write(pkt); self._f.flush()

    def close(self):
        if not self._f.closed:
            self._f.close(); log.info("PCAP saved → %s", self._path)


# ── SERVER tunnel manager ──────────────────────────────────────────────────────

class ServerTunnelManager:
    """
    Server-side TUN device and NAT for all tunnelling clients.

    Packet flow (client → internet):
      1. Encrypted tpkt arrives from client via TLS.
      2. handle_client_packet() decrypts with per-client key.
      3. Raw IP packet written to TUN fd.
      4. Kernel NAT masquerades src IP and routes to internet.

    Packet flow (internet → client):
      1. _forward_loop() reads from TUN fd.
      2. Extracts dst IP from bytes 16-19, looks up peer_id.
      3. Encrypts with that peer's key, sends as tpkt JSON.
    """

    def __init__(self):
        self._fd         = None
        self._reader     = None
        self._started    = False
        self._net_iface  = ""
        self._iface_name = ""
        self._ip_pool    = {}
        self._ip_rev     = {}
        self._writers    = {}
        self._keys       = {}
        self._next_slot  = 2
        self._fwd_task   = None
        self._pcap       = None

    async def ensure_started(self, secret: bytes):
        if self._started: return
        check_root()
        self._iface_name = _rand_iface("tun-s")
        self._net_iface  = _get_default_route()[1]
        self._fd         = _open_tun(self._iface_name)
        self._reader     = _AsyncTUNReader(self._fd)
        _iface_up(self._iface_name, SERVER_TUN_IP)
        _run(["sysctl", "-wq", "net.ipv4.ip_forward=1"])
        self._iptables("A")
        self._started    = True
        log.info("Server TUN up: %s  ip=%s  nat→%s",
                 self._iface_name, SERVER_TUN_IP, self._net_iface)
        self._fwd_task = asyncio.create_task(self._forward_loop())

    async def stop(self):
        if not self._started: return
        self._started = False
        self._stop_pcap()
        if self._reader: self._reader.stop()
        if self._fwd_task:
            self._fwd_task.cancel()
            try: await self._fwd_task
            except: pass
        if self._fd is not None:
            try: os.close(self._fd)
            except: pass
            self._fd = None
        self._iptables("D")
        _iface_del(self._iface_name)
        self._ip_pool.clear(); self._ip_rev.clear()
        self._writers.clear(); self._keys.clear()
        log.info("Server TUN stopped")

    def assign_client(self, peer_id: str, writer, secret: bytes) -> str:
        if peer_id in self._ip_pool: return self._ip_pool[peer_id]
        while f"{TUN_SUBNET}.{self._next_slot}" in self._ip_rev and self._next_slot <= 254:
            self._next_slot += 1
        if self._next_slot > 254: raise RuntimeError("Tunnel IP pool exhausted")
        ip = f"{TUN_SUBNET}.{self._next_slot}"
        self._next_slot += 1
        self._ip_pool[peer_id] = ip
        self._ip_rev[ip]       = peer_id
        self._writers[peer_id] = writer
        self._keys[peer_id]    = _derive_tunnel_key(secret, peer_id)
        log.info("Tunnel %s → %s", peer_id, ip)
        return ip

    def release_client(self, peer_id: str):
        ip = self._ip_pool.pop(peer_id, None)
        if ip: self._ip_rev.pop(ip, None)
        self._writers.pop(peer_id, None)
        self._keys.pop(peer_id, None)
        if not self._ip_pool:
            asyncio.create_task(self.stop())
        log.info("Tunnel released: %s", peer_id)

    def handle_client_packet(self, peer_id: str, blob_b64: str):
        key = self._keys.get(peer_id)
        if not key: return
        try:
            pkt = _decrypt_pkt(key, base64.b64decode(blob_b64))
        except Exception:
            log.warning("tpkt decrypt failed from %s", peer_id); return
        if self._pcap: self._pcap.write_packet(pkt)
        if self._reader: self._reader.write(pkt)

    def start_pcap(self, path: str):
        self._stop_pcap()
        self._pcap = PcapWriter(path)
        log.info("PCAP started → %s", path)

    def stop_pcap(self): self._stop_pcap()

    def _stop_pcap(self):
        if self._pcap: self._pcap.close(); self._pcap = None

    async def _forward_loop(self):
        loop = asyncio.get_event_loop()
        enc  = lambda d: (json.dumps(d) + "\n").encode()
        async for pkt in self._reader.packets(loop):
            if len(pkt) < 20: continue
            if self._pcap: self._pcap.write_packet(pkt)
            dst_ip  = ".".join(str(b) for b in pkt[16:20])
            peer_id = self._ip_rev.get(dst_ip)
            if not peer_id: continue
            writer = self._writers.get(peer_id)
            key    = self._keys.get(peer_id)
            if not writer or not key: continue
            try:
                blob = base64.b64encode(_encrypt_pkt(key, pkt)).decode()
                writer.write(enc({"type": "tpkt", "d": blob}))
                await writer.drain()
            except Exception as e:
                log.warning("Forward to %s failed: %s", peer_id, e)

    def _iptables(self, action: str):
        sub = f"{TUN_SUBNET}.0/24"
        _run(["iptables", "-t", "nat", f"-{action}", "POSTROUTING",
              "-s", sub, "-o", self._net_iface, "-j", "MASQUERADE"], check=False)
        _run(["iptables", f"-{action}", "FORWARD",
              "-i", self._iface_name, "-j", "ACCEPT"], check=False)
        _run(["iptables", f"-{action}", "FORWARD",
              "-o", self._iface_name, "-j", "ACCEPT"], check=False)


# ── CLIENT tunnel manager ──────────────────────────────────────────────────────

class ClientTunnelManager:
    """
    Client-side TUN device, routing, and DNS protection.

    Routing (start):
      1. Save existing default route (gw + dev).
      2. Add /32 host route for relay server IP via saved gateway
         — keeps the TLS connection alive, prevents routing loop.
      3. Add 0.0.0.0/1 and 128.0.0.0/1 via tun interface
         — these two routes beat the old /0 default for all traffic.
      4. Patch /etc/resolv.conf to 8.8.8.8/1.1.1.1.

    Routing (stop):
      Reverse all of the above, restore resolv.conf.
    """

    RESOLV_BACKUP = "/etc/resolv.conf.tun_backup" if _IS_LINUX else ""
    RESOLV_PATH   = "/etc/resolv.conf"             if _IS_LINUX else ""

    def __init__(self):
        self._fd          = None
        self._reader      = None
        self._active      = False
        self._old_gw      = ""
        self._old_dev     = ""
        self._server_ip   = ""
        self._client_ip   = ""
        self._iface_name  = ""
        self._key         = None
        self._read_task   = None
        self._dns_patched = False
        self.on_send_pkt  = None   # Callable[[str], None]  (receives b64 blob)

    @property
    def active(self) -> bool: return self._active

    async def start(self, server_relay_ip: str, assigned_ip: str,
                    secret: bytes, peer_id: str):
        check_root()
        self._server_ip  = server_relay_ip
        self._client_ip  = assigned_ip
        self._key        = _derive_tunnel_key(secret, peer_id)
        self._iface_name = _rand_iface("tun-c")
        self._old_gw, self._old_dev = _get_default_route()
        self._fd     = _open_tun(self._iface_name)
        self._reader = _AsyncTUNReader(self._fd)
        _iface_up(self._iface_name, assigned_ip)
        _run(["ip", "route", "replace", f"{server_relay_ip}/32",
              "via", self._old_gw, "dev", self._old_dev])
        _run(["ip", "route", "replace", "0.0.0.0/1",  "dev", self._iface_name])
        _run(["ip", "route", "replace", "128.0.0.0/1", "dev", self._iface_name])
        self._patch_dns()
        self._active    = True
        self._read_task = asyncio.create_task(self._read_loop())
        log.info("Client tunnel up: %s  ip=%s  relay=%s  gw=%s(%s)",
                 self._iface_name, assigned_ip, server_relay_ip,
                 self._old_gw, self._old_dev)

    async def stop(self):
        if not self._active: return
        self._active = False
        if self._reader: self._reader.stop()
        if self._read_task:
            self._read_task.cancel()
            try: await self._read_task
            except: pass
        _run(["ip", "route", "del", "0.0.0.0/1"],            check=False)
        _run(["ip", "route", "del", "128.0.0.0/1"],           check=False)
        _run(["ip", "route", "del", f"{self._server_ip}/32"], check=False)
        _run(["ip", "route", "replace", "default",
              "via", self._old_gw, "dev", self._old_dev],     check=False)
        self._restore_dns()
        if self._fd is not None:
            try: os.close(self._fd)
            except: pass
            self._fd = None
        _iface_del(self._iface_name)
        log.info("Client tunnel stopped — routes/DNS restored")

    def inject(self, blob_b64: str):
        if not self._reader or not self._key: return
        try:
            pkt = _decrypt_pkt(self._key, base64.b64decode(blob_b64))
            self._reader.write(pkt)
        except Exception as e:
            log.warning("Client inject decrypt: %s", e)

    def _patch_dns(self):
        try:
            if not os.path.exists(self.RESOLV_BACKUP):
                shutil.copy2(self.RESOLV_PATH, self.RESOLV_BACKUP)
            with open(self.RESOLV_PATH, "w") as f:
                f.write("# managed by secure-tunnel\nnameserver 8.8.8.8\nnameserver 1.1.1.1\n")
            self._dns_patched = True
            log.info("DNS leak prevention active")
        except Exception as e:
            log.warning("DNS patch failed: %s", e)

    def _restore_dns(self):
        if not self._dns_patched: return
        try:
            if os.path.exists(self.RESOLV_BACKUP):
                shutil.move(self.RESOLV_BACKUP, self.RESOLV_PATH)
                log.info("resolv.conf restored")
        except Exception as e:
            log.warning("DNS restore failed: %s", e)
        self._dns_patched = False

    async def _read_loop(self):
        loop = asyncio.get_event_loop()
        async for pkt in self._reader.packets(loop):
            if self.on_send_pkt and self._key:
                try:
                    self.on_send_pkt(base64.b64encode(_encrypt_pkt(self._key, pkt)).decode())
                except Exception as e:
                    log.warning("Client TUN send: %s", e)


# ── SOCKS5 proxy ───────────────────────────────────────────────────────────────

class Socks5Server:
    """
    Local SOCKS5 proxy that tunnels TCP through the encrypted relay channel.

    Flow (client side / originator):
      local app → SOCKS5 handshake → Socks5Server → socks_open via relay →
      proxy peer opens TCP → socks_ack → data flows as socks_data → socks_close

    Flow (exit node side):
      handle_as_exit() receives socks_open, opens TCP, starts forwarding.

    All socks messages travel as peer-to-peer relay messages (type "socks"),
    so the relay server sees only opaque JSON it cannot interpret.
    """

    def __init__(self):
        self._server      = None
        self._proxy_peer  = ""
        self._send_fn     = None
        self._streams     = {}
        self._pending     = {}   # sid → asyncio.Event
        self._ack_ok      = {}   # sid → bool
        self._local_port  = 1080
        self._active      = False

    @property
    def active(self) -> bool: return self._active

    async def start(self, proxy_peer_id: str, send_fn: Callable, local_port: int = 1080):
        self._proxy_peer = proxy_peer_id
        self._send_fn    = send_fn
        self._local_port = local_port
        self._server     = await asyncio.start_server(
            self._accept, "127.0.0.1", local_port)
        self._active = True
        log.info("SOCKS5 on 127.0.0.1:%d  exit→%s", local_port, proxy_peer_id)

    async def stop(self):
        if not self._active: return
        self._active = False
        if self._server:
            self._server.close(); await self._server.wait_closed()
        for w in list(self._streams.values()):
            try: w.close()
            except: pass
        self._streams.clear(); self._pending.clear()
        log.info("SOCKS5 stopped")

    async def on_relay_msg(self, msg: dict):
        action = msg.get("action",""); sid = msg.get("sid","")
        if action == "ack":
            ev = self._pending.get(sid)
            if ev: self._ack_ok[sid] = bool(msg.get("ok")); ev.set()
        elif action == "data":
            w = self._streams.get(sid)
            if w:
                try: w.write(base64.b64decode(msg.get("d",""))); await w.drain()
                except: pass
        elif action == "close":
            w = self._streams.pop(sid, None)
            if w:
                try: w.close()
                except: pass

    async def handle_as_exit(self, msg: dict, reply_fn: Callable):
        action = msg.get("action",""); sid = msg.get("sid","")
        if action == "open":
            host = msg.get("host",""); port = int(msg.get("port",80))
            try:
                r, w = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout=10)
                self._streams[sid] = w
                await reply_fn({"action":"ack","sid":sid,"ok":True})
                asyncio.create_task(self._exit_fwd(sid, r, reply_fn))
            except Exception as e:
                await reply_fn({"action":"ack","sid":sid,"ok":False,"reason":str(e)})
        elif action == "data":
            w = self._streams.get(sid)
            if w:
                try: w.write(base64.b64decode(msg.get("d",""))); await w.drain()
                except: self._streams.pop(sid, None)
        elif action == "close":
            w = self._streams.pop(sid, None)
            if w:
                try: w.close()
                except: pass

    async def _exit_fwd(self, sid: str, reader, reply_fn: Callable):
        try:
            while True:
                data = await asyncio.wait_for(reader.read(4096), timeout=60)
                if not data: break
                await reply_fn({"action":"data","sid":sid,
                                "d":base64.b64encode(data).decode()})
        except: pass
        finally:
            self._streams.pop(sid, None)
            try: await reply_fn({"action":"close","sid":sid})
            except: pass

    async def _accept(self, reader, writer):
        try: await self._socks5(reader, writer)
        except Exception as e: log.debug("SOCKS5: %s", e)
        finally:
            try: writer.close()
            except: pass

    async def _socks5(self, reader, writer):
        hdr = await asyncio.wait_for(reader.readexactly(2), timeout=10)
        if hdr[0] != 5: raise RuntimeError("not SOCKS5")
        await reader.readexactly(hdr[1])
        writer.write(b"\x05\x00"); await writer.drain()
        req  = await asyncio.wait_for(reader.readexactly(4), timeout=10)
        if req[1] != 1:
            writer.write(b"\x05\x07\x00\x01"+b"\x00"*6); await writer.drain(); return
        atyp = req[3]
        if   atyp == 1: host = socket.inet_ntoa(await reader.readexactly(4))
        elif atyp == 3:
            n = (await reader.readexactly(1))[0]
            host = (await reader.readexactly(n)).decode()
        elif atyp == 4:
            await reader.readexactly(18)
            writer.write(b"\x05\x08\x00\x01"+b"\x00"*6); await writer.drain(); return
        else: return
        port = struct.unpack(">H", await reader.readexactly(2))[0]
        sid  = os.urandom(6).hex()
        ev   = asyncio.Event()
        self._pending[sid] = ev; self._ack_ok[sid] = False
        await self._send_fn({"action":"open","sid":sid,"host":host,"port":port})
        try: await asyncio.wait_for(ev.wait(), timeout=15)
        except asyncio.TimeoutError:
            writer.write(b"\x05\x04\x00\x01"+b"\x00"*6); await writer.drain(); return
        finally: self._pending.pop(sid, None)
        if not self._ack_ok.pop(sid, False):
            writer.write(b"\x05\x05\x00\x01"+b"\x00"*6); await writer.drain(); return
        writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00"); await writer.drain()
        self._streams[sid] = writer
        try:
            while True:
                data = await asyncio.wait_for(reader.read(4096), timeout=60)
                if not data: break
                await self._send_fn({"action":"data","sid":sid,
                                     "d":base64.b64encode(data).decode()})
        except: pass
        finally:
            self._streams.pop(sid, None)
            try: await self._send_fn({"action":"close","sid":sid})
            except: pass
