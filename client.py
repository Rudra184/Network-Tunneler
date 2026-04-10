#!/usr/bin/env python3
"""
client.py — Secure E2E tunnel client
  pip install cryptography pillow
  python3 client.py --relay <ip> --secret <key> --name <you> [options]

══ STEGANOGRAPHY ══════════════════════════════════════════════════════════════

  SENDER (Steg tab → ENCODE):
    1. Enter a cover image path (JPG, PNG, BMP, TIFF, WebP …)
    2. Choose "Hide a file" (any type) or "Hide a text message"
    3. Enter a steg password — tell the receiver this out-of-band
    4. Click Embed & Send

  RECEIVER (Steg tab → DECODE):
    1. Accept the incoming file popup — stego PNG is saved to:
         <same folder as client.py>/received_steg/
    2. Go to Steg tab → DECODE section (path is auto-filled)
    3. Enter the steg password the sender told you
    4. Click Decode
       • Hidden FILE  → saved to disk, full path shown
       • Hidden TEXT  → shown on screen in the result panel

  SECURITY:
    • Steg password is NEVER transmitted over the network
    • AES-256-GCM key derived via PBKDF2-HMAC-SHA256 (200k iterations)
    • Without the password, extracted LSBs are indistinguishable from noise

══════════════════════════════════════════════════════════════════════════════
"""

import asyncio, json, os, sys, argparse, logging, base64, zipfile
import struct, hmac, hashlib, ssl, time, tempfile, random, subprocess
import shutil, platform, urllib.request, io
from collections import defaultdict
from urllib.parse import urlparse

# ── Windows: force UTF-8 on stdout/stderr so Unicode chars don't crash ────────
if platform.system().lower() == "windows":
    import ctypes
    try:
        ctypes.windll.kernel32.SetConsoleOutputCP(65001)   # CP_UTF8
    except Exception:
        pass
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ── Tab-completion: readline on Linux/macOS, pyreadline3 on Windows, else off ─
_HAS_READLINE = False
try:
    import readline as rl
    _HAS_READLINE = True
except ImportError:
    try:
        import pyreadline3 as rl          # pip install pyreadline3
        _HAS_READLINE = True
    except ImportError:
        rl = None                          # no completion — still works fine

try:
    from tunnel import ClientTunnelManager, Socks5Server
except ImportError:
    ClientTunnelManager = None; Socks5Server = None

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256

logging.basicConfig(level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(message)s", datefmt="%H:%M:%S")
log = logging.getLogger("client")

CHUNK = 65536
SYSTEM = platform.system().lower()

# Stego PNGs received are always saved here — predictable and absolute
STEG_RECV_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "received_steg")

# ── Aliases ───────────────────────────────────────────────────────────────────

ALIAS_FILE = "aliases.json"

def load_aliases():
    try:    return json.load(open(ALIAS_FILE))
    except: return {}

def save_aliases(a):
    json.dump(a, open(ALIAS_FILE, "w"), indent=2)

aliases = load_aliases()

def resolve(x):
    return aliases.get(x, x)

# ── Auto Tor ──────────────────────────────────────────────────────────────────

TOR_PORT     = 9055
TOR_DIR      = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".tor_data")
_tor_process = None

def _tor_binary():
    t = shutil.which("tor")
    if t: return t
    local = os.path.join(TOR_DIR, "bin", "tor" + (".exe" if SYSTEM == "windows" else ""))
    return local if os.path.isfile(local) else None

def start_tor():
    global _tor_process
    if not _tor_binary():
        if SYSTEM == "linux":
            for mgr, cmd in [
                ("apt-get", ["sudo","apt-get","install","-y","tor"]),
                ("dnf",     ["sudo","dnf","install","-y","tor"]),
                ("pacman",  ["sudo","pacman","-Sy","--noconfirm","tor"]),
            ]:
                if shutil.which(mgr): subprocess.run(cmd, check=True); break
        elif SYSTEM == "darwin":
            subprocess.run(["brew","install","tor"], check=True)
        else:
            raise RuntimeError("Install Tor manually and ensure 'tor' is on PATH")
    os.makedirs(TOR_DIR, exist_ok=True)
    torrc = os.path.join(TOR_DIR, "torrc")
    open(torrc,"w").write(
        f"SocksPort 127.0.0.1:{TOR_PORT}\nDataDirectory {TOR_DIR}\nLog notice stderr\n"
    )
    log.info("Starting Tor on 127.0.0.1:%d …", TOR_PORT)
    _popen_kwargs = dict(
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    if platform.system().lower() == "windows":
        _popen_kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
    _tor_process = subprocess.Popen(
        [_tor_binary(), "-f", torrc], **_popen_kwargs
    )
    deadline = time.time() + 60
    while time.time() < deadline:
        line = _tor_process.stderr.readline()
        if not line:
            if _tor_process.poll() is not None:
                raise RuntimeError(f"Tor exited ({_tor_process.returncode})")
            time.sleep(0.1); continue
        if "Bootstrapped 100" in line: log.info("Tor ready"); return
    raise RuntimeError("Tor did not bootstrap in 60s")

def stop_tor():
    global _tor_process
    if _tor_process and _tor_process.poll() is None:
        _tor_process.terminate()
        try: _tor_process.wait(timeout=5)
        except: _tor_process.kill()
        _tor_process = None

# ── Port knocking ─────────────────────────────────────────────────────────────

async def send_knock_sequence(host, ports):
    log.info("Knocking %s: %s", host, " → ".join(map(str, ports)))
    for port in ports:
        try:
            _, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=3)
            w.close()
            try: await w.wait_closed()
            except: pass
        except: pass
        await asyncio.sleep(0.2)
    log.info("Knock sent — waiting 2s …"); await asyncio.sleep(2.0)

# ── SOCKS5 ────────────────────────────────────────────────────────────────────

async def socks5_connect(proxy_host, proxy_port, target_host, target_port):
    reader, writer = await asyncio.open_connection(proxy_host, proxy_port)
    writer.write(b"\x05\x01\x00"); await writer.drain()
    resp = await reader.readexactly(2)
    if resp != b"\x05\x00": raise RuntimeError(f"SOCKS5 auth rejected: {resp.hex()}")
    host_b = target_host.encode()
    writer.write(b"\x05\x01\x00\x03" + bytes([len(host_b)]) + host_b + struct.pack(">H", target_port))
    await writer.drain()
    hdr = await reader.readexactly(4)
    if hdr[1] != 0:
        codes = {1:"general failure",2:"not allowed",3:"net unreachable",4:"host unreachable",5:"connection refused"}
        raise RuntimeError(f"SOCKS5: {codes.get(hdr[1], str(hdr[1]))}")
    atyp = hdr[3]
    if   atyp == 1: await reader.readexactly(6)
    elif atyp == 3: n=(await reader.readexactly(1))[0]; await reader.readexactly(n+2)
    elif atyp == 4: await reader.readexactly(18)
    return reader, writer

# ── TLS ───────────────────────────────────────────────────────────────────────

_CIPHERS = [
    "TLS_AES_256_GCM_SHA384","TLS_AES_128_GCM_SHA256","TLS_CHACHA20_POLY1305_SHA256",
    "ECDHE-RSA-AES256-GCM-SHA384","ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384","ECDHE-RSA-CHACHA20-POLY1305",
]

def build_tls_ctx():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    try: ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    except: pass
    ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    shuffled = _CIPHERS[:]; random.shuffle(shuffled)
    try: ctx.set_ciphers(":".join(shuffled))
    except: pass
    return ctx

def get_fp(writer):
    cert_der = writer.get_extra_info("ssl_object").getpeercert(binary_form=True)
    return hashlib.sha256(cert_der).hexdigest()

# ── TOTP ──────────────────────────────────────────────────────────────────────

def _totp(secret, drift=0, interval=30, digits=6):
    counter = (int(time.time()) // interval) + drift
    h   = hmac.new(secret, struct.pack(">Q", counter), hashlib.sha1).digest()
    off = h[-1] & 0x0F
    code = (struct.unpack(">I", h[off:off+4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)

# ── Crypto helpers ────────────────────────────────────────────────────────────

def sha256_file(path):
    h = hashlib.sha256()
    with open(path,"rb") as f:
        for block in iter(lambda: f.read(65536), b""): h.update(block)
    return h.hexdigest()

def compute_encrypted_size(file_size):
    n = max(1, (file_size + CHUNK - 1) // CHUNK)
    return 32 + n * (4 + 12 + 16) + file_size

# ── Steganography — Pillow LSB with PBKDF2 password ──────────────────────────

_PBKDF2_ITERS = 200_000

def _check_pillow():
    try:    import PIL
    except: raise RuntimeError("Pillow not installed. Run: pip install pillow")

def _derive_steg_key(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _PBKDF2_ITERS, dklen=32)

def _open_rgb(src):
    _check_pillow()
    from PIL import Image
    try:
        img = Image.open(src if isinstance(src, (str, os.PathLike)) else io.BytesIO(src))
        return img.convert("RGB")
    except Exception as e:
        raise RuntimeError(f"Cannot open image: {e}")

def steg_encode(cover_path: str, payload: bytes, password: str,
                content_type: str = "file", filename: str = "") -> bytes:
    """
    Embed payload into cover image using Pillow LSB.
    Key derived from password via PBKDF2 — password never transmitted.
    Output is always PNG (lossless). Any input format accepted.
    """
    if not password:
        raise RuntimeError("Steg password cannot be empty.")
    img    = _open_rgb(cover_path)
    w, h   = img.size
    pixels = list(img.getdata())
    total  = len(pixels) * 3

    ct_byte  = b"\x00" if content_type == "file" else b"\x01"
    fn_bytes = filename.encode("utf-8")[:65535]
    plain    = ct_byte + struct.pack(">H", len(fn_bytes)) + fn_bytes + payload

    salt       = os.urandom(16)
    key        = _derive_steg_key(password, salt)
    nonce      = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, plain, None)

    blob        = salt + nonce + ciphertext
    full        = struct.pack(">I", len(blob)) + blob
    bits_needed = len(full) * 8

    if bits_needed > total:
        cap  = total // (8 * 1024)
        need = bits_needed // (8 * 1024) + 1
        raise RuntimeError(
            f"Cover image too small.\n"
            f"  {w}×{h} px → ~{cap} KB capacity,  payload needs ~{need} KB.\n"
            f"  Use a larger image."
        )

    flat = []
    for r, g, b in pixels:
        flat.append(r); flat.append(g); flat.append(b)

    idx = 0
    for byte in full:
        for shift in range(7, -1, -1):
            flat[idx] = (flat[idx] & 0xFE) | ((byte >> shift) & 1)
            idx += 1

    from PIL import Image
    out = Image.new("RGB", (w, h))
    out.putdata([(flat[i], flat[i+1], flat[i+2]) for i in range(0, len(flat), 3)])
    buf = io.BytesIO()
    out.save(buf, format="PNG", optimize=False)
    return buf.getvalue()


def steg_decode(image_path_or_bytes, password: str) -> dict:
    """
    Extract and decrypt hidden payload from a stego PNG.
    Returns dict with keys: content_type ("file"/"msg"), filename, payload (bytes).
    Raises RuntimeError with a user-friendly message on any failure.
    """
    if not password:
        raise RuntimeError("Steg password cannot be empty.")

    img    = _open_rgb(image_path_or_bytes)
    pixels = list(img.getdata())
    flat   = []
    for r, g, b in pixels:
        flat.append(r); flat.append(g); flat.append(b)

    length = 0
    for i in range(32):
        length = (length << 1) | (flat[i] & 1)

    if length <= 0 or 32 + length * 8 > len(flat):
        raise RuntimeError(
            "No steganographic payload found in this image.\n"
            "Make sure this is the stego PNG received, not the original cover."
        )

    raw = bytearray()
    for bi in range(length):
        byte = 0
        for bp in range(8):
            byte = (byte << 1) | (flat[32 + bi * 8 + bp] & 1)
        raw.append(byte)
    raw = bytes(raw)

    if len(raw) < 16 + 12 + 17:
        raise RuntimeError("Extracted data too short — image may be corrupt.")

    salt, nonce, ciphertext = raw[:16], raw[16:28], raw[28:]
    key = _derive_steg_key(password, salt)

    try:
        plain = AESGCM(key).decrypt(nonce, ciphertext, None)
    except Exception:
        raise RuntimeError(
            "Wrong password — decryption failed.\n"
            "Use the exact same password the sender used."
        )

    if len(plain) < 3:
        raise RuntimeError("Decrypted payload is malformed.")

    fn_len   = struct.unpack(">H", plain[1:3])[0]
    if len(plain) < 3 + fn_len:
        raise RuntimeError("Decrypted payload truncated.")

    return {
        "content_type": "file" if plain[0] == 0x00 else "msg",
        "filename":     plain[3:3+fn_len].decode("utf-8", errors="replace"),
        "payload":      plain[3+fn_len:],
    }

# ── Tab completion ────────────────────────────────────────────────────────────

COMMANDS = ["list","myid","send","steg","stegmsg","stegdecode",
            "chat","msg","alias","aliases","history","exit"]

class Completer:
    def __init__(self, c): self.client = c
    def complete(self, text, state):
        line  = rl.get_line_buffer(); parts = line.split()
        peers = list(self.client.peers.keys()) if self.client else []
        al    = list(aliases.keys())
        if len(parts) == 0 or (len(parts)==1 and not line.endswith(" ")):
            opts = [c for c in COMMANDS if c.startswith(text)]
        elif len(parts)==1 or (len(parts)==2 and not line.endswith(" ")):
            opts = [p for p in peers+al if p.startswith(text)]
        else: opts = []
        try:    return opts[state]
        except: return None

# ── RelayClient ───────────────────────────────────────────────────────────────

class RelayClient:
    def __init__(self, host, port, name, secret,
                 fingerprint=None, proxy=None,
                 knock_ports=None, auto_accept=False):
        self.host        = host;         self.port        = port
        self.name        = name;         self.secret      = secret.encode()
        self.fingerprint = fingerprint;  self.proxy       = proxy
        self.knock_ports = knock_ports or []
        self.auto_accept = auto_accept

        self.my_id = None; self.peers = {}
        self.reader = None; self.writer = None; self._task = None

        self._priv    = X25519PrivateKey.generate()
        self._pub_raw = self._priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self._pubkey_raw  = {}; self._pubkey_wait = defaultdict(list)
        self._key_cache   = {}; self._xfer_done   = asyncio.Event()
        self._history     = []; self._chat_peer   = None

        # _file_gate: SET = _recv_loop may readline(); CLEAR = file bytes in
        # flight, _recv_loop must block so it doesn't chew through binary data.
        # PNG payloads contain 0x0A bytes — readline() would silently consume
        # chunks of the payload before _receive_file even wakes up.
        self._file_gate = asyncio.Event()
        self._file_gate.set()   # open by default

        # TUI hooks — set by tui.py before connect()
        # _on_stego_saved(saved_path: str, from_name: str, size: int)
        self._on_stego_saved = None
        # _on_xfer_status(message: str, is_error: bool)
        self._on_xfer_status = None
        # _on_tunnel_status(message: str, is_error: bool)
        self._on_tunnel_status = None

        # Traffic tunnel state
        self._tunnel : object = None   # ClientTunnelManager when active
        self._socks  : object = None   # Socks5Server when active
        # _on_socks_status(msg, is_err)
        self._on_socks_status = None
        # _on_pcap_ack(ok, path_or_msg)
        self._on_pcap_ack = None
        # _on_channel_msg(channel_id, from_name, text)
        self._on_channel_msg = None
        # local channel key store: channel_id → bytes
        self._channel_keys: dict = {}

    def _xfer_log(self, msg: str, err: bool = False):
        """Route a status message to TUI callback or print()."""
        if self._on_xfer_status:
            self._on_xfer_status(msg, err)
        else:
            prefix = "✗" if err else "✓"
            print(f"  {prefix} {msg}")

    # ── connection ────────────────────────────────────────────

    async def connect(self):
        if self.knock_ports: await send_knock_sequence(self.host, self.knock_ports)
        ctx = build_tls_ctx()
        if self.proxy:
            rr, rw = await socks5_connect(self.proxy.hostname, self.proxy.port, self.host, self.port)
            sock = rw.transport.get_extra_info("socket")
            self.reader, self.writer = await asyncio.open_connection(sock=sock, ssl=ctx, server_hostname=self.host)
        else:
            self.reader, self.writer = await asyncio.open_connection(self.host, self.port, ssl=ctx)

        actual_fp = get_fp(self.writer)
        if self.fingerprint:
            if not hmac.compare_digest(actual_fp, self.fingerprint):
                self.writer.close()
                raise RuntimeError(f"TLS FINGERPRINT MISMATCH\n  Expected: {self.fingerprint}\n  Got: {actual_fp}")
            log.info("Cert fingerprint OK ✓")
        else:
            print(f"\n  ⚠  Server fingerprint: {actual_fp}\n")

        raw       = await self.reader.readline()
        challenge = json.loads(raw.decode().strip())
        if challenge.get("type") != "challenge": raise RuntimeError(f"Bad handshake: {challenge}")

        nonce    = challenge["nonce"]; ts = int(time.time())
        hmac_val = hmac.new(self.secret, f"{nonce}{ts}".encode(), hashlib.sha256).hexdigest()
        totp_key = hashlib.sha256(self.secret + b":totp").digest()
        await self._send({
            "type":"register","name":self.name,"nonce":nonce,"ts":ts,
            "hmac":hmac_val,"totp":_totp(totp_key),
            "pubkey":base64.b64encode(self._pub_raw).decode(),
        })

        raw = await self.reader.readline()
        if not raw: raise RuntimeError("Auth rejected")
        welcome = json.loads(raw.decode().strip())
        if welcome.get("type") != "welcome": raise RuntimeError(f"Auth failed: {welcome}")
        self.my_id = welcome["your_id"]
        log.info("Connected  id=%s", self.my_id)
        self._task = asyncio.create_task(self._recv_loop())

    async def disconnect(self):
        if self._socks:
            try: await self._socks.stop()
            except: pass
            self._socks = None
        if self._tunnel:
            try:
                await self._send({"type": "tunnel_stop"})
            except Exception:
                pass
            try:
                await self._tunnel.stop()
            except Exception:
                pass
            self._tunnel = None
        if self._task: self._task.cancel()
        if self.writer:
            self.writer.close()
            try: await self.writer.wait_closed()
            except: pass

    async def _send(self, obj):
        self.writer.write((json.dumps(obj) + "\n").encode())
        await self.writer.drain()

    # ── pubkey / ECDH ─────────────────────────────────────────

    async def get_pubkey_raw(self, pid):
        if pid in self._pubkey_raw: return self._pubkey_raw[pid]
        loop = asyncio.get_event_loop()
        fut  = loop.create_future()
        self._pubkey_wait[pid].append(fut)
        await self._send({"type":"get_pubkey","peer_id":pid})
        try:    return await asyncio.wait_for(fut, timeout=10)
        except: return None

    async def get_shared_key(self, pid):
        if pid in self._key_cache: return self._key_cache[pid]
        raw = await self.get_pubkey_raw(pid)
        if raw is None: return None
        shared = self._priv.exchange(X25519PublicKey.from_public_bytes(raw))
        key    = HKDF(algorithm=SHA256(), length=32, salt=None, info=b"e2e-key").derive(shared)
        self._key_cache[pid] = key
        return key

    # ── accept prompt ─────────────────────────────────────────

    async def _prompt_accept(self, tid, from_name, filename, size_bytes):
        if self.auto_accept: return True
        size_str = (
            f"{size_bytes/(1024*1024):.1f} MB" if size_bytes > 1_048_576
            else f"{size_bytes//1024} KB"       if size_bytes > 1024
            else f"{size_bytes} bytes"
        )
        print(f"\n  ┌─ Incoming ────────────────────────────────────────")
        print(f"  │  From : {from_name}")
        print(f"  │  File : {filename}")
        print(f"  │  Size : {size_str}")
        print(f"  │  [y]es / [n]o  (auto-rejects in 30 s)")
        print(f"  └───────────────────────────────────────────────────")
        loop   = asyncio.get_event_loop()
        ev     = asyncio.Event()
        result = {"ok": False}
        self._pending = (ev, result)
        try:    await asyncio.wait_for(ev.wait(), timeout=30)
        except: print("  ✗ Auto-rejected"); result["ok"] = False
        return result["ok"]

    # ── steg send ─────────────────────────────────────────────

    async def send_steg(self, target_id: str, cover_path: str,
                        payload: bytes, password: str,
                        content_type: str = "file", filename: str = ""):
        if not os.path.isfile(cover_path):
            raise RuntimeError(f"Cover image not found: {cover_path}")
        if target_id not in self.peers:
            raise RuntimeError(f"Peer {target_id!r} not connected")
        if not password:
            raise RuntimeError("Steg password cannot be empty.")

        log.info("Steg encode: %d B %s payload → PBKDF2+AES → LSB embed", len(payload), content_type)
        steg_png = steg_encode(cover_path, payload, password, content_type, filename)
        log.info("Steg PNG ready: %d bytes → sending to %s", len(steg_png), target_id)

        key    = await self.get_shared_key(target_id)
        aesgcm = AESGCM(key) if key else None
        fn_b64 = ""
        if aesgcm:
            fn_n   = os.urandom(12)
            fn_b64 = base64.b64encode(
                fn_n + aesgcm.encrypt(fn_n, os.path.basename(cover_path).encode(), None)
            ).decode()

        await self._send({
            "type":         "send_file",
            "to":           target_id,
            "filename_enc": fn_b64,
            "size":         len(steg_png),
            "hash":         hashlib.sha256(steg_png).hexdigest(),
            "steg":         True,
            "transfer_id":  os.urandom(8).hex(),
            "display_name": os.path.basename(cover_path),
        })
        self.writer.write(steg_png)
        await self.writer.drain()

        self._xfer_done.clear()
        try:    await asyncio.wait_for(self._xfer_done.wait(), timeout=120)
        except: log.warning("No ack within 120s")

    # ── normal file send ──────────────────────────────────────

    async def send_file(self, target_id, path):
        tmp = None
        if os.path.isdir(path):
            tmp = tempfile.mktemp(suffix=".zip")
            with zipfile.ZipFile(tmp,"w",zipfile.ZIP_DEFLATED) as z:
                for root,_,files in os.walk(path):
                    for fn in files:
                        fp = os.path.join(root,fn)
                        z.write(fp, os.path.relpath(fp, os.path.dirname(path)))
            path = tmp

        if not os.path.isfile(path):
            if tmp: os.unlink(tmp); return
        if target_id not in self.peers:
            if tmp: os.unlink(tmp); return
        key = await self.get_shared_key(target_id)
        if key is None:
            if tmp: os.unlink(tmp); return

        fname  = os.path.basename(path); fsize = os.path.getsize(path)
        fhash  = sha256_file(path)
        aesgcm = AESGCM(key); fn_n = os.urandom(12)
        fn_b64 = base64.b64encode(fn_n + aesgcm.encrypt(fn_n, fname.encode(), None)).decode()
        enc_size = compute_encrypted_size(fsize)

        await self._send({
            "type":"send_file","to":target_id,"filename_enc":fn_b64,
            "size":enc_size,"hash":fhash,"steg":False,
            "transfer_id":os.urandom(8).hex(),"display_name":fname,
        })

        salt     = os.urandom(32)
        xfer_key = HKDF(algorithm=SHA256(), length=32, salt=salt, info=b"xfer").derive(key)
        xfer_gcm = AESGCM(xfer_key)
        self.writer.write(salt)

        sent = 0
        with open(path,"rb") as f:
            while True:
                chunk = f.read(CHUNK)
                if not chunk: break
                nonce = os.urandom(12); ct = xfer_gcm.encrypt(nonce, chunk, None)
                frame = nonce + ct
                self.writer.write(struct.pack("<I",len(frame)) + frame)
                sent += len(chunk)
                if fsize > 0:
                    print(f"\r  Uploading {fname} … {sent*100//fsize}%  ", end="", flush=True)

        await self.writer.drain(); print()
        self._xfer_done.clear()
        try:    await asyncio.wait_for(self._xfer_done.wait(), timeout=180)
        except: log.warning("No ack within 180s")
        if tmp: os.unlink(tmp)

    # ── chat ──────────────────────────────────────────────────

    async def send_message(self, target_id, text):
        if target_id not in self.peers: return
        key = await self.get_shared_key(target_id)
        if key is None: return
        nonce = os.urandom(12); ct = AESGCM(key).encrypt(nonce, text.encode(), None)
        await self._send({
            "type":"msg","to":target_id,
            "payload":base64.b64encode(ct).decode(),
            "nonce":base64.b64encode(nonce).decode(),
        })

    # ── receive loop ──────────────────────────────────────────

    async def _recv_loop(self):
        try:
            while True:
             
                await self._file_gate.wait()

                raw = await self.reader.readline()
                if not raw: break
                try:    msg = json.loads(raw.decode().strip())
                except: continue
                t = msg.get("type")
                if t == "peer_list":
                    self.peers = {p["id"]:p["name"] for p in msg["peers"]}
                    for pid in self.peers:
                        if pid not in self._pubkey_raw:
                            asyncio.create_task(self._prefetch_pubkey(pid))
                elif t == "pubkey_response":
                    pid = msg["peer_id"]; rb = base64.b64decode(msg["pubkey"])
                    self._pubkey_raw[pid] = rb
                    for fut in self._pubkey_wait.pop(pid,[]):
                        if not fut.done(): fut.set_result(rb)
                elif t == "incoming_file":
                    # Cache sender's pubkey from the inline field the server
                    # provides.  We must not send a get_pubkey request here:
                    # the server is already streaming file bytes to us on the
                    # same TCP connection, so any control message response
                    # would be interleaved with binary data, corrupting the
                    # transfer.  The server includes from_pubkey precisely to
                    # avoid this extra round-trip.
                    from_id  = msg.get("from_id")
                    fp_b64   = msg.get("from_pubkey", "")
                    if from_id and fp_b64 and from_id not in self._pubkey_raw:
                        try:
                            rb = base64.b64decode(fp_b64)
                            self._pubkey_raw[from_id] = rb
                            for fut in self._pubkey_wait.pop(from_id, []):
                                if not fut.done(): fut.set_result(rb)
                        except Exception as e:
                            log.warning("Could not cache inline pubkey for %s: %s", from_id, e)
                    # Close the gate BEFORE scheduling the task so the next
                    # await self._file_gate.wait() above blocks immediately.
                    self._file_gate.clear()
                    asyncio.create_task(self._receive_file(msg))
                elif t == "msg":
                    await self._receive_message(msg)
                elif t == "send_ok":
                    self._history.append({"dir":"sent","ts":time.time(),"size":msg.get("size",0)})
                    self._xfer_done.set()
                elif t == "error":
                    self._xfer_log(f"Relay error: {msg.get('msg','')}", err=True)
                    self._xfer_done.set()
                elif t == "tunnel_ready":
                    asyncio.create_task(self._on_tunnel_ready(msg))
                elif t == "tunnel_error":
                    emsg = msg.get("msg", "unknown error")
                    log.warning("Tunnel error from server: %s", emsg)
                    if self._on_tunnel_status:
                        self._on_tunnel_status(f"✗ Tunnel error: {emsg}", True)
                elif t == "tpkt":
                    # Encrypted inbound tunnel packet from server
                    if self._tunnel and self._tunnel.active:
                        self._tunnel.inject(msg.get("d", ""))
                elif t == "socks":
                    asyncio.create_task(self._handle_socks_msg(msg))
                elif t == "tunnel_pcap_ack":
                    if self._on_pcap_ack:
                        ok   = msg.get("ok", False)
                        info = msg.get("path","") or msg.get("msg","")
                        self._on_pcap_ack(ok, info)
                elif t == "channel_msg":
                    asyncio.create_task(self._handle_channel_msg(msg))
        except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
            log.warning("Connection lost")
        except asyncio.CancelledError: pass
        except Exception as e: log.exception("Recv loop: %s", e)

    # ── traffic tunnel ───────────────────────────────────────

    async def start_tunnel(self):
        """Request a traffic tunnel from the relay server."""
        if ClientTunnelManager is None:
            raise RuntimeError("tunnel.py not found — place it alongside client.py")
        if self._tunnel and self._tunnel.active:
            raise RuntimeError("Tunnel already active")
        if not self.writer:
            raise RuntimeError("Not connected")
        await self._send({"type": "tunnel_start"})
        # Response handled in recv_loop → _on_tunnel_ready

    async def stop_tunnel(self):
        """Tear down the traffic tunnel."""
        if self._tunnel and self._tunnel.active:
            try:
                await self._send({"type": "tunnel_stop"})
            except Exception:
                pass
            await self._tunnel.stop()
            self._tunnel = None
            if self._on_tunnel_status:
                self._on_tunnel_status("Tunnel stopped — routes restored", False)

    async def _on_tunnel_ready(self, msg: dict):
        """Called when server confirms tunnel_ready with assigned IP."""
        client_ip = msg.get("client_ip", "")
        if not client_ip:
            if self._on_tunnel_status:
                self._on_tunnel_status("✗ Tunnel: server sent no client IP", True)
            return
        if ClientTunnelManager is None:
            return
        try:
            tun = ClientTunnelManager()

            def _send_pkt(blob_b64: str):
                # blob_b64 is already encrypted by ClientTunnelManager._read_loop
                # Write as a short JSON line — no drain() call here to avoid
                # creating a coroutine from a sync context.  The StreamWriter
                # buffers up to 64 KB before blocking; drain() fires naturally
                # in the next await in _recv_loop.
                if not self.writer: return
                try:
                    self.writer.write(
                        (json.dumps({"type": "tpkt", "d": blob_b64}) + "\n").encode())
                except Exception as e:
                    log.warning("TUN pkt send: %s", e)

            tun.on_send_pkt = _send_pkt
            await tun.start(
                server_relay_ip=self.host,
                assigned_ip=client_ip,
                secret=self.secret,
                peer_id=self.my_id or "unknown",
            )
            self._tunnel = tun
            if self._on_tunnel_status:
                self._on_tunnel_status(
                    f"🌐 Tunnel active — all traffic via relay  (your tun IP: {client_ip})",
                    False)
            log.info("Traffic tunnel up: %s", client_ip)
        except Exception as e:
            log.exception("Tunnel start failed: %s", e)
            if self._on_tunnel_status:
                self._on_tunnel_status(f"✗ Tunnel failed: {e}", True)

    # ── SOCKS5 proxy ─────────────────────────────────────────

    async def start_socks(self, proxy_peer_id: str, local_port: int = 1080):
        """Open a local SOCKS5 listener that exits through proxy_peer_id."""
        if Socks5Server is None:
            raise RuntimeError("tunnel.py not found")
        if self._socks and self._socks.active:
            raise RuntimeError("SOCKS5 proxy already running")
        if proxy_peer_id not in self.peers:
            raise RuntimeError(f"Peer {proxy_peer_id!r} not connected")
        socks = Socks5Server()

        async def _relay(action_dict: dict):
            await self._send({
                "type":   "socks",
                "to":     proxy_peer_id,
                **action_dict,
            })

        await socks.start(proxy_peer_id, _relay, local_port)
        self._socks = socks
        if self._on_socks_status:
            self._on_socks_status(
                f"🧦 SOCKS5 active on 127.0.0.1:{local_port}  exit→{proxy_peer_id}", False)

    async def stop_socks(self):
        if self._socks:
            await self._socks.stop()
            self._socks = None
            if self._on_socks_status:
                self._on_socks_status("SOCKS5 stopped", False)

    async def toggle_pcap(self, enable: bool, path: str = ""):
        """Ask the server to start/stop pcap capture (requires server-side root)."""
        await self._send({"type": "tunnel_pcap", "enable": enable, "path": path})

    async def _handle_socks_msg(self, msg: dict):
        """
        Dispatch an incoming socks relay message.
        Two roles:
          - Originator side: message is an ack/data/close from the exit peer.
            Deliver to Socks5Server.on_relay_msg().
          - Exit node side: message is open/data/close from originator.
            Handle via Socks5Server.handle_as_exit() and reply back.
        """
        action  = msg.get("action", "")
        from_id = msg.get("from_id", "")

        if self._socks and self._socks.active and self._socks._proxy_peer == from_id:
            # We are the originator; this is a reply from our chosen exit peer
            await self._socks.on_relay_msg(msg)
        else:
            # We are the exit node — handle and reply back to originator
            if Socks5Server is None: return
            # Reuse or create a transient exit-role Socks5Server instance
            if not hasattr(self, "_socks_exit"):
                self._socks_exit = Socks5Server()

            async def _reply(d: dict):
                await self._send({"type": "socks", "to": from_id, **d})

            await self._socks_exit.handle_as_exit(msg, _reply)

    # ── channel / group chat ────────────────────────────────────

    async def send_channel_msg(self, channel_id: str, key: bytes, text: str):
        """Encrypt text with channel key and broadcast to the channel."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        nonce = os.urandom(12)
        # Include sender name in payload so receivers can display it
        inner = json.dumps({"from": self.name, "text": text}).encode()
        ct    = AESGCM(key).encrypt(nonce, inner, None)
        await self._send({
            "type":       "channel_msg",
            "channel_id": channel_id,
            "payload":    base64.b64encode(ct).decode(),
            "nonce":      base64.b64encode(nonce).decode(),
        })
        # Store key locally so incoming messages from same channel can be decrypted
        self._channel_keys[channel_id] = key

    def register_channel_key(self, channel_id: str, key: bytes):
        """Register a channel key so incoming messages can be decrypted."""
        self._channel_keys[channel_id] = key

    async def _handle_channel_msg(self, msg: dict):
        """Try to decrypt an incoming channel message with known channel keys."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        channel_id = msg.get("channel_id", "")
        from_name  = msg.get("from_name", "?")
        payload_b  = msg.get("payload", "")
        nonce_b    = msg.get("nonce", "")
        if not payload_b or not nonce_b: return
        key = self._channel_keys.get(channel_id)
        if not key: return
        try:
            ct    = base64.b64decode(payload_b)
            nonce = base64.b64decode(nonce_b)
            inner = AESGCM(key).decrypt(nonce, ct, None)
            data  = json.loads(inner.decode())
            sender = data.get("from", from_name)
            text   = data.get("text", "")
            if self._on_channel_msg:
                self._on_channel_msg(channel_id, sender, text)
        except Exception as e:
            log.debug("channel_msg decrypt failed cid=%s: %s", channel_id, e)

    async def _prefetch_pubkey(self, pid):
        await self.get_pubkey_raw(pid)

    async def _receive_file(self, meta):
        """
        Receive an incoming file or stego PNG.

        IMPORTANT: This runs inside asyncio.create_task() — unhandled exceptions
        would be silently swallowed. Every code path explicitly calls _xfer_log
        so errors always surface in the TUI or terminal.

        The _file_gate Event in _recv_loop is ALWAYS re-opened in the finally
        block below, even on exception, so subsequent transfers can proceed.
        """
        try:
            await self._receive_file_impl(meta)
        except Exception as e:
            log.exception("_receive_file crashed: %s", e)
            self._xfer_log(f"✗ Internal receive error: {e}", err=True)
        finally:
            # Re-open the gate so _recv_loop can readline() for the next message.
            self._file_gate.set()

    async def _receive_file_impl(self, meta):
        from_id   = meta["from_id"];    from_name = meta["from_name"]
        size      = int(meta["size"]); fhash     = meta.get("hash","")
        fn_b64    = meta.get("filename_enc","")
        is_steg   = meta.get("steg", False)
        disp_name = meta.get("display_name","file")
        xfer_id   = meta.get("transfer_id", os.urandom(8).hex())

        log.info("Incoming %s from %s  size=%d  steg=%s",
                 disp_name, from_name, size, is_steg)

        # ── Get shared key ────────────────────────────────────
        # _recv_loop caches the sender's pubkey from the inline from_pubkey
        # field before the gate closes.  Only CPU work needed here — no
        # network requests, no deadlock risk.
        key = self._key_cache.get(from_id)
        if key is None and from_id in self._pubkey_raw:
            try:
                raw_pk = self._pubkey_raw[from_id]
                shared = self._priv.exchange(X25519PublicKey.from_public_bytes(raw_pk))
                key    = HKDF(algorithm=SHA256(), length=32, salt=None, info=b"e2e-key").derive(shared)
                self._key_cache[from_id] = key
            except Exception as e:
                log.warning("Key derivation failed for %s: %s", from_id, e)
        aesgcm = AESGCM(key) if key else None

        # Decrypt cover/display name for the accept prompt
        cover_name = disp_name
        if aesgcm and fn_b64:
            try:
                fn_raw     = base64.b64decode(fn_b64)
                cover_name = aesgcm.decrypt(fn_raw[:12], fn_raw[12:], None).decode()
                cover_name = os.path.basename(cover_name)
            except Exception as e:
                log.debug("Could not decrypt cover name: %s", e)

        prompt_name = (
            f"stego image: {cover_name}  [decode with steg password]"
            if is_steg else cover_name
        )

        # ── Accept prompt ─────────────────────────────────────
        accepted = await self._prompt_accept(xfer_id, from_name, prompt_name, size)

        # Yield to the event loop so any I/O callbacks that arrived while the
        # user was deciding (modal open) are flushed before we start reading.
        # This avoids a race where read() returns 0 bytes on the first call
        # because asyncio's internal read buffer hasn't been populated yet.
        await asyncio.sleep(0)

        if not accepted:
            # Drain the bytes so the stream stays in sync
            log.info("Transfer rejected — draining %d bytes", size)
            rem = size
            while rem > 0:
                try:
                    c = await asyncio.wait_for(
                        self.reader.read(min(CHUNK, rem)), timeout=30)
                except asyncio.TimeoutError:
                    log.warning("Drain timeout after rejection")
                    break
                if not c: break
                rem -= len(c)
            self._xfer_log(f"✗ Rejected transfer from {from_name}")
            return

        # ── Read the incoming bytes ───────────────────────────
        if is_steg:
            # ── Stego PNG receive ─────────────────────────────
            log.info("Reading stego PNG: %d bytes expected", size)
            data = b""; rem = size
            while rem > 0:
                try:
                    # Use 120s timeout per chunk — the user may have taken up
                    # to 30s on the accept popup; the sender + server pipeline
                    # continues independently, but the OS buffers may not have
                    # all bytes flushed to our asyncio reader yet.
                    c = await asyncio.wait_for(
                        self.reader.read(min(CHUNK, rem)), timeout=120)
                except asyncio.TimeoutError:
                    self._xfer_log(
                        f"✗ Stego receive timeout at {len(data)}/{size} bytes", err=True)
                    return
                if not c:
                    self._xfer_log(
                        f"✗ Connection closed mid-receive ({len(data)}/{size} bytes)", err=True)
                    return
                data += c; rem -= len(c)
                print(f"\r  Receiving stego PNG … {len(data)}/{size} bytes  ",
                      end="", flush=True)
            print()

            log.info("Stego PNG received: %d bytes", len(data))

            if len(data) != size:
                self._xfer_log(
                    f"✗ Stego size mismatch: expected {size}, got {len(data)}", err=True)
                return

            # Integrity check on the PNG itself
            if fhash:
                got = hashlib.sha256(data).hexdigest()
                if not hmac.compare_digest(got, fhash):
                    self._xfer_log("⚠ Stego image hash mismatch — image may be corrupt", err=True)
                else:
                    log.info("Stego PNG hash OK ✓")

            # Create received_steg/ directory — do this BEFORE trying to save
            try:
                os.makedirs(STEG_RECV_DIR, exist_ok=True)
                log.info("Save directory: %s", STEG_RECV_DIR)
            except Exception as e:
                self._xfer_log(
                    f"✗ Cannot create received_steg/ directory: {e}\n"
                    f"  Check write permissions for: {os.path.dirname(STEG_RECV_DIR)}",
                    err=True)
                return

            # Build save filename: <cover_base>_<from_name>_<timestamp>.steg.png
            base = os.path.splitext(cover_name)[0] if cover_name else "stego"
            ts   = time.strftime("%Y%m%d_%H%M%S")
            save = os.path.join(STEG_RECV_DIR, f"{base}_{from_name}_{ts}.steg.png")
            n = 1
            while os.path.exists(save):
                save = os.path.join(STEG_RECV_DIR, f"{base}_{from_name}_{ts}_{n}.steg.png")
                n += 1

            # Save the raw stego PNG
            try:
                with open(save, "wb") as f:
                    f.write(data)
                saved_path = os.path.abspath(save)
                log.info("Stego PNG saved: %s", saved_path)
            except Exception as e:
                self._xfer_log(
                    f"✗ Failed to save stego PNG: {e}\n  Path attempted: {save}",
                    err=True)
                return

            # Verify the file was actually written
            if not os.path.exists(saved_path) or os.path.getsize(saved_path) == 0:
                self._xfer_log(
                    f"✗ Save verification failed — file is missing or empty: {saved_path}",
                    err=True)
                return

            # Success message — this MUST appear in the TUI or terminal
            self._xfer_log(
                f"🖼  Stego PNG saved  →  {saved_path}  ({len(data)} bytes)\n"
                f"    Steg tab (F4) → DECODE → enter password to extract"
            )

            # Notify TUI (auto-fills decode path, switches to Steg tab)
            if self._on_stego_saved:
                try:
                    self._on_stego_saved(saved_path, from_name, len(data))
                except Exception as e:
                    log.warning("_on_stego_saved callback error: %s", e)

            self._history.append({
                "dir":"received","ts":time.time(),
                "filename":saved_path,"size":len(data),"from":from_name,"steg":True
            })

        else:
            # ── Normal encrypted file receive ─────────────────
            if not aesgcm:
                self._xfer_log(f"✗ No shared key for {from_name} — cannot decrypt", err=True)
                rem = size
                while rem > 0:
                    c = await self.reader.read(min(CHUNK,rem))
                    if not c: break
                    rem -= len(c)
                return

            try:
                fn_raw  = base64.b64decode(fn_b64)
                fname   = aesgcm.decrypt(fn_raw[:12], fn_raw[12:], None).decode()
                fname   = os.path.basename(fname)
            except:
                fname = f"received_{int(time.time())}"

            save = fname
            b_, e_ = os.path.splitext(fname); n = 1
            while os.path.exists(save): save = f"{b_}_{n}{e_}"; n += 1

            try:
                salt = await self.reader.readexactly(32)
            except asyncio.IncompleteReadError:
                self._xfer_log("✗ Transfer interrupted (salt missing)", err=True); return

            xfer_key = HKDF(algorithm=SHA256(), length=32, salt=salt, info=b"xfer").derive(key)
            xfer_gcm = AESGCM(xfer_key); remaining = size - 32; received = 0

            try:
                with open(save,"wb") as f:
                    while remaining > 0:
                        if remaining < 4: break
                        flen = struct.unpack("<I", await self.reader.readexactly(4))[0]
                        remaining -= 4; flen = min(flen, remaining)
                        frame = await self.reader.readexactly(flen); remaining -= flen
                        try:    plain = xfer_gcm.decrypt(frame[:12], frame[12:], None)
                        except Exception as e:
                            self._xfer_log(f"✗ Chunk decrypt failed at {received} bytes: {e}", err=True)
                            return
                        f.write(plain); received += len(plain)
                        print(f"\r  Receiving {fname} … {received} bytes  ", end="", flush=True)
            except asyncio.IncompleteReadError:
                self._xfer_log(f"✗ Transfer cut at {received} bytes", err=True); return
            print()

            saved_path = os.path.abspath(save)
            if fhash:
                ok = hmac.compare_digest(sha256_file(save), fhash)
                self._xfer_log(
                    f"Saved → {saved_path}  [{'SHA-256 OK ✓' if ok else 'HASH MISMATCH ⚠'}]",
                    err=not ok
                )
            else:
                self._xfer_log(f"Saved → {saved_path}")

            self._history.append({
                "dir":"received","ts":time.time(),
                "filename":save,"size":received,"from":from_name
            })
            if save.endswith(".zip"):
                out = save[:-4]
                try:
                    with zipfile.ZipFile(save) as z: z.extractall(out)
                    self._xfer_log(f"Extracted → {out}/")
                except: pass

    async def _receive_message(self, msg):
        from_id = msg["from_id"]; from_name = msg["from_name"]
        try:
            pl = base64.b64decode(msg.get("payload","")); n = base64.b64decode(msg.get("nonce",""))
        except: return
        key = await self.get_shared_key(from_id)
        if key is None: return
        try:
            text = AESGCM(key).decrypt(n, pl, None).decode()
            ts   = time.strftime("%H:%M:%S")
            if self._chat_peer == from_id:
                print(f"\r  [{ts}] {from_name}: {text}\n  you: ", end="", flush=True)
            else:
                print(f"\n  [{ts}] {from_name} [{from_id}]: {text}\n> ", end="", flush=True)
        except Exception as e:
            print(f"\n  ✗ Decrypt from {from_name}: {e}")


# ── CLI ───────────────────────────────────────────────────────────────────────

async def cli_loop(client: RelayClient):
    loop = asyncio.get_event_loop()
    if _HAS_READLINE and rl is not None:
        comp = Completer(client)
        rl.set_completer(comp.complete)
        rl.set_completer_delims(" \t")
        try:
            rl.parse_and_bind("tab: complete")      # Linux/macOS GNU readline
        except Exception:
            pass                                      # pyreadline3 may differ
    def readline(p=""):
        try:    return input(p)
        except: return None

    print(f"\n  Received stego PNGs → {STEG_RECV_DIR}")
    print("  list | myid | send <id> <path>")
    print("  steg    <id> <cover> <file>    <password>  — hide a file")
    print("  stegmsg <id> <cover> <message> <password>  — hide a message")
    print("  stegdecode <stego.png>          <password>  — extract hidden content")
    print("  chat <id> | msg <id> <text> | history | exit\n")

    while True:
        line = await loop.run_in_executor(None, readline, "> ")
        if line is None: break
        parts = line.strip().split(None, 4)
        if not parts: continue
        cmd = parts[0].lower()

        if cmd == "exit": break
        elif cmd == "myid": print(f"  {client.my_id}")

        elif cmd == "list":
            await client._send({"type":"list"}); await asyncio.sleep(0.3)
            if client.peers:
                id2al = {v:k for k,v in aliases.items()}
                for pid, pname in client.peers.items():
                    print(f"  {pid:<12}  {id2al.get(pid,''):<14}  {pname}")
            else: print("  (no peers online)")

        elif cmd == "send":
            if len(parts) < 3: print("  send <id/alias> <path>"); continue
            await client.send_file(resolve(parts[1]), parts[2])

        elif cmd == "steg":
            if len(parts) < 5:
                print("  steg <id/alias> <cover_image> <file_to_hide> <password>"); continue
            cover, fp, pw = parts[2], parts[3], parts[4]
            if not os.path.isfile(cover): print(f"  ✗ Cover not found: {cover}"); continue
            if not os.path.isfile(fp):    print(f"  ✗ File not found: {fp}"); continue
            try:
                payload = open(fp,"rb").read(); fname = os.path.basename(fp)
                await client.send_steg(resolve(parts[1]), cover, payload, pw,
                                       content_type="file", filename=fname)
                print(f"  ✓ Sent stego PNG hiding '{fname}'")
                print(f"  Tell receiver the steg password out-of-band!")
            except RuntimeError as e: print(f"  ✗ {e}")

        elif cmd == "stegmsg":
            if len(parts) < 5:
                print("  stegmsg <id/alias> <cover_image> <message> <password>"); continue
            cover, message, pw = parts[2], parts[3], parts[4]
            if not os.path.isfile(cover): print(f"  ✗ Cover not found: {cover}"); continue
            try:
                await client.send_steg(resolve(parts[1]), cover, message.encode(), pw,
                                       content_type="msg", filename="")
                print(f"  ✓ Sent stego PNG hiding a message")
            except RuntimeError as e: print(f"  ✗ {e}")

        elif cmd == "stegdecode":
            if len(parts) < 3:
                print("  stegdecode <stego.png> <password>"); continue
            stego_path, pw = parts[1], parts[2]
            if not os.path.isfile(stego_path):
                print(f"  ✗ Not found: {stego_path}"); continue
            try:
                result = steg_decode(stego_path, pw)
                if result["content_type"] == "msg":
                    print(f"  ✓ Hidden message:")
                    print(f"  \"{result['payload'].decode('utf-8', errors='replace')}\"")
                else:
                    save = result["filename"] or f"decoded_{int(time.time())}"
                    b_, e_ = os.path.splitext(save); n = 1
                    while os.path.exists(save): save = f"{b_}_{n}{e_}"; n += 1
                    open(save,"wb").write(result["payload"])
                    print(f"  ✓ Extracted → {os.path.abspath(save)}  ({len(result['payload'])} bytes)")
            except RuntimeError as e: print(f"  ✗ {e}")

        elif cmd == "msg":
            if len(parts) < 3: print("  msg <id/alias> <text>"); continue
            await client.send_message(resolve(parts[1]), " ".join(parts[2:]))

        elif cmd == "chat":
            if len(parts) < 2: print("  chat <id/alias>"); continue
            pid = resolve(parts[1])
            if pid not in client.peers: print(f"  ✗ {pid!r} not online"); continue
            print(f"\n  ── Chat with {client.peers[pid]} ──  (Ctrl+C exits)\n")
            client._chat_peer = pid
            try:
                while True:
                    text = await loop.run_in_executor(None, readline, "  you: ")
                    if text is None: break
                    text = text.strip()
                    if text: await client.send_message(pid, text)
            except (KeyboardInterrupt, asyncio.CancelledError): pass
            finally: client._chat_peer = None; print(f"\n  ── Exited chat ──\n")

        elif cmd == "alias":
            if len(parts) < 3: continue
            aliases[parts[1]] = parts[2]; save_aliases(aliases)
            print(f"  Saved: {parts[1]} → {parts[2]}")

        elif cmd == "aliases":
            for n, pid in aliases.items(): print(f"  {n:<14}  {pid}")

        elif cmd == "history":
            for h in client._history[-20:]:
                ts   = time.strftime("%H:%M:%S", time.localtime(h["ts"]))
                d    = h["dir"].upper()
                mark = " [STEG]" if h.get("steg") else ""
                if d == "SENT":
                    print(f"  {ts}  {d:<8}  {h.get('size',0):>12} bytes{mark}")
                else:
                    print(f"  {ts}  {d:<8}  {h.get('size',0):>12} bytes  "
                          f"{h.get('filename','')}{mark}  ← {h.get('from','')}")

        else: print(f"  Unknown: {cmd!r}")

async def run(args):
    proxy = None
    if args.proxy:   proxy = urlparse(args.proxy)
    elif args.tor:   proxy = urlparse(f"socks5://127.0.0.1:{TOR_PORT}")
    knock_ports = []
    if args.knock_ports: knock_ports = list(map(int, args.knock_ports.split(",")))
    tor_managed = False
    if args.tor:
        try: start_tor(); tor_managed = True
        except Exception as e: print(f"  Tor failed: {e}")
    delay = 3
    while True:
        client = RelayClient(
            host=args.relay, port=args.port, name=args.name, secret=args.secret,
            fingerprint=args.fingerprint or None, proxy=proxy,
            knock_ports=knock_ports, auto_accept=args.auto_accept,
        )
        try:
            await client.connect(); delay = 3
            await cli_loop(client); break
        except ConnectionRefusedError:
            print(f"  Cannot reach {args.relay}:{args.port} — retry in {delay}s …")
            await asyncio.sleep(delay); delay = min(delay*2, 60)
        except RuntimeError as e: print(f"  Fatal: {e}"); break
        except Exception as e:
            log.warning("Lost (%s) — retry in %ds …", e, delay)
            await asyncio.sleep(delay); delay = min(delay*2, 60)
        finally: await client.disconnect()
    if tor_managed: stop_tor()

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--relay",       required=True)
    ap.add_argument("--secret",      required=True)
    ap.add_argument("--name",        default="peer")
    ap.add_argument("--port",        default=4001, type=int)
    ap.add_argument("--fingerprint", default="")
    ap.add_argument("--knock-ports", default="", dest="knock_ports")
    ap.add_argument("--tor",         action="store_true")
    ap.add_argument("--proxy",       default="")
    ap.add_argument("--auto-accept", action="store_true", dest="auto_accept")
    args = ap.parse_args()
    # ProactorEventLoop is the Windows default since Python 3.8.
    # set_event_loop_policy() is deprecated in 3.12 and removed in 3.16 — skip it.
    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        print("\n  Disconnected"); sys.exit(0)
