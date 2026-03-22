#!/usr/bin/env python3
"""
client.py — Secure E2E tunnel client
  pip install cryptography
  python3 client.py --relay <ip> --secret <key> --name <you> [options]

Options:
  --fingerprint <fp>              TLS cert pin (printed by server on startup)
  --knock-ports 6132,8152,3101    port knock before connecting
  --tor                           auto-install + start Tor, stop on exit
  --proxy socks5://127.0.0.1:9050 manual SOCKS5 proxy
  --steg                          hide all file transfers inside PNG images
  --auto-accept                   accept all incoming files without prompt

Commands:
  list                            show online peers
  myid                            your peer ID
  send   <id/alias> <path>        send file or folder
  steg   <id/alias> <img> <file>  hide file in cover image (PNG or JPG)
  stegmsg <id/alias> <img> <txt>  hide text in cover image (PNG or JPG)
  chat   <id/alias>               dedicated chat mode  (Ctrl+C exits)
  msg    <id/alias> <text>        send a single encrypted message
  alias  <n> <peer_id>         save a name for a peer ID
  aliases                         list saved aliases
  history                         last 20 transfers
  exit                            quit
"""

import asyncio, json, os, sys, argparse, logging, base64, zipfile
import struct, hmac, hashlib, ssl, time, tempfile, random, subprocess
import shutil, platform, urllib.request
import readline as rl
from collections import defaultdict
from urllib.parse import urlparse

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger("client")

CHUNK  = 65536
SYSTEM = platform.system().lower()

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
TOR_WIN_URL  = (
    "https://archive.torproject.org/tor-package-archive/"
    "torbrowser/13.0.15/tor-expert-bundle-windows-x86_64-13.0.15.tar.gz"
)

def _tor_binary():
    t = shutil.which("tor")
    if t: return t
    local = os.path.join(TOR_DIR, "bin", "tor" + (".exe" if SYSTEM == "windows" else ""))
    return local if os.path.isfile(local) else None

def _install_tor():
    log.info("Tor not found — installing ...")
    if SYSTEM == "linux":
        for mgr, cmd in [
            ("apt-get", ["sudo","apt-get","install","-y","tor"]),
            ("dnf",     ["sudo","dnf","install","-y","tor"]),
            ("pacman",  ["sudo","pacman","-Sy","--noconfirm","tor"]),
            ("apk",     ["sudo","apk","add","tor"]),
        ]:
            if shutil.which(mgr):
                subprocess.run(cmd, check=True)
                return
        raise RuntimeError("No package manager found. Install tor manually.")
    elif SYSTEM == "darwin":
        if shutil.which("brew"):
            subprocess.run(["brew","install","tor"], check=True)
        else:
            raise RuntimeError("Homebrew not found. Run: brew install tor")
    elif SYSTEM == "windows":
        import tarfile
        os.makedirs(TOR_DIR, exist_ok=True)
        archive = os.path.join(TOR_DIR, "tor.tar.gz")
        log.info("Downloading Tor Expert Bundle ...")
        urllib.request.urlretrieve(
            TOR_WIN_URL, archive,
            reporthook=lambda b,bs,ts: print(
                f"\r  Downloading ... {min(100,int(b*bs*100/(ts or 1)))}%",
                end="", flush=True
            )
        )
        print()
        with tarfile.open(archive,"r:gz") as tar:
            tar.extractall(TOR_DIR)
        for root,_,files in os.walk(TOR_DIR):
            for f in files:
                if f.lower()=="tor.exe":
                    dest=os.path.join(TOR_DIR,"bin")
                    os.makedirs(dest,exist_ok=True)
                    shutil.copy2(os.path.join(root,f),os.path.join(dest,"tor.exe"))
                    return
        raise RuntimeError("tor.exe not found in archive")
    else:
        raise RuntimeError(f"Unsupported OS: {SYSTEM}")

def start_tor():
    global _tor_process
    if not _tor_binary(): _install_tor()
    if not _tor_binary(): raise RuntimeError("Tor not found after install")
    os.makedirs(TOR_DIR, exist_ok=True)
    torrc = os.path.join(TOR_DIR, "torrc")
    open(torrc,"w").write(
        f"SocksPort 127.0.0.1:{TOR_PORT}\n"
        f"DataDirectory {TOR_DIR}\n"
        "Log notice stderr\n"
        "ControlPort 0\n"
    )
    log.info("Starting Tor on 127.0.0.1:%d ...", TOR_PORT)
    _tor_process = subprocess.Popen(
        [_tor_binary(), "-f", torrc],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    deadline = time.time() + 60
    while time.time() < deadline:
        line = _tor_process.stderr.readline()
        if not line:
            if _tor_process.poll() is not None:
                raise RuntimeError(f"Tor exited (code {_tor_process.returncode})")
            time.sleep(0.1)
            continue
        if "100%" in line or "Bootstrapped 100" in line:
            log.info("Tor ready on 127.0.0.1:%d", TOR_PORT)
            return
    raise RuntimeError("Tor did not bootstrap within 60s")

def stop_tor():
    global _tor_process
    if _tor_process and _tor_process.poll() is None:
        log.info("Stopping Tor ...")
        _tor_process.terminate()
        try:    _tor_process.wait(timeout=5)
        except: _tor_process.kill()
        _tor_process = None
        log.info("Tor stopped")

# ── Port knocking ─────────────────────────────────────────────────────────────

async def send_knock_sequence(host, ports):
    log.info("Knocking %s  →  %s", host, " → ".join(map(str, ports)))
    for port in ports:
        try:
            _, w = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=3
            )
            w.close()
            try:    await w.wait_closed()
            except: pass
        except Exception:
            pass
        await asyncio.sleep(0.2)
    log.info("Knock sent — waiting 2s for iptables rule ...")
    await asyncio.sleep(2.0)

# ── SOCKS5 ────────────────────────────────────────────────────────────────────

async def socks5_connect(proxy_host, proxy_port, target_host, target_port):
    reader, writer = await asyncio.open_connection(proxy_host, proxy_port)
    writer.write(b"\x05\x01\x00"); await writer.drain()
    resp = await reader.readexactly(2)
    if resp != b"\x05\x00":
        raise RuntimeError(f"SOCKS5 auth rejected: {resp.hex()}")
    host_b = target_host.encode()
    writer.write(
        b"\x05\x01\x00\x03" + bytes([len(host_b)]) + host_b +
        struct.pack(">H", target_port)
    )
    await writer.drain()
    hdr = await reader.readexactly(4)
    if hdr[1] != 0:
        codes = {1:"general failure",2:"not allowed",3:"net unreachable",
                 4:"host unreachable",5:"connection refused"}
        raise RuntimeError(f"SOCKS5: {codes.get(hdr[1], str(hdr[1]))}")
    atyp = hdr[3]
    if   atyp == 1: await reader.readexactly(6)
    elif atyp == 3:
        n = (await reader.readexactly(1))[0]
        await reader.readexactly(n + 2)
    elif atyp == 4: await reader.readexactly(18)
    log.info("SOCKS5 tunnel → %s:%d", target_host, target_port)
    return reader, writer

# ── JA3 randomization ────────────────────────────────────────────────────────

_CIPHERS = [
    "TLS_AES_256_GCM_SHA384","TLS_AES_128_GCM_SHA256",
    "TLS_CHACHA20_POLY1305_SHA256","ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES128-GCM-SHA256","ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-AES128-GCM-SHA256","ECDHE-RSA-CHACHA20-POLY1305",
    "DHE-RSA-AES256-GCM-SHA384",
]

def build_tls_ctx():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    try:    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    except: pass
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    shuffled = _CIPHERS[:]
    random.shuffle(shuffled)
    try:    ctx.set_ciphers(":".join(shuffled))
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

def encrypt_payload(data, key):
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, data, None)

def decrypt_payload(data, key):
    return AESGCM(key).decrypt(data[:12], data[12:], None)

# ── Steganography — PNG and JPG support ──────────────────────────────────────

def _jpg_to_png(jpg_path):
    """
    Convert a JPEG to PNG using only stdlib so we can do LSB steganography.
    Strategy: decode JPEG pixels via the 'struct' trick is not possible in
    pure Python, so we use the `PIL` / `Pillow` library if available,
    otherwise fall back to writing the raw JPEG bytes into a PNG wrapper
    by re-encoding via the built-in `imghdr` + manual DCT is not feasible.

    Simpler approach: if Pillow is installed use it; if not, instruct the
    user to convert manually or install Pillow. We check gracefully.
    """
    try:
        from PIL import Image
        img = Image.open(jpg_path).convert("RGB")
        tmp = tempfile.mktemp(suffix=".png")
        img.save(tmp, "PNG")
        return tmp, True   # (path, is_temp)
    except ImportError:
        raise ValueError(
            "Pillow is required to use JPG cover images.\n"
            "  Install it:  pip install pillow\n"
            "  Or convert your image to PNG first and use that."
        )

def steg_embed(cover_path, payload):
    """
    Embed payload bytes into the LSBs of a cover image (PNG or JPG).

    Supports:
      • PNG  — direct LSB encoding, no extra dependencies
      • JPG  — converted to PNG first (requires Pillow: pip install pillow)

    The payload is AES-256-GCM encrypted before embedding, so even if
    someone extracts the LSBs without the key they see only ciphertext.
    Output is always a PNG (regardless of input format).
    """
    ext        = os.path.splitext(cover_path)[1].lower()
    tmp_png    = None
    work_path  = cover_path

    if ext in (".jpg", ".jpeg"):
        work_path, _ = _jpg_to_png(cover_path)
        tmp_png      = work_path

    try:
        raw = open(work_path, "rb").read()
        if raw[:4] != b"\x89PNG":
            raise ValueError(f"Unsupported image format: {ext}. Use PNG or JPG.")

        pixels, w, h, ct = _png_decode(raw)
        full = struct.pack(">I", len(payload)) + payload

        if len(full) * 8 > len(pixels):
            capacity_kb = len(pixels) // (8 * 1024)
            needed_kb   = (len(full) * 8) // (8 * 1024) + 1
            raise ValueError(
                f"Cover image too small.\n"
                f"  Image capacity : ~{capacity_kb} KB of hidden data\n"
                f"  Payload needs  : ~{needed_kb} KB\n"
                f"  Use a larger image."
            )

        px = bytearray(pixels)
        for i, bit in enumerate(_to_bits(full)):
            px[i] = (px[i] & 0xFE) | bit

        return _png_encode(bytes(px), w, h)
    finally:
        if tmp_png and os.path.exists(tmp_png):
            os.unlink(tmp_png)

def steg_extract(png_bytes):
    """Extract hidden payload bytes from a steganographic PNG."""
    pixels, w, h, ct = _png_decode(png_bytes)
    length = 0
    for i in range(32):
        length = (length << 1) | (pixels[i] & 1)
    if length <= 0 or length * 8 + 32 > len(pixels):
        raise ValueError("No steganographic payload found in this image")
    result = bytearray()
    for i in range(length):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | (pixels[32 + i*8 + j] & 1)
        result.append(byte)
    return bytes(result)

def _to_bits(data):
    for byte in data:
        for i in range(7, -1, -1):
            yield (byte >> i) & 1

def _png_decode(png_bytes):
    import zlib
    pos = 8; w = h = ct = 0; idat = b""
    while pos < len(png_bytes):
        length = struct.unpack(">I", png_bytes[pos:pos+4])[0]
        ctype  = png_bytes[pos+4:pos+8]
        cdata  = png_bytes[pos+8:pos+8+length]
        pos   += 12 + length
        if ctype == b"IHDR":
            w, h = struct.unpack(">II", cdata[:8])
            ct   = cdata[8]
            if ct not in (2, 6):
                raise ValueError(
                    "Cover PNG must be RGB or RGBA color mode.\n"
                    "  (Grayscale and indexed PNG are not supported.)\n"
                    "  Convert it: open in any image editor and save as RGB PNG."
                )
        elif ctype == b"IDAT": idat += cdata
        elif ctype == b"IEND": break
    raw    = zlib.decompress(idat)
    stride = w * (4 if ct == 6 else 3) + 1
    pixels = bytearray()
    for row in range(h):
        row_data = raw[row*stride+1 : row*stride+1 + w*(4 if ct==6 else 3)]
        if ct == 6:
            for i in range(w): pixels += row_data[i*4:i*4+3]
        else:
            pixels += row_data
    return bytes(pixels), w, h, ct

def _png_encode(pixels, w, h):
    import zlib
    rows = b""
    for row in range(h):
        rows += b"\x00" + pixels[row*w*3:(row+1)*w*3]
    def chunk(t, d):
        c = t + d
        return struct.pack(">I",len(d)) + c + struct.pack(">I",zlib.crc32(c)&0xFFFFFFFF)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(rows, 6))
        + chunk(b"IEND", b"")
    )

def _make_noise_png(path, min_payload_bytes):
    import zlib
    bits = (min_payload_bytes + 4) * 8
    n    = (bits + 2) // 3
    w    = max(64, int(n**0.5) + 1)
    h    = (n + w - 1) // w
    raw  = os.urandom(w * h * 3)
    rows = b""
    for row in range(h): rows += b"\x00" + raw[row*w*3:(row+1)*w*3]
    def chunk(t, d):
        c = t + d
        return struct.pack(">I",len(d)) + c + struct.pack(">I",zlib.crc32(c)&0xFFFFFFFF)
    open(path,"wb").write(
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(rows, 6))
        + chunk(b"IEND", b"")
    )

# ── Tab completion ────────────────────────────────────────────────────────────

COMMANDS = ["list","myid","send","steg","stegmsg","chat",
            "msg","alias","aliases","history","exit"]

class Completer:
    def __init__(self, client_ref):
        self.client = client_ref
    def complete(self, text, state):
        line  = rl.get_line_buffer()
        parts = line.split()
        peers = list(self.client.peers.keys()) if self.client else []
        al    = list(aliases.keys())
        if len(parts) == 0 or (len(parts) == 1 and not line.endswith(" ")):
            opts = [c for c in COMMANDS if c.startswith(text)]
        elif len(parts) == 1 or (len(parts) == 2 and not line.endswith(" ")):
            opts = [p for p in peers + al if p.startswith(text)]
        else:
            opts = []
        try:    return opts[state]
        except: return None

# ── RelayClient ───────────────────────────────────────────────────────────────

class RelayClient:
    def __init__(self, host, port, name, secret,
                 fingerprint=None, proxy=None,
                 use_steg=False, knock_ports=None, auto_accept=False):
        self.host        = host
        self.port        = port
        self.name        = name
        self.secret      = secret.encode()
        self.fingerprint = fingerprint
        self.proxy       = proxy
        self.use_steg    = use_steg
        self.knock_ports = knock_ports or []
        self.auto_accept = auto_accept

        self.my_id      = None
        self.peers      = {}
        self.reader     = None
        self.writer     = None
        self._task      = None

        self._priv    = X25519PrivateKey.generate()
        self._pub_raw = self._priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

        self._pubkey_raw  = {}
        self._pubkey_wait = defaultdict(list)
        self._key_cache   = {}
        self._xfer_done   = asyncio.Event()
        self._history     = []
        self._chat_peer   = None

        # pending transfer_id -> asyncio.Event for accept/reject
        self._pending_transfers = {}
        # transfer_id -> bool (True=accepted, False=rejected)
        self._transfer_decisions = {}

    # ── Connection ────────────────────────────────────────────────────────────

    async def connect(self):
        if self.knock_ports:
            await send_knock_sequence(self.host, self.knock_ports)

        ctx = build_tls_ctx()
        if self.proxy:
            raw_r, raw_w = await socks5_connect(
                self.proxy.hostname, self.proxy.port, self.host, self.port
            )
            sock = raw_w.transport.get_extra_info("socket")
            self.reader, self.writer = await asyncio.open_connection(
                sock=sock, ssl=ctx, server_hostname=self.host
            )
        else:
            self.reader, self.writer = await asyncio.open_connection(
                self.host, self.port, ssl=ctx
            )

        actual_fp = get_fp(self.writer)
        if self.fingerprint:
            if not hmac.compare_digest(actual_fp, self.fingerprint):
                self.writer.close()
                raise RuntimeError(
                    f"TLS FINGERPRINT MISMATCH\n"
                    f"  Expected : {self.fingerprint}\n"
                    f"  Got      : {actual_fp}\n"
                    f"  Aborting — possible MITM."
                )
            log.info("Cert fingerprint OK ✓")
        else:
            print(f"\n  ⚠  Server fingerprint: {actual_fp}")
            print(f"  ⚠  Pass --fingerprint {actual_fp} next time.\n")

        raw       = await self.reader.readline()
        challenge = json.loads(raw.decode().strip())
        if challenge.get("type") != "challenge":
            raise RuntimeError(f"Bad handshake: {challenge}")

        nonce    = challenge["nonce"]
        ts       = int(time.time())
        hmac_val = hmac.new(self.secret, f"{nonce}{ts}".encode(), hashlib.sha256).hexdigest()
        totp_key = hashlib.sha256(self.secret + b":totp").digest()

        await self._send({
            "type":   "register",
            "name":   self.name,
            "nonce":  nonce,
            "ts":     ts,
            "hmac":   hmac_val,
            "totp":   _totp(totp_key),
            "pubkey": base64.b64encode(self._pub_raw).decode(),
        })

        raw = await self.reader.readline()
        if not raw:
            raise RuntimeError("Auth rejected — wrong secret or banned IP")
        welcome = json.loads(raw.decode().strip())
        if welcome.get("type") != "welcome":
            raise RuntimeError(f"Auth failed: {welcome}")

        self.my_id = welcome["your_id"]
        flags = " ".join(filter(None,[
            "knock"       if self.knock_ports else "",
            "SOCKS5"      if self.proxy       else "",
            "steg"        if self.use_steg    else "",
            "auto-accept" if self.auto_accept else "",
        ]))
        log.info("Connected  id=%s  [%s]", self.my_id, flags or "direct TLS")
        self._task = asyncio.create_task(self._recv_loop())

    async def disconnect(self):
        if self._task: self._task.cancel()
        if self.writer:
            self.writer.close()
            try:    await self.writer.wait_closed()
            except: pass

    async def _send(self, obj):
        self.writer.write((json.dumps(obj) + "\n").encode())
        await self.writer.drain()

    # ── Pubkey / ECDH ─────────────────────────────────────────────────────────

    async def get_pubkey_raw(self, peer_id):
        if peer_id in self._pubkey_raw:
            return self._pubkey_raw[peer_id]
        loop = asyncio.get_event_loop()
        fut  = loop.create_future()
        self._pubkey_wait[peer_id].append(fut)
        await self._send({"type":"get_pubkey","peer_id":peer_id})
        try:    return await asyncio.wait_for(fut, timeout=10)
        except: return None

    async def get_shared_key(self, peer_id):
        if peer_id in self._key_cache:
            return self._key_cache[peer_id]
        raw = await self.get_pubkey_raw(peer_id)
        if raw is None: return None
        shared = self._priv.exchange(X25519PublicKey.from_public_bytes(raw))
        key    = HKDF(algorithm=SHA256(), length=32, salt=None, info=b"e2e-key").derive(shared)
        self._key_cache[peer_id] = key
        return key

    # ── File accept / reject ──────────────────────────────────────────────────

    async def _prompt_accept(self, transfer_id, from_name, filename, size_bytes):
        """
        Show an accept/reject prompt for an incoming file transfer.
        Returns True if accepted, False if rejected.
        If auto_accept is set, always returns True.
        Times out after 30 seconds and auto-rejects.
        """
        if self.auto_accept:
            return True

        size_str = (
            f"{size_bytes/(1024*1024):.1f} MB" if size_bytes > 1024*1024
            else f"{size_bytes//1024} KB" if size_bytes > 1024
            else f"{size_bytes} bytes"
        )

        # Print the prompt — interrupt any current input line cleanly
        print(f"\n  ┌─ Incoming file ────────────────────────────────")
        print(f"  │  From    : {from_name}")
        print(f"  │  File    : {filename}")
        print(f"  │  Size    : {size_str}")
        print(f"  │  Accept? : [y]es / [n]o  (auto-rejects in 30s)")
        print(f"  └────────────────────────────────────────────────")
        print(f"  > ", end="", flush=True)

        loop   = asyncio.get_event_loop()
        event  = asyncio.Event()
        result = {"accepted": False}

        self._pending_transfers[transfer_id] = (event, result)

        try:
            await asyncio.wait_for(event.wait(), timeout=30)
        except asyncio.TimeoutError:
            print(f"\n  ✗ Transfer timed out — auto-rejected")
            result["accepted"] = False

        self._pending_transfers.pop(transfer_id, None)
        return result["accepted"]

    def handle_transfer_response(self, response):
        """
        Called from CLI when user types y/n at a transfer prompt.
        Finds the pending transfer and resolves it.
        """
        if not self._pending_transfers:
            return False   # nothing pending

        # Resolve the most recent pending transfer
        transfer_id, (event, result) = next(iter(self._pending_transfers.items()))
        accepted = response.strip().lower() in ("y", "yes")
        result["accepted"] = accepted
        event.set()
        print(f"  {'✓ Accepted' if accepted else '✗ Rejected'}")
        return True

    # ── Steg send ─────────────────────────────────────────────────────────────

    async def send_steg(self, target_id, cover_path, payload, label="data"):
        if not os.path.isfile(cover_path):
            print(f"  ✗ Cover image not found: {cover_path}")
            return
        if target_id not in self.peers:
            print(f"  ✗ Peer {target_id!r} not connected")
            return
        key = await self.get_shared_key(target_id)
        if key is None:
            print("  ✗ Could not get peer key")
            return

        ext = os.path.splitext(cover_path)[1].lower()
        print(f"  Encrypting {label} ({len(payload)} bytes) ...")
        encrypted = encrypt_payload(payload, key)

        print(f"  Embedding into {os.path.basename(cover_path)} "
              f"({'JPG→PNG' if ext in ('.jpg','.jpeg') else 'PNG'}) ...")
        try:
            steg_png = steg_embed(cover_path, encrypted)
        except ValueError as e:
            print(f"  ✗ {e}")
            return

        aesgcm = AESGCM(key)
        fn_n   = os.urandom(12)
        fn_b64 = base64.b64encode(
            fn_n + aesgcm.encrypt(fn_n, os.path.basename(cover_path).encode(), None)
        ).decode()

        steg_type = "msg" if label == "message" else "file"
        xfer_id   = os.urandom(8).hex()

        await self._send({
            "type":         "send_file",
            "to":           target_id,
            "filename_enc": fn_b64,
            "size":         len(steg_png),
            "hash":         hashlib.sha256(steg_png).hexdigest(),
            "steg":         True,
            "steg_type":    steg_type,
            "transfer_id":  xfer_id,
            "display_name": os.path.basename(cover_path),
        })
        self.writer.write(steg_png)
        await self.writer.drain()

        self._xfer_done.clear()
        try:    await asyncio.wait_for(self._xfer_done.wait(), timeout=120)
        except: log.warning("No ack within 120s")

    # ── Normal file send ──────────────────────────────────────────────────────

    async def send_file(self, target_id, path):
        tmp = None
        if os.path.isdir(path):
            tmp = tempfile.mktemp(suffix=".zip")
            print(f"  Compressing {path} ...")
            with zipfile.ZipFile(tmp,"w",zipfile.ZIP_DEFLATED) as z:
                for root,_,files in os.walk(path):
                    for fn in files:
                        fp = os.path.join(root,fn)
                        z.write(fp, os.path.relpath(fp, os.path.dirname(path)))
            path = tmp

        if not os.path.isfile(path):
            print(f"  ✗ Not found: {path}")
            if tmp: os.unlink(tmp)
            return
        if target_id not in self.peers:
            print(f"  ✗ {target_id!r} not connected — run 'list'")
            if tmp: os.unlink(tmp)
            return

        key = await self.get_shared_key(target_id)
        if key is None:
            print("  ✗ No peer key")
            if tmp: os.unlink(tmp)
            return

        fname  = os.path.basename(path)
        fsize  = os.path.getsize(path)
        fhash  = sha256_file(path)
        aesgcm = AESGCM(key)
        fn_n   = os.urandom(12)
        fn_b64 = base64.b64encode(
            fn_n + aesgcm.encrypt(fn_n, fname.encode(), None)
        ).decode()

        if self.use_steg:
            tmp_cover = tempfile.mktemp(suffix=".png")
            _make_noise_png(tmp_cover, compute_encrypted_size(fsize))
            await self.send_steg(target_id, tmp_cover, open(path,"rb").read(), label=fname)
            os.unlink(tmp_cover)
            if tmp: os.unlink(tmp)
            return

        enc_size = compute_encrypted_size(fsize)
        xfer_id  = os.urandom(8).hex()

        await self._send({
            "type":         "send_file",
            "to":           target_id,
            "filename_enc": fn_b64,
            "size":         enc_size,
            "hash":         fhash,
            "steg":         False,
            "transfer_id":  xfer_id,
            "display_name": fname,
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
                nonce = os.urandom(12)
                ct    = xfer_gcm.encrypt(nonce, chunk, None)
                frame = nonce + ct
                self.writer.write(struct.pack("<I",len(frame)) + frame)
                sent += len(chunk)
                if fsize > 0:
                    print(f"\r  Uploading {fname} ... {sent*100//fsize}%  ",
                          end="", flush=True)

        await self.writer.drain()
        print()

        self._xfer_done.clear()
        try:    await asyncio.wait_for(self._xfer_done.wait(), timeout=180)
        except: log.warning("No ack within 180s")
        if tmp: os.unlink(tmp)

    # ── Chat ──────────────────────────────────────────────────────────────────

    async def send_message(self, target_id, text):
        if target_id not in self.peers:
            print(f"  ✗ {target_id!r} not connected")
            return
        key = await self.get_shared_key(target_id)
        if key is None: return
        nonce = os.urandom(12)
        ct    = AESGCM(key).encrypt(nonce, text.encode(), None)
        await self._send({
            "type":    "msg",
            "to":      target_id,
            "payload": base64.b64encode(ct).decode(),
            "nonce":   base64.b64encode(nonce).decode(),
        })

    # ── Receive loop ──────────────────────────────────────────────────────────

    async def _recv_loop(self):
        try:
            while True:
                raw = await self.reader.readline()
                if not raw:
                    log.warning("Relay closed connection")
                    break
                try:    msg = json.loads(raw.decode().strip())
                except: continue

                t = msg.get("type")

                if t == "peer_list":
                    self.peers = {p["id"]:p["name"] for p in msg["peers"]}
                    for pid in self.peers:
                        if pid not in self._pubkey_raw:
                            asyncio.create_task(self._prefetch_pubkey(pid))

                elif t == "pubkey_response":
                    pid = msg["peer_id"]
                    rb  = base64.b64decode(msg["pubkey"])
                    self._pubkey_raw[pid] = rb
                    for fut in self._pubkey_wait.pop(pid,[]):
                        if not fut.done(): fut.set_result(rb)

                elif t == "incoming_file":
                    asyncio.create_task(self._receive_file(msg))

                elif t == "msg":
                    await self._receive_message(msg)

                elif t == "send_ok":
                    size = msg.get("size",0)
                    print(f"\n  ✓ Delivered  ({size} bytes)")
                    self._history.append({"dir":"sent","ts":time.time(),"size":size})
                    self._xfer_done.set()

                elif t == "error":
                    print(f"\n  ✗ Relay: {msg.get('msg','')}")
                    self._xfer_done.set()

                elif t in ("pong","file_done","welcome"):
                    pass

        except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
            log.warning("Connection lost")
        except asyncio.CancelledError:
            pass
        except Exception as e:
            log.exception("Recv: %s", e)

    async def _prefetch_pubkey(self, pid):
        await self.get_pubkey_raw(pid)

    async def _receive_file(self, meta):
        from_id   = meta["from_id"]
        from_name = meta["from_name"]
        size      = int(meta["size"])
        fhash     = meta.get("hash","")
        fn_b64    = meta.get("filename_enc","")
        is_steg   = meta.get("steg", False)
        steg_type = meta.get("steg_type","file")
        xfer_id   = meta.get("transfer_id", os.urandom(8).hex())
        disp_name = meta.get("display_name","file")

        key = await self.get_shared_key(from_id)
        if key is None:
            # drain bytes so connection stays in sync
            rem = size
            while rem > 0:
                c = await self.reader.read(min(CHUNK,rem))
                if not c: break
                rem -= len(c)
            return

        aesgcm = AESGCM(key)

        # Decrypt filename
        try:
            fn_raw   = base64.b64decode(fn_b64)
            filename = aesgcm.decrypt(fn_raw[:12], fn_raw[12:], None).decode()
            filename = os.path.basename(filename)
        except Exception:
            filename = f"received_{int(time.time())}" + (".png" if is_steg else "")

        # ── ACCEPT / REJECT prompt ────────────────────────────────────────────
        accepted = await self._prompt_accept(
            xfer_id, from_name,
            f"{filename} (hidden in {disp_name})" if is_steg else filename,
            size
        )

        if not accepted:
            # Drain the bytes from the stream so connection stays in sync
            log.info("Transfer rejected — draining %d bytes", size)
            rem = size
            while rem > 0:
                c = await self.reader.read(min(CHUNK, rem))
                if not c: break
                rem -= len(c)
            print(f"  ✗ Transfer from {from_name} rejected")
            # Notify sender via relay that transfer was rejected
            await self._send({
                "type": "msg",
                "to":   from_id,
                "payload": base64.b64encode(
                    AESGCM(key).encrypt(
                        os.urandom(12),
                        f"[SYSTEM] {self.name} rejected your file transfer: {filename}".encode(),
                        None
                    )
                ).decode(),
                "nonce": base64.b64encode(os.urandom(12)).decode(),
            })
            return

        print(f"\n  ↓ {'[STEG] ' if is_steg else ''}Receiving: {filename}  "
              f"from {from_name} [{from_id}]")

        # Unique save path
        save = filename
        b_, e_ = os.path.splitext(filename)
        n = 1
        while os.path.exists(save):
            save = f"{b_}_{n}{e_}"
            n += 1

        if is_steg:
            data = b""
            rem  = size
            while rem > 0:
                c = await self.reader.read(min(CHUNK,rem))
                if not c: break
                data += c; rem -= len(c)
                print(f"\r  Receiving ... {len(data)} bytes  ", end="", flush=True)
            print()

            if fhash and not hmac.compare_digest(
                hashlib.sha256(data).hexdigest(), fhash
            ):
                print("  ⚠  Image hash mismatch")

            try:
                enc_data = steg_extract(data)
                payload  = decrypt_payload(enc_data, key)
            except Exception as e:
                print(f"  ✗ Extract/decrypt failed: {e}")
                open(save,"wb").write(data)
                return

            if steg_type == "msg":
                ts = time.strftime("%H:%M:%S")
                print(f"  ✓ Hidden message from {from_name}:")
                print(f"  [{ts}] {from_name}: {payload.decode('utf-8', errors='replace')}")
            else:
                open(save,"wb").write(payload)
                print(f"  ✓ Hidden file → {save}  ({len(payload)} bytes)")
                if save.endswith(".zip"):
                    out = save[:-4]
                    try:
                        with zipfile.ZipFile(save) as z: z.extractall(out)
                        print(f"  ✓ Extracted → {out}/")
                    except: pass

            self._history.append({
                "dir":"received","ts":time.time(),
                "filename":save,"size":len(payload),"from":from_name
            })

        else:
            try:
                salt = await self.reader.readexactly(32)
            except asyncio.IncompleteReadError:
                print("  ✗ Interrupted (salt)")
                return

            xfer_key  = HKDF(algorithm=SHA256(), length=32, salt=salt, info=b"xfer").derive(key)
            xfer_gcm  = AESGCM(xfer_key)
            remaining = size - 32
            received  = 0

            try:
                with open(save,"wb") as f:
                    while remaining > 0:
                        if remaining < 4: break
                        flen = struct.unpack("<I", await self.reader.readexactly(4))[0]
                        remaining -= 4
                        flen  = min(flen, remaining)
                        frame = await self.reader.readexactly(flen)
                        remaining -= flen
                        try:
                            plain = xfer_gcm.decrypt(frame[:12], frame[12:], None)
                        except Exception as e:
                            print(f"\n  ✗ Chunk decrypt: {e}"); return
                        f.write(plain)
                        received += len(plain)
                        print(f"\r  Receiving {filename} ... {received} bytes  ",
                              end="", flush=True)
            except asyncio.IncompleteReadError:
                print(f"\n  ✗ Cut at {received} bytes"); return

            print()
            if fhash:
                ok = hmac.compare_digest(sha256_file(save), fhash)
                print(f"  ✓ Saved → {save}  "
                      f"[{'SHA-256 OK ✓' if ok else 'HASH MISMATCH ⚠'}]")
            else:
                print(f"  ✓ Saved → {save}")

            self._history.append({
                "dir":"received","ts":time.time(),
                "filename":save,"size":received,"from":from_name
            })

            if save.endswith(".zip"):
                out = save[:-4]
                try:
                    with zipfile.ZipFile(save) as z: z.extractall(out)
                    print(f"  ✓ Extracted → {out}/")
                except: pass

    async def _receive_message(self, msg):
        from_id = msg["from_id"]; from_name = msg["from_name"]
        try:
            pl = base64.b64decode(msg.get("payload",""))
            n  = base64.b64decode(msg.get("nonce",""))
        except Exception:
            print(f"\n  ✗ Malformed from {from_name}"); return
        key = await self.get_shared_key(from_id)
        if key is None: return
        try:
            text = AESGCM(key).decrypt(n, pl, None).decode()
            ts   = time.strftime("%H:%M:%S")
            if self._chat_peer == from_id:
                print(f"\r  [{ts}] {from_name}: {text}")
                print(f"  you: ", end="", flush=True)
            else:
                print(f"\n  [{ts}] {from_name} [{from_id}]: {text}\n> ",
                      end="", flush=True)
        except Exception as e:
            print(f"\n  ✗ Decrypt from {from_name}: {e}")

# ── CLI ───────────────────────────────────────────────────────────────────────

async def cli_loop(client: RelayClient):
    loop = asyncio.get_event_loop()
    comp = Completer(client)
    rl.set_completer(comp.complete)
    rl.set_completer_delims(" \t")
    rl.parse_and_bind("tab: complete")

    def readline(p=""):
        try:    return input(p)
        except: return None

    print()
    print("  list | myid | send <id> <path> | steg <id> <img> <file>")
    print("  stegmsg <id> <img> <text> | chat <id> | msg <id> <text>")
    print("  alias <n> <id> | aliases | history | exit")
    if client.use_steg:    print("  [--steg ON: all transfers hidden in PNG]")
    if client.auto_accept: print("  [--auto-accept ON: all incoming files auto-accepted]")
    print()

    while True:
        line = await loop.run_in_executor(None, readline, "> ")
        if line is None: break

        # ── Handle y/n for pending transfer prompts ───────────────────────────
        stripped = line.strip().lower()
        if stripped in ("y","yes","n","no") and client._pending_transfers:
            client.handle_transfer_response(stripped)
            continue

        parts = line.strip().split(None, 3)
        if not parts: continue
        cmd = parts[0].lower()

        if cmd == "exit": break

        elif cmd == "myid":
            print(f"  {client.my_id}")

        elif cmd == "list":
            await client._send({"type":"list"})
            await asyncio.sleep(0.3)
            if client.peers:
                id2al = {v:k for k,v in aliases.items()}
                print(f"  {'ID':<12}  {'Alias':<14}  Name")
                print(f"  {'─'*10}  {'─'*12}  {'─'*20}")
                for pid, pname in client.peers.items():
                    print(f"  {pid:<12}  {id2al.get(pid,''):<14}  {pname}")
            else:
                print("  (no peers online)")

        elif cmd == "send":
            if len(parts) < 3:
                print("  Usage: send <id/alias> <path>")
                continue
            await client.send_file(resolve(parts[1]), parts[2])

        elif cmd == "steg":
            if len(parts) < 4:
                print("  Usage: steg <id/alias> <cover.png or cover.jpg> <file>")
                continue
            if not os.path.isfile(parts[3]):
                print(f"  ✗ File not found: {parts[3]}")
                continue
            payload = open(parts[3],"rb").read()
            await client.send_steg(
                resolve(parts[1]), parts[2],
                payload, label=os.path.basename(parts[3])
            )

        elif cmd == "stegmsg":
            if len(parts) < 4:
                print("  Usage: stegmsg <id/alias> <cover.png or cover.jpg> <message>")
                continue
            await client.send_steg(
                resolve(parts[1]), parts[2],
                parts[3].encode(), label="message"
            )

        elif cmd == "msg":
            if len(parts) < 3:
                print("  Usage: msg <id/alias> <text>")
                continue
            await client.send_message(resolve(parts[1]), " ".join(parts[2:]))

        elif cmd == "chat":
            if len(parts) < 2:
                print("  Usage: chat <id/alias>")
                continue
            pid   = resolve(parts[1])
            pname = client.peers.get(pid, pid)
            if pid not in client.peers:
                print(f"  ✗ {pid!r} not online")
                continue
            print(f"\n  ── Chat with {pname} [{pid}] ──  (Ctrl+C exits)\n")
            client._chat_peer = pid
            try:
                while True:
                    text = await loop.run_in_executor(None, readline, "  you: ")
                    if text is None: break
                    text = text.strip()
                    if text: await client.send_message(pid, text)
            except (KeyboardInterrupt, asyncio.CancelledError): pass
            finally:
                client._chat_peer = None
                print(f"\n  ── Exited chat ──\n")

        elif cmd == "alias":
            if len(parts) < 3:
                print("  Usage: alias <n> <peer_id>")
                continue
            aliases[parts[1]] = parts[2]
            save_aliases(aliases)
            print(f"  Saved: {parts[1]} → {parts[2]}")

        elif cmd == "aliases":
            if aliases:
                print(f"  {'Alias':<14}  Peer ID")
                for n, pid in aliases.items():
                    print(f"  {n:<14}  {pid}")
            else:
                print("  (none — use: alias <n> <peer_id>)")

        elif cmd == "history":
            if not client._history:
                print("  (no transfers yet)")
            for h in client._history[-20:]:
                ts = time.strftime("%H:%M:%S", time.localtime(h["ts"]))
                d  = h["dir"].upper()
                if d == "SENT":
                    print(f"  {ts}  {d:<8}  {h.get('size',0):>12} bytes")
                else:
                    print(f"  {ts}  {d:<8}  {h.get('size',0):>12} bytes  "
                          f"{h.get('filename','')}  ← {h.get('from','')}")
        else:
            print(f"  Unknown: {cmd!r}")

# ── Auto-reconnect ────────────────────────────────────────────────────────────

async def run(args):
    proxy = None
    if args.proxy:
        proxy = urlparse(args.proxy)
    elif args.tor:
        proxy = urlparse(f"socks5://127.0.0.1:{TOR_PORT}")

    knock_ports = []
    if args.knock_ports:
        knock_ports = list(map(int, args.knock_ports.split(",")))

    delay = 3
    while True:
        client = RelayClient(
            host=args.relay, port=args.port,
            name=args.name,  secret=args.secret,
            fingerprint=args.fingerprint or None,
            proxy=proxy, use_steg=args.steg,
            knock_ports=knock_ports,
            auto_accept=args.auto_accept,
        )
        try:
            await client.connect()
            delay = 3
            await cli_loop(client)
            break
        except ConnectionRefusedError:
            print(f"  Cannot reach {args.relay}:{args.port} — retry in {delay}s ...")
            await asyncio.sleep(delay)
            delay = min(delay * 2, 60)
        except RuntimeError as e:
            print(f"  Fatal: {e}")
            break
        except Exception as e:
            log.warning("Lost connection (%s) — retry in %ds ...", e, delay)
            await asyncio.sleep(delay)
            delay = min(delay * 2, 60)
        finally:
            await client.disconnect()

# ── Entry ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Secure E2E tunnel client")
    ap.add_argument("--relay",       required=True)
    ap.add_argument("--secret",      required=True)
    ap.add_argument("--name",        default="peer")
    ap.add_argument("--port",        default=4001, type=int)
    ap.add_argument("--fingerprint", default="")
    ap.add_argument("--knock-ports", default="")
    ap.add_argument("--tor",         action="store_true")
    ap.add_argument("--proxy",       default="")
    ap.add_argument("--steg",        action="store_true")
    ap.add_argument("--auto-accept", action="store_true",
                    help="Auto-accept all incoming file transfers without prompting")
    args = ap.parse_args()

    tor_managed = False
    if args.tor:
        try:
            start_tor()
            tor_managed = True
        except Exception as e:
            print(f"  Tor startup failed: {e}")
            print("  Continuing without Tor.")
            args.tor = False

    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        print("\n  Disconnected")
    finally:
        if tor_managed: stop_tor()
        sys.exit(0)
