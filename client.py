#!/usr/bin/env python3
"""
client.py — Secure E2E tunnel client
  pip install cryptography pillow
  python3 client.py --relay <ip> --secret <key> --name <you> [options]

Steganography (Pillow LSB):
  Any image format (JPG, PNG, BMP, TIFF, WebP) accepted as cover.
  The payload is AES-256-GCM encrypted with the shared E2E key before
  embedding — without the key, extracted LSBs are indistinguishable
  from noise. Output is always PNG (lossless) so embedded bits survive.

How to use steg:
  SENDER (TUI):
    1. Go to the Steg tab (F4)
    2. Enter the cover image path (any JPG or PNG you own)
    3. Choose "Hide a file" or "Hide a text message"
    4. Enter the file path or message text
    5. Click "Embed & Send" — the hidden data goes to the selected peer

  RECEIVER (TUI):
    1. A popup appears: "Incoming Transfer" — click Accept
    2. The steg PNG is downloaded automatically
    3. The hidden content is extracted + decrypted
    4. For a hidden FILE: saved to disk, path shown in the Files tab log
    5. For a hidden MESSAGE: shown directly in the Files tab log

  ENCODING (what happens internally):
    payload → AES-256-GCM encrypt → embed in cover image LSBs → send as PNG

  DECODING (what happens internally):
    receive PNG → extract LSBs → AES-256-GCM decrypt → save hidden file / show message
"""

import asyncio, json, os, sys, argparse, logging, base64, zipfile
import struct, hmac, hashlib, ssl, time, tempfile, random, subprocess
import shutil, platform, urllib.request, io
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
    log.info("Tor not found — installing …")
    if SYSTEM == "linux":
        for mgr, cmd in [
            ("apt-get", ["sudo","apt-get","install","-y","tor"]),
            ("dnf",     ["sudo","dnf","install","-y","tor"]),
            ("pacman",  ["sudo","pacman","-Sy","--noconfirm","tor"]),
            ("apk",     ["sudo","apk","add","tor"]),
        ]:
            if shutil.which(mgr): subprocess.run(cmd, check=True); return
        raise RuntimeError("No package manager found. Install tor manually.")
    elif SYSTEM == "darwin":
        if shutil.which("brew"): subprocess.run(["brew","install","tor"], check=True)
        else: raise RuntimeError("Run: brew install tor")
    elif SYSTEM == "windows":
        import tarfile
        os.makedirs(TOR_DIR, exist_ok=True)
        archive = os.path.join(TOR_DIR, "tor.tar.gz")
        urllib.request.urlretrieve(TOR_WIN_URL, archive,
            reporthook=lambda b,bs,ts: print(f"\r  Downloading … {min(100,int(b*bs*100/(ts or 1)))}%", end="", flush=True))
        print()
        with tarfile.open(archive,"r:gz") as tar: tar.extractall(TOR_DIR)
        for root,_,files in os.walk(TOR_DIR):
            for f in files:
                if f.lower()=="tor.exe":
                    dest=os.path.join(TOR_DIR,"bin"); os.makedirs(dest,exist_ok=True)
                    shutil.copy2(os.path.join(root,f),os.path.join(dest,"tor.exe")); return
        raise RuntimeError("tor.exe not found in archive")
    else:
        raise RuntimeError(f"Unsupported OS: {SYSTEM}")

def start_tor():
    global _tor_process
    if not _tor_binary(): _install_tor()
    os.makedirs(TOR_DIR, exist_ok=True)
    torrc = os.path.join(TOR_DIR, "torrc")
    open(torrc,"w").write(
        f"SocksPort 127.0.0.1:{TOR_PORT}\n"
        f"DataDirectory {TOR_DIR}\n"
        "Log notice stderr\nControlPort 0\n"
    )
    log.info("Starting Tor on 127.0.0.1:%d …", TOR_PORT)
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
            time.sleep(0.1); continue
        if "100%" in line or "Bootstrapped 100" in line:
            log.info("Tor ready on 127.0.0.1:%d", TOR_PORT); return
    raise RuntimeError("Tor did not bootstrap within 60s")

def stop_tor():
    global _tor_process
    if _tor_process and _tor_process.poll() is None:
        log.info("Stopping Tor …")
        _tor_process.terminate()
        try:    _tor_process.wait(timeout=5)
        except: _tor_process.kill()
        _tor_process = None

# ── Port knocking ─────────────────────────────────────────────────────────────

async def send_knock_sequence(host, ports):
    log.info("Knocking %s  →  %s", host, " → ".join(map(str, ports)))
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
        codes = {1:"general failure",2:"not allowed",3:"net unreachable",
                 4:"host unreachable",5:"connection refused"}
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
    "ECDHE-ECDSA-AES256-GCM-SHA384","ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-RSA-CHACHA20-POLY1305","DHE-RSA-AES256-GCM-SHA384",
]

def build_tls_ctx():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    try:    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    except: pass
    ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    shuffled = _CIPHERS[:]; random.shuffle(shuffled)
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

# ── Crypto ────────────────────────────────────────────────────────────────────

def sha256_file(path):
    h = hashlib.sha256()
    with open(path,"rb") as f:
        for block in iter(lambda: f.read(65536), b""): h.update(block)
    return h.hexdigest()

def compute_encrypted_size(file_size):
    n = max(1, (file_size + CHUNK - 1) // CHUNK)
    return 32 + n * (4 + 12 + 16) + file_size

def encrypt_payload(data: bytes, key: bytes) -> bytes:
    """AES-256-GCM encrypt. Returns: 12-byte nonce + ciphertext+tag."""
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, data, None)

def decrypt_payload(data: bytes, key: bytes) -> bytes:
    """Decrypt output of encrypt_payload."""
    return AESGCM(key).decrypt(data[:12], data[12:], None)

# ── Steganography — Pillow LSB ────────────────────────────────────────────────

def _check_pillow():
    try:
        import PIL
    except ImportError:
        raise RuntimeError(
            "Pillow is required for steganography.\n"
            "Install:  pip install pillow\n"
            "(Only needed for the Steg feature.)"
        )


def steg_embed(cover_path: str, encrypted_payload: bytes) -> bytes:
    """
    Embed an already-encrypted payload into a cover image using Pillow LSB.

    Accepts any image format Pillow can open (JPG, PNG, BMP, TIFF, WebP …).
    Opens the image, converts to RGB, modifies the LSB of each channel.
    Output is always PNG (lossless) so the embedded bits survive.

    Only 1 bit per channel is changed — visually imperceptible (±1 out of 255).
    The payload is already AES-256-GCM encrypted by the caller — without the
    shared key, the embedded data looks like random noise.
    """
    _check_pillow()
    from PIL import Image

    try:
        img = Image.open(cover_path).convert("RGB")
    except Exception as e:
        raise RuntimeError(
            f"Cannot open cover image: {os.path.basename(cover_path)}\n"
            f"  Error: {e}\n"
            f"  Supported: JPG, PNG, BMP, TIFF, WebP and most other formats."
        )

    width, height  = img.size
    pixels         = list(img.getdata())
    total_channels = len(pixels) * 3

    # Layout in image: 4-byte big-endian length header + payload bytes
    full        = struct.pack(">I", len(encrypted_payload)) + encrypted_payload
    bits_needed = len(full) * 8

    if bits_needed > total_channels:
        cap_kb  = total_channels // (8 * 1024)
        need_kb = bits_needed   // (8 * 1024) + 1
        raise RuntimeError(
            f"Cover image too small.\n"
            f"  Image capacity : {width}×{height} px  →  ~{cap_kb} KB\n"
            f"  Payload needs  : ~{need_kb} KB\n"
            f"  Use a larger or higher-resolution image."
        )

    flat = []
    for r, g, b in pixels:
        flat.append(r); flat.append(g); flat.append(b)

    bit_idx = 0
    for byte in full:
        for shift in range(7, -1, -1):
            flat[bit_idx] = (flat[bit_idx] & 0xFE) | ((byte >> shift) & 1)
            bit_idx += 1

    new_pixels = [(flat[i], flat[i+1], flat[i+2]) for i in range(0, len(flat), 3)]
    out = Image.new("RGB", (width, height))
    out.putdata(new_pixels)

    buf = io.BytesIO()
    out.save(buf, format="PNG", optimize=False)
    return buf.getvalue()


def steg_extract(png_bytes: bytes) -> bytes:
    """
    Extract encrypted payload from a stego PNG produced by steg_embed.
    Returns raw encrypted bytes — caller decrypts with decrypt_payload().
    """
    _check_pillow()
    from PIL import Image

    try:
        img = Image.open(io.BytesIO(png_bytes)).convert("RGB")
    except Exception as e:
        raise RuntimeError(f"Cannot decode received stego image: {e}")

    pixels = list(img.getdata())
    flat   = []
    for r, g, b in pixels:
        flat.append(r); flat.append(g); flat.append(b)

    length = 0
    for i in range(32):
        length = (length << 1) | (flat[i] & 1)

    if length <= 0:
        raise RuntimeError("No steganographic payload found in this image.")

    if length * 8 + 32 > len(flat):
        raise RuntimeError(
            f"Payload length ({length} B) exceeds image capacity.\n"
            "The image may be corrupt or was not encoded with this tool."
        )

    result = bytearray()
    for byte_idx in range(length):
        byte = 0
        for bit_pos in range(8):
            byte = (byte << 1) | (flat[32 + byte_idx * 8 + bit_pos] & 1)
        result.append(byte)

    return bytes(result)


def _make_noise_png(path: str, min_payload_bytes: int):
    """Generate a random-pixel PNG large enough to hold min_payload_bytes."""
    _check_pillow()
    from PIL import Image
    bits  = (min_payload_bytes + 4) * 8
    n_px  = (bits + 2) // 3
    side  = max(64, int(n_px ** 0.5) + 1)
    w, h  = side, (n_px + side - 1) // side + 1
    raw   = [(random.randint(0,255), random.randint(0,255), random.randint(0,255))
             for _ in range(w * h)]
    img = Image.new("RGB", (w, h))
    img.putdata(raw)
    img.save(path, format="PNG")

# ── Tab completion ────────────────────────────────────────────────────────────

COMMANDS = ["list","myid","send","steg","stegmsg","chat","msg","alias","aliases","history","exit"]

class Completer:
    def __init__(self, c): self.client = c
    def complete(self, text, state):
        line  = rl.get_line_buffer(); parts = line.split()
        peers = list(self.client.peers.keys()) if self.client else []
        al    = list(aliases.keys())
        if len(parts) == 0 or (len(parts) == 1 and not line.endswith(" ")):
            opts = [c for c in COMMANDS if c.startswith(text)]
        elif len(parts) == 1 or (len(parts) == 2 and not line.endswith(" ")):
            opts = [p for p in peers + al if p.startswith(text)]
        else: opts = []
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

        self.my_id = None; self.peers = {}
        self.reader = None; self.writer = None; self._task = None

        self._priv    = X25519PrivateKey.generate()
        self._pub_raw = self._priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

        self._pubkey_raw  = {}; self._pubkey_wait = defaultdict(list)
        self._key_cache   = {}; self._xfer_done   = asyncio.Event()
        self._history     = []; self._chat_peer   = None

        # Optional callbacks set by the TUI so it can show status without print()
        # _on_steg_received(saved_path, size_bytes, from_name, steg_type)
        self._on_steg_received = None
        # _on_xfer_status(message_str, is_error)
        self._on_xfer_status   = None

    def _xfer_log(self, msg: str, err: bool = False):
        """Write a status line — goes to TUI callback if set, else print()."""
        if self._on_xfer_status:
            self._on_xfer_status(msg, err)
        else:
            print(msg)

    # ── connection ────────────────────────────────────────────

    async def connect(self):
        if self.knock_ports: await send_knock_sequence(self.host, self.knock_ports)
        ctx = build_tls_ctx()
        if self.proxy:
            raw_r, raw_w = await socks5_connect(
                self.proxy.hostname, self.proxy.port, self.host, self.port)
            sock = raw_w.transport.get_extra_info("socket")
            self.reader, self.writer = await asyncio.open_connection(
                sock=sock, ssl=ctx, server_hostname=self.host)
        else:
            self.reader, self.writer = await asyncio.open_connection(
                self.host, self.port, ssl=ctx)

        actual_fp = get_fp(self.writer)
        if self.fingerprint:
            if not hmac.compare_digest(actual_fp, self.fingerprint):
                self.writer.close()
                raise RuntimeError(
                    f"TLS FINGERPRINT MISMATCH\n"
                    f"  Expected : {self.fingerprint}\n"
                    f"  Got      : {actual_fp}")
            log.info("Cert fingerprint OK ✓")
        else:
            print(f"\n  ⚠  Server fingerprint: {actual_fp}\n")

        raw       = await self.reader.readline()
        challenge = json.loads(raw.decode().strip())
        if challenge.get("type") != "challenge":
            raise RuntimeError(f"Bad handshake: {challenge}")

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
        if welcome.get("type") != "welcome":
            raise RuntimeError(f"Auth failed: {welcome}")

        self.my_id = welcome["your_id"]
        log.info("Connected  id=%s", self.my_id)
        self._task = asyncio.create_task(self._recv_loop())

    async def disconnect(self):
        if self._task: self._task.cancel()
        if self.writer:
            self.writer.close()
            try: await self.writer.wait_closed()
            except: pass

    async def _send(self, obj):
        self.writer.write((json.dumps(obj) + "\n").encode())
        await self.writer.drain()

    # ── pubkey / ECDH ─────────────────────────────────────────

    async def get_pubkey_raw(self, peer_id):
        if peer_id in self._pubkey_raw: return self._pubkey_raw[peer_id]
        loop = asyncio.get_event_loop()
        fut  = loop.create_future()
        self._pubkey_wait[peer_id].append(fut)
        await self._send({"type":"get_pubkey","peer_id":peer_id})
        try:    return await asyncio.wait_for(fut, timeout=10)
        except: return None

    async def get_shared_key(self, peer_id):
        if peer_id in self._key_cache: return self._key_cache[peer_id]
        raw = await self.get_pubkey_raw(peer_id)
        if raw is None: return None
        shared = self._priv.exchange(X25519PublicKey.from_public_bytes(raw))
        key    = HKDF(algorithm=SHA256(), length=32, salt=None, info=b"e2e-key").derive(shared)
        self._key_cache[peer_id] = key
        return key

    # ── accept / reject ───────────────────────────────────────

    async def _prompt_accept(self, transfer_id, from_name, filename, size_bytes):
        """Default terminal prompt. Replaced by tui.py with a modal."""
        if self.auto_accept: return True
        size_str = (
            f"{size_bytes/(1024*1024):.1f} MB" if size_bytes > 1_048_576
            else f"{size_bytes//1024} KB"       if size_bytes > 1024
            else f"{size_bytes} bytes"
        )
        print(f"\n  ┌─ Incoming file ─────────────────────────────────")
        print(f"  │  From : {from_name}")
        print(f"  │  File : {filename}")
        print(f"  │  Size : {size_str}")
        print(f"  │  [y]es / [n]o   (auto-rejects in 30 s)")
        print(f"  └────────────────────────────────────────────────")
        loop   = asyncio.get_event_loop()
        event  = asyncio.Event()
        result = {"accepted": False}
        self._pending = (event, result)
        try:    await asyncio.wait_for(event.wait(), timeout=30)
        except: print("  ✗ Auto-rejected"); result["accepted"] = False
        return result["accepted"]

    # ── steg send ─────────────────────────────────────────────

    async def send_steg(self, target_id: str, cover_path: str,
                        payload: bytes, label: str = "data"):
        """
        Encrypt payload, embed into cover image, send to target.

        The metadata sent to the relay includes TWO encrypted filenames:
          filename_enc    = cover image name (what the stego PNG is called)
          hidden_name_enc = actual hidden content name (the file/label)

        BUG FIX: previously only the cover name was sent, so the receiver
        saved the extracted file with the wrong name (e.g. "photo.jpg"
        instead of "document.pdf"). Now hidden_name_enc carries the real name.
        """
        if not os.path.isfile(cover_path):
            raise RuntimeError(f"Cover image not found: {cover_path}")
        if target_id not in self.peers:
            raise RuntimeError(f"Peer {target_id!r} not connected")

        key = await self.get_shared_key(target_id)
        if key is None:
            raise RuntimeError("Could not retrieve peer public key")

        # Step 1: encrypt the payload
        encrypted = encrypt_payload(payload, key)

        # Step 2: embed into cover image
        steg_png = steg_embed(cover_path, encrypted)

        aesgcm = AESGCM(key)

        # Step 3: encrypt the cover filename (relay never sees real filenames)
        fn_n   = os.urandom(12)
        fn_b64 = base64.b64encode(
            fn_n + aesgcm.encrypt(fn_n, os.path.basename(cover_path).encode(), None)
        ).decode()

        # Step 4: encrypt the hidden content's name so receiver knows what to call it
        # For "steg file.pdf photo.jpg" the hidden name is "file.pdf"
        # For "stegmsg"                 the hidden name is "message" (no file to save)
        hn_n   = os.urandom(12)
        hn_b64 = base64.b64encode(
            hn_n + aesgcm.encrypt(hn_n, label.encode(), None)
        ).decode()

        steg_type = "msg" if label == "message" else "file"

        log.info("Steg send: %d B payload → %d B PNG → %s (type=%s)",
                 len(payload), len(steg_png), target_id, steg_type)

        await self._send({
            "type":             "send_file",
            "to":               target_id,
            "filename_enc":     fn_b64,       # cover image name (for display)
            "hidden_name_enc":  hn_b64,       # actual hidden file/label name ← NEW
            "size":             len(steg_png),
            "hash":             hashlib.sha256(steg_png).hexdigest(),
            "steg":             True,
            "steg_type":        steg_type,
            "transfer_id":      os.urandom(8).hex(),
            "display_name":     os.path.basename(cover_path),
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

        if self.use_steg:
            tmp_cover = tempfile.mktemp(suffix=".png")
            _make_noise_png(tmp_cover, compute_encrypted_size(fsize))
            try:    await self.send_steg(target_id, tmp_cover, open(path,"rb").read(), label=fname)
            finally: os.unlink(tmp_cover)
            if tmp: os.unlink(tmp); return

        enc_size = compute_encrypted_size(fsize)
        await self._send({
            "type":"send_file","to":target_id,"filename_enc":fn_b64,
            "hidden_name_enc":"","size":enc_size,"hash":fhash,"steg":False,
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
                    asyncio.create_task(self._receive_file(msg))
                elif t == "msg":
                    await self._receive_message(msg)
                elif t == "send_ok":
                    self._history.append({"dir":"sent","ts":time.time(),"size":msg.get("size",0)})
                    self._xfer_done.set()
                elif t == "error":
                    self._xfer_log(f"  ✗ Relay: {msg.get('msg','')}", err=True)
                    self._xfer_done.set()
        except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
            log.warning("Connection lost")
        except asyncio.CancelledError: pass
        except Exception as e: log.exception("Recv: %s", e)

    async def _prefetch_pubkey(self, pid):
        await self.get_pubkey_raw(pid)

    async def _receive_file(self, meta):
        from_id    = meta["from_id"]; from_name = meta["from_name"]
        size       = int(meta["size"]); fhash = meta.get("hash","")
        fn_b64     = meta.get("filename_enc","")
        hn_b64     = meta.get("hidden_name_enc","")   # hidden content name ← NEW
        is_steg    = meta.get("steg", False)
        steg_type  = meta.get("steg_type","file")
        disp_name  = meta.get("display_name","file")
        xfer_id    = meta.get("transfer_id", os.urandom(8).hex())

        key = await self.get_shared_key(from_id)
        if key is None:
            rem = size
            while rem > 0:
                c = await self.reader.read(min(CHUNK,rem))
                if not c: break
                rem -= len(c)
            return

        aesgcm = AESGCM(key)

        # Decrypt cover image filename (used for the accept prompt display name)
        try:
            fn_raw    = base64.b64decode(fn_b64)
            cover_name = aesgcm.decrypt(fn_raw[:12], fn_raw[12:], None).decode()
            cover_name = os.path.basename(cover_name)
        except:
            cover_name = disp_name or f"stego_{int(time.time())}.png"

        # Decrypt the HIDDEN CONTENT name (the actual file to extract)
        # BUG FIX: this is what gets saved, not the cover name
        hidden_name = None
        if hn_b64:
            try:
                hn_raw      = base64.b64decode(hn_b64)
                hidden_name = aesgcm.decrypt(hn_raw[:12], hn_raw[12:], None).decode()
                hidden_name = os.path.basename(hidden_name)
            except:
                hidden_name = None

        # Accept / reject prompt
        # Show the hidden content name in the prompt, not the stego PNG name
        if is_steg and steg_type == "file" and hidden_name:
            prompt_name = f"{hidden_name} (hidden inside {cover_name})"
        elif is_steg and steg_type == "msg":
            prompt_name = f"hidden message (inside {cover_name})"
        else:
            try:
                fn_raw2   = base64.b64decode(fn_b64)
                prompt_name = aesgcm.decrypt(fn_raw2[:12], fn_raw2[12:], None).decode()
                prompt_name = os.path.basename(prompt_name)
            except:
                prompt_name = disp_name

        accepted = await self._prompt_accept(xfer_id, from_name, prompt_name, size)

        if not accepted:
            rem = size
            while rem > 0:
                c = await self.reader.read(min(CHUNK, rem))
                if not c: break
                rem -= len(c)
            self._xfer_log(f"  ✗ Rejected transfer from {from_name}")
            return

        if is_steg:
            # ── Receive stego PNG and extract hidden content ──────────────────
            data = b""; rem = size
            while rem > 0:
                c = await self.reader.read(min(CHUNK,rem))
                if not c: break
                data += c; rem -= len(c)
                # In CLI mode show progress; TUI mode this is invisible (OK)
                print(f"\r  Receiving stego image … {len(data)} bytes  ", end="", flush=True)
            print()

            if fhash and not hmac.compare_digest(hashlib.sha256(data).hexdigest(), fhash):
                self._xfer_log("  ⚠  Image hash mismatch — possible corruption", err=True)

            # Extract and decrypt
            try:
                enc_data = steg_extract(data)
                payload  = decrypt_payload(enc_data, key)
            except Exception as e:
                self._xfer_log(f"  ✗ Steg extract/decrypt failed: {e}", err=True)
                # Save the raw stego PNG so user can inspect it
                raw_save = f"stego_raw_{int(time.time())}.png"
                open(raw_save,"wb").write(data)
                self._xfer_log(f"  Raw PNG saved to {raw_save} for inspection")
                return

            if steg_type == "msg":
                # Hidden text message — display it, don't save to disk
                text = payload.decode("utf-8", errors="replace")
                self._xfer_log(f"  ✉  Hidden message from {from_name}:")
                self._xfer_log(f"  \"{text}\"")

                # Tell TUI about this (uses the special callback)
                if self._on_steg_received:
                    self._on_steg_received(
                        saved_path  = None,
                        size        = len(payload),
                        from_name   = from_name,
                        steg_type   = "msg",
                        message_text= text,
                    )
                self._history.append({
                    "dir":"received","ts":time.time(),
                    "filename":"(hidden message)","size":len(payload),"from":from_name
                })

            else:
                # Hidden file — save it with the CORRECT original filename
                # Use hidden_name if available, else fall back to cover name
                save = hidden_name or cover_name or f"extracted_{int(time.time())}"

                # Avoid overwriting existing files
                base_, ext = os.path.splitext(save); n = 1
                while os.path.exists(save):
                    save = f"{base_}_{n}{ext}"; n += 1

                open(save,"wb").write(payload)
                saved_path = os.path.abspath(save)

                self._xfer_log(
                    f"  ✓ Hidden file extracted → {saved_path}  ({len(payload)} bytes)"
                )

                # Notify TUI
                if self._on_steg_received:
                    self._on_steg_received(
                        saved_path   = saved_path,
                        size         = len(payload),
                        from_name    = from_name,
                        steg_type    = "file",
                        message_text = None,
                    )

                self._history.append({
                    "dir":"received","ts":time.time(),
                    "filename":save,"size":len(payload),"from":from_name
                })

                # Auto-extract zips
                if save.endswith(".zip"):
                    out = save[:-4]
                    try:
                        with zipfile.ZipFile(save) as z: z.extractall(out)
                        self._xfer_log(f"  ✓ Extracted → {out}/")
                    except: pass

        else:
            # ── Normal streaming file ─────────────────────────────────────────
            # Decrypt the actual filename for saving
            try:
                fn_raw2 = base64.b64decode(fn_b64)
                fname   = aesgcm.decrypt(fn_raw2[:12], fn_raw2[12:], None).decode()
                fname   = os.path.basename(fname)
            except:
                fname = f"received_{int(time.time())}"

            save = fname
            base_, ext = os.path.splitext(fname); n = 1
            while os.path.exists(save):
                save = f"{base_}_{n}{ext}"; n += 1

            try: salt = await self.reader.readexactly(32)
            except asyncio.IncompleteReadError: return
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
                        except: return
                        f.write(plain); received += len(plain)
                        print(f"\r  Receiving {fname} … {received} bytes  ", end="", flush=True)
            except asyncio.IncompleteReadError: return
            print()
            if fhash:
                ok = hmac.compare_digest(sha256_file(save), fhash)
                self._xfer_log(f"  ✓ Saved → {os.path.abspath(save)}  [{'SHA-256 OK ✓' if ok else 'HASH MISMATCH ⚠'}]")
            self._history.append({
                "dir":"received","ts":time.time(),
                "filename":save,"size":received,"from":from_name
            })
            if save.endswith(".zip"):
                out = save[:-4]
                try:
                    with zipfile.ZipFile(save) as z: z.extractall(out)
                    self._xfer_log(f"  ✓ Extracted → {out}/")
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


# ── CLI (terminal mode) ───────────────────────────────────────────────────────

async def cli_loop(client: RelayClient):
    loop = asyncio.get_event_loop()
    comp = Completer(client)
    rl.set_completer(comp.complete); rl.set_completer_delims(" \t")
    rl.parse_and_bind("tab: complete")
    def readline(p=""):
        try:    return input(p)
        except: return None
    print("\n  list | myid | send <id> <path> | steg <id> <cover> <file>")
    print("  stegmsg <id> <cover> <text> | chat <id> | msg <id> <text>")
    print("  alias <n> <id> | aliases | history | exit\n")
    while True:
        line = await loop.run_in_executor(None, readline, "> ")
        if line is None: break
        parts = line.strip().split(None, 3)
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
            if len(parts) < 4: print("  steg <id/alias> <cover_image> <file_to_hide>"); continue
            if not os.path.isfile(parts[3]): print(f"  ✗ Not found: {parts[3]}"); continue
            try: await client.send_steg(resolve(parts[1]), parts[2],
                                        open(parts[3],"rb").read(), label=os.path.basename(parts[3]))
            except RuntimeError as e: print(f"  ✗ {e}")
        elif cmd == "stegmsg":
            if len(parts) < 4: print("  stegmsg <id/alias> <cover_image> <text>"); continue
            try: await client.send_steg(resolve(parts[1]), parts[2],
                                        parts[3].encode(), label="message")
            except RuntimeError as e: print(f"  ✗ {e}")
        elif cmd == "msg":
            if len(parts) < 3: print("  msg <id/alias> <text>"); continue
            await client.send_message(resolve(parts[1]), " ".join(parts[2:]))
        elif cmd == "chat":
            if len(parts) < 2: print("  chat <id/alias>"); continue
            pid = resolve(parts[1])
            if pid not in client.peers: print(f"  ✗ {pid!r} not online"); continue
            print(f"\n  ── Chat with {client.peers[pid]} [{pid}] ──  (Ctrl+C exits)\n")
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
                ts = time.strftime("%H:%M:%S", time.localtime(h["ts"]))
                d  = h["dir"].upper()
                if d == "SENT": print(f"  {ts}  {d:<8}  {h.get('size',0):>12} bytes")
                else: print(f"  {ts}  {d:<8}  {h.get('size',0):>12} bytes  {h.get('filename','')}  ← {h.get('from','')}")
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
            use_steg=args.steg, knock_ports=knock_ports, auto_accept=args.auto_accept,
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
    ap.add_argument("--steg",        action="store_true")
    ap.add_argument("--auto-accept", action="store_true", dest="auto_accept")
    args = ap.parse_args()
    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        print("\n  Disconnected"); sys.exit(0)
