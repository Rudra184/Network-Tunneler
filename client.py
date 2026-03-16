#!/usr/bin/env python3
"""
client.py  —  E2E-encrypted file/folder transfer + chat
  pip install cryptography          (one-time install)

  python3 client.py --relay 3.229.137.161 --secret <key> --name alice
  python3 client.py --relay 3.229.137.161 --secret <key> --name bob

Commands:
  list                      — show online peers
  myid                      — print your peer ID
  send <peer_id> <path>     — send a file OR folder (auto-detected)
  msg  <peer_id> <text>     — send an encrypted chat message
  exit                      — quit

How E2E encryption works:
  1. On startup each client generates an X25519 keypair.
  2. The public key is sent to the relay on registration.
  3. Before sending anything, the sender fetches the recipient's public
     key from the relay and derives a shared AES-256-GCM key via ECDH.
  4. Files are encrypted in 64 KB chunks (each chunk: nonce + ciphertext).
  5. Chat messages are AES-256-GCM encrypted and base64-encoded in JSON.
  6. The relay only ever sees ciphertext — never plaintext.
"""

import asyncio, json, os, sys, argparse, logging, base64, zipfile, io, shutil, tempfile
from collections import defaultdict


from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256


logging.basicConfig(level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(message)s", datefmt="%H:%M:%S")
log = logging.getLogger("client")

CHUNK = 65536   # 64 KB per encryption chunk

# ── Crypto helpers ────────────────────────────────────────────────────────────

def generate_keypair():
    priv = X25519PrivateKey.generate()
    pub  = priv.public_key()
    return priv, pub

def pubkey_to_b64(pub) -> str:
    raw = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.b64encode(raw).decode()

def b64_to_pubkey(b64: str):
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
    raw = base64.b64decode(b64)
    return X25519PublicKey.from_public_bytes(raw)

def derive_shared_key(my_priv, peer_pub) -> bytes:
    """ECDH → HKDF-SHA256 → 32-byte AES key."""
    shared = my_priv.exchange(peer_pub)
    return HKDF(algorithm=SHA256(), length=32, salt=None,
                info=b"filetunnel-v2").derive(shared)

def encrypt_chunk(aesgcm: AESGCM, base_nonce: bytes, idx: int, data: bytes) -> bytes:
    """Encrypt one chunk. Returns: 4-byte-len + nonce(12) + ct+tag."""
    nonce = base_nonce[:8] + (int.from_bytes(base_nonce[8:], 'big') ^ idx).to_bytes(4, 'big')
    ct    = aesgcm.encrypt(nonce, data, None)   # ct includes 16-byte GCM tag
    return len(ct).to_bytes(4, 'big') + nonce + ct

def decrypt_chunk(aesgcm: AESGCM, frame: bytes) -> bytes:
    """frame = nonce(12) + ct+tag. Returns plaintext."""
    nonce, ct = frame[:12], frame[12:]
    return aesgcm.decrypt(nonce, ct, None)

def encrypt_file_to_buffer(key: bytes, src_path: str) -> tuple[io.BytesIO, int]:
    """
    Encrypt src_path → in-memory buffer.
    Layout: base_nonce(12) | [4-byte-ct-len + nonce(12) + ct+tag] * N
    Returns (buffer_seeked_to_0, total_enc_bytes).
    """
    aesgcm     = AESGCM(key)
    base_nonce = os.urandom(12)
    buf        = io.BytesIO()
    buf.write(base_nonce)
    idx = 0
    with open(src_path, 'rb') as f:
        while True:
            chunk = f.read(CHUNK)
            if not chunk: break
            buf.write(encrypt_chunk(aesgcm, base_nonce, idx, chunk))
            idx += 1
    size = buf.tell()
    buf.seek(0)
    return buf, size

def decrypt_stream_to_file(key: bytes, reader_bytes: bytes, dst_path: str):
    """Decrypt bytes (from relay) and write plaintext to dst_path."""
    aesgcm     = AESGCM(key)
    pos        = 0
    base_nonce = reader_bytes[pos:pos+12]; pos += 12
    with open(dst_path, 'wb') as f:
        while pos < len(reader_bytes):
            if pos + 4 > len(reader_bytes): break
            ct_len = int.from_bytes(reader_bytes[pos:pos+4], 'big'); pos += 4
            frame  = reader_bytes[pos:pos+12+ct_len]; pos += 12 + ct_len
            f.write(decrypt_chunk(aesgcm, frame))

def encrypt_message(key: bytes, text: str) -> tuple[str, str]:
    """Encrypt a chat string. Returns (b64_nonce, b64_ciphertext)."""
    aesgcm = AESGCM(key)
    nonce  = os.urandom(12)
    ct     = aesgcm.encrypt(nonce, text.encode(), None)
    return base64.b64encode(nonce).decode(), base64.b64encode(ct).decode()

def decrypt_message(key: bytes, b64_nonce: str, b64_ct: str) -> str:
    """Decrypt a chat string."""
    aesgcm = AESGCM(key)
    nonce  = base64.b64decode(b64_nonce)
    ct     = base64.b64decode(b64_ct)
    return aesgcm.decrypt(nonce, ct, None).decode()

def folder_to_zip_bytes(folder_path: str) -> bytes:
    """Zip a folder into memory and return raw zip bytes."""
    buf = io.BytesIO()
    base_dir = os.path.dirname(os.path.abspath(folder_path))
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(folder_path):
            for fname in files:
                full = os.path.join(root, fname)
                arcname = os.path.relpath(full, base_dir)
                zf.write(full, arcname)
    return buf.getvalue()


# ── Client ────────────────────────────────────────────────────────────────────

class RelayClient:
    def __init__(self, host, port, name, secret):
        self.host   = host
        self.port   = port
        self.name   = name
        self.secret = secret

        # Identity
        self._priv, self._pub = generate_keypair()
        self._my_pubkey_b64   = pubkey_to_b64(self._pub)

        self.my_id = None
        self.peers: dict[str, str] = {}   # peer_id -> name

        self.reader = None
        self.writer = None
        self._recv_task = None

        # Per-peer shared AES key cache: peer_id -> bytes
        self._key_cache: dict[str, bytes] = {}

        # Pending pubkey futures: peer_id -> asyncio.Future
        self._pending_pubkeys: dict[str, asyncio.Future] = {}

        # File receive buffer
        self._recv_buf: dict[str, bytes] = {}  # peer_id -> accumulating bytes

        # Transfer done event
        self._transfer_done = asyncio.Event()

    # ── Connection ────────────────────────────────────────────────────────────

    async def connect(self):
        log.info("Connecting to %s:%s ...", self.host, self.port)
        self.reader, self.writer = await asyncio.open_connection(self.host, self.port)
        log.info("Connected")

        await self._send({
            "type":   "register",
            "name":   self.name,
            "secret": self.secret,
            "pubkey": self._my_pubkey_b64,   # share our public key on register
        })

        raw = await self.reader.readline()
        if not raw:
            raise RuntimeError("Server closed immediately — wrong secret?")
        msg = json.loads(raw.decode().strip())
        if msg.get("type") != "welcome":
            raise RuntimeError(f"Auth failed: {msg}")

        self.my_id = msg["your_id"]
        log.info("Authenticated  id=%-8s  name=%s", self.my_id, msg["your_name"])
        log.info("Encryption ready (X25519 + AES-256-GCM)")

        self._recv_task = asyncio.create_task(self._recv_loop())

    async def disconnect(self):
        if self._recv_task: self._recv_task.cancel()
        if self.writer:
            self.writer.close()
            try: await self.writer.wait_closed()
            except Exception: pass

    # ── Internal send ─────────────────────────────────────────────────────────

    async def _send(self, obj: dict):
        self.writer.write((json.dumps(obj) + "\n").encode())
        await self.writer.drain()

    # ── Key exchange ──────────────────────────────────────────────────────────

    async def _get_shared_key(self, peer_id: str) -> bytes:
        """Fetch peer's pubkey from relay (if not cached) and derive shared key."""
        if peer_id in self._key_cache:
            return self._key_cache[peer_id]

        loop = asyncio.get_event_loop()
        fut  = loop.create_future()
        self._pending_pubkeys[peer_id] = fut

        await self._send({"type": "get_pubkey", "peer_id": peer_id})

        try:
            peer_pubkey_bytes = await asyncio.wait_for(fut, timeout=10)
        except asyncio.TimeoutError:
            raise RuntimeError(f"Timeout fetching pubkey for {peer_id}")

        peer_pub = b64_to_pubkey(base64.b64encode(peer_pubkey_bytes).decode())
        key      = derive_shared_key(self._priv, peer_pub)
        self._key_cache[peer_id] = key
        log.info("Shared key derived for peer %s (E2E active)", peer_id)
        return key

    # ── Send file or folder ───────────────────────────────────────────────────

    async def send_path(self, peer_id: str, path: str):
        """Auto-detect file vs folder and send with E2E encryption."""
        if not os.path.exists(path):
            print(f"  Error: path not found: {path!r}"); return
        if peer_id not in self.peers:
            print(f"  Error: peer {peer_id!r} not found — run 'list' first"); return

        is_folder = os.path.isdir(path)

        # For folders: zip into a temp file first
        if is_folder:
            folder_name = os.path.basename(path.rstrip('/\\'))
            display     = folder_name + "/"
            zip_bytes   = folder_to_zip_bytes(path)
            # Write zip to temp file so we can use the same file-encrypt path
            tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
            tmp.write(zip_bytes); tmp.close()
            src_path  = tmp.name
            filename  = folder_name + ".zip"
            log.info("Zipped %s  →  %d bytes (before encryption)", display, len(zip_bytes))
        else:
            src_path  = path
            filename  = os.path.basename(path)
            display   = filename

        try:
            # Fetch/derive shared key
            key = await self._get_shared_key(peer_id)

            # Encrypt to in-memory buffer
            log.info("Encrypting %s ...", display)
            enc_buf, enc_size = encrypt_file_to_buffer(key, src_path)

            log.info("Sending  %-25s  %d enc-bytes  →  %s (%s)",
                     display, enc_size, peer_id, self.peers[peer_id])

            # Send header
            await self._send({
                "type":      "send_file",
                "to":        peer_id,
                "filename":  filename,
                "enc_size":  enc_size,
                "is_folder": is_folder,
            })

            # Send encrypted bytes
            self._transfer_done.clear()
            sent = 0
            while True:
                chunk = enc_buf.read(65536)
                if not chunk: break
                self.writer.write(chunk)
                sent += len(chunk)
                pct = sent * 100 // enc_size
                print(f"\r  Uploading {display} ... {pct}%  ", end="", flush=True)
            await self.writer.drain()
            print()

            try:
                await asyncio.wait_for(self._transfer_done.wait(), timeout=60)
            except asyncio.TimeoutError:
                log.warning("No ack within 60s")

        finally:
            if is_folder:
                os.unlink(src_path)  # remove temp zip

    # ── Send chat message ─────────────────────────────────────────────────────

    async def send_chat(self, peer_id: str, text: str):
        if peer_id not in self.peers:
            print(f"  Error: peer {peer_id!r} not found — run 'list' first"); return
        key   = await self._get_shared_key(peer_id)
        nonce, ct = encrypt_message(key, text)
        await self._send({"type": "chat", "to": peer_id, "nonce": nonce, "ciphertext": ct})
        print(f"  → [{self.peers[peer_id]}] {text}")

    # ── Receive loop ──────────────────────────────────────────────────────────

    async def _recv_loop(self):
        try:
            while True:
                raw = await self.reader.readline()
                if not raw: log.warning("Relay closed connection"); break
                try:    msg = json.loads(raw.decode().strip())
                except: continue

                t = msg.get("type")

                if t == "peer_list":
                    self.peers = {p["id"]: p["name"] for p in msg["peers"]}

                elif t == "pubkey_response":
                    pid  = msg["peer_id"]
                    fut  = self._pending_pubkeys.pop(pid, None)
                    if fut and not fut.done():
                        fut.set_result(base64.b64decode(msg["pubkey"]))

                elif t == "incoming_file":
                    await self._receive_file(msg)

                elif t == "chat":
                    await self._receive_chat(msg)

                elif t == "send_ok":
                    print(f"\n  ✓ Delivered: {msg['filename']}  ({msg['enc_size']} enc-bytes)")
                    self._transfer_done.set()

                elif t == "error":
                    print(f"\n  ✗ Server error: {msg['msg']}")
                    self._transfer_done.set()

                elif t in ("pong", "file_done", "welcome"): pass

                else: log.debug("Unknown: %s", t)

        except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
            log.warning("Lost connection to relay")
        except asyncio.CancelledError: pass
        except Exception as e: log.exception("Recv loop: %s", e)

    # ── Receive file ──────────────────────────────────────────────────────────

    async def _receive_file(self, meta: dict):
        from_id   = meta["from_id"]
        from_name = meta["from_name"]
        filename  = os.path.basename(meta["filename"])
        enc_size  = int(meta["enc_size"])
        is_folder = bool(meta.get("is_folder", False))

        print(f"\n  ↓ Incoming {'folder' if is_folder else 'file'}: "
              f"{filename}  ({enc_size} enc-bytes)  from {from_name} [{from_id}]")

        # Read exactly enc_size bytes from the relay stream
        enc_data = b""
        while len(enc_data) < enc_size:
            chunk = await self.reader.read(min(65536, enc_size - len(enc_data)))
            if not chunk: break
            enc_data += chunk
            pct = len(enc_data) * 100 // enc_size
            print(f"\r  Downloading {filename} ... {pct}%  ", end="", flush=True)
        print()

        if len(enc_data) < enc_size:
            print(f"  ✗ Incomplete transfer ({len(enc_data)}/{enc_size} bytes)"); return

        # Derive shared key and decrypt
        try:
            key = await self._get_shared_key(from_id)
        except RuntimeError as e:
            print(f"  ✗ Key exchange failed: {e}"); return

        # Choose a safe save path
        save_path = filename
        base, ext = os.path.splitext(filename)
        n = 1
        while os.path.exists(save_path):
            save_path = f"{base}_{n}{ext}"; n += 1

        try:
            decrypt_stream_to_file(key, enc_data, save_path)
        except Exception as e:
            print(f"  ✗ Decryption failed: {e}"); return

        # If it's a folder (zip), extract it
        if is_folder and save_path.endswith(".zip"):
            extract_dir = base  # folder name without .zip
            n2 = 1
            while os.path.exists(extract_dir):
                extract_dir = f"{base}_{n2}"; n2 += 1
            with zipfile.ZipFile(save_path, 'r') as zf:
                zf.extractall(extract_dir)
            os.remove(save_path)
            print(f"  ✓ Extracted folder  →  {extract_dir}/")
        else:
            plain_size = os.path.getsize(save_path)
            print(f"  ✓ Saved  →  {save_path}  ({plain_size} bytes, decrypted)")

    # ── Receive chat ──────────────────────────────────────────────────────────

    async def _receive_chat(self, msg: dict):
        from_id   = msg["from_id"]
        from_name = msg["from_name"]
        try:
            key  = await self._get_shared_key(from_id)
            text = decrypt_message(key, msg["nonce"], msg["ciphertext"])
            print(f"\n  💬 [{from_name}]: {text}\n> ", end="", flush=True)
        except Exception as e:
            print(f"\n  ✗ Chat decrypt failed from {from_name}: {e}\n> ", end="", flush=True)


# ── CLI ───────────────────────────────────────────────────────────────────────

async def cli_loop(client: RelayClient):
    loop = asyncio.get_event_loop()

    def read_line():
        try:    return input("> ")
        except EOFError: return None

    print()
    print("Commands:")
    print("  list                      — show online peers")
    print("  myid                      — your peer ID")
    print("  send <peer_id> <path>     — send a file or folder (E2E encrypted)")
    print("  msg  <peer_id> <text>     — send an encrypted chat message")
    print("  exit                      — quit")
    print()

    while True:
        line = await loop.run_in_executor(None, read_line)
        if line is None: break
        parts = line.strip().split(None, 3)
        if not parts: continue
        cmd = parts[0].lower()

        if cmd == "exit": break

        elif cmd == "myid":
            print(f"  {client.my_id}")

        elif cmd == "list":
            await client._send({"type": "list"})
            await asyncio.sleep(0.3)
            if client.peers:
                print(f"  {'ID':<12} Name")
                print(f"  {'-'*10} ----")
                for pid, pname in client.peers.items():
                    print(f"  {pid:<12} {pname}")
            else:
                print("  No other peers online yet")

        elif cmd == "send":
            if len(parts) < 3:
                print("  Usage: send <peer_id> <file_or_folder>"); continue
            await client.send_path(parts[1], parts[2])

        elif cmd == "msg":
            if len(parts) < 3:
                print("  Usage: msg <peer_id> <message text>"); continue
            text = parts[3] if len(parts) > 3 else parts[2]
            # re-split to grab everything after peer_id as message
            full_parts = line.strip().split(None, 2)
            if len(full_parts) < 3:
                print("  Usage: msg <peer_id> <message text>"); continue
            await client.send_chat(full_parts[1], full_parts[2])

        else:
            print(f"  Unknown command: {cmd!r}")


async def run(host, port, name, secret):
    client = RelayClient(host, port, name, secret)
    try:
        await client.connect()
        await cli_loop(client)
    except ConnectionRefusedError:
        print(f"\nERROR: Cannot connect to {host}:{port}")
        print("  → Is relay running?  Is port 4001 open in Security Group?")
        sys.exit(1)
    except RuntimeError as e:
        print(f"\nERROR: {e}"); sys.exit(1)
    finally:
        await client.disconnect()
        print("Disconnected.")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="E2E-encrypted file transfer client")
    ap.add_argument("--relay",  required=True)
    ap.add_argument("--secret", required=True)
    ap.add_argument("--name",   default="peer")
    ap.add_argument("--port",   default=4001, type=int)
    args = ap.parse_args()
    try:
        asyncio.run(run(args.relay, args.port, args.name, args.secret))
    except KeyboardInterrupt:
        print("\nInterrupted")
