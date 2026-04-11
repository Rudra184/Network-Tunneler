import asyncio, os, struct, logging, time
from typing import Dict, Optional, Callable, Tuple, Set
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256

log = logging.getLogger("p2p")

_T_HELLO     = 0x01
_T_HELLO_ACK = 0x02
_T_DATA      = 0x03
_T_KEEPALIVE = 0x04

_PUNCH_PROBES   = 8
_PUNCH_INTERVAL = 0.12   # s between probes
_PUNCH_TIMEOUT  = 4.0    # s to wait for completed handshake
_KEEPALIVE_S    = 25.0   # s between keepalives
_SEQ_WINDOW     = 256    # replay protection window size


# ── Session key derivation ────────────────────────────────────────────────────

def _derive_session_key(eph_priv: X25519PrivateKey,
                         eph_pub_remote: bytes,
                         my_id: str, peer_id: str) -> bytes:
    shared = eph_priv.exchange(X25519PublicKey.from_public_bytes(eph_pub_remote))
    salt   = b"|".join(sorted([my_id.encode(), peer_id.encode()]))
    return HKDF(
        algorithm=SHA256(), length=32, salt=salt, info=b"p2p-session-v1"
    ).derive(shared)


# ── DirectSession ─────────────────────────────────────────────────────────────

class DirectSession:
    """
    One encrypted UDP session with a specific peer.
    Thread-safe: all methods called from within the asyncio event loop.
    """

    def __init__(self, peer_id: str, addr: Tuple[str, int], key: bytes):
        self.peer_id   = peer_id
        self.addr      = addr          # (ip, port)
        self._key      = key           # 32-byte AES-256 session key
        self._send_seq = 0
        self._recv_max = -1
        self._recv_seen: Set[int] = set()
        self._last_rx  = time.monotonic()
        self.alive     = True

    # ── encode ────────────────────────────────────────────────────────────────

    def encode_data(self, payload: bytes) -> bytes:
        seq   = self._send_seq
        self._send_seq = (self._send_seq + 1) & 0xFFFF_FFFF
        nonce = os.urandom(12)
        aad   = struct.pack(">I", seq)
        ct    = AESGCM(self._key).encrypt(nonce, payload, aad)
        return bytes([_T_DATA]) + aad + nonce + ct

    def encode_keepalive(self) -> bytes:
        seq = self._send_seq
        self._send_seq = (self._send_seq + 1) & 0xFFFF_FFFF
        return bytes([_T_KEEPALIVE]) + struct.pack(">I", seq)

    # ── decode ────────────────────────────────────────────────────────────────

    def decode(self, data: bytes) -> Optional[bytes]:
        """
        Decode and verify an incoming DATA frame.
        Returns plaintext payload, or None on tamper / replay / malformed.
        """
        if len(data) < 1 + 4 + 12 + 16:
            return None
        t = data[0]
        if t == _T_KEEPALIVE:
            self._last_rx = time.monotonic()
            return None   # no payload; caller only needs to know it was valid
        if t != _T_DATA:
            return None
        aad   = data[1:5]
        seq   = struct.unpack(">I", aad)[0]
        nonce = data[5:17]
        ct    = data[17:]
        # replay check
        if seq in self._recv_seen:
            log.debug("p2p replay from %s seq=%d", self.peer_id, seq)
            return None
        if self._recv_max >= 0 and seq < self._recv_max - _SEQ_WINDOW:
            log.debug("p2p old seq from %s", self.peer_id)
            return None
        try:
            plain = AESGCM(self._key).decrypt(nonce, ct, aad)
        except Exception:
            log.warning("p2p decrypt failed from %s", self.peer_id)
            return None
        # update state
        self._recv_seen.add(seq)
        if seq > self._recv_max:
            self._recv_max = seq
        if len(self._recv_seen) > _SEQ_WINDOW * 2:
            cutoff = self._recv_max - _SEQ_WINDOW
            self._recv_seen = {s for s in self._recv_seen if s >= cutoff}
        self._last_rx = time.monotonic()
        return plain

    @property
    def stale(self) -> bool:
        return time.monotonic() - self._last_rx > _KEEPALIVE_S * 3


# ── UDP asyncio protocol ──────────────────────────────────────────────────────

class _UDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, manager: "PeerManager"):
        self._mgr = manager

    def connection_made(self, transport):
        self._mgr._transport = transport

    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        asyncio.ensure_future(self._mgr._dispatch(data, addr))

    def error_received(self, exc: Exception):
        log.warning("UDP error: %s", exc)

    def connection_lost(self, exc):
        pass


# ── PeerManager ───────────────────────────────────────────────────────────────

class PeerManager:
    """
    Manages a single UDP socket and all direct peer sessions.

    Lifecycle
    ─────────
    1. await start(my_peer_id)           — bind UDP socket, return local port
    2. await punch(peer_id, "ip:port")   — attempt hole punch + handshake
    3. await send(peer_id, payload)      — encrypt and send via direct session
       returns False if no direct session (caller should use relay fallback)
    4. await stop()                      — close everything

    Callbacks
    ─────────
    on_message(peer_id, payload_bytes)   — called for each incoming DATA frame
    on_status(peer_id, connected: bool)  — called on session up/down
    """

    def __init__(self):
        self._my_id    : str                               = ""
        self._transport: Optional[asyncio.DatagramTransport] = None
        self._sessions : Dict[str, DirectSession]          = {}
        self._addr_map : Dict[Tuple[str,int], str]         = {}  # addr → peer_id
        # per-punch state: peer_id → (our eph priv, Event)
        self._pending  : Dict[str, Tuple[X25519PrivateKey, asyncio.Event]] = {}
        self._local_port: int                              = 0
        self._ka_task  : Optional[asyncio.Task]            = None
        self._running  : bool                              = False

        self.on_message: Optional[Callable[[str, bytes], None]] = None
        self.on_status : Optional[Callable[[str, bool], None]]  = None

    # ── public API ────────────────────────────────────────────────────────────

    async def start(self, my_peer_id: str) -> int:
        """Bind UDP socket. Returns the local port."""
        import platform as _plt
        self._my_id   = my_peer_id
        self._running = True
        loop = asyncio.get_event_loop()
        # On Windows with ProactorEventLoop, create_datagram_endpoint uses
        # a background thread internally — works fine on Python 3.8+.
        # On all other platforms it is a native asyncio operation.
        try:
            _, proto = await loop.create_datagram_endpoint(
                lambda: _UDPProtocol(self),
                local_addr=("0.0.0.0", 0))
        except NotImplementedError:
            # Some older Windows Python builds don't support UDP datagrams in
            # ProactorEventLoop.  Fallback: P2P unavailable, relay is used.
            log.warning("P2P UDP not supported on this platform — using relay only")
            self._running = False
            return 0
        sock = self._transport.get_extra_info("socket")
        self._local_port = sock.getsockname()[1]
        log.info("P2P UDP bound on port %d", self._local_port)
        self._ka_task = asyncio.create_task(self._keepalive_loop())
        return self._local_port

    async def stop(self):
        self._running = False
        if self._ka_task:
            self._ka_task.cancel()
            try: await self._ka_task
            except: pass
        if self._transport:
            self._transport.close()
        self._sessions.clear()
        self._addr_map.clear()
        self._pending.clear()
        log.info("P2P stopped")

    @property
    def local_port(self) -> int:
        return self._local_port

    def has_session(self, peer_id: str) -> bool:
        s = self._sessions.get(peer_id)
        return s is not None and s.alive and not s.stale

    async def send(self, peer_id: str, payload: bytes) -> bool:
        """
        Send payload via direct session.
        Returns True on success, False if no live session (use relay fallback).
        """
        s = self._sessions.get(peer_id)
        if not s or not s.alive or s.stale:
            if s and s.stale:
                self._drop_session(peer_id)
            return False
        try:
            frame = s.encode_data(payload)
            self._transport.sendto(frame, s.addr)
            return True
        except Exception as e:
            log.warning("P2P send to %s failed: %s", peer_id, e)
            self._drop_session(peer_id)
            return False

    async def punch(self, peer_id: str, addr_str: str):
        """
        Attempt UDP hole punch to peer_id at addr_str ("ip:port").
        Returns True if direct session established, False if failed.
        Caller should not await this — it runs as a background task.
        """
        asyncio.create_task(self._punch_task(peer_id, addr_str))

    def session_info(self, peer_id: str) -> Optional[dict]:
        """Return {addr, latency_ms} for a live session or None."""
        s = self._sessions.get(peer_id)
        if not s or not s.alive: return None
        return {"addr": f"{s.addr[0]}:{s.addr[1]}",
                "age_s": int(time.monotonic() - s._last_rx)}

    # ── hole punch ────────────────────────────────────────────────────────────

    async def _punch_task(self, peer_id: str, addr_str: str):
        try:
            host, port_s = addr_str.rsplit(":", 1)
            addr = (host, int(port_s))
        except ValueError:
            log.warning("Bad punch addr: %s", addr_str)
            return

        if self.has_session(peer_id):
            return   # already connected

        eph_priv = X25519PrivateKey.generate()
        eph_pub  = eph_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        ev       = asyncio.Event()
        self._pending[peer_id] = (eph_priv, ev)

        # Build HELLO frame
        pid_b  = self._my_id.encode()
        hello  = bytes([_T_HELLO]) + eph_pub + bytes([len(pid_b)]) + pid_b

        log.info("P2P punch → %s at %s", peer_id, addr_str)
        for _ in range(_PUNCH_PROBES):
            if not self._transport: break
            try:
                self._transport.sendto(hello, addr)
            except Exception:
                pass
            await asyncio.sleep(_PUNCH_INTERVAL)
            if ev.is_set():
                break

        # Wait for handshake to complete
        try:
            await asyncio.wait_for(ev.wait(), timeout=_PUNCH_TIMEOUT)
        except asyncio.TimeoutError:
            pass

        self._pending.pop(peer_id, None)

        if self.has_session(peer_id):
            log.info("P2P direct session UP: %s (%s)", peer_id, addr_str)
            if self.on_status:
                self.on_status(peer_id, True)
        else:
            log.info("P2P punch failed for %s — using relay", peer_id)

    # ── incoming datagram dispatch ────────────────────────────────────────────

    async def _dispatch(self, data: bytes, addr: Tuple[str, int]):
        if not data: return
        t = data[0]

        if t in (_T_HELLO, _T_HELLO_ACK):
            await self._handle_hello(data, addr, is_ack=(t == _T_HELLO_ACK))

        elif t == _T_DATA:
            peer_id = self._addr_map.get(addr)
            if not peer_id: return
            s = self._sessions.get(peer_id)
            if not s: return
            payload = s.decode(data)
            if payload is not None and self.on_message:
                self.on_message(peer_id, payload)

        elif t == _T_KEEPALIVE:
            peer_id = self._addr_map.get(addr)
            if peer_id:
                s = self._sessions.get(peer_id)
                if s: s._last_rx = time.monotonic()

    async def _handle_hello(self, data: bytes, addr: Tuple[str, int], is_ack: bool):
        # Parse: [type 1][eph_pub 32][peer_id_len 1][peer_id ...]
        if len(data) < 1 + 32 + 1:
            return
        their_eph_pub = data[1:33]
        pid_len       = data[33]
        if len(data) < 34 + pid_len:
            return
        peer_id = data[34:34+pid_len].decode(errors="replace")

        if is_ack:
            # We sent HELLO, they replied — complete session setup
            entry = self._pending.get(peer_id)
            if not entry:
                return
            eph_priv, ev = entry
            key = _derive_session_key(eph_priv, their_eph_pub, self._my_id, peer_id)
            self._register_session(peer_id, addr, key)
            ev.set()
        else:
            # They sent HELLO to us — send HELLO_ACK and open session
            eph_priv = X25519PrivateKey.generate()
            eph_pub  = eph_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            key      = _derive_session_key(eph_priv, their_eph_pub, self._my_id, peer_id)
            self._register_session(peer_id, addr, key)
            pid_b = self._my_id.encode()
            ack   = bytes([_T_HELLO_ACK]) + eph_pub + bytes([len(pid_b)]) + pid_b
            try:
                self._transport.sendto(ack, addr)
            except Exception:
                pass
            log.info("P2P session opened (as responder): %s", peer_id)
            if self.on_status:
                self.on_status(peer_id, True)

    def _register_session(self, peer_id: str, addr: Tuple[str, int], key: bytes):
        # Remove old entry if addr changed
        old = self._sessions.get(peer_id)
        if old and old.addr in self._addr_map:
            del self._addr_map[old.addr]
        s = DirectSession(peer_id, addr, key)
        self._sessions[peer_id] = s
        self._addr_map[addr]    = peer_id

    def _drop_session(self, peer_id: str):
        s = self._sessions.pop(peer_id, None)
        if s:
            self._addr_map.pop(s.addr, None)
            s.alive = False
        if self.on_status:
            self.on_status(peer_id, False)

    # ── keep-alive loop ───────────────────────────────────────────────────────

    async def _keepalive_loop(self):
        while self._running:
            await asyncio.sleep(_KEEPALIVE_S)
            dead = []
            for pid, s in list(self._sessions.items()):
                if s.stale:
                    dead.append(pid)
                elif s.alive and self._transport:
                    try:
                        self._transport.sendto(s.encode_keepalive(), s.addr)
                    except Exception:
                        dead.append(pid)
            for pid in dead:
                log.info("P2P session timed out: %s", pid)
                self._drop_session(pid)
