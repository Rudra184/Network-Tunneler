#!/usr/bin/env python3


import asyncio, json, logging, argparse, sys, time, os, hmac, hashlib
import struct, ssl, uuid, base64
from collections import defaultdict
try:
    from tunnel import ServerTunnelManager
    _server_tun = ServerTunnelManager()
except ImportError:
    _server_tun = None

logging.basicConfig(level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(message)s", datefmt="%H:%M:%S")
log = logging.getLogger("relay")

# ── Global state ──────────────────────────────────────────────────────────────
peers         = {}
channels      = {}               # channel_id → set(peer_id)
ip_conn_count = defaultdict(int)
ip_auth_fails = defaultdict(lambda: [0, 0.0])
used_nonces   = {}
ip_bw         = {}

SECRET_BYTES   = b""
AUDIT_FILE     = None
KNOCK_SEQUENCE = [6132, 8152, 3101]   # default sequence

MAX_CONN      = 5
MAX_FAILS     = 3
BAN_DUR       = 3600
REG_TIMEOUT   = 10
MAX_FILE      = 2 * 1024 ** 3
NONCE_TTL     = 120
CHUNK         = 65536
BW_RATE       = 20 * 1024 * 1024
BW_CAP        = 40 * 1024 * 1024


# ── TLS ───────────────────────────────────────────────────────────────────────

def generate_cert(cert_file="relay.crt", key_file="relay.key"):
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    import datetime
    key  = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "relay")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )
    open(cert_file, "wb").write(cert.public_bytes(serialization.Encoding.PEM))
    open(key_file,  "wb").write(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()
    ))
    log.info("Generated TLS cert → %s / %s", cert_file, key_file)

def cert_fingerprint(cert_file):
    pem = open(cert_file).read()
    der = ssl.PEM_cert_to_DER_cert(pem)
    return hashlib.sha256(der).hexdigest()

def build_ssl_ctx(cert_file, key_file):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    except AttributeError:
        pass
    ctx.load_cert_chain(cert_file, key_file)
    return ctx

# ── TOTP ──────────────────────────────────────────────────────────────────────

def _totp(secret, drift=0, interval=30, digits=6):
    counter = (int(time.time()) // interval) + drift
    h   = hmac.new(secret, struct.pack(">Q", counter), hashlib.sha1).digest()
    off = h[-1] & 0x0F
    code = (struct.unpack(">I", h[off:off+4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)

def verify_totp(secret, code, window=1):
    for d in range(-window, window + 1):
        if hmac.compare_digest(_totp(secret, d), code):
            return True
    return False

# ── Audit ─────────────────────────────────────────────────────────────────────

def audit(event, **kw):
    if AUDIT_FILE:
        AUDIT_FILE.write(json.dumps({"ts": time.time(), "event": event, **kw}) + "\n")
        AUDIT_FILE.flush()

# ── Helpers ───────────────────────────────────────────────────────────────────

def enc(obj):
    return (json.dumps(obj) + "\n").encode()

def is_banned(ip):
    fails, until = ip_auth_fails[ip]
    if until > time.time():
        return True
    if until:
        ip_auth_fails[ip] = [0, 0.0]
    return False

def record_fail(ip):
    fails, until = ip_auth_fails[ip]
    fails += 1
    if fails >= MAX_FAILS:
        until = time.time() + BAN_DUR
        log.warning("Banned %s for %ds", ip, BAN_DUR)
        audit("ip_banned", ip=ip)
    ip_auth_fails[ip] = [fails, until]

def check_replay(nonce, ts):
    now = time.time()
    for k in [k for k, v in used_nonces.items() if v < now]:
        del used_nonces[k]
    if abs(now - ts) > 60:
        return False, "timestamp out of window"
    if nonce in used_nonces:
        return False, "replay detected"
    used_nonces[nonce] = now + NONCE_TTL
    return True, "ok"

def broadcast_peer_list():
    msg = enc({"type": "peer_list",
               "peers": [{"id": pid, "name": p["name"]} for pid, p in peers.items()]})
    for p in peers.values():
        try:
            p["writer"].write(msg)
        except Exception:
            pass

async def throttle(ip, n_bytes):
    now = time.monotonic()
    bw  = ip_bw.setdefault(ip, {"tokens": BW_CAP, "last": now})
    elapsed      = now - bw["last"]
    bw["tokens"] = min(BW_CAP, bw["tokens"] + elapsed * BW_RATE)
    bw["last"]   = now
    if bw["tokens"] < n_bytes:
        await asyncio.sleep((n_bytes - bw["tokens"]) / BW_RATE)
        bw["tokens"] = 0
    else:
        bw["tokens"] -= n_bytes

# ── File relay ────────────────────────────────────────────────────────────────

async def relay_file(sender_id, sender_name, sender_ip, msg, reader, writer, send):
    target_id    = msg.get("to")
    filename_enc = msg.get("filename_enc", "")
    size         = int(msg.get("size", 0))
    file_hash    = msg.get("hash", "")
    is_steg      = msg.get("steg", False)
    # Forward these so the receiver can name saved files correctly and match
    # the transfer ID shown in the accept prompt.
    display_name = msg.get("display_name", "file")
    transfer_id  = msg.get("transfer_id",  "")

    if target_id not in peers:
        return await send({"type": "error", "msg": "Target peer not connected"})
    if not (0 < size <= MAX_FILE):
        return await send({"type": "error", "msg": "Invalid file size"})

    tw = peers[target_id]["writer"]
    tw.write(enc({
        "type":         "incoming_file",
        "from_id":      sender_id,
        "from_name":    sender_name,
        "filename_enc": filename_enc,
        "size":         size,
        "hash":         file_hash,
        "steg":         is_steg,
        "display_name": display_name,
        "transfer_id":  transfer_id,
        # Inline pubkey so receiver never needs a separate get_pubkey
        # request while file bytes are already in-flight on the stream.
        "from_pubkey":  peers.get(sender_id, {}).get("pubkey", ""),
    }))
    await tw.drain()

    remaining, ok = size, True
    while remaining > 0:
        chunk = await reader.read(min(CHUNK, remaining))
        if not chunk:
            ok = False
            break
        await throttle(sender_ip, len(chunk))
        tw.write(chunk)
        remaining -= len(chunk)

    try:
        await tw.drain()
    except Exception:
        ok = False

    if ok:
        audit("file_relayed", sender=sender_id, target=target_id, size=size, steg=is_steg)
        log.info("Relayed %d bytes  %s → %s  steg=%s", size, sender_id, target_id, is_steg)
        await send({"type": "send_ok", "size": size})
        tw.write(enc({"type": "file_done", "size": size}))
        await tw.drain()
    else:
        await send({"type": "error", "msg": "Transfer dropped mid-way"})

# ── Connection handler ────────────────────────────────────────────────────────

async def handle_client(reader, writer):
    addr    = writer.get_extra_info("peername")
    ip      = addr[0]
    peer_id = str(uuid.uuid4())[:8]
    name    = peer_id

    async def drop():
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    async def send(obj):
        writer.write(enc(obj))
        await writer.drain()

    if is_banned(ip):
        audit("rejected_banned", ip=ip); await drop(); return
    if ip_conn_count[ip] >= MAX_CONN:
        audit("rejected_flood", ip=ip);  await drop(); return

    ip_conn_count[ip] += 1

    try:
        nonce = os.urandom(32).hex()
        await send({"type": "challenge", "nonce": nonce})

        try:
            raw = await asyncio.wait_for(reader.readline(), timeout=REG_TIMEOUT)
        except asyncio.TimeoutError:
            await drop(); return

        if not raw:
            await drop(); return

        try:
            msg = json.loads(raw.decode().strip())
        except json.JSONDecodeError:
            record_fail(ip); await drop(); return

        if msg.get("type") != "register":
            record_fail(ip); await drop(); return

        ts           = int(msg.get("ts", 0))
        client_nonce = msg.get("nonce", "")
        client_hmac  = msg.get("hmac",  "")
        client_totp  = msg.get("totp",  "")

        if client_nonce != nonce:
            record_fail(ip); audit("bad_nonce", ip=ip); await drop(); return

        ok, reason = check_replay(nonce, ts)
        if not ok:
            record_fail(ip); audit("replay", ip=ip, reason=reason); await drop(); return

        expected = hmac.new(SECRET_BYTES, f"{nonce}{ts}".encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, client_hmac):
            record_fail(ip); audit("bad_hmac", ip=ip); await drop(); return

        totp_key = hashlib.sha256(SECRET_BYTES + b":totp").digest()
        if not verify_totp(totp_key, client_totp):
            record_fail(ip); audit("bad_totp", ip=ip); await drop(); return

        name    = str(msg.get("name", peer_id))[:32]
        pubkey  = msg.get("pubkey", "")
        udp_port = int(msg.get("udp_port", 0))

        peers[peer_id] = {
            "name": name, "writer": writer, "pubkey": pubkey, "ip": ip,
            "udp_port": udp_port,   # 0 = no direct UDP (behind symmetric NAT)
        }
        log.info("Auth OK  id=%-8s  name=%-15s  ip=%s", peer_id, name, ip)
        audit("registered", peer_id=peer_id, name=name, ip=ip)

        await send({"type": "welcome", "your_id": peer_id, "your_name": name})
        broadcast_peer_list()

        while True:
            raw = await reader.readline()
            if not raw:
                break
            try:
                msg = json.loads(raw.decode().strip())
            except json.JSONDecodeError:
                await send({"type": "error", "msg": "Invalid JSON"}); continue

            t = msg.get("type")

            if t == "list":
                await send({"type": "peer_list",
                            "peers": [{"id": p, "name": peers[p]["name"]}
                                      for p in peers if p != peer_id]})

            elif t == "get_pubkey":
                tid = msg.get("peer_id")
                if tid in peers:
                    await send({"type": "pubkey_response",
                                "peer_id": tid, "pubkey": peers[tid]["pubkey"]})
                else:
                    await send({"type": "error", "msg": f"Peer {tid!r} not found"})

            elif t == "send_file":
                await relay_file(peer_id, name, ip, msg, reader, writer, send)

            elif t == "msg":
                tid = msg.get("to")
                if tid in peers:
                    peers[tid]["writer"].write(enc({
                        "type":      "msg",
                        "from_id":   peer_id,
                        "from_name": name,
                        "payload":   msg.get("payload", ""),
                        "nonce":     msg.get("nonce",   ""),
                    }))
                    try:
                        await peers[tid]["writer"].drain()
                    except Exception:
                        pass
                else:
                    await send({"type": "error", "msg": "Target not connected"})

            elif t == "register_udp":
                # Client telling us their UDP port (bound before connect)
                udp_p = int(msg.get("udp_port", 0))
                if 1024 <= udp_p <= 65535:
                    peers[peer_id]["udp_port"] = udp_p
                    log.info("P2P UDP registered: %s → %s:%d", peer_id, ip, udp_p)

            elif t == "get_udp_addr":
                # Return another peer's public (ip, udp_port)
                tid = msg.get("peer_id", "")
                if tid in peers and peers[tid]["udp_port"]:
                    await send({
                        "type":     "udp_addr",
                        "peer_id":  tid,
                        "addr":     f"{peers[tid]['ip']}:{peers[tid]['udp_port']}",
                    })
                else:
                    await send({"type": "udp_addr", "peer_id": tid, "addr": ""})

            elif t == "punch_request":
                # Peer A wants to punch to peer B.
                # Send punch_now to BOTH simultaneously so they fire probes at
                # the same time — this is the "simultaneous open" coordination.
                tid = msg.get("target_id", "")
                if tid in peers and peers[peer_id]["udp_port"] and peers[tid]["udp_port"]:
                    a_addr = f"{ip}:{peers[peer_id]['udp_port']}"
                    b_addr = f"{peers[tid]['ip']}:{peers[tid]['udp_port']}"
                    # Send to requester (A): here is B's addr
                    writer.write(enc({
                        "type": "punch_now",
                        "peer_id": tid,
                        "addr": b_addr,
                    }))
                    await writer.drain()
                    # Send to target (B): here is A's addr
                    if tid in peers:
                        peers[tid]["writer"].write(enc({
                            "type": "punch_now",
                            "peer_id": peer_id,
                            "addr": a_addr,
                        }))
                        try: await peers[tid]["writer"].drain()
                        except: pass
                    log.info("P2P punch coordinated: %s ↔ %s", peer_id, tid)
                else:
                    await send({"type": "punch_now", "peer_id": tid, "addr": ""})

            elif t == "join_channel":
                cid = msg.get("channel_id", "")[:64]
                if cid:
                    channels.setdefault(cid, set()).add(peer_id)

            elif t == "leave_channel":
                cid = msg.get("channel_id", "")
                if cid in channels:
                    channels[cid].discard(peer_id)
                    if not channels[cid]:
                        del channels[cid]

            elif t == "channel_msg":
                cid     = msg.get("channel_id", "")
                payload = msg.get("payload", "")
                nonce   = msg.get("nonce", "")
                if cid and payload and nonce:
                    members = channels.get(cid, set())
                    for mid in list(members):
                        if mid != peer_id and mid in peers:
                            try:
                                peers[mid]["writer"].write(enc({
                                    "type":       "channel_msg",
                                    "channel_id": cid,
                                    "from_id":    peer_id,
                                    "from_name":  name,
                                    "payload":    payload,
                                    "nonce":      nonce,
                                }))
                                await peers[mid]["writer"].drain()
                            except Exception:
                                pass

            elif t == "ping":
                await send({"type": "pong"})

            elif t == "tunnel_start":
                if _server_tun is None:
                    await send({"type": "tunnel_error", "msg": "tunnel module not available"})
                else:
                    try:
                        await _server_tun.ensure_started(SECRET_BYTES)
                        client_tun_ip = _server_tun.assign_client(
                            peer_id, writer, SECRET_BYTES)
                        await send({"type": "tunnel_ready",
                                    "client_ip": client_tun_ip,
                                    "server_tun_ip": "10.8.0.1"})
                        audit("tunnel_start", peer_id=peer_id, ip=client_tun_ip)
                        log.info("Tunnel started for %s → %s", peer_id, client_tun_ip)
                    except Exception as e:
                        await send({"type": "tunnel_error", "msg": str(e)})

            elif t == "tpkt":
                # Encrypted tunnel packet — decrypted per-client inside handle_client_packet
                if _server_tun and peer_id in (_server_tun._ip_pool or {}):
                    _server_tun.handle_client_packet(peer_id, msg.get("d", ""))

            elif t == "tunnel_stop":
                if _server_tun:
                    _server_tun.release_client(peer_id)
                    audit("tunnel_stop", peer_id=peer_id)
                    log.info("Tunnel stopped for %s", peer_id)

            elif t == "tunnel_pcap":
                # Admin toggles packet capture (only works when tunnel is active)
                if _server_tun and _server_tun._started:
                    enable = msg.get("enable", False)
                    if enable:
                        path = msg.get("path", f"capture_{int(time.time())}.pcap")
                        _server_tun.start_pcap(path)
                        await send({"type": "tunnel_pcap_ack", "ok": True, "path": path})
                    else:
                        _server_tun.stop_pcap()
                        await send({"type": "tunnel_pcap_ack", "ok": True, "path": ""})
                else:
                    await send({"type": "tunnel_pcap_ack", "ok": False,
                                "msg": "Tunnel not active"})

            elif t == "socks":
                # Relay SOCKS5 control messages between peers (peer-to-peer, like "msg")
                tid = msg.get("to")
                if tid in peers:
                    peers[tid]["writer"].write(enc({
                        "type":      "socks",
                        "from_id":   peer_id,
                        "from_name": name,
                        "action":    msg.get("action", ""),
                        "sid":       msg.get("sid", ""),
                        "host":      msg.get("host", ""),
                        "port":      msg.get("port", 0),
                        "ok":        msg.get("ok", False),
                        "reason":    msg.get("reason", ""),
                        "d":         msg.get("d", ""),
                    }))
                    try: await peers[tid]["writer"].drain()
                    except: pass
                else:
                    await send({"type": "error", "msg": "SOCKS target not connected"})

            else:
                await send({"type": "error", "msg": f"Unknown type {t!r}"})

    except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
        pass
    except Exception as e:
        log.exception("id=%s: %s", peer_id, e)
    finally:
        peers.pop(peer_id, None)
        for cid in list(channels):
            channels[cid].discard(peer_id)
            if not channels[cid]:
                del channels[cid]
        if _server_tun:
            _server_tun.release_client(peer_id)
        ip_conn_count[ip] = max(0, ip_conn_count[ip] - 1)
        writer.close()
        log.info("Disconnected  id=%-8s  name=%s", peer_id, name)
        audit("disconnected", peer_id=peer_id, name=name)
        broadcast_peer_list()

# ── Entry ─────────────────────────────────────────────────────────────────────

async def main(host, port, cert, key):
    ctx = build_ssl_ctx(cert, key)
    server = await asyncio.start_server(handle_client, host, port, ssl=ctx)
    fp = cert_fingerprint(cert)
    log.info("=" * 62)
    log.info("Secure relay  %s:%d  [TLS 1.3]", host, port)
    log.info("Fingerprint : %s", fp)
    log.info("Knock ports : %s", " → ".join(map(str, KNOCK_SEQUENCE)))
    log.info("=" * 62)
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--secret",      required=True)
    ap.add_argument("--host",        default="0.0.0.0")
    ap.add_argument("--port",        default=4001, type=int)
    ap.add_argument("--cert",        default="relay.crt")
    ap.add_argument("--key",         default="relay.key")
    ap.add_argument("--audit-log",   default="audit.log")
    ap.add_argument("--knock-ports", default="6132,8152,3101",
                    help="Comma-separated knock sequence (default: 6132,8152,3101)")
    args = ap.parse_args()

    SECRET_BYTES   = args.secret.encode()
    AUDIT_FILE     = open(args.audit_log, "a")
    KNOCK_SEQUENCE = list(map(int, args.knock_ports.split(",")))
    audit("server_start", port=args.port, knock=KNOCK_SEQUENCE)

    if not os.path.exists(args.cert) or not os.path.exists(args.key):
        generate_cert(args.cert, args.key)
    else:
        log.info("Using existing cert: %s", args.cert)

    fp = cert_fingerprint(args.cert)
    print(f"\n  Fingerprint  : {fp}")
    print(f"  Knock ports  : {' → '.join(map(str, KNOCK_SEQUENCE))}")
    print(f"\n  Client cmd   : python3 client.py \\")
    print(f"    --relay <ip> --port {args.port} --secret {args.secret} \\")
    print(f"    --fingerprint {fp} --name <you> \\")
    print(f"    --knock-ports {args.knock_ports}\n")

    try:
        asyncio.run(main(args.host, args.port, args.cert, args.key))
    except KeyboardInterrupt:
        audit("server_stop")
        AUDIT_FILE.close()
        sys.exit(0)
