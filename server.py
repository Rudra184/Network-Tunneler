#!/usr/bin/env python3
"""
relay_server.py  —  run this on your EC2 instance
  python3 relay_server.py
  python3 relay_server.py --port 5000   # optional, default 4001

How it works:
  1. Every client connects and registers with a human-readable name.
  2. The server keeps a registry: { peer_id -> (name, writer) }
  3. To send a file, the sender tells the server who the target is;
     the server pipes the bytes straight to the target.
  4. All control messages are newline-delimited JSON.
  5. File payloads are raw bytes (no encoding overhead).
"""

import asyncio
import json
import logging
import argparse
import uuid
import sys

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("relay")

# peer_id -> {"name": str, "writer": asyncio.StreamWriter}
peers: dict[str, dict] = {}


def broadcast_peer_list():
    """Send an updated peer list to every connected client."""
    peer_list = [{"id": pid, "name": p["name"]} for pid, p in peers.items()]
    msg = _encode({"type": "peer_list", "peers": peer_list})
    for p in peers.values():
        try:
            p["writer"].write(msg)
        except Exception:
            pass


def _encode(obj: dict) -> bytes:
    return (json.dumps(obj) + "\n").encode()


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    addr = writer.get_extra_info("peername")
    peer_id = str(uuid.uuid4())[:8]   # short 8-char ID, easy to type
    log.info("New connection from %s  →  assigned id=%s", addr, peer_id)

    async def send(obj: dict):
        writer.write(_encode(obj))
        await writer.drain()

    # ── Step 1: wait for REGISTER message ──────────────────────────────────
    try:
        raw = await asyncio.wait_for(reader.readline(), timeout=15)
    except asyncio.TimeoutError:
        log.warning("id=%s timed out during registration", peer_id)
        writer.close()
        return

    try:
        msg = json.loads(raw.decode().strip())
    except json.JSONDecodeError:
        log.warning("id=%s sent invalid JSON during handshake", peer_id)
        writer.close()
        return

    if msg.get("type") != "register":
        await send({"type": "error", "msg": "First message must be {type:register, name:...}"})
        writer.close()
        return

    name = str(msg.get("name", peer_id))[:32]
    peers[peer_id] = {"name": name, "writer": writer}
    log.info("Registered  id=%-8s  name=%s", peer_id, name)

    await send({"type": "welcome", "your_id": peer_id, "your_name": name})
    broadcast_peer_list()

    # ── Step 2: main message loop ───────────────────────────────────────────
    try:
        while True:
            raw = await reader.readline()
            if not raw:
                break   # client disconnected

            try:
                msg = json.loads(raw.decode().strip())
            except json.JSONDecodeError:
                await send({"type": "error", "msg": "Invalid JSON"})
                continue

            mtype = msg.get("type")

            # ── LIST ────────────────────────────────────────────────────────
            if mtype == "list":
                peer_list = [
                    {"id": pid, "name": p["name"]}
                    for pid, p in peers.items()
                    if pid != peer_id
                ]
                await send({"type": "peer_list", "peers": peer_list})

            # ── SEND FILE ───────────────────────────────────────────────────
            elif mtype == "send_file":
                target_id = msg.get("to")
                filename  = msg.get("filename", "received_file")
                size      = int(msg.get("size", 0))

                if target_id not in peers:
                    await send({"type": "error", "msg": f"Peer {target_id!r} not found"})
                    continue
                if size <= 0 or size > 2 * 1024 ** 3:  # max 2 GB
                    await send({"type": "error", "msg": "Invalid file size"})
                    continue

                target_writer = peers[target_id]["writer"]

                # Tell the target a file is coming
                note = _encode({
                    "type":     "incoming_file",
                    "from_id":  peer_id,
                    "from_name": name,
                    "filename": filename,
                    "size":     size,
                })
                target_writer.write(note)
                await target_writer.drain()

                # Relay raw bytes from sender → target in 64 KB chunks
                remaining = size
                ok = True
                while remaining > 0:
                    chunk = await reader.read(min(65536, remaining))
                    if not chunk:
                        log.warning("Sender id=%s disconnected mid-transfer", peer_id)
                        ok = False
                        break
                    target_writer.write(chunk)
                    remaining -= len(chunk)

                try:
                    await target_writer.drain()
                except Exception as e:
                    log.warning("Target drain error: %s", e)
                    ok = False

                if ok:
                    log.info(
                        "Relayed  %-25s  %d bytes  %s → %s",
                        filename, size, peer_id, target_id,
                    )
                    await send({"type": "send_ok", "filename": filename, "size": size})
                    # notify target transfer is complete
                    target_writer.write(_encode({
                        "type": "file_done",
                        "filename": filename,
                        "size": size,
                    }))
                    await target_writer.drain()
                else:
                    await send({"type": "error", "msg": "Transfer failed mid-way"})

            # ── PING ────────────────────────────────────────────────────────
            elif mtype == "ping":
                await send({"type": "pong"})

            else:
                await send({"type": "error", "msg": f"Unknown message type {mtype!r}"})

    except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
        pass
    except Exception as e:
        log.exception("Unexpected error for id=%s: %s", peer_id, e)
    finally:
        peers.pop(peer_id, None)
        writer.close()
        log.info("Disconnected  id=%-8s  name=%s", peer_id, name)
        broadcast_peer_list()


async def main(host: str, port: int):
    server = await asyncio.start_server(handle_client, host, port)
    addrs = [s.getsockname() for s in server.sockets]
    log.info("==============================================")
    log.info("Relay server listening on %s", addrs)
    log.info("==============================================")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="libp2p-free Python relay server")
    ap.add_argument("--host", default="0.0.0.0", help="Bind address (default 0.0.0.0)")
    ap.add_argument("--port", default=4001, type=int, help="Port (default 4001)")
    args = ap.parse_args()
    try:
        asyncio.run(main(args.host, args.port))
    except KeyboardInterrupt:
        log.info("Relay shut down")
        sys.exit(0)
