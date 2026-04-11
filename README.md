# Secure Tunnel

A fully encrypted, peer-to-peer communication platform with a terminal UI. Supports encrypted messaging, file transfer, steganography, traffic tunneling, SOCKS5 proxying, secret group channels, and direct P2P connections without a central relay.

```
┌──────────────────────────────────────────────────────┐
│  ⚙ Settings │ 💬 Chat │ 📁 Files │ 🔏 Stego │ 👥 Peers │
│  🌐 Network │ 📡 Capture │ 🔐 Groups                  │
├──────────────────────────────────────────────────────┤
│  PEERS          │                                     │
│  ⟳ alice        │   [chat / files / stego / groups]  │
│  · bob          │                                     │
└──────────────────────────────────────────────────────┘
```

---

## Features

| Feature | Description |
|---------|-------------|
| **E2E Encrypted Chat** | AES-256-GCM messages, X25519 key exchange, perfect forward secrecy |
| **File Transfer** | Encrypted chunked transfer with SHA-256 integrity verification |
| **Steganography** | Hide files or text inside cover images using LSB + AES-256-GCM |
| **Secret Group Channels** | Password-derived hidden channels; server sees only opaque channel IDs |
| **Traffic Tunnel** | Route all device traffic through the relay (Linux, requires root) |
| **SOCKS5 Proxy** | Proxy any app through a peer's connection — E2E encrypted, no root needed |
| **Direct P2P** | UDP hole-punching for direct connections; relay is fallback only |
| **Tor Support** | Route connection through Tor for anonymity |
| **Port Knocking** | Server only accepts connections after correct knock sequence |
| **PCAP Capture** | Capture tunnelled packets to a Wireshark-compatible `.pcap` file |
| **TLS 1.3** | All relay traffic uses TLS with certificate fingerprint pinning |

---

## Requirements

```
Python 3.8+
pip install cryptography pillow textual
```

For Tor support: install `tor` via your package manager.  
For traffic tunnel / PCAP: Linux only, requires root.  
Everything else works on **Windows, macOS, and Linux**.

---

## File Layout

```
project/
├── server.py       # Relay server
├── client.py       # Core client logic (CLI + library)
├── tui.py          # Terminal UI
├── tunnel.py       # TUN device, SOCKS5, PCAP (Linux)
├── peer.py         # Direct P2P UDP sessions
├── requirements.txt
└── aliases.json    # Auto-created: saved peer aliases
```

---

## Quick Start

### 1 — Start the server (your cloud instance)

```bash
python3 server.py --secret YOUR_SECRET --port 4001 --knock-ports 1000,2000,3000
```

On first run, a self-signed TLS certificate is generated. The terminal prints:

```
  Fingerprint  : a3f2b1c4d5e6...
  Knock ports  : 1000 → 2000 → 3000

  Client cmd   : python3 client.py \
    --relay <ip> --port 4001 --secret YOUR_SECRET \
    --fingerprint a3f2b1c4d5e6... --name <you> \
    --knock-ports 1000,2000,3000
```

Save the fingerprint — you will paste it into each client's Settings.

To run as a systemd service that auto-starts on reboot:

```ini
# /etc/systemd/system/secure-tunnel.service
[Unit]
Description=Secure Tunnel Relay
After=network-online.target

[Service]
WorkingDirectory=/path/to/project
ExecStart=/usr/bin/python3 /path/to/project/server.py \
    --secret YOUR_SECRET --port 4001 \
    --knock-ports 1000,2000,3000
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now secure-tunnel
```

---

### 2 — Start the TUI (each client machine)

```bash
# Normal use (chat, files, steg, groups, SOCKS5, P2P)
python3 tui.py --relay <server-ip> --secret YOUR_SECRET --name alice \
  --fingerprint a3f2b1c4d5e6... --knock-ports 1000,2000,3000

# Traffic tunnel requires root (Linux)
sudo python3 tui.py --relay <server-ip> --secret YOUR_SECRET --name alice \
  --fingerprint a3f2b1c4d5e6... --knock-ports 1000,2000,3000
```

Or use the CLI directly (headless / scripting):

```bash
python3 client.py --relay <server-ip> --secret YOUR_SECRET --name alice \
  --fingerprint a3f2b1c4d5e6... --knock-ports 1000,2000,3000
```

---

## TUI Navigation

| Key | Tab |
|-----|-----|
| F1 | ⚙ Settings — connection, theme, auto-accept |
| F2 | 💬 Chat — encrypted 1-to-1 messaging |
| F3 | 📁 Files — send files/folders |
| F4 | 🔏 Stego — steganography encode/decode |
| F5 | 👥 Peers — online peers, aliases |
| F6 | 🌐 Network — Tor, tunnel, SOCKS5 |
| F7 | 📡 Capture — PCAP packet capture |
| F8 | 🔐 Groups — secret channels |
| Ctrl+Q | Quit |

The sidebar shows all online peers. `⟳` means a direct P2P UDP session is active; `·` means relay is being used.

---

## Feature Guide

### Encrypted Chat (F2)

Click a peer in the sidebar, type in the input at the bottom, press Enter or click Send. Messages are AES-256-GCM encrypted with a key derived via X25519 ECDH. The relay server never sees plaintext.

CLI equivalent:
```
> msg a1b2c3d4 hello from alice
> chat a1b2c3d4          # enter live chat mode, Ctrl+C to exit
```

---

### File Transfer (F3)

Paste a file or folder path, select a peer in the sidebar, click Send. Folders are auto-zipped. Each file is encrypted with a per-transfer AES key; SHA-256 is verified on arrival.

When **auto-accept is OFF** (default), the receiver sees a popup with the filename, sender, and size. They have 30 seconds to accept or reject. When **auto-accept is ON**, files save immediately without a prompt.

CLI:
```
> send a1b2c3d4 /path/to/file.pdf
> send a1b2c3d4 /path/to/folder/
```

---

### Steganography (F4)

Hide any file or text message inside an ordinary cover image using LSB embedding. The hidden payload is AES-256-GCM encrypted with a password-derived key (PBKDF2-HMAC-SHA256, 200 000 iterations). The resulting PNG looks identical to the original.

**Encode and send:**
1. Enter a cover image path (JPG, PNG, BMP, TIFF, WebP)
2. Choose "Hide a file" or "Hide a text message"
3. Enter the steg password — share this out-of-band with the receiver
4. Click **Embed & Send**

**Decode on the receiver side:**
- When a stego PNG arrives, the Steg tab opens automatically with the path pre-filled
- Enter the steg password and click **Decode**
- Hidden files are saved to disk; hidden text is shown on screen

Received stego PNGs are always saved to `received_steg/` in the project folder.

CLI:
```
> steg     <peer-id> cover.jpg secret.pdf  mypassword
> stegmsg  <peer-id> cover.jpg "meet at 3" mypassword
> stegdecode received_steg/cover_alice.steg.png mypassword
```

---

### Secret Group Channels (F8)

Channels are hidden from everyone, including the relay server. The server only knows an opaque `channel_id` (SHA-256 hash of the name and password combined). All messages are encrypted with a key derived from the channel password.

**Create a new channel:**
1. Go to Groups (F8)
2. In the green **New Channel** card: enter a name and password
3. Click **Create Channel**
4. Share the name and password with people you want to invite (out-of-band)

**Join an existing channel:**
1. Go to Groups (F8)
2. In the blue **Join Channel** card: enter the exact name and password the creator told you
3. Click **Join Channel**

Create and join are functionally identical (both derive the same channel ID from name+password), but the UI separates them for clarity.

**Leave a channel:** Click the **Leave** button in the top-right of the chat area.

Multiple channels can be active simultaneously. Click a channel name in the left panel to switch between them.

---

### Traffic Tunnel (F6 → Traffic Tunnel)

Routes **all** traffic from your device through the relay server. Requires Linux and root.

1. Connect to the relay (Settings F1)
2. Go to Network (F6)
3. Click **Enable Tunnel**

What happens:
- A TUN interface is created with a random name
- Your existing default route is saved
- Two `/1` cover routes point all traffic at the TUN device
- The relay server's real IP gets a specific `/32` route via your original gateway (prevents routing loop)
- `/etc/resolv.conf` is patched to `8.8.8.8` / `1.1.1.1` to prevent DNS leaks
- All packets are AES-256-GCM encrypted before leaving your machine — the relay server cannot read them

Everything is restored automatically when you click **Disable Tunnel** or quit the TUI.

Verify it's working:
```bash
curl https://ifconfig.me          # should show the server's IP
ip route show                     # should show 0.0.0.0/1 and 128.0.0.0/1 via tun-*
cat /etc/resolv.conf              # should show 8.8.8.8
```

---

### SOCKS5 Proxy (F6 → SOCKS5 Proxy)

Proxy any app through a peer's internet connection. No root required.

1. Click a peer in the sidebar (they become the exit node)
2. Go to Network (F6)
3. Set a local port (default 1080)
4. Click **Start SOCKS5**

Configure your app:
```bash
curl --proxy socks5://127.0.0.1:1080 https://ifconfig.me
# Returns the exit peer's IP

proxychains nmap -sT target.com
# In /etc/proxychains.conf: socks5 127.0.0.1 1080
```

The exit peer's machine handles the actual TCP connections. All SOCKS5 control messages travel through the existing E2E-encrypted relay channel — the relay server only sees opaque ciphertext.

Click **Stop SOCKS5** to shut down the proxy.

---

### Direct P2P (automatic)

When you connect to the relay, `peer.py` binds a UDP socket and registers the port with the server. The server coordinates simultaneous hole-punching between peers — both fire UDP probes at each other at the same time, opening holes in both NATs.

Success rate: ~82% of consumer NAT devices (the remaining ~18%, mostly cellular or large corporate networks, use the relay as fallback automatically).

You do not need to do anything. The `⟳` icon next to a peer in the sidebar means a direct session is active. Direct sessions use ephemeral X25519 key exchange for per-session forward secrecy — even if the long-term identity key is compromised, past direct-session traffic remains protected.

---

### Tor (F6 → Privacy)

Toggle **Route via Tor** and reconnect. The `tor` binary must be installed.

```bash
# Linux
sudo apt install tor

# macOS
brew install tor
```

Alternatively, pass a manual SOCKS5 proxy address (e.g. `socks5://127.0.0.1:9050` for Tor Browser) in the proxy field.

---

### Port Knocking

The server ignores all connection attempts until it receives TCP SYN packets to the knock ports in the correct order. The client sends the knock sequence automatically before connecting.

The default sequence is `1000,2000,3000`. Change it with `--knock-ports` on both server and client.

---

### PCAP Capture (F7)

Captures all packets routed through the traffic tunnel to a standard libpcap file. The traffic tunnel must be active.

1. Go to Capture (F7)
2. Enter a filename (e.g. `capture.pcap`)
3. Click **Start Capture**
4. Generate traffic
5. Click **Stop Capture**
6. Open the file in Wireshark: `wireshark capture.pcap`

---

### Themes

Go to Settings (F1) → Theme and select from:

| Theme | Style |
|-------|-------|
| Dark (default) | Neutral dark, Textual built-in |
| Nord | Arctic blue/teal |
| Gruvbox | Warm amber/brown retro |
| Monokai | Vivid high-contrast |
| Tokyo Night | Deep purple/indigo |

---

### Aliases

Save short names for peer IDs:

```
> alias bob a1b2c3d4
> msg   bob hello
> send  bob /path/to/file
> chat  bob
```

Aliases are stored in `aliases.json` and persist across restarts. In the TUI, use the Peers tab (F5).

---

## CLI Reference

```
python3 client.py --relay <ip> --secret <key> --name <you> [options]

Options:
  --port          Relay port (default: 4001)
  --fingerprint   TLS certificate SHA-256 fingerprint
  --knock-ports   Comma-separated knock sequence (e.g. 1000,2000,3000)
  --tor           Route via Tor
  --proxy         Manual SOCKS5 proxy (e.g. socks5://127.0.0.1:9050)
  --auto-accept   Auto-accept incoming files without prompt
```

Commands once connected:
```
list                                 — list online peers
myid                                 — show your peer ID
msg    <id|alias> <text>             — send encrypted message
chat   <id|alias>                    — enter live chat (Ctrl+C to exit)
send   <id|alias> <path>             — send file or folder
steg   <id|alias> <cover> <file> <pw>     — hide file in image and send
stegmsg <id|alias> <cover> <msg> <pw>     — hide text in image and send
stegdecode <stego.png> <pw>               — extract hidden content
alias  <name> <id>                   — save alias
aliases                              — list saved aliases
history                              — last 20 transfers
exit                                 — disconnect and quit
```

---

## Security Model

| Layer | Mechanism |
|-------|-----------|
| Transport | TLS 1.3, self-signed cert with SHA-256 fingerprint pinning |
| Authentication | HMAC-SHA256 challenge-response + TOTP on each connection |
| Message encryption | X25519 ECDH → HKDF-SHA256 → AES-256-GCM |
| File encryption | Per-transfer AES-256-GCM with HKDF-derived key + SHA-256 integrity |
| Steganography | PBKDF2-HMAC-SHA256 (200k iter) → AES-256-GCM before LSB embed |
| Channel encryption | HKDF(SHA256(password)) → AES-256-GCM, server sees only channel ID hash |
| Tunnel encryption | Per-client HKDF(secret, peer_id) → AES-256-GCM per packet + padding |
| P2P sessions | Ephemeral X25519 → HKDF → AES-256-GCM, forward secrecy per session |
| Replay protection | Nonces + 32-bit sequence numbers with sliding window |
| Server knowledge | Sees: peer IDs, connection times, encrypted blobs. Never sees: keys, plaintext |

The relay server is a dumb router. It cannot read message contents, file data, steganography payloads, channel messages, or tunnel traffic. Even if the server is seized, an attacker gets only authenticated-but-encrypted blobs and connection metadata.

---

## Windows Compatibility

All features work on Windows except:
- **Traffic Tunnel** — requires Linux TUN device and iptables
- **PCAP Capture** — requires Linux traffic tunnel

Everything else — chat, file transfer, steganography, groups, SOCKS5, Tor, P2P, aliases — is fully supported on Windows. Run:

```cmd
python tui.py --relay <server-ip> --secret <key> --name <you>
```

For P2P on older Windows builds where UDP datagrams are not available in the asyncio ProactorEventLoop, `peer.py` silently falls back to relay-only mode — all features continue to work, just without direct connections.

---

## Troubleshooting

**"Cannot reach server" on connect**  
Check firewall rules allow TCP on `--port` and the knock ports. The client must reach all knock ports before the main port.

**File transfer shows "Rejected" even after clicking Accept**  
This was a known bug fixed in the current version. Ensure you are running the latest `tui.py` and `client.py`.

**Steganography: "Cover image too small"**  
Use a larger image. A 1920×1080 JPEG can hold ~800 KB of hidden data. The formula is `(width × height × 3 bits) / 8 bytes`.

**Wrong steg password gives "decryption failed"**  
The steg password is never transmitted — both sides must use the exact same string. Share it out-of-band (e.g. verbally or via a separate secure channel).

**Channel messages not appearing**  
Both peers must join the channel using the exact same name and password (case-sensitive). The channel ID is a SHA-256 hash of `name:password` — one character difference creates a completely different channel.

**P2P not establishing (stays at `·`)**  
You are likely behind symmetric NAT (common on mobile networks and some corporate VPNs). The relay is used as fallback automatically — all features work normally.

**Traffic tunnel: DNS still leaks**  
Check `/etc/resolv.conf` — it should show `8.8.8.8`. If your system uses `systemd-resolved`, the file may be a symlink. Disable it temporarily or configure the resolved stub to use `8.8.8.8`.

---

## License

MIT
