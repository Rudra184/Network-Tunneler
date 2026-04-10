#!/usr/bin/env python3
"""
tui.py — Secure Tunnel TUI
  pip install textual cryptography pillow
  python3 tui.py
"""

import asyncio, os, sys, argparse, base64, logging, time, platform, hashlib
from collections import defaultdict
from urllib.parse import urlparse
from datetime import datetime

if platform.system().lower() == "windows":
    import ctypes
    try: ctypes.windll.kernel32.SetConsoleOutputCP(65001)
    except: pass
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except: pass

try:
    from textual.app import App, ComposeResult
    from textual.binding import Binding
    from textual.containers import Container, Horizontal, Vertical, ScrollableContainer, VerticalScroll
    from textual.widgets import (
        Header, Footer, TabbedContent, TabPane,
        Label, Input, Button, Switch, Static, Select, Rule, RichLog
    )
    from textual.reactive import reactive
    from textual.screen import ModalScreen
    from textual.message import Message
    from textual.css.query import NoMatches
except ImportError:
    print("ERROR: Run:  pip install textual"); sys.exit(1)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from client import (RelayClient, start_tor, stop_tor, TOR_PORT,
                        load_aliases, save_aliases, steg_decode, STEG_RECV_DIR)
    _ok = True
except ImportError as e:
    _ok = False; _err = str(e)

logging.disable(logging.CRITICAL)
log = logging.getLogger("tui")
_PEER_BTN_PREFIX  = "PEERBTN__"
_CHAN_BTN_PREFIX   = "CHANBTN__"
_IS_WINDOWS = platform.system().lower() == "windows"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _derive_channel(name: str, password: str):
    """Return (channel_id_hex_32, aes_key_32_bytes)."""
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.hashes import SHA256
    cid = hashlib.sha256(f"{name.lower()}:{password}".encode()).hexdigest()[:32]
    key = HKDF(algorithm=SHA256(), length=32,
               salt=name.lower().encode(), info=b"channel-msg-v1"
               ).derive(hashlib.sha256(password.encode()).digest())
    return cid, key


# ── Messages ──────────────────────────────────────────────────────────────────

class IncomingChat(Message):
    def __init__(self, peer_id, from_name, text):
        super().__init__()
        self.peer_id = peer_id; self.from_name = from_name; self.text = text

class IncomingGroupMsg(Message):
    def __init__(self, channel_id, from_name, text):
        super().__init__()
        self.channel_id = channel_id; self.from_name = from_name; self.text = text

class XferLog(Message):
    def __init__(self, line):
        super().__init__(); self.line = line

class ShowAcceptModal(Message):
    def __init__(self, from_name, filename, size_str, tid, callback):
        super().__init__()
        self.from_name = from_name; self.filename = filename
        self.size_str  = size_str;  self.tid = tid; self.callback = callback

class StegoSaved(Message):
    def __init__(self, saved_path, from_name, size):
        super().__init__()
        self.saved_path = saved_path; self.from_name = from_name; self.size = size


# ── Accept modal ──────────────────────────────────────────────────────────────

class AcceptModal(ModalScreen):
    CSS = """
    AcceptModal { align: center middle; }
    #dlg { width: 64; height: auto; padding: 1 2; border: thick $accent; background: $surface; }
    #dlg-title { text-style: bold; color: $accent; margin-bottom: 1; }
    #dlg-btns  { margin-top: 1; align: center middle; }
    #b-yes     { margin-right: 2; }
    """
    def __init__(self, from_name, filename, size_str, tid):
        super().__init__()
        self.from_name = from_name; self.filename = filename
        self.size_str  = size_str;  self.tid = tid

    def compose(self) -> ComposeResult:
        with Container(id="dlg"):
            yield Label("Incoming Transfer", id="dlg-title")
            yield Rule()
            yield Label(f"From : {self.from_name}")
            yield Label(f"File : {self.filename}")
            yield Label(f"Size : {self.size_str}")
            yield Rule()
            yield Label("Auto-rejects in 30 s", classes="muted")
            with Horizontal(id="dlg-btns"):
                yield Button("Accept", id="b-yes", variant="success")
                yield Button("Reject", id="b-no",  variant="error")

    def on_button_pressed(self, e: Button.Pressed):
        e.stop()
        self.dismiss(e.button.id == "b-yes")

    def on_mount(self):
        self.set_timer(30, lambda: self.dismiss(False))


# ── App ───────────────────────────────────────────────────────────────────────

class TunnelApp(App):
    TITLE     = "Secure Tunnel"
    SUB_TITLE = "E2E Encrypted · Steganography · Groups"

    CSS = """
    .muted       { color: $text-muted; }
    .card-title  { text-style: bold; color: $accent; margin-bottom: 1; }
    .sec-encode  { text-style: bold; color: $success; margin-bottom: 1; }
    .sec-decode  { text-style: bold; color: $warning; margin-bottom: 1; }

    #root        { layout: horizontal; height: 1fr; }
    #sidebar     { width: 22; height: 1fr; border-right: solid $accent;
                   layout: vertical; padding: 0 1; background: $surface; }
    #sb-title    { text-style: bold; color: $accent; height: 3; padding-left: 1;
                   content-align: left middle; border-bottom: solid $accent; }
    #peer-scroll { height: 1fr; }
    .peer-btn    { width: 100%; height: 3; background: transparent; border: none;
                   text-align: left; padding: 0 1; color: $text; }
    .peer-btn:hover { background: $accent 20%; }
    .peer-btn.-sel  { background: $accent 40%; text-style: bold; }
    #no-peers    { color: $text-muted; text-style: italic; padding: 1 1; height: 3; }
    #myid-box    { height: 4; border-top: solid $accent; padding: 1 0 0 0; }
    #myid-val    { color: $success; text-style: bold; }
    #statusbar   { height: 1; dock: bottom; background: $panel;
                   padding: 0 2; color: $text-muted; }

    /* ── Settings ── */
    #stg-scroll  { height: 1fr; padding: 1 2; }
    .card        { border: solid $panel; padding: 1 2; margin-bottom: 1; height: auto; }
    .field       { layout: vertical; height: auto; margin-bottom: 1; }
    .field > Label { height: 1; color: $text-muted; }
    .field > Input { height: 3; }
    .tog         { layout: horizontal; height: 3; align: left middle; margin-bottom: 1; }
    .tog > Label { width: 28; color: $text-muted; }
    .desc        { color: $text-muted; text-style: italic; height: auto; margin: 0 0 1 2; }
    #stg-btns    { layout: horizontal; height: 3; margin-top: 1; }
    #btn-connect { margin-right: 1; }
    #stg-msg     { height: 2; margin-top: 1; color: $success; }
    #stg-msg.err { color: $error; }

    /* ── Chat ── */
    #chat-wrap   { height: 1fr; layout: vertical; padding: 1; }
    #chat-who    { height: 2; color: $text-muted; text-style: italic; }
    #chat-log    { height: 1fr; border: solid $panel; padding: 0 1; }
    #chat-row    { layout: horizontal; height: 3; margin-top: 1; }
    #chat-inp    { width: 1fr; }
    #btn-csend   { width: 10; margin-left: 1; }

    /* ── Files ── */
    #files-wrap  { height: 1fr; layout: horizontal; }
    #f-left      { width: 30; height: 1fr; border-right: solid $panel;
                   padding: 1; layout: vertical; }
    #f-right     { width: 1fr; height: 1fr; padding: 1; layout: vertical; }
    #f-hint      { height: 5; border: dashed $panel; padding: 1;
                   color: $text-muted; text-style: italic; margin-bottom: 1;
                   content-align: center middle; }
    #f-path      { height: 3; margin-bottom: 1; }
    #f-to        { height: 2; color: $text-muted; }
    #btn-fsend   { margin-top: 1; }
    #xfer-log    { height: 1fr; border: solid $panel; padding: 0 1; }

    /* ── Steganography ── */
    #steg-scroll { height: 1fr; padding: 1 2; }
    #enc-card    { border: solid $success; padding: 1 2; margin-bottom: 1; height: auto; }
    .ef          { layout: vertical; height: auto; margin-bottom: 1; }
    .ef > Label  { height: 1; color: $text-muted; }
    .ef > Input  { height: 3; }
    #enc-sel     { height: 3; margin-bottom: 1; }
    #enc-to      { height: 2; color: $text-muted; margin-bottom: 1; }
    #btn-encode  { margin-top: 1; }
    #enc-status  { height: 2; margin-top: 1; }
    #dec-card    { border: solid $warning; padding: 1 2; margin-bottom: 1; height: auto; }
    #dec-recv-dir { height: 3; color: $success; text-style: italic; margin-bottom: 1; }
    .df          { layout: vertical; height: auto; margin-bottom: 1; }
    .df > Label  { height: 1; color: $text-muted; }
    .df > Input  { height: 3; }
    #btn-decode  { margin-top: 1; }
    #dec-status  { height: 2; margin-top: 1; }
    #dec-result  { height: 8; border: solid $panel; padding: 0 1; margin-top: 1; }

    /* ── Peers ── */
    #peers-wrap    { height: 1fr; layout: vertical; padding: 1; }
    #peers-log     { height: 1fr; border: solid $panel; padding: 0 1; }
    #alias-section { height: 20; border-top: solid $panel; padding: 1;
                     margin-top: 1; layout: vertical; }
    #inp-alias-name { height: 3; margin-bottom: 1; }
    #inp-alias-id   { height: 3; margin-bottom: 1; }
    #btn-save-alias { margin-bottom: 1; }
    #alias-log      { height: 1fr; border: solid $panel; padding: 0 1; }

    /* ── Network tab ── */
    #net-scroll  { height: 1fr; padding: 1 2; }
    #tun-card    { border: solid $warning; padding: 1 2; margin-bottom: 1; height: auto; }
    #tun-status  { height: 2; margin-top: 1; }
    #btn-tunnel  { width: 26; }
    #socks-card  { border: solid $primary; padding: 1 2; margin-bottom: 1; height: auto; }
    #socks-status { height: 2; margin-top: 1; }
    #btn-socks   { width: 26; }
    #socks-peer-lbl { height: 2; color: $text-muted; margin-bottom: 1; }

    /* ── Capture tab ── */
    #pcap-wrap     { height: 1fr; layout: vertical; padding: 1; }
    #pcap-ctrl     { layout: vertical; height: auto; margin-bottom: 1; }
    #inp-pcap-path { height: 3; margin-bottom: 1; }
    #btn-pcap      { height: 3; }
    #pcap-status   { height: 2; color: $text-muted; margin-bottom: 1; }
    #pcap-log      { height: 1fr; border: solid $panel; padding: 0 1; }

    /* ── Groups tab ── */
    #grp-wrap    { height: 1fr; layout: horizontal; }
    #grp-left    { width: 32; height: 1fr; border-right: solid $panel;
                   padding: 1; layout: vertical; }
    #grp-right   { width: 1fr; height: 1fr; padding: 1; layout: vertical; }
    #grp-chan-scroll { height: 1fr; }
    .grp-chan-btn { width: 100%; height: 3; background: transparent; border: none;
                    text-align: left; padding: 0 1; color: $text; margin-bottom: 0; }
    .grp-chan-btn:hover { background: $accent 20%; }
    .grp-chan-btn.-sel  { background: $accent 40%; text-style: bold; }
    #grp-who     { height: 2; color: $text-muted; text-style: italic; }
    #grp-log     { height: 1fr; border: solid $panel; padding: 0 1; }
    #grp-inp-row { layout: horizontal; height: 3; margin-top: 1; }
    #grp-inp     { width: 1fr; }
    #btn-grp-send { width: 10; margin-left: 1; }
    #grp-create-card  { border: solid $success; padding: 1 2;
                        margin-bottom: 1; height: auto; }
    #grp-action-row   { layout: horizontal; height: 3; margin-top: 1; }
    #grp-action-row Button { width: 1fr; margin-right: 1; }
    #grp-action-row Button:last-of-type { margin-right: 0; }
    #grp-header-row   { layout: horizontal; height: 2; margin-bottom: 0; }
    #grp-who          { width: 1fr; color: $text-muted; text-style: italic; }
    .grp-leave-btn    { width: 10; height: 2; min-width: 0; }
    #sel-theme        { height: 3; margin-top: 1; }
    """

    BINDINGS = [
        Binding("ctrl+q", "quit",        "Quit"),
        Binding("f1",     "go_settings", "⚙ Settings"),
        Binding("f2",     "go_chat",     "💬 Chat"),
        Binding("f3",     "go_files",    "📁 Files"),
        Binding("f4",     "go_steg",     "🔏 Stego"),
        Binding("f5",     "go_peers",    "👥 Peers"),
        Binding("f6",     "go_network",  "🌐 Network"),
        Binding("f7",     "go_capture",  "📡 Capture"),
        Binding("f8",     "go_groups",   "🔐 Groups"),
    ]

    connected     = reactive(False)
    selected_peer = reactive("")
    tunnel_active = reactive(False)
    socks_active  = reactive(False)
    pcap_active   = reactive(False)

    def __init__(self, args):
        super().__init__()
        self._client       = None; self._tor_managed  = False
        self._chat_logs    = defaultdict(list)
        self._channel_logs = defaultdict(list)   # channel_id → [(ts, who, text)]
        self._channels     = {}                  # channel_id → {name, key}
        self._current_channel: str = ""
        self._aliases      = load_aliases()
        self._msg_task     = None; self._mounted = False
        self._shown_peers: dict = {}
        self._relay        = args.relay;   self._port   = args.port
        self._secret       = args.secret;  self._name   = args.name
        self._fp           = getattr(args, "fingerprint", "")
        self._knock        = getattr(args, "knock_ports",  "")
        self._use_tor      = getattr(args, "tor",          False)
        self._proxy        = getattr(args, "proxy",        "")
        self._auto_accept  = getattr(args, "auto_accept",  False)
        self._pcap_path    = ""
        self._pcap_counter = 0

    # ── compose ───────────────────────────────────────────────────────────────

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="root"):
            with Vertical(id="sidebar"):
                yield Label("PEERS", id="sb-title")
                with VerticalScroll(id="peer-scroll"):
                    yield Label("(not connected)", id="no-peers", classes="muted")
                with Vertical(id="myid-box"):
                    yield Label("Your ID", classes="muted")
                    yield Label("—", id="myid-val")

            with TabbedContent(id="tabs", initial="tab-settings"):

                # ── F1 Settings ──────────────────────────────────────────────
                with TabPane("⚙  Settings", id="tab-settings"):
                    with ScrollableContainer(id="stg-scroll"):
                        yield Static("Fill in details and click Connect.", classes="muted")
                        yield Rule()
                        with Vertical(classes="card"):
                            yield Label("Connection", classes="card-title")
                            with Vertical(classes="field"):
                                yield Label("Relay server IP / hostname")
                                yield Input(value=self._relay,
                                            placeholder="e.g. 100.31.6.224", id="i-relay")
                            with Vertical(classes="field"):
                                yield Label("Port")
                                yield Input(value=str(self._port),
                                            placeholder="4001", id="i-port")
                            with Vertical(classes="field"):
                                yield Label("Secret key")
                                yield Input(value=self._secret, password=True,
                                            placeholder="Shared tunnel secret", id="i-secret")
                            with Vertical(classes="field"):
                                yield Label("Your display name")
                                yield Input(value=self._name,
                                            placeholder="e.g. alice", id="i-name")
                            with Vertical(classes="field"):
                                yield Label("TLS Fingerprint  (leave blank to skip)")
                                yield Input(value=self._fp,
                                            placeholder="SHA-256 hex", id="i-fp")
                        with Vertical(classes="card"):
                            yield Label("Port Knocking", classes="card-title")
                            with Vertical(classes="field"):
                                yield Label("Knock sequence  (comma-separated)")
                                yield Input(value=self._knock,
                                            placeholder="e.g. 1000,2000,3000", id="i-knock")
                        with Vertical(classes="card"):
                            yield Label("Transfers", classes="card-title")
                            with Horizontal(classes="tog"):
                                yield Label("Auto-accept incoming files")
                                yield Switch(value=self._auto_accept, id="sw-aa")
                            yield Static(
                                "When OFF: popup lets you accept or reject each transfer.",
                                classes="desc")
                        with Vertical(classes="card"):
                            yield Label("Theme", classes="card-title")
                            yield Select(
                                [
                                    ("Dark  (default)",  "textual-dark"),
                                    ("Nord  (arctic)",   "nord"),
                                    ("Gruvbox  (warm)",  "gruvbox"),
                                    ("Monokai  (vivid)", "monokai"),
                                    ("Tokyo Night",      "tokyo-night"),
                                ],
                                id="sel-theme", value="textual-dark")
                        yield Rule()
                        with Horizontal(id="stg-btns"):
                            yield Button("Connect",    id="btn-connect",    variant="success")
                            yield Button("Disconnect", id="btn-disconnect", variant="error")
                        yield Label("", id="stg-msg")

                # ── F2 Chat ───────────────────────────────────────────────────
                with TabPane("💬 Chat", id="tab-chat"):
                    with Vertical(id="chat-wrap"):
                        yield Label("Click a peer in the sidebar to chat", id="chat-who")
                        yield RichLog(id="chat-log", auto_scroll=True,
                                      markup=True, highlight=True)
                        with Horizontal(id="chat-row"):
                            yield Input(placeholder="Type a message …", id="chat-inp")
                            yield Button("Send", id="btn-csend", variant="primary")

                # ── F3 Files ──────────────────────────────────────────────────
                with TabPane("📁 Files", id="tab-files"):
                    with Horizontal(id="files-wrap"):
                        with Vertical(id="f-left"):
                            yield Label("Send a file or folder", classes="card-title")
                            yield Static(
                                "Paste the full path below.\nFolders are auto-zipped.",
                                id="f-hint")
                            yield Input(placeholder="/home/user/secret.pdf", id="f-path")
                            yield Label("To: (select peer in sidebar)", id="f-to")
                            yield Button("Send", id="btn-fsend", variant="primary")
                        with Vertical(id="f-right"):
                            yield Label("Transfer log", classes="card-title")
                            yield RichLog(id="xfer-log", auto_scroll=True, markup=True)

                # ── F4 Steganography ──────────────────────────────────────────
                with TabPane("🔏 Stego", id="tab-steg"):
                    with ScrollableContainer(id="steg-scroll"):
                        yield Label("ENCODE — hide data inside a cover image",
                                    classes="sec-encode")
                        with Vertical(id="enc-card"):
                            with Vertical(classes="ef"):
                                yield Label("Cover image  (JPG, PNG, BMP, TIFF, WebP)")
                                yield Input(placeholder="/home/user/photo.jpg",
                                            id="enc-cover")
                            yield Label("What to hide", classes="muted")
                            yield Select(
                                [("Hide a file", "file"), ("Hide a text message", "msg")],
                                id="enc-sel", value="file")
                            with Vertical(classes="ef"):
                                yield Label("File to hide")
                                yield Input(placeholder="/home/user/document.pdf",
                                            id="enc-file")
                            with Vertical(classes="ef"):
                                yield Label("Message to hide")
                                yield Input(placeholder="Type your secret message …",
                                            id="enc-msg")
                            with Vertical(classes="ef"):
                                yield Label("Steg password  (tell receiver out-of-band)")
                                yield Input(placeholder="correct-horse-battery-staple",
                                            id="enc-pass", password=True)
                            yield Label("To: (select peer in sidebar)", id="enc-to")
                            yield Button("Embed & Send", id="btn-encode", variant="success")
                            yield Label("", id="enc-status")
                        yield Rule()
                        yield Label("DECODE — extract hidden data from a stego image",
                                    classes="sec-decode")
                        with Vertical(id="dec-card"):
                            yield Label(
                                f"Received stego PNGs saved to:\n  {STEG_RECV_DIR}",
                                id="dec-recv-dir")
                            with Vertical(classes="df"):
                                yield Label("Stego image path  (auto-filled on receive)")
                                yield Input(
                                    placeholder=f"{STEG_RECV_DIR}/photo.steg.png",
                                    id="dec-path")
                            with Vertical(classes="df"):
                                yield Label("Steg password")
                                yield Input(placeholder="Enter the steg password …",
                                            id="dec-pass", password=True)
                            yield Button("Decode", id="btn-decode", variant="warning")
                            yield Label("", id="dec-status")
                            yield RichLog(id="dec-result", auto_scroll=True, markup=True)

                # ── F5 Peers ──────────────────────────────────────────────────
                with TabPane("👥 Peers", id="tab-peers"):
                    with Vertical(id="peers-wrap"):
                        yield Label("Online peers", classes="card-title")
                        yield RichLog(id="peers-log", auto_scroll=False, markup=True)
                        with Vertical(id="alias-section"):
                            yield Label("Aliases", classes="card-title")
                            yield Label("Save a short name for a peer ID.",
                                        classes="muted")
                            yield Input(placeholder="Alias  e.g. bob",
                                        id="inp-alias-name")
                            yield Input(placeholder="Peer ID  e.g. a1b2c3d4",
                                        id="inp-alias-id")
                            yield Button("Save alias", id="btn-save-alias",
                                         variant="primary")
                            yield RichLog(id="alias-log", auto_scroll=False,
                                          markup=True)

                # ── F6 Network ────────────────────────────────────────────────
                with TabPane("🌐 Network", id="tab-network"):
                    with ScrollableContainer(id="net-scroll"):
                        yield Static(
                            "Privacy routing, traffic tunnel, and SOCKS5 proxy.",
                            classes="muted")
                        yield Rule()
                        with Vertical(classes="card"):
                            yield Label("Privacy", classes="card-title")
                            with Horizontal(classes="tog"):
                                yield Label("Route via Tor")
                                yield Switch(value=self._use_tor, id="sw-tor")
                            yield Static(
                                "Tor must be installed.  Connects via local SOCKS5 proxy.",
                                classes="desc")
                            with Vertical(classes="field"):
                                yield Label("Manual SOCKS5 proxy  (overrides Tor)")
                                yield Input(value=self._proxy,
                                            placeholder="socks5://127.0.0.1:9050",
                                            id="i-proxy")
                        with Vertical(id="tun-card"):
                            yield Label("Traffic Tunnel", classes="card-title")
                            yield Static(
                                "Routes ALL device traffic through the relay server.\n"
                                "Requires root/sudo.  Linux only.",
                                classes="desc")
                            yield Button("Enable Tunnel", id="btn-tunnel",
                                         variant="warning")
                            yield Label("", id="tun-status")
                        with Vertical(id="socks-card"):
                            yield Label("SOCKS5 Proxy", classes="card-title")
                            yield Static(
                                "Proxy any app through a peer's internet connection.\n"
                                "Configure your app to use SOCKS5 on 127.0.0.1:1080.\n"
                                "E2E encrypted — relay server sees nothing.",
                                classes="desc")
                            with Vertical(classes="field"):
                                yield Label("Local listener port")
                                yield Input(value="1080", placeholder="1080",
                                            id="i-socks-port")
                            yield Label("Exit peer: select in sidebar",
                                        id="socks-peer-lbl", classes="muted")
                            yield Button("Start SOCKS5", id="btn-socks",
                                         variant="primary")
                            yield Label("", id="socks-status")

                # ── F7 Capture ────────────────────────────────────────────────
                with TabPane("📡 Capture", id="tab-capture"):
                    with Vertical(id="pcap-wrap"):
                        yield Label("PCAP Packet Capture", classes="card-title")
                        yield Static(
                            "Capture all tunnelled packets to a libpcap file.\n"
                            "Traffic tunnel must be active.  Opens in Wireshark.",
                            classes="desc")
                        with Vertical(id="pcap-ctrl"):
                            yield Input(
                                placeholder="capture.pcap",
                                id="inp-pcap-path")
                            yield Button("  Start Capture", id="btn-pcap",
                                         variant="success")
                        yield Label("", id="pcap-status")
                        yield Label("Capture log", classes="card-title")
                        yield RichLog(id="pcap-log", auto_scroll=True, markup=True)

                # ── F8 Groups ─────────────────────────────────────────────────
                with TabPane("🔐 Groups", id="tab-groups"):
                    with Horizontal(id="grp-wrap"):
                        with Vertical(id="grp-left"):
                            yield Label("Secret Channels", classes="card-title")
                            yield Static(
                                "Channels are hidden — only peers with\n"
                                "the name and password can join.",
                                classes="muted")
                            with Vertical(id="grp-create-card"):
                                yield Label("Channel", classes="card-title")
                                with Vertical(classes="field"):
                                    yield Label("Channel name")
                                    yield Input(placeholder="e.g. ops-alpha",
                                                id="inp-grp-name")
                                with Vertical(classes="field"):
                                    yield Label("Password")
                                    yield Input(placeholder="channel password",
                                                id="inp-grp-pass", password=True)
                                with Horizontal(id="grp-action-row"):
                                    yield Button("Create", id="btn-grp-create",
                                                 variant="success")
                                    yield Button("Join", id="btn-grp-join",
                                                 variant="primary")
                            yield Label("Active channels", classes="muted")
                            with VerticalScroll(id="grp-chan-scroll"):
                                yield Label("(none)", id="no-channels",
                                            classes="muted")
                        with Vertical(id="grp-right"):
                            with Horizontal(id="grp-header-row"):
                                yield Label("No channel selected", id="grp-who")
                                yield Button("Leave", id="btn-grp-leave",
                                             variant="error",
                                             classes="grp-leave-btn")
                            yield RichLog(id="grp-log", auto_scroll=True,
                                          markup=True, highlight=True)
                            with Horizontal(id="grp-inp-row"):
                                yield Input(placeholder="Type a message …",
                                            id="grp-inp")
                                yield Button("Send", id="btn-grp-send",
                                             variant="primary")

        yield Label("Settings (F1) → fill details → Connect", id="statusbar")
        yield Footer()

    # ── lifecycle ──────────────────────────────────────────────────────────────

    async def on_mount(self):
        self._mounted = True; self._draw_alias_log()
        self.set_interval(1.0, self._tick)
        if self._relay and self._secret:
            asyncio.get_event_loop().call_later(
                0.4, lambda: asyncio.create_task(self._do_connect()))

    async def on_unmount(self):
        if self._mounted:
            try: await self._disconnect()
            except: pass

    async def action_quit(self):
        try: await self._disconnect()
        except: pass
        self.exit()

    # ── message handlers ───────────────────────────────────────────────────────

    def on_incoming_chat(self, msg: IncomingChat):
        ts = datetime.now().strftime("%H:%M")
        self._chat_logs[msg.peer_id].append((ts, msg.from_name, msg.text))
        if self.selected_peer == msg.peer_id:
            rl = self._q("#chat-log", RichLog)
            if rl: rl.write(f"[{ts}] [bold cyan]{msg.from_name}[/bold cyan]: {msg.text}")

    def on_incoming_group_msg(self, msg: IncomingGroupMsg):
        ts = datetime.now().strftime("%H:%M")
        self._channel_logs[msg.channel_id].append(
            (ts, msg.from_name, msg.text))
        if self._current_channel == msg.channel_id:
            rl = self._q("#grp-log", RichLog)
            if rl: rl.write(
                f"[{ts}] [bold cyan]{msg.from_name}[/bold cyan]: {msg.text}")

    def on_xfer_log(self, msg: XferLog):
        xl = self._q("#xfer-log", RichLog)
        if xl: xl.write(msg.line)

    def on_show_accept_modal(self, msg: ShowAcceptModal):
        def _cb(result):
            msg.callback(result is True)
        self.push_screen(
            AcceptModal(msg.from_name, msg.filename, msg.size_str, msg.tid),
            callback=_cb)

    def on_stego_saved(self, msg: StegoSaved):
        ts = datetime.now().strftime("%H:%M")
        xl = self._q("#xfer-log", RichLog)
        if xl:
            xl.write(
                f"[{ts}] [bold magenta]Stego PNG received[/bold magenta] "
                f"from [cyan]{msg.from_name}[/cyan]  ({msg.size} bytes)\n"
                f"  Saved to [bold]{msg.saved_path}[/bold]\n"
                f"  Stego tab (F4) → DECODE → enter password")
        dec = self._q("#dec-path", Input)
        if dec: dec.value = msg.saved_path
        ds = self._q("#dec-status", Label)
        if ds: ds.update(
            f"[bold cyan]Stego received from {msg.from_name}[/bold cyan]  "
            f"Enter password above and click Decode.")
        dr = self._q("#dec-result", RichLog)
        if dr:
            dr.clear()
            dr.write(f"[bold yellow]Ready to decode:[/bold yellow]  {msg.saved_path}")
        self._go("tab-steg")

    # ── tick ──────────────────────────────────────────────────────────────────

    async def _tick(self):
        if not self._client or not self.connected: return
        await self._update_sidebar(); self._draw_peers_log()

    # ── sidebar ───────────────────────────────────────────────────────────────

    async def _update_sidebar(self):
        if not self._client: return
        current = dict(self._client.peers)
        id2al   = {v: k for k, v in self._aliases.items()}
        desired = {}
        for pid, pname in current.items():
            al = id2al.get(pid, "")
            desired[pid] = f"  {pname}" + (f" ({al})" if al else "")
        if desired == self._shown_peers: return
        scroll = self._q("#peer-scroll", VerticalScroll)
        if not scroll: return
        for btn in list(scroll.query(Button)):
            if btn.id and btn.id.startswith(_PEER_BTN_PREFIX):
                await btn.remove()
        np = self._q("#no-peers", Label)
        if not desired:
            if np: np.display = True
            self._shown_peers = {}; return
        if np: np.display = False
        for pid, lbl in desired.items():
            btn = Button(lbl, id=f"{_PEER_BTN_PREFIX}{pid}", classes="peer-btn")
            if pid == self.selected_peer: btn.add_class("-sel")
            await scroll.mount(btn)
        self._shown_peers = desired

    def _q(self, sel, cls=None):
        try:    return self.query_one(sel, cls) if cls else self.query_one(sel)
        except NoMatches: return None

    def _val(self, sel):
        w = self._q(sel, Input); return w.value.strip() if w else ""

    def _sw(self, sel):
        w = self._q(sel, Switch); return bool(w.value) if w else False

    def watch_connected(self, val):
        sb = self._q("#statusbar", Label)
        if not sb: return
        if val and self._client:
            sb.update(
                f"Connected  |  {self._relay}:{self._port}"
                f"  |  {self._name}  |  id: {self._client.my_id}")
        else:
            sb.update("Disconnected — Settings (F1) → Connect")
        np = self._q("#no-peers", Label)
        if np:
            np.update("(not connected)" if not val else "(no peers yet)")
            np.display = not val

    def watch_selected_peer(self, pid):
        if not self._mounted: return
        for btn in self.query(Button):
            if btn.id and btn.id.startswith(_PEER_BTN_PREFIX):
                btn_pid = btn.id[len(_PEER_BTN_PREFIX):]
                if btn_pid == pid: btn.add_class("-sel")
                else:              btn.remove_class("-sel")
        w = self._q("#chat-who", Label)
        if w:
            if pid and self._client and pid in self._client.peers:
                pname = self._client.peers[pid]
                al    = {v: k for k, v in self._aliases.items()}.get(pid, "")
                w.update(
                    f"Chatting with [bold]{pname}[/bold] [{pid}]"
                    + (f"  alias:{al}" if al else ""))
                self._restore_chat(pid)
            else:
                w.update("Click a peer in the sidebar to chat")
        txt = self._peer_display()
        lbl_s = self._q("#socks-peer-lbl", Label)
        if lbl_s: lbl_s.update(
            f"Exit peer: [bold]{txt}[/bold]" if pid else
            "Exit peer: select in sidebar")
        for sel in ("#f-to", "#enc-to"):
            lbl = self._q(sel, Label)
            if lbl: lbl.update(
                f"To: [bold]{txt}[/bold]" if pid else
                "To: (select peer in sidebar)")

    def _go(self, tab):
        tc = self._q("#tabs", TabbedContent)
        if tc: tc.active = tab

    def action_go_settings(self): self._go("tab-settings")
    def action_go_chat(self):     self._go("tab-chat")
    def action_go_files(self):    self._go("tab-files")
    def action_go_steg(self):     self._go("tab-steg")
    def action_go_peers(self):    self._go("tab-peers")
    def action_go_network(self):  self._go("tab-network")
    def action_go_capture(self):  self._go("tab-capture")
    def action_go_groups(self):   self._go("tab-groups")

    # ── button dispatch ───────────────────────────────────────────────────────

    async def on_button_pressed(self, e: Button.Pressed):
        bid = e.button.id or ""
        if bid.startswith(_PEER_BTN_PREFIX):
            self.selected_peer = bid[len(_PEER_BTN_PREFIX):]; return
        if bid.startswith(_CHAN_BTN_PREFIX):
            self._current_channel = bid[len(_CHAN_BTN_PREFIX):]
            self._restore_group_chat(self._current_channel)
            self._update_chan_buttons()
            return
        handlers = {
            "btn-connect":     lambda: (self._read_settings(),
                                        asyncio.ensure_future(self._do_connect())),
            "btn-disconnect":  lambda: asyncio.ensure_future(self._disconnect()),
            "btn-csend":       lambda: asyncio.ensure_future(self._send_chat()),
            "btn-fsend":       lambda: asyncio.ensure_future(self._send_file()),
            "btn-encode":      lambda: asyncio.ensure_future(self._send_steg()),
            "btn-decode":      lambda: asyncio.ensure_future(self._decode_steg()),
            "btn-save-alias":  lambda: self._save_alias(),
            "btn-tunnel":      lambda: asyncio.ensure_future(self._toggle_tunnel()),
            "btn-socks":       lambda: asyncio.ensure_future(self._toggle_socks()),
            "btn-pcap":        lambda: asyncio.ensure_future(self._toggle_pcap()),
            "btn-grp-create":  lambda: asyncio.ensure_future(self._create_channel()),
            "btn-grp-join":    lambda: asyncio.ensure_future(self._join_channel()),
            "btn-grp-leave":   lambda: asyncio.ensure_future(self._leave_channel()),
            "btn-grp-send":    lambda: asyncio.ensure_future(self._send_group_msg()),
        }
        h = handlers.get(bid)
        if h: h()

    async def on_input_submitted(self, e):
        if e.input.id == "chat-inp": await self._send_chat()
        if e.input.id == "grp-inp":  await self._send_group_msg()

    def on_select_changed(self, e: Select.Changed):
        if e.select.id == "sel-theme" and e.value:
            try:
                self.theme = str(e.value)
            except Exception:
                pass   # theme not available in this textual version — ignore

    # ── settings ──────────────────────────────────────────────────────────────

    def _read_settings(self):
        self._relay = self._val("#i-relay")
        self._secret = self._val("#i-secret")
        self._name  = self._val("#i-name") or "peer"
        self._fp    = self._val("#i-fp")
        self._knock = self._val("#i-knock")
        self._proxy = self._val("#i-proxy")
        self._use_tor     = self._sw("#sw-tor")
        self._auto_accept = self._sw("#sw-aa")
        try:    self._port = int(self._val("#i-port") or "4001")
        except: self._port = 4001

    def _stg_msg(self, msg, err=False):
        w = self._q("#stg-msg", Label)
        if not w: return
        w.update(msg)
        if err: w.add_class("err")
        else:   w.remove_class("err")

    # ── connect / disconnect ──────────────────────────────────────────────────

    async def _do_connect(self):
        if self.connected:   self._stg_msg("Already connected"); return
        if not self._relay:  self._stg_msg("Relay IP is required", err=True); return
        if not self._secret: self._stg_msg("Secret key is required", err=True); return
        self._stg_msg("Connecting …")

        if self._use_tor and not self._tor_managed:
            try:
                await asyncio.get_event_loop().run_in_executor(None, start_tor)
                self._tor_managed = True
            except Exception as ex:
                self._stg_msg(f"Tor failed: {ex} — connecting directly", err=True)

        proxy = None
        if self._use_tor: proxy = urlparse(f"socks5://127.0.0.1:{TOR_PORT}")
        elif self._proxy: proxy = urlparse(self._proxy)

        knock_ports = []
        if self._knock:
            try:    knock_ports = list(map(int, self._knock.split(",")))
            except: self._stg_msg("Bad knock format", err=True); return

        self._client = RelayClient(
            host=self._relay, port=self._port, name=self._name,
            secret=self._secret, fingerprint=self._fp or None,
            proxy=proxy, knock_ports=knock_ports,
            auto_accept=self._auto_accept,
        )

        app_ref = self

        # ── Hook: accept prompt ───────────────────────────────────────────────
        async def tui_prompt_accept(tid, from_name, filename, size_bytes):
            if app_ref._auto_accept: return True
            size_str = (
                f"{size_bytes/(1024*1024):.1f} MB" if size_bytes > 1_048_576
                else f"{size_bytes//1024} KB"       if size_bytes > 1024
                else f"{size_bytes} B")
            accepted_result = [False]
            accepted_event  = asyncio.Event()
            def _on_modal_done(accepted: bool):
                accepted_result[0] = accepted; accepted_event.set()
            app_ref.post_message(ShowAcceptModal(
                from_name, filename, size_str, tid, _on_modal_done))
            deadline = time.monotonic() + 36
            while not accepted_event.is_set() and time.monotonic() < deadline:
                await asyncio.sleep(0.05)
            return accepted_result[0]

        def on_stego_saved(saved_path, from_name, size):
            app_ref.post_message(StegoSaved(saved_path, from_name, size))

        def on_xfer_status(msg_str, is_err):
            ts  = datetime.now().strftime("%H:%M")
            col = "red" if is_err else "green"
            app_ref.post_message(XferLog(f"[{ts}] [{col}]{msg_str}[/{col}]"))

        def on_tunnel_status(msg_str: str, is_err: bool):
            app_ref.tunnel_active = (not is_err and "active" in msg_str)
            lbl = app_ref._q("#tun-status", Label)
            col = "red" if is_err else "green"
            if lbl: lbl.update(f"[{col}]{msg_str}[/{col}]")
            ts = datetime.now().strftime("%H:%M")
            app_ref.post_message(XferLog(f"[{ts}] [{col}]{msg_str}[/{col}]"))

        def on_socks_status(msg_str: str, is_err: bool):
            app_ref.socks_active = (not is_err and "active" in msg_str)
            lbl = app_ref._q("#socks-status", Label)
            col = "red" if is_err else "green"
            if lbl: lbl.update(f"[{col}]{msg_str}[/{col}]")

        def on_pcap_ack(ok: bool, info: str):
            ts  = datetime.now().strftime("%H:%M")
            col = "green" if ok else "red"
            pl  = app_ref._q("#pcap-log", RichLog)
            if pl: pl.write(f"[{ts}] [{col}]PCAP: {info}[/{col}]")
            ps  = app_ref._q("#pcap-status", Label)
            if ps: ps.update(f"[{col}]{info}[/{col}]")

        def on_channel_msg(channel_id: str, from_name: str, text: str):
            app_ref.post_message(IncomingGroupMsg(channel_id, from_name, text))

        self._client._prompt_accept    = tui_prompt_accept
        self._client._on_stego_saved   = on_stego_saved
        self._client._on_xfer_status   = on_xfer_status
        self._client._on_tunnel_status = on_tunnel_status
        self._client._on_socks_status  = on_socks_status
        self._client._on_pcap_ack      = on_pcap_ack
        self._client._on_channel_msg   = on_channel_msg

        try:
            await self._client.connect()
        except Exception as ex:
            self._stg_msg(f"Failed: {ex}", err=True)
            self._client = None; return

        self.connected = True
        w = self._q("#myid-val", Label)
        if w: w.update(self._client.my_id or "—")
        self._stg_msg(f"Connected  id = {self._client.my_id}")
        self._msg_task = asyncio.create_task(self._intercept_callbacks())

        # Re-join any channels we were in before reconnect
        for cid, info in self._channels.items():
            try:
                await self._client._send({"type": "join_channel", "channel_id": cid})
            except Exception:
                pass

    async def _disconnect(self):
        if self._client and getattr(self._client, "_socks", None):
            try: await self._client.stop_socks()
            except: pass
        self.socks_active = False
        if self._client and getattr(self._client, "_tunnel", None):
            try: await self._client.stop_tunnel()
            except: pass
        self.tunnel_active = False
        # Leave all channels
        if self._client:
            for cid in list(self._channels):
                try:
                    await self._client._send(
                        {"type": "leave_channel", "channel_id": cid})
                except: pass
        if self._msg_task:
            self._msg_task.cancel(); self._msg_task = None
        if self._client:
            try: await self._client.disconnect()
            except: pass
            self._client = None
        if self._tor_managed:
            try: await asyncio.get_event_loop().run_in_executor(None, stop_tor)
            except: pass
            self._tor_managed = False
        self.connected = False; self.selected_peer = ""; self._shown_peers = {}
        scroll = self._q("#peer-scroll", VerticalScroll)
        if scroll:
            for btn in list(scroll.query(Button)):
                if btn.id and btn.id.startswith(_PEER_BTN_PREFIX):
                    try: await btn.remove()
                    except: pass
        np = self._q("#no-peers", Label)
        if np: np.update("(not connected)"); np.display = True

    # ── intercept callbacks ───────────────────────────────────────────────────

    async def _intercept_callbacks(self):
        if not self._client: return
        orig_msg  = self._client._receive_message
        orig_file = self._client._receive_file
        app_ref   = self

        async def intercept_msg(msg):
            from_id   = msg.get("from_id", "?")
            from_name = msg.get("from_name", from_id)
            key = await app_ref._client.get_shared_key(from_id)
            if key:
                try:
                    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                    pl   = base64.b64decode(msg.get("payload", ""))
                    n    = base64.b64decode(msg.get("nonce", ""))
                    text = AESGCM(key).decrypt(n, pl, None).decode()
                    app_ref.post_message(IncomingChat(from_id, from_name, text))
                    return
                except Exception: pass
            await orig_msg(msg)

        async def intercept_file(meta):
            await orig_file(meta)
            if not meta.get("steg", False):
                from_name = meta.get("from_name", "?")
                fname     = meta.get("display_name", "file")
                size      = meta.get("size", 0)
                ts        = datetime.now().strftime("%H:%M")
                app_ref.post_message(XferLog(
                    f"[{ts}] [cyan]{from_name}[/cyan]: "
                    f"[bold]{fname}[/bold]  ({size} B)"))

        self._client._receive_message = intercept_msg
        self._client._receive_file    = intercept_file

        while self.connected and self._client:
            await asyncio.sleep(5.0)

    # ── tunnel ────────────────────────────────────────────────────────────────

    def watch_tunnel_active(self, val: bool):
        btn = self._q("#btn-tunnel", Button)
        if not btn: return
        btn.label   = "Disable Tunnel" if val else "Enable Tunnel"
        btn.variant = "error"          if val else "warning"

    async def _toggle_tunnel(self):
        if _IS_WINDOWS:
            self._stg_msg("Traffic tunnel is Linux-only", err=True); return
        if not self.connected or not self._client:
            self._stg_msg("Connect first", err=True); return
        lbl    = self._q("#tun-status", Label)
        tunnel = getattr(self._client, "_tunnel", None)
        if tunnel and tunnel.active:
            if lbl: lbl.update("[yellow]Stopping tunnel …[/yellow]")
            try:
                await self._client.stop_tunnel()
                self.tunnel_active = False
                if lbl: lbl.update("[green]Tunnel stopped — routes restored[/green]")
            except Exception as e:
                if lbl: lbl.update(f"[red]Stop failed: {e}[/red]")
        else:
            if lbl: lbl.update("[yellow]Requesting tunnel from server …[/yellow]")
            try:
                await self._client.start_tunnel()
            except Exception as e:
                if lbl: lbl.update(f"[red]{e}[/red]")

    # ── socks ─────────────────────────────────────────────────────────────────

    def watch_socks_active(self, val: bool):
        btn = self._q("#btn-socks", Button)
        if not btn: return
        btn.label   = "Stop SOCKS5"  if val else "Start SOCKS5"
        btn.variant = "error"        if val else "primary"

    async def _toggle_socks(self):
        if not self.connected or not self._client:
            self._stg_msg("Connect first", err=True); return
        lbl   = self._q("#socks-status", Label)
        socks = getattr(self._client, "_socks", None)
        if socks and socks.active:
            if lbl: lbl.update("[yellow]Stopping SOCKS5 …[/yellow]")
            try:
                await self._client.stop_socks()
                self.socks_active = False
                if lbl: lbl.update("[green]SOCKS5 stopped[/green]")
            except Exception as e:
                if lbl: lbl.update(f"[red]{e}[/red]")
        else:
            if not self.selected_peer:
                if lbl: lbl.update("[red]Select an exit peer in the sidebar first[/red]")
                return
            try:    port = int(self._val("#i-socks-port") or "1080")
            except: port = 1080
            if lbl: lbl.update("[yellow]Starting SOCKS5 …[/yellow]")
            try:
                await self._client.start_socks(self.selected_peer, port)
            except Exception as e:
                if lbl: lbl.update(f"[red]{e}[/red]")

    # ── pcap ──────────────────────────────────────────────────────────────────

    def watch_pcap_active(self, val: bool):
        btn = self._q("#btn-pcap", Button)
        if not btn: return
        btn.label   = "Stop Capture"  if val else "Start Capture"
        btn.variant = "error"         if val else "success"

    async def _toggle_pcap(self):
        if not self.connected or not self._client:
            self._stg_msg("Connect first", err=True); return
        pl = self._q("#pcap-log", RichLog)
        ps = self._q("#pcap-status", Label)
        if self.pcap_active:
            try:
                await self._client.toggle_pcap(enable=False)
                self.pcap_active = False
                if ps: ps.update("[green]Capture stopped[/green]")
                if pl: pl.write(
                    f"[{datetime.now().strftime('%H:%M')}] "
                    "[yellow]Capture stopped[/yellow]")
            except Exception as e:
                if ps: ps.update(f"[red]{e}[/red]")
        else:
            path = self._val("#inp-pcap-path") or \
                   f"capture_{int(time.time())}.pcap"
            try:
                await self._client.toggle_pcap(enable=True, path=path)
                self.pcap_active = True
                if ps: ps.update(
                    f"[green]Capturing → {path}[/green]")
                if pl: pl.write(
                    f"[{datetime.now().strftime('%H:%M')}] "
                    f"[green]Capture started → {path}[/green]")
            except Exception as e:
                if ps: ps.update(f"[red]{e}[/red]")

    # ── groups / channels ─────────────────────────────────────────────────────

    async def _enter_channel(self, name: str, pw: str, verb: str):
        """Shared logic for create and join — derives channel id and registers it."""
        if not self.connected or not self._client:
            self._stg_msg("Connect first", err=True); return
        if not name or not pw: return
        cid, key = _derive_channel(name, pw)
        if cid not in self._channels:
            self._channels[cid] = {"name": name, "key": key}
            # Register key so incoming messages can be decrypted immediately
            self._client.register_channel_key(cid, key)
            try:
                await self._client._send({"type": "join_channel", "channel_id": cid})
            except Exception as e:
                self._stg_msg(f"Channel {verb} failed: {e}", err=True)
                del self._channels[cid]; return
            await self._rebuild_chan_list()
        # Switch to this channel
        self._current_channel = cid
        self._restore_group_chat(cid)
        self._update_chan_buttons()
        ts = datetime.now().strftime("%H:%M")
        rl = self._q("#grp-log", RichLog)
        if rl: rl.write(
            f"[{ts}] [green]{verb.capitalize()}d channel "
            f"[bold]{name}[/bold][/green]")
        # Clear inputs
        for sel in ("#inp-grp-name", "#inp-grp-pass"):
            inp = self._q(sel, Input)
            if inp: inp.value = ""

    async def _create_channel(self):
        name = self._val("#inp-grp-name").strip()
        pw   = self._val("#inp-grp-pass").strip()
        if not name:
            rl = self._q("#grp-log", RichLog)
            if rl: rl.write("[red]Enter a channel name first[/red]"); return
        if not pw:
            rl = self._q("#grp-log", RichLog)
            if rl: rl.write("[red]Enter a channel password first[/red]"); return
        await self._enter_channel(name, pw, "create")

    async def _join_channel(self):
        name = self._val("#inp-grp-name").strip()
        pw   = self._val("#inp-grp-pass").strip()
        if not name:
            rl = self._q("#grp-log", RichLog)
            if rl: rl.write("[red]Enter the channel name to join[/red]"); return
        if not pw:
            rl = self._q("#grp-log", RichLog)
            if rl: rl.write("[red]Enter the channel password[/red]"); return
        await self._enter_channel(name, pw, "join")

    async def _leave_channel(self):
        cid = self._current_channel
        if not cid: return
        info = self._channels.pop(cid, None)
        if not info: return
        # Remove from client key store
        if self._client:
            self._client._channel_keys.pop(cid, None)
            try:
                await self._client._send({"type": "leave_channel", "channel_id": cid})
            except Exception: pass
        # Clear logs for this channel
        self._channel_logs.pop(cid, None)
        self._current_channel = ""
        await self._rebuild_chan_list()
        # Reset right panel
        rl = self._q("#grp-log", RichLog)
        if rl: rl.clear(); rl.write("[dim]Left channel.[/dim]")
        w = self._q("#grp-who", Label)
        if w: w.update("No channel selected")

    async def _send_group_msg(self):
        if not self.connected or not self._client: return
        if not self._current_channel: return
        inp  = self._q("#grp-inp", Input)
        if not inp: return
        text = inp.value.strip()
        if not text: return
        info = self._channels.get(self._current_channel)
        if not info: return
        try:
            await self._client.send_channel_msg(self._current_channel,
                                                 info["key"], text)
            ts = datetime.now().strftime("%H:%M")
            self._channel_logs[self._current_channel].append(
                (ts, "you", text))
            rl = self._q("#grp-log", RichLog)
            if rl: rl.write(
                f"[{ts}] [bold green]you[/bold green]: {text}")
            inp.value = ""
        except Exception as e:
            rl = self._q("#grp-log", RichLog)
            if rl: rl.write(f"[red]{e}[/red]")

    def _restore_group_chat(self, cid: str):
        rl = self._q("#grp-log", RichLog)
        if not rl: return
        rl.clear()
        info = self._channels.get(cid, {})
        name = info.get("name", cid[:8])
        rl.write(f"[dim]--- Channel: {name} ---[/dim]")
        for ts, who, text in self._channel_logs.get(cid, []):
            c = "bold green" if who == "you" else "bold cyan"
            rl.write(f"[{ts}] [{c}]{who}[/{c}]: {text}")
        w = self._q("#grp-who", Label)
        if w: w.update(
            f"Channel: [bold]{name}[/bold]  "
            f"[dim](id: {cid[:8]}…)[/dim]")

    async def _rebuild_chan_list(self):
        scroll = self._q("#grp-chan-scroll", VerticalScroll)
        if not scroll: return
        for btn in list(scroll.query(Button)):
            if btn.id and btn.id.startswith(_CHAN_BTN_PREFIX):
                await btn.remove()
        nc = self._q("#no-channels", Label)
        if not self._channels:
            if nc: nc.display = True; return
        if nc: nc.display = False
        for cid, info in self._channels.items():
            btn = Button(
                f"# {info['name']}",
                id=f"{_CHAN_BTN_PREFIX}{cid}",
                classes="grp-chan-btn")
            if cid == self._current_channel:
                btn.add_class("-sel")
            await scroll.mount(btn)

    def _update_chan_buttons(self):
        for btn in self.query(Button):
            if btn.id and btn.id.startswith(_CHAN_BTN_PREFIX):
                cid = btn.id[len(_CHAN_BTN_PREFIX):]
                if cid == self._current_channel: btn.add_class("-sel")
                else:                            btn.remove_class("-sel")

    # ── chat ──────────────────────────────────────────────────────────────────

    async def _send_chat(self):
        if not self._check_ready(): return
        inp = self._q("#chat-inp", Input)
        if not inp: return
        text = inp.value.strip()
        if not text: return
        await self._client.send_message(self.selected_peer, text)
        ts = datetime.now().strftime("%H:%M")
        self._chat_logs[self.selected_peer].append((ts, "you", text))
        rl = self._q("#chat-log", RichLog)
        if rl: rl.write(f"[{ts}] [bold green]you[/bold green]: {text}")
        inp.value = ""

    def _restore_chat(self, pid):
        rl = self._q("#chat-log", RichLog)
        if not rl: return
        rl.clear()
        for ts, who, text in self._chat_logs.get(pid, []):
            c = "bold green" if who == "you" else "bold cyan"
            rl.write(f"[{ts}] [{c}]{who}[/{c}]: {text}")

    # ── file send ─────────────────────────────────────────────────────────────

    async def _send_file(self):
        if not self._check_ready(): return
        path = self._val("#f-path")
        xl   = self._q("#xfer-log", RichLog)
        if not path:
            if xl: xl.write("[red]Enter a file or folder path[/red]"); return
        if not os.path.exists(path):
            if xl: xl.write(f"[red]Not found: {path}[/red]"); return
        name = os.path.basename(path.rstrip("/\\"))
        if xl: xl.write(f"Sending [bold]{name}[/bold] to {self._peer_display()} …")
        try:
            await self._client.send_file(self.selected_peer, path)
            if xl: xl.write(f"[green]Sent {name}[/green]")
        except Exception as ex:
            if xl: xl.write(f"[red]{ex}[/red]")

    # ── steg ENCODE ───────────────────────────────────────────────────────────

    async def _send_steg(self):
        if not self._check_ready(): return
        cover    = self._val("#enc-cover")
        sel_w    = self._q("#enc-sel", Select)
        mode     = sel_w.value if sel_w else "file"
        password = self._val("#enc-pass")
        st_lbl   = self._q("#enc-status", Label)

        def st(m, err=False):
            col = "red" if err else "cyan"
            if st_lbl: st_lbl.update(f"[{col}]{m}[/{col}]")

        if not cover:                 st("Enter a cover image path"); return
        if not os.path.isfile(cover): st(f"Cover not found: {cover}"); return
        if not password:              st("Enter a steg password"); return

        if mode == "file":
            fp = self._val("#enc-file")
            if not fp or not os.path.isfile(fp):
                st("Enter a valid file path to hide"); return
            payload = open(fp, "rb").read()
            ct = "file"; fn = os.path.basename(fp); label = fn
        else:
            txt = self._val("#enc-msg")
            if not txt: st("Enter a message to hide"); return
            payload = txt.encode(); ct = "msg"; fn = ""; label = "message"

        st("Encrypting + embedding …")
        try:
            await self._client.send_steg(
                self.selected_peer, cover, payload, password,
                content_type=ct, filename=fn)
            st(f"Sent stego PNG  (hides '{label}')  — tell receiver the password!")
        except Exception as ex:
            st(f"{ex}", err=True)

    # ── steg DECODE ───────────────────────────────────────────────────────────

    async def _decode_steg(self):
        image_path = self._val("#dec-path")
        password   = self._val("#dec-pass")
        st_lbl     = self._q("#dec-status", Label)
        dr         = self._q("#dec-result", RichLog)

        def st(m, err=False):
            col = "red" if err else "green"
            if st_lbl: st_lbl.update(f"[{col}]{m}[/{col}]")

        if not image_path:                 st("Enter the stego image path", err=True); return
        if not os.path.isfile(image_path): st(f"Not found: {image_path}", err=True); return
        if not password:                   st("Enter the steg password", err=True); return

        st("Deriving key + decrypting …")
        if dr: dr.clear(); dr.write("[dim]Working …[/dim]")

        loop = asyncio.get_event_loop()
        try:
            result = await loop.run_in_executor(None, steg_decode, image_path, password)
        except RuntimeError as e:
            st(f"{e}", err=True)
            if dr: dr.clear(); dr.write(f"[red]{e}[/red]")
            return
        except Exception as e:
            st(f"Unexpected: {e}", err=True); return

        ts = datetime.now().strftime("%H:%M")
        if dr: dr.clear()

        if result["content_type"] == "msg":
            text = result["payload"].decode("utf-8", errors="replace")
            st(f"Decoded hidden message ({len(result['payload'])} bytes)")
            if dr:
                dr.write(f"[{ts}] [bold magenta]Hidden message:[/bold magenta]")
                dr.write(f'[white italic]"{text}"[/white italic]')
        else:
            save = result["filename"] or f"decoded_{int(time.time())}"
            b_, e_ = os.path.splitext(save); n = 1
            while os.path.exists(save): save = f"{b_}_{n}{e_}"; n += 1
            open(save, "wb").write(result["payload"])
            saved = os.path.abspath(save)
            st(f"Extracted → {saved}  ({len(result['payload'])} bytes)")
            if dr:
                dr.write(f"[{ts}] [bold magenta]Hidden file:[/bold magenta]")
                dr.write(f"[bold green]{saved}[/bold green]")
            if save.endswith(".zip"):
                out = save[:-4]
                try:
                    import zipfile
                    with zipfile.ZipFile(save) as z: z.extractall(out)
                    if dr: dr.write(f"[green]Extracted → {out}/[/green]")
                except: pass

    # ── aliases ───────────────────────────────────────────────────────────────

    def _save_alias(self):
        name = self._val("#inp-alias-name"); pid = self._val("#inp-alias-id")
        if not name or not pid: return
        self._aliases[name] = pid; save_aliases(self._aliases)
        self._draw_alias_log()
        for sel in ("#inp-alias-name", "#inp-alias-id"):
            w = self._q(sel, Input)
            if w: w.value = ""
        self._shown_peers = {}

    def _draw_alias_log(self):
        w = self._q("#alias-log", RichLog)
        if not w: return
        w.clear()
        if not self._aliases:
            w.write("[dim](none saved)[/dim]"); return
        w.write(f"[bold]{'Alias':<16}  Peer ID[/bold]"); w.write("─" * 36)
        for n, p in self._aliases.items(): w.write(f"{n:<16}  {p}")

    def _draw_peers_log(self):
        w = self._q("#peers-log", RichLog)
        if not w or not self._client: return
        w.clear()
        if not self._client.peers:
            w.write("[dim](no peers online)[/dim]"); return
        id2al = {v: k for k, v in self._aliases.items()}
        w.write(f"[bold]{'ID':<12}  {'Alias':<14}  Name[/bold]")
        w.write("─" * 46)
        for pid, pname in self._client.peers.items():
            al = id2al.get(pid, "")
            w.write(f"{pid:<12}  {al:<14}  {pname}")

    # ── helpers ───────────────────────────────────────────────────────────────

    def _check_ready(self):
        if not self.connected or not self._client:
            self._stg_msg("Not connected — Settings (F1) → Connect", err=True)
            return False
        if not self.selected_peer:
            sb = self._q("#statusbar", Label)
            if sb: sb.update("Click a peer in the sidebar first")
            return False
        if self.selected_peer not in self._client.peers:
            sb = self._q("#statusbar", Label)
            if sb: sb.update("That peer is no longer online")
            return False
        return True

    def _peer_display(self):
        if not self.selected_peer or not self._client: return "(none selected)"
        pname = self._client.peers.get(self.selected_peer, self.selected_peer)
        id2al = {v: k for k, v in self._aliases.items()}
        al    = id2al.get(self.selected_peer, "")
        return f"{pname} ({al})" if al else pname


# ── entry ─────────────────────────────────────────────────────────────────────

def main():
    if not _ok:
        print(f"ERROR: could not import client.py\nDetail: {_err}")
        print("Make sure client.py is in the same directory as tui.py")
        sys.exit(1)
    ap = argparse.ArgumentParser()
    ap.add_argument("--relay",       default="")
    ap.add_argument("--secret",      default="")
    ap.add_argument("--name",        default="peer")
    ap.add_argument("--port",        default=4001, type=int)
    ap.add_argument("--fingerprint", default="")
    ap.add_argument("--knock-ports", default="", dest="knock_ports")
    ap.add_argument("--tor",         action="store_true")
    ap.add_argument("--proxy",       default="")
    ap.add_argument("--auto-accept", action="store_true", dest="auto_accept")
    args = ap.parse_args()
    TunnelApp(args).run()

if __name__ == "__main__":
    main()
