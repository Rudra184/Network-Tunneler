#!/usr/bin/env python3
"""
tui.py — Secure Tunnel TUI
  pip install textual cryptography pillow
  python3 tui.py
"""

import asyncio, os, sys, argparse, base64, logging, time, platform
from collections import defaultdict
from urllib.parse import urlparse
from datetime import datetime

# ── Windows: force UTF-8 console so Unicode chars don't crash CMD ─────────────
if platform.system().lower() == "windows":
    import ctypes
    try:
        ctypes.windll.kernel32.SetConsoleOutputCP(65001)  # CP_UTF8
    except Exception:
        pass
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    # NOTE: ProactorEventLoop is the Windows default since Python 3.8.
    # asyncio.set_event_loop_policy(WindowsProactorEventLoopPolicy()) is
    # deprecated in 3.12 and removed in 3.16 — no call needed here.

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
_PEER_BTN_PREFIX = "PEERBTN__"


# ── Messages ──────────────────────────────────────────────────────────────────

class IncomingChat(Message):
    def __init__(self, peer_id, from_name, text):
        super().__init__()
        self.peer_id = peer_id; self.from_name = from_name; self.text = text

class XferLog(Message):
    def __init__(self, line):
        super().__init__(); self.line = line

class ShowAcceptModal(Message):
    """Posted from an asyncio Task to ask Textual to show the accept dialog.

    Uses a plain callback + asyncio.Event instead of asyncio.Future so that
    asyncio.wait_for timeout/cancellation can never corrupt the result.
    The callback is always called exactly once (Accept → True, anything else → False).
    """
    def __init__(self, from_name, filename, size_str, tid, callback):
        super().__init__()
        self.from_name = from_name; self.filename = filename
        self.size_str  = size_str;  self.tid = tid; self.callback = callback

class StegoSaved(Message):
    """Posted when a received stego PNG has been saved to disk."""
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
            yield Label("📥  Incoming Transfer", id="dlg-title")
            yield Rule()
            yield Label(f"From : {self.from_name}")
            yield Label(f"File : {self.filename}")
            yield Label(f"Size : {self.size_str}")
            yield Rule()
            yield Label("Auto-rejects in 30 s", classes="muted")
            with Horizontal(id="dlg-btns"):
                yield Button("✓  Accept", id="b-yes", variant="success")
                yield Button("✗  Reject", id="b-no",  variant="error")

    def on_button_pressed(self, e: Button.Pressed):
        e.stop()   # prevent event bubbling to TunnelApp.on_button_pressed
        self.dismiss(e.button.id == "b-yes")

    def on_mount(self):
        self.set_timer(30, lambda: self.dismiss(False))


# ── App ───────────────────────────────────────────────────────────────────────

class TunnelApp(App):
    TITLE     = "Secure Tunnel"
    SUB_TITLE = "E2E Encrypted  •  Port Knock  •  Steganography"

    CSS = """
    .muted       { color: $text-muted; }
    .card-title  { text-style: bold; color: $accent; margin-bottom: 1; }
    .sec-encode  { text-style: bold; color: $success; margin-bottom: 1; }
    .sec-decode  { text-style: bold; color: $warning; margin-bottom: 1; }

    #root { layout: horizontal; height: 1fr; }
    #sidebar { width: 22; height: 1fr; border-right: solid $accent; layout: vertical; padding: 0 1; background: $surface; }
    #sb-title { text-style: bold; color: $accent; height: 3; padding-left: 1; content-align: left middle; border-bottom: solid $accent; }
    #peer-scroll { height: 1fr; }
    .peer-btn { width: 100%; height: 3; background: transparent; border: none; text-align: left; padding: 0 1; color: $text; }
    .peer-btn:hover { background: $accent 20%; }
    .peer-btn.-sel  { background: $accent 40%; text-style: bold; }
    #no-peers { color: $text-muted; text-style: italic; padding: 1 1; height: 3; }
    #myid-box { height: 4; border-top: solid $accent; padding: 1 0 0 0; }
    #myid-val { color: $success; text-style: bold; }
    #statusbar { height: 1; dock: bottom; background: $panel; padding: 0 2; color: $text-muted; }

    #stg-scroll { height: 1fr; padding: 1 2; }
    .card  { border: solid $panel; padding: 1 2; margin-bottom: 1; height: auto; }
    .field         { layout: vertical; height: auto; margin-bottom: 1; }
    .field > Label { height: 1; color: $text-muted; }
    .field > Input { height: 3; }
    .tog           { layout: horizontal; height: 3; align: left middle; margin-bottom: 1; }
    .tog > Label   { width: 28; color: $text-muted; }
    .desc          { color: $text-muted; text-style: italic; height: auto; margin: 0 0 1 2; }
    #stg-btns    { layout: horizontal; height: 3; margin-top: 1; }
    #btn-connect { margin-right: 1; }
    #stg-msg     { height: 2; margin-top: 1; color: $success; }
    #stg-msg.err { color: $error; }

    #chat-wrap { height: 1fr; layout: vertical; padding: 1; }
    #chat-who  { height: 2; color: $text-muted; text-style: italic; }
    #chat-log  { height: 1fr; border: solid $panel; padding: 0 1; }
    #chat-row  { layout: horizontal; height: 3; margin-top: 1; }
    #chat-inp  { width: 1fr; }
    #btn-csend { width: 10; margin-left: 1; }

    #files-wrap { height: 1fr; layout: horizontal; }
    #f-left     { width: 30; height: 1fr; border-right: solid $panel; padding: 1; layout: vertical; }
    #f-right    { width: 1fr; height: 1fr; padding: 1; layout: vertical; }
    #f-hint     { height: 5; border: dashed $panel; padding: 1; color: $text-muted; text-style: italic; margin-bottom: 1; content-align: center middle; }
    #f-path     { height: 3; margin-bottom: 1; }
    #f-to       { height: 2; color: $text-muted; }
    #btn-fsend  { margin-top: 1; }
    #xfer-log   { height: 1fr; border: solid $panel; padding: 0 1; }

    #steg-scroll    { height: 1fr; padding: 1 2; }
    #enc-card       { border: solid $success; padding: 1 2; margin-bottom: 1; height: auto; }
    .ef             { layout: vertical; height: auto; margin-bottom: 1; }
    .ef > Label     { height: 1; color: $text-muted; }
    .ef > Input     { height: 3; }
    #enc-sel        { height: 3; margin-bottom: 1; }
    #enc-to         { height: 2; color: $text-muted; margin-bottom: 1; }
    #btn-encode     { margin-top: 1; }
    #enc-status     { height: 2; margin-top: 1; }
    #dec-card       { border: solid $warning; padding: 1 2; margin-bottom: 1; height: auto; }
    #dec-recv-dir   { height: 3; color: $success; text-style: italic; margin-bottom: 1; }
    .df             { layout: vertical; height: auto; margin-bottom: 1; }
    .df > Label     { height: 1; color: $text-muted; }
    .df > Input     { height: 3; }
    #btn-decode     { margin-top: 1; }
    #dec-status     { height: 2; margin-top: 1; }
    #dec-result     { height: 8; border: solid $panel; padding: 0 1; margin-top: 1; }

    #peers-wrap    { height: 1fr; layout: vertical; padding: 1; }
    #peers-log     { height: 1fr; border: solid $panel; padding: 0 1; }
    #alias-section { height: 20; border-top: solid $panel; padding: 1; margin-top: 1; layout: vertical; }
    #inp-alias-name { height: 3; margin-bottom: 1; }
    #inp-alias-id   { height: 3; margin-bottom: 1; }
    #btn-save-alias { margin-bottom: 1; }
    #alias-log { height: 1fr; border: solid $panel; padding: 0 1; }
    #tun-card   { border: solid $warning; padding: 1 2; margin-bottom: 1; height: auto; }
    #tun-status { height: 2; margin-top: 1; }
    #btn-tunnel   { width: 26; }
    #socks-card   { border: solid $primary; padding: 1 2; margin-bottom: 1; height: auto; }
    #socks-status { height: 2; margin-top: 1; }
    #btn-socks    { width: 26; }
    """

    BINDINGS = [
        Binding("ctrl+q","quit","Quit"),
        Binding("f1","go_settings","Settings"),
        Binding("f2","go_chat","Chat"),
        Binding("f3","go_files","Files"),
        Binding("f4","go_steg","Steg"),
        Binding("f5","go_peers","Peers"),
    ]

    connected     = reactive(False)
    selected_peer = reactive("")
    tunnel_active = reactive(False)
    socks_active  = reactive(False)

    def __init__(self, args):
        super().__init__()
        self._client      = None; self._tor_managed = False
        self._chat_logs   = defaultdict(list); self._aliases = load_aliases()
        self._msg_task    = None; self._mounted = False; self._shown_peers: dict = {}
        self._relay       = args.relay;  self._port        = args.port
        self._secret      = args.secret; self._name        = args.name
        self._fp          = getattr(args,"fingerprint","")
        self._knock       = getattr(args,"knock_ports","")
        self._use_tor     = getattr(args,"tor",False)
        self._proxy       = getattr(args,"proxy","")
        self._auto_accept = getattr(args,"auto_accept",False)
        self._tunnel_error: str = ""

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="root"):
            with Vertical(id="sidebar"):
                yield Label("⬡  PEERS", id="sb-title")
                with VerticalScroll(id="peer-scroll"):
                    yield Label("(not connected)", id="no-peers", classes="muted")
                with Vertical(id="myid-box"):
                    yield Label("Your ID", classes="muted")
                    yield Label("—", id="myid-val")

            with TabbedContent(id="tabs", initial="tab-settings"):

                with TabPane("⚙ Settings", id="tab-settings"):
                    with ScrollableContainer(id="stg-scroll"):
                        yield Static("👋  Fill in details and click Connect.", classes="muted")
                        yield Rule()
                        with Vertical(classes="card"):
                            yield Label("🔌  Connection", classes="card-title")
                            with Vertical(classes="field"):
                                yield Label("Relay server IP")
                                yield Input(value=self._relay, placeholder="e.g. 100.31.6.224", id="i-relay")
                            with Vertical(classes="field"):
                                yield Label("Port")
                                yield Input(value=str(self._port), placeholder="4001", id="i-port")
                            with Vertical(classes="field"):
                                yield Label("Secret key")
                                yield Input(value=self._secret, password=True, placeholder="Shared tunnel secret", id="i-secret")
                            with Vertical(classes="field"):
                                yield Label("Your display name")
                                yield Input(value=self._name, placeholder="e.g. alice", id="i-name")
                            with Vertical(classes="field"):
                                yield Label("TLS Fingerprint  (printed by server on startup)")
                                yield Input(value=self._fp, placeholder="SHA-256 hex — leave blank to skip", id="i-fp")
                        with Vertical(classes="card"):
                            yield Label("🚪  Port Knocking", classes="card-title")
                            with Vertical(classes="field"):
                                yield Label("Knock sequence  (comma-separated)")
                                yield Input(value=self._knock, placeholder="e.g. 1000, 2000, 3000", id="i-knock")
                        with Vertical(classes="card"):
                            yield Label("🧅  Privacy", classes="card-title")
                            with Horizontal(classes="tog"):
                                yield Label("Route via Tor"); yield Switch(value=self._use_tor, id="sw-tor")
                            with Vertical(classes="field"):
                                yield Label("Manual SOCKS5 proxy")
                                yield Input(value=self._proxy, placeholder="socks5://127.0.0.1:9050", id="i-proxy")
                        with Vertical(classes="card"):
                            yield Label("📁  Transfers", classes="card-title")
                            with Horizontal(classes="tog"):
                                yield Label("Auto-accept incoming files")
                                yield Switch(value=self._auto_accept, id="sw-aa")
                            yield Static("When OFF: popup lets you accept or reject each transfer.", classes="desc")
                        with Vertical(id="tun-card"):
                            yield Label("🌐  Traffic Tunnel", classes="card-title")
                            yield Static(
                                "Routes ALL device traffic through the relay server.\n"
                                "Requires root/sudo on both ends.  Linux only.", classes="desc")
                            yield Button("⬤  Enable Tunnel", id="btn-tunnel", variant="warning")
                            yield Label("", id="tun-status")
                        with Vertical(id="socks-card"):
                            yield Label("🧦  SOCKS5 Proxy", classes="card-title")
                            yield Static(
                                "Proxy apps through a peer's internet connection.\n"
                                "Point app at 127.0.0.1:1080 as SOCKS5 proxy.\n"
                                "E2E encrypted — relay server sees nothing.", classes="desc")
                            with Vertical(classes="field"):
                                yield Label("Local port")
                                yield Input(value="1080", placeholder="1080", id="i-socks-port")
                            yield Label("Exit peer: select in sidebar", id="socks-peer-lbl", classes="muted")
                            yield Button("⬤  Start SOCKS5", id="btn-socks", variant="primary")
                            yield Label("", id="socks-status")
                        yield Rule()
                        with Horizontal(id="stg-btns"):
                            yield Button("⚡  Connect",    id="btn-connect",    variant="success")
                            yield Button("✖  Disconnect", id="btn-disconnect", variant="error")
                        yield Label("", id="stg-msg")

                with TabPane("💬 Chat", id="tab-chat"):
                    with Vertical(id="chat-wrap"):
                        yield Label("← Click a peer in the sidebar to chat", id="chat-who")
                        yield RichLog(id="chat-log", auto_scroll=True, markup=True, highlight=True)
                        with Horizontal(id="chat-row"):
                            yield Input(placeholder="Type a message and press Enter …", id="chat-inp")
                            yield Button("Send", id="btn-csend", variant="primary")

                with TabPane("📁 Files", id="tab-files"):
                    with Horizontal(id="files-wrap"):
                        with Vertical(id="f-left"):
                            yield Label("Send a file or folder", classes="card-title")
                            yield Static("Paste the full path below.\nFolders are auto-zipped.", id="f-hint")
                            yield Input(placeholder="/home/user/secret.pdf", id="f-path")
                            yield Label("To: (select peer in sidebar)", id="f-to")
                            yield Button("⬆  Send", id="btn-fsend", variant="primary")
                        with Vertical(id="f-right"):
                            yield Label("Transfer log", classes="card-title")
                            yield RichLog(id="xfer-log", auto_scroll=True, markup=True)

                with TabPane("🖼 Steg", id="tab-steg"):
                    with ScrollableContainer(id="steg-scroll"):

                        yield Label("🔒  ENCODE — hide data inside a cover image", classes="sec-encode")
                        with Vertical(id="enc-card"):
                            with Vertical(classes="ef"):
                                yield Label("Cover image  (JPG, PNG, BMP, TIFF, WebP …)")
                                yield Input(placeholder="/home/user/photo.jpg", id="enc-cover")
                            yield Label("What to hide", classes="muted")
                            yield Select([("Hide a file","file"),("Hide a text message","msg")],
                                         id="enc-sel", value="file")
                            with Vertical(classes="ef"):
                                yield Label("File to hide  (any type: PDF, ZIP, image, doc …)")
                                yield Input(placeholder="/home/user/document.pdf", id="enc-file")
                            with Vertical(classes="ef"):
                                yield Label("Message to hide")
                                yield Input(placeholder="Type your secret message …", id="enc-msg")
                            with Vertical(classes="ef"):
                                yield Label("🔑  Steg password  (tell receiver out-of-band — NEVER transmitted)")
                                yield Input(placeholder="e.g. correct-horse-battery-staple", id="enc-pass", password=True)
                            yield Label("To: (select peer in sidebar)", id="enc-to")
                            yield Button("🖼  Embed & Send", id="btn-encode", variant="success")
                            yield Label("", id="enc-status")

                        yield Rule()

                        yield Label("🔓  DECODE — extract hidden data from a stego image", classes="sec-decode")
                        with Vertical(id="dec-card"):
                            yield Label(
                                f"Received stego PNGs are saved to:\n  {STEG_RECV_DIR}",
                                id="dec-recv-dir"
                            )
                            with Vertical(classes="df"):
                                yield Label("Stego image path  (auto-filled when you receive one)")
                                yield Input(placeholder=f"{STEG_RECV_DIR}/photo_alice_20250101.steg.png", id="dec-path")
                            with Vertical(classes="df"):
                                yield Label("🔑  Steg password  (same one the sender told you)")
                                yield Input(placeholder="Enter the steg password …", id="dec-pass", password=True)
                            yield Button("🔓  Decode", id="btn-decode", variant="warning")
                            yield Label("", id="dec-status")
                            yield RichLog(id="dec-result", auto_scroll=True, markup=True)

                with TabPane("👥 Peers", id="tab-peers"):
                    with Vertical(id="peers-wrap"):
                        yield Label("Online peers", classes="card-title")
                        yield RichLog(id="peers-log", auto_scroll=False, markup=True)
                        with Vertical(id="alias-section"):
                            yield Label("Aliases", classes="card-title")
                            yield Label("Save a short name for a peer ID.", classes="muted")
                            yield Input(placeholder="Alias name  e.g. bob", id="inp-alias-name")
                            yield Input(placeholder="Peer ID     e.g. a1b2c3d4", id="inp-alias-id")
                            yield Button("💾  Save alias", id="btn-save-alias", variant="primary")
                            yield RichLog(id="alias-log", auto_scroll=False, markup=True)

        yield Label("⬡  Settings (F1) → fill details → Connect", id="statusbar")
        yield Footer()

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

    # ── message handlers (run in Textual's widget context) ────

    def on_incoming_chat(self, msg: IncomingChat):
        ts = datetime.now().strftime("%H:%M")
        self._chat_logs[msg.peer_id].append((ts, msg.from_name, msg.text))
        if self.selected_peer == msg.peer_id:
            log = self._q("#chat-log", RichLog)
            if log: log.write(f"[{ts}] [bold cyan]{msg.from_name}[/bold cyan]: {msg.text}")

    def on_xfer_log(self, msg: XferLog):
        xl = self._q("#xfer-log", RichLog)
        if xl: xl.write(msg.line)

    def on_show_accept_modal(self, msg: ShowAcceptModal):
        """Show the accept/reject dialog and fire msg.callback with the result.

        Uses push_screen + callback (the canonical Textual pattern) instead of
        push_screen_wait inside an async handler.  The async-handler+wait
        approach is unreliable: if anything disturbs the screen stack while the
        handler is suspended, push_screen_wait's internal future never resolves
        and the except block silently calls msg.callback(False) — causing every
        manual accept to look like a rejection.  The sync + callback pattern has
        no such timing dependency: callback() is invoked synchronously inside
        dismiss(), always exactly once.
        """
        def _screen_callback(result):
            # Called by Textual synchronously when AcceptModal.dismiss() fires.
            # We are inside the asyncio event loop at this point, so setting
            # an asyncio.Event is safe.
            msg.callback(result is True)   # None / False → False

        self.push_screen(
            AcceptModal(msg.from_name, msg.filename, msg.size_str, msg.tid),
            callback=_screen_callback,
        )

    def on_stego_saved(self, msg: StegoSaved):
        """
        Called when receiver saves a stego PNG to disk.

        Runs in Textual's widget context (Message handler) — safe to touch
        widgets directly. No call_later or lambda needed.

        The key rule: _go() called directly here works because Message handlers
        always run inside Textual's event loop context.
        """
        ts = datetime.now().strftime("%H:%M")

        # 1. Log in Files tab
        xl = self._q("#xfer-log", RichLog)
        if xl:
            xl.write(
                f"[{ts}] [bold magenta]🖼 STEG PNG received[/bold magenta] "
                f"from [cyan]{msg.from_name}[/cyan]  ({msg.size} bytes)\n"
                f"  Saved → [bold]{msg.saved_path}[/bold]\n"
                f"  → Go to Steg tab (F4) → DECODE → enter password"
            )

        # 2. Auto-fill the decode path field
        dec = self._q("#dec-path", Input)
        if dec: dec.value = msg.saved_path

        # 3. Show instruction in decode status
        ds = self._q("#dec-status", Label)
        if ds:
            ds.update(
                f"[bold cyan]Stego PNG received from {msg.from_name}![/bold cyan]  "
                f"Enter the password above and click Decode."
            )

        # 4. Write to decode result log
        dr = self._q("#dec-result", RichLog)
        if dr:
            dr.clear()
            dr.write(f"[bold yellow]Ready to decode:[/bold yellow]  {msg.saved_path}")
            dr.write("[dim]Enter the steg password the sender told you, then click Decode.[/dim]")

        # 5. Switch to Steg tab — direct call works here (Message handler context)
        self._go("tab-steg")

    # ── tick ──────────────────────────────────────────────────

    async def _tick(self):
        if not self._client or not self.connected: return
        await self._update_sidebar(); self._draw_peers_log()

    # ── sidebar ───────────────────────────────────────────────

    async def _update_sidebar(self):
        if not self._client: return
        current = dict(self._client.peers)
        id2al   = {v:k for k,v in self._aliases.items()}
        desired: dict[str,str] = {}
        for pid, pname in current.items():
            al = id2al.get(pid,"")
            desired[pid] = f"● {pname}" + (f" ({al})" if al else "")
        if desired == self._shown_peers: return
        scroll = self._q("#peer-scroll", VerticalScroll)
        if not scroll: return
        for btn in list(scroll.query(Button)):
            if btn.id and btn.id.startswith(_PEER_BTN_PREFIX): await btn.remove()
        np = self._q("#no-peers", Label)
        if not desired:
            if np: np.display = True; self._shown_peers = {}; return
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
            sb.update(f"⬡  Connected  │  {self._relay}:{self._port}  │  {self._name}  │  id: {self._client.my_id}")
        else:
            sb.update("⬡  Disconnected — Settings (F1) → Connect")
        np = self._q("#no-peers", Label)
        if np: np.update("(not connected)" if not val else "(no peers yet)"); np.display = not val

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
                al    = {v:k for k,v in self._aliases.items()}.get(pid,"")
                w.update(f"Chatting with [bold]{pname}[/bold] [{pid}]" + (f"  alias:{al}" if al else ""))
                self._restore_chat(pid)
            else: w.update("← Click a peer in the sidebar to chat")
        txt = self._peer_display()
        lbl_s = self._q("#socks-peer-lbl", Label)
        if lbl_s: lbl_s.update(
            f"Exit peer: [bold]{txt}[/bold]" if pid else "Exit peer: select in sidebar")
        for sel in ("#f-to","#enc-to"):
            lbl = self._q(sel, Label)
            if lbl: lbl.update(f"To: [bold]{txt}[/bold]" if pid else "To: (select peer in sidebar)")

    def _go(self, tab):
        tc = self._q("#tabs", TabbedContent)
        if tc: tc.active = tab

    def action_go_settings(self): self._go("tab-settings")
    def action_go_chat(self):     self._go("tab-chat")
    def action_go_files(self):    self._go("tab-files")
    def action_go_steg(self):     self._go("tab-steg")
    def action_go_peers(self):    self._go("tab-peers")

    async def on_button_pressed(self, e: Button.Pressed):
        bid = e.button.id or ""
        if bid.startswith(_PEER_BTN_PREFIX):
            self.selected_peer = bid[len(_PEER_BTN_PREFIX):]; return
        if   bid == "btn-socks":      await self._toggle_socks()
        elif bid == "btn-tunnel":     await self._toggle_tunnel()
        elif bid == "btn-connect":    self._read_settings(); await self._do_connect()
        elif bid == "btn-disconnect": await self._disconnect()
        elif bid == "btn-csend":      await self._send_chat()
        elif bid == "btn-fsend":      await self._send_file()
        elif bid == "btn-encode":     await self._send_steg()
        elif bid == "btn-decode":     await self._decode_steg()
        elif bid == "btn-save-alias": self._save_alias()

    async def on_input_submitted(self, e):
        if e.input.id == "chat-inp": await self._send_chat()

    def _read_settings(self):
        self._relay = self._val("#i-relay"); self._secret = self._val("#i-secret")
        self._name  = self._val("#i-name") or "peer"; self._fp = self._val("#i-fp")
        self._knock = self._val("#i-knock"); self._proxy = self._val("#i-proxy")
        self._use_tor = self._sw("#sw-tor"); self._auto_accept = self._sw("#sw-aa")
        try:    self._port = int(self._val("#i-port") or "4001")
        except: self._port = 4001

    def _stg_msg(self, msg, err=False):
        w = self._q("#stg-msg", Label)
        if not w: return
        w.update(msg)
        if err: w.add_class("err")
        else:   w.remove_class("err")

    async def _do_connect(self):
        if self.connected: self._stg_msg("Already connected ✓"); return
        if not self._relay: self._stg_msg("Relay IP is required", err=True); return
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
            host=self._relay, port=self._port, name=self._name, secret=self._secret,
            fingerprint=self._fp or None, proxy=proxy,
            knock_ports=knock_ports, auto_accept=self._auto_accept,
        )

        app_ref = self

        # ── Hook 1: Accept prompt (shows TUI modal) ───────────────────────────
        async def tui_prompt_accept(tid, from_name, filename, size_bytes):
            if app_ref._auto_accept: return True
            size_str = (
                f"{size_bytes/(1024*1024):.1f} MB" if size_bytes > 1_048_576
                else f"{size_bytes//1024} KB"       if size_bytes > 1024
                else f"{size_bytes} B"
            )

            # accepted_result is a one-element list so the nested callback can
            # write to it from a sync context without nonlocal/closure issues.
            accepted_result = [False]
            accepted_event  = asyncio.Event()

            def _on_modal_done(accepted: bool):
                # Called synchronously from within AcceptModal.dismiss() via
                # push_screen callback.  We are inside the asyncio event loop,
                # so setting an asyncio.Event here is safe.
                accepted_result[0] = accepted
                accepted_event.set()

            app_ref.post_message(ShowAcceptModal(from_name, filename, size_str, tid, _on_modal_done))

            # Poll the event instead of asyncio.wait_for — avoids the Python
            # 3.12+ behaviour where wait_for cancels the inner coroutine on
            # timeout, which can race with the callback setting the event and
            # leave accepted_result[0] as False even after the user accepted.
            # 36 s > the modal's own 30 s auto-reject timer, so this is just
            # a safety net; in normal use _on_modal_done fires long before.
            deadline = time.monotonic() + 36
            while not accepted_event.is_set() and time.monotonic() < deadline:
                await asyncio.sleep(0.05)

            return accepted_result[0]

        # ── Hook 2: Stego saved (auto-fill decode path, switch tab) ──────────
        # Set BEFORE connect() so it's ready even if a transfer arrives immediately
        def on_stego_saved(saved_path, from_name, size):
            # post_message is safe from any async context
            app_ref.post_message(StegoSaved(saved_path, from_name, size))

        # ── Hook 3: Transfer status lines (shown in Files log) ────────────────
        def on_xfer_status(msg_str, is_err):
            ts  = datetime.now().strftime("%H:%M")
            col = "red" if is_err else "green"
            app_ref.post_message(XferLog(f"[{ts}] [{col}]{msg_str}[/{col}]"))

        # ── Hook 4: Tunnel status ──────────────────────────────────────
        def on_tunnel_status(msg_str: str, is_err: bool):
            app_ref.tunnel_active = (not is_err and "active" in msg_str)
            lbl = app_ref._q("#tun-status", Label)
            col = "red" if is_err else "green"
            if lbl: lbl.update(f"[{col}]{msg_str}[/{col}]")
            ts = datetime.now().strftime("%H:%M")
            app_ref.post_message(XferLog(f"[{ts}] [{col}]{msg_str}[/{col}]"))

        # Set all hooks BEFORE connect() — this is critical
        self._client._prompt_accept    = tui_prompt_accept
        self._client._on_stego_saved   = on_stego_saved
        self._client._on_xfer_status   = on_xfer_status
        self._client._on_tunnel_status = on_tunnel_status

        def on_socks_status(msg_str: str, is_err: bool):
            app_ref.socks_active = (not is_err and "active" in msg_str)
            lbl = app_ref._q("#socks-status", Label)
            col = "red" if is_err else "green"
            if lbl: lbl.update(f"[{col}]{msg_str}[/{col}]")

        def on_pcap_ack(ok: bool, info: str):
            ts  = datetime.now().strftime("%H:%M")
            col = "green" if ok else "red"
            app_ref.post_message(XferLog(f"[{ts}] [{col}]PCAP: {info}[/{col}]"))

        self._client._on_socks_status = on_socks_status
        self._client._on_pcap_ack     = on_pcap_ack

        try:
            await self._client.connect()
        except Exception as ex:
            self._stg_msg(f"Failed: {ex}", err=True); self._client = None; return

        self.connected = True
        w = self._q("#myid-val", Label)
        if w: w.update(self._client.my_id or "—")
        self._stg_msg(f"Connected ✓  id = {self._client.my_id}")
        self._msg_task = asyncio.create_task(self._intercept_callbacks())

    async def _disconnect(self):
        if self._client and getattr(self._client, "_socks", None):
            try: await self._client.stop_socks()
            except: pass
        self.socks_active = False
        if self._client and getattr(self._client, "_tunnel", None):
            try:
                await self._client.stop_tunnel()
            except Exception:
                pass
        self.tunnel_active = False
        if self._msg_task: self._msg_task.cancel(); self._msg_task = None
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

    async def _intercept_callbacks(self):
        """
        Replace _receive_message with a TUI-aware version that posts IncomingChat.
        For files: the original _receive_file already uses _on_stego_saved and
        _on_xfer_status hooks, so we just add a log line for normal files.
        """
        if not self._client: return
        orig_msg  = self._client._receive_message
        orig_file = self._client._receive_file
        app_ref   = self

        async def intercept_msg(msg):
            from_id   = msg.get("from_id","?"); from_name = msg.get("from_name", from_id)
            key = await app_ref._client.get_shared_key(from_id)
            if key:
                try:
                    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                    pl   = base64.b64decode(msg.get("payload",""))
                    n    = base64.b64decode(msg.get("nonce",""))
                    text = AESGCM(key).decrypt(n, pl, None).decode()
                    app_ref.post_message(IncomingChat(from_id, from_name, text))
                    return
                except Exception: pass
            await orig_msg(msg)

        async def intercept_file(meta):
            # orig_file handles steg save + _on_stego_saved + _on_xfer_status
            await orig_file(meta)
            # Only add a Files-tab log line for normal (non-steg) files
            # Steg files are logged via the _on_xfer_status hook
            if not meta.get("steg", False):
                from_name = meta.get("from_name","?")
                fname     = meta.get("display_name","file")
                size      = meta.get("size",0)
                ts        = datetime.now().strftime("%H:%M")
                app_ref.post_message(XferLog(
                    f"[{ts}] [cyan]↓ {from_name}[/cyan]: [bold]{fname}[/bold]  ({size} B)"
                ))

        self._client._receive_message = intercept_msg
        self._client._receive_file    = intercept_file

        while self.connected and self._client:
            await asyncio.sleep(5.0)

    # ── tunnel ───────────────────────────────────────────────

    def watch_tunnel_active(self, val: bool):
        btn = self._q("#btn-tunnel", Button)
        if not btn: return
        if val:
            btn.label   = "⬛  Disable Tunnel"
            btn.variant = "error"
        else:
            btn.label   = "⬤  Enable Tunnel"
            btn.variant = "warning"

    async def _toggle_tunnel(self):
        if not self.connected or not self._client:
            self._stg_msg("Connect first before enabling the tunnel", err=True)
            return
        lbl    = self._q("#tun-status", Label)
        tunnel = getattr(self._client, "_tunnel", None)
        if tunnel and tunnel.active:
            if lbl: lbl.update("[yellow]Stopping tunnel …[/yellow]")
            try:
                await self._client.stop_tunnel()
                self.tunnel_active = False
                if lbl: lbl.update("[green]Tunnel stopped — routes restored ✓[/green]")
            except Exception as e:
                if lbl: lbl.update(f"[red]Stop failed: {e}[/red]")
        else:
            if lbl: lbl.update("[yellow]Requesting tunnel from server …[/yellow]")
            try:
                await self._client.start_tunnel()
                # Status update arrives via on_tunnel_status callback
            except Exception as e:
                if lbl: lbl.update(f"[red]{e}[/red]")

    # ── socks ────────────────────────────────────────────────

    def watch_socks_active(self, val: bool):
        btn = self._q("#btn-socks", Button)
        if not btn: return
        if val:
            btn.label   = "⬛  Stop SOCKS5"
            btn.variant = "error"
        else:
            btn.label   = "⬤  Start SOCKS5"
            btn.variant = "primary"

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
                if lbl: lbl.update("[green]SOCKS5 stopped ✓[/green]")
            except Exception as e:
                if lbl: lbl.update(f"[red]{e}[/red]")
        else:
            if not self.selected_peer:
                if lbl: lbl.update("[red]Select an exit peer in the sidebar first[/red]")
                return
            try:
                port = int(self._val("#i-socks-port") or "1080")
            except ValueError:
                port = 1080
            if lbl: lbl.update("[yellow]Starting SOCKS5 …[/yellow]")
            try:
                await self._client.start_socks(self.selected_peer, port)
            except Exception as e:
                if lbl: lbl.update(f"[red]{e}[/red]")

    # ── chat ──────────────────────────────────────────────────

    async def _send_chat(self):
        if not self._check_ready(): return
        inp = self._q("#chat-inp", Input)
        if not inp: return
        text = inp.value.strip()
        if not text: return
        await self._client.send_message(self.selected_peer, text)
        ts = datetime.now().strftime("%H:%M")
        self._chat_logs[self.selected_peer].append((ts, "you", text))
        log = self._q("#chat-log", RichLog)
        if log: log.write(f"[{ts}] [bold green]you[/bold green]: {text}")
        inp.value = ""

    def _restore_chat(self, pid):
        log = self._q("#chat-log", RichLog)
        if not log: return
        log.clear()
        for ts, who, text in self._chat_logs.get(pid, []):
            c = "bold green" if who == "you" else "bold cyan"
            log.write(f"[{ts}] [{c}]{who}[/{c}]: {text}")

    # ── file send ─────────────────────────────────────────────

    async def _send_file(self):
        if not self._check_ready(): return
        path = self._val("#f-path"); xl = self._q("#xfer-log", RichLog)
        if not path:
            if xl: xl.write("[red]Enter a file or folder path first[/red]"); return
        if not os.path.exists(path):
            if xl: xl.write(f"[red]✗ Not found: {path}[/red]"); return
        name = os.path.basename(path.rstrip("/\\"))
        if xl: xl.write(f"↑ Sending [bold]{name}[/bold] → {self._peer_display()} …")
        try:
            await self._client.send_file(self.selected_peer, path)
            if xl: xl.write(f"[green]✓ Sent {name}[/green]")
        except Exception as ex:
            if xl: xl.write(f"[red]✗ {ex}[/red]")

    # ── steg ENCODE ───────────────────────────────────────────

    async def _send_steg(self):
        if not self._check_ready(): return
        cover    = self._val("#enc-cover")
        sel_w    = self._q("#enc-sel", Select)
        mode     = sel_w.value if sel_w else "file"
        password = self._val("#enc-pass")
        st_lbl   = self._q("#enc-status", Label)

        def st(m, err=False):
            if st_lbl: st_lbl.update(("[red]" if err else "[cyan]") + m + ("[/red]" if err else "[/cyan]"))

        if not cover:                 st("⚠  Enter a cover image path"); return
        if not os.path.isfile(cover): st(f"⚠  Cover not found: {cover}"); return
        if not password:              st("⚠  Enter a steg password — receiver needs it to decode"); return

        if mode == "file":
            fp = self._val("#enc-file")
            if not fp or not os.path.isfile(fp): st("⚠  Enter a valid file path to hide"); return
            payload = open(fp,"rb").read(); ct = "file"; fn = os.path.basename(fp); label = fn
        else:
            txt = self._val("#enc-msg")
            if not txt: st("⚠  Enter a message to hide"); return
            payload = txt.encode(); ct = "msg"; fn = ""; label = "message"

        st("Encrypting + embedding … (PBKDF2 key derivation, takes a moment)")
        try:
            await self._client.send_steg(self.selected_peer, cover, payload, password,
                                         content_type=ct, filename=fn)
            st(f"✓ Sent stego PNG  (hides '{label}')  — tell receiver the password!")
        except Exception as ex:
            st(f"✗ {ex}", err=True)

    # ── steg DECODE ───────────────────────────────────────────

    async def _decode_steg(self):
        image_path = self._val("#dec-path")
        password   = self._val("#dec-pass")
        st_lbl     = self._q("#dec-status", Label)
        dr         = self._q("#dec-result", RichLog)

        def st(m, err=False):
            if st_lbl: st_lbl.update(("[red]" if err else "[green]") + m + ("[/red]" if err else "[/green]"))

        if not image_path:                st("⚠  Enter the stego image path", err=True); return
        if not os.path.isfile(image_path): st(f"⚠  Not found: {image_path}", err=True); return
        if not password:                  st("⚠  Enter the steg password", err=True); return

        st("Deriving key + decrypting … (may take a moment)")
        if dr: dr.clear(); dr.write("[dim]Working …[/dim]")

        loop = asyncio.get_event_loop()
        try:
            result = await loop.run_in_executor(None, steg_decode, image_path, password)
        except RuntimeError as e:
            st(f"✗ {e}", err=True)
            if dr: dr.clear(); dr.write(f"[red]{e}[/red]")
            return
        except Exception as e:
            st(f"✗ Unexpected: {e}", err=True); return

        ts = datetime.now().strftime("%H:%M")
        if dr: dr.clear()

        if result["content_type"] == "msg":
            text = result["payload"].decode("utf-8", errors="replace")
            st(f"✓ Decoded hidden message ({len(result['payload'])} bytes)")
            if dr:
                dr.write(f"[{ts}] [bold magenta]Hidden message:[/bold magenta]")
                dr.write(f'[white italic]"{text}"[/white italic]')
        else:
            save = result["filename"] or f"decoded_{int(time.time())}"
            b_, e_ = os.path.splitext(save); n = 1
            while os.path.exists(save): save = f"{b_}_{n}{e_}"; n += 1
            open(save, "wb").write(result["payload"])
            saved = os.path.abspath(save)
            st(f"✓ Extracted → {saved}  ({len(result['payload'])} bytes)")
            if dr:
                dr.write(f"[{ts}] [bold magenta]Hidden file extracted:[/bold magenta]")
                dr.write(f"[bold green]{saved}[/bold green]")
                dr.write(f"[dim]{len(result['payload'])} bytes  |  ready to open[/dim]")
            if save.endswith(".zip"):
                out = save[:-4]
                try:
                    import zipfile
                    with zipfile.ZipFile(save) as z: z.extractall(out)
                    if dr: dr.write(f"[green]Extracted → {out}/[/green]")
                except: pass

    # ── aliases ───────────────────────────────────────────────

    def _save_alias(self):
        name = self._val("#inp-alias-name"); pid = self._val("#inp-alias-id")
        if not name or not pid: return
        self._aliases[name] = pid; save_aliases(self._aliases); self._draw_alias_log()
        for sel in ("#inp-alias-name","#inp-alias-id"):
            w = self._q(sel, Input)
            if w: w.value = ""
        self._shown_peers = {}

    def _draw_alias_log(self):
        w = self._q("#alias-log", RichLog)
        if not w: return
        w.clear()
        if not self._aliases: w.write("[dim](none saved)[/dim]"); return
        w.write(f"[bold]{'Alias':<16}  Peer ID[/bold]"); w.write("─"*36)
        for n, p in self._aliases.items(): w.write(f"{n:<16}  {p}")

    def _draw_peers_log(self):
        w = self._q("#peers-log", RichLog)
        if not w or not self._client: return
        w.clear()
        if not self._client.peers: w.write("[dim](no peers online)[/dim]"); return
        id2al = {v:k for k,v in self._aliases.items()}
        w.write(f"[bold]{'ID':<12}  {'Alias':<14}  Name[/bold]"); w.write("─"*46)
        for pid, pname in self._client.peers.items():
            al = id2al.get(pid,""); w.write(f"{pid:<12}  {al:<14}  {pname}")

    # ── helpers ───────────────────────────────────────────────

    # NOT named _ready — Textual has an internal _ready() coroutine,
    # shadowing it causes TypeError: object bool can't be used in 'await'
    def _check_ready(self):
        if not self.connected or not self._client:
            self._stg_msg("Not connected — Settings (F1) → Connect", err=True); return False
        if not self.selected_peer:
            sb = self._q("#statusbar", Label)
            if sb: sb.update("⬡  Click a peer in the sidebar first"); return False
        if self.selected_peer not in self._client.peers:
            sb = self._q("#statusbar", Label)
            if sb: sb.update("⬡  That peer is no longer online"); return False
        return True

    def _peer_display(self):
        if not self.selected_peer or not self._client: return "(none selected)"
        pname = self._client.peers.get(self.selected_peer, self.selected_peer)
        id2al = {v:k for k,v in self._aliases.items()}
        al    = id2al.get(self.selected_peer,"")
        return f"{pname} ({al})" if al else pname


def main():
    if not _ok:
        print(f"ERROR: could not import client.py\nDetail: {_err}")
        print("Make sure client.py is in the same directory as tui.py"); sys.exit(1)
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
