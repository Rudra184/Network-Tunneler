#!/usr/bin/env python3
"""
tui.py — Secure Tunnel TUI
  pip install textual cryptography pillow
  python3 tui.py
"""

import asyncio, os, sys, argparse, base64, logging
from collections import defaultdict
from urllib.parse import urlparse
from datetime import datetime

try:
    from textual.app import App, ComposeResult
    from textual.binding import Binding
    from textual.containers import Container, Horizontal, Vertical, ScrollableContainer, VerticalScroll
    from textual.widgets import (
        Header, Footer, TabbedContent, TabPane,
        Label, Input, Button, Switch,
        Static, Select, Rule, RichLog
    )
    from textual.reactive import reactive
    from textual.screen import ModalScreen
    from textual.message import Message
    from textual.css.query import NoMatches
except ImportError:
    print("ERROR: Run:  pip install textual"); sys.exit(1)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from client import (RelayClient, start_tor, stop_tor, TOR_PORT, load_aliases, save_aliases)
    _ok = True
except ImportError as e:
    _ok = False; _err = str(e)

logging.disable(logging.CRITICAL)
_PEER_BTN_PREFIX = "PEERBTN__"


# ── Custom messages ───────────────────────────────────────────────────────────

class IncomingChat(Message):
    def __init__(self, peer_id, from_name, text):
        super().__init__()
        self.peer_id = peer_id; self.from_name = from_name; self.text = text

class XferLog(Message):
    """A line to write to the Files tab transfer log."""
    def __init__(self, line, is_steg=False):
        super().__init__()
        self.line = line; self.is_steg = is_steg

class ShowAcceptModal(Message):
    def __init__(self, from_name, filename, size_str, tid, future):
        super().__init__()
        self.from_name = from_name; self.filename = filename
        self.size_str  = size_str;  self.tid      = tid; self.future = future


# ── Accept modal ──────────────────────────────────────────────────────────────

class AcceptModal(ModalScreen):
    CSS = """
    AcceptModal { align: center middle; }
    #dlg { width: 62; height: auto; padding: 1 2; border: thick $accent; background: $surface; }
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
        self.dismiss(e.button.id == "b-yes")

    def on_mount(self):
        self.set_timer(30, lambda: self.dismiss(False))


# ── App ───────────────────────────────────────────────────────────────────────

class TunnelApp(App):
    TITLE     = "Secure Tunnel"
    SUB_TITLE = "E2E Encrypted  •  Port Knock  •  Steganography"

    CSS = """
    .muted { color: $text-muted; }
    .card-title { text-style: bold; color: $accent; margin-bottom: 1; }
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
    #steg-info      { border: solid $panel; padding: 1; margin-bottom: 1; color: $text-muted; text-style: italic; height: auto; }
    .st-field           { layout: vertical; height: auto; margin-bottom: 1; }
    .st-field > Label   { height: 1; color: $text-muted; }
    .st-field > Input   { height: 3; }
    #steg-sel { height: 3; margin-bottom: 1; }
    #steg-to  { height: 2; color: $text-muted; }
    #btn-steg { margin-top: 1; }
    #steg-out { height: 2; margin-top: 1; }
    #peers-wrap    { height: 1fr; layout: vertical; padding: 1; }
    #peers-log     { height: 1fr; border: solid $panel; padding: 0 1; }
    #alias-section { height: 20; border-top: solid $panel; padding: 1; margin-top: 1; layout: vertical; }
    #inp-alias-name { height: 3; margin-bottom: 1; }
    #inp-alias-id   { height: 3; margin-bottom: 1; }
    #btn-save-alias { margin-bottom: 1; }
    #alias-log { height: 1fr; border: solid $panel; padding: 0 1; }
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

    def __init__(self, args):
        super().__init__()
        self._client      = None; self._tor_managed = False
        self._chat_logs   = defaultdict(list); self._aliases = load_aliases()
        self._msg_task    = None; self._mounted = False; self._shown_peers: dict = {}
        self._relay       = args.relay;  self._port   = args.port
        self._secret      = args.secret; self._name   = args.name
        self._fp          = getattr(args,"fingerprint","");  self._knock = getattr(args,"knock_ports","")
        self._use_tor     = getattr(args,"tor",False);       self._proxy = getattr(args,"proxy","")
        self._use_steg    = getattr(args,"steg",False);      self._auto_accept = getattr(args,"auto_accept",False)

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="root"):
            with Vertical(id="sidebar"):
                yield Label("⬡  PEERS", id="sb-title")
                with VerticalScroll(id="peer-scroll"):
                    yield Label("(not connected)", id="no-peers", classes="muted")
                with Vertical(id="myid-box"):
                    yield Label("Your ID", classes="muted"); yield Label("—", id="myid-val")

            with TabbedContent(id="tabs", initial="tab-settings"):

                with TabPane("⚙ Settings", id="tab-settings"):
                    with ScrollableContainer(id="stg-scroll"):
                        yield Static("👋  Fill in your details and click Connect. All settings can be changed without restarting.", classes="muted")
                        yield Rule()
                        with Vertical(classes="card"):
                            yield Label("🔌  Connection", classes="card-title")
                            with Vertical(classes="field"):
                                yield Label("Relay server IP"); yield Input(value=self._relay, placeholder="e.g. 100.31.6.224", id="i-relay")
                            with Vertical(classes="field"):
                                yield Label("Port"); yield Input(value=str(self._port), placeholder="4001", id="i-port")
                            with Vertical(classes="field"):
                                yield Label("Secret key"); yield Input(value=self._secret, password=True, placeholder="Shared tunnel secret", id="i-secret")
                            with Vertical(classes="field"):
                                yield Label("Your display name"); yield Input(value=self._name, placeholder="e.g. alice", id="i-name")
                            with Vertical(classes="field"):
                                yield Label("TLS Fingerprint  (printed by server on startup)"); yield Input(value=self._fp, placeholder="SHA-256 hex — leave blank to skip pinning", id="i-fp")
                        with Vertical(classes="card"):
                            yield Label("🚪  Port Knocking", classes="card-title")
                            with Vertical(classes="field"):
                                yield Label("Knock sequence  (comma-separated ports)"); yield Input(value=self._knock, placeholder="e.g. 6132,8152,3101", id="i-knock")
                            yield Static("Client sends TCP SYN to each port in order. knockd opens 4001 for your IP for 30 s. Leave blank to skip.", classes="desc")
                        with Vertical(classes="card"):
                            yield Label("🧅  Privacy", classes="card-title")
                            with Horizontal(classes="tog"):
                                yield Label("Route via Tor"); yield Switch(value=self._use_tor, id="sw-tor")
                            yield Static("Auto-installs Tor if missing, routes all traffic through it, stops on quit.", classes="desc")
                            with Vertical(classes="field"):
                                yield Label("Manual SOCKS5 proxy  (ignored when Tor is ON)"); yield Input(value=self._proxy, placeholder="socks5://127.0.0.1:9050", id="i-proxy")
                        with Vertical(classes="card"):
                            yield Label("📁  Transfers", classes="card-title")
                            with Horizontal(classes="tog"):
                                yield Label("Steganography mode"); yield Switch(value=self._use_steg, id="sw-steg")
                            yield Static("When ON: files sent via Files tab are hidden inside a generated PNG. Use the Steg tab to choose a specific cover image.", classes="desc")
                            with Horizontal(classes="tog"):
                                yield Label("Auto-accept incoming files"); yield Switch(value=self._auto_accept, id="sw-aa")
                            yield Static("When OFF: a popup lets you accept or reject each incoming file.", classes="desc")
                        yield Rule()
                        with Horizontal(id="stg-btns"):
                            yield Button("⚡  Connect", id="btn-connect", variant="success")
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
                            yield Static("Paste the full path below.\nFolders are auto-zipped.\nAll transfers are E2E encrypted.", id="f-hint")
                            yield Input(placeholder="/home/user/secret.pdf", id="f-path")
                            yield Label("To: (select peer in sidebar)", id="f-to")
                            yield Button("⬆  Send to selected peer", id="btn-fsend", variant="primary")
                        with Vertical(id="f-right"):
                            yield Label("Transfer log  (sent, received and steg results)", classes="card-title")
                            yield RichLog(id="xfer-log", auto_scroll=True, markup=True)

                with TabPane("🖼 Steg", id="tab-steg"):
                    with ScrollableContainer(id="steg-scroll"):
                        yield Label("Steganography — hide data inside an image", classes="card-title")
                        yield Static(
                            "How encoding works:\n"
                            "  1. You pick a cover image (JPG, PNG, BMP, TIFF, WebP …)\n"
                            "  2. Your file or message is AES-256-GCM encrypted with the shared key\n"
                            "  3. The ciphertext is embedded into the image's pixel LSBs (±1 per channel)\n"
                            "  4. The result is sent as a PNG — looks identical to the original\n\n"
                            "How decoding works (automatic on receiver's side):\n"
                            "  1. Receiver sees the accept/reject popup — click Accept\n"
                            "  2. The stego PNG downloads automatically\n"
                            "  3. LSBs are extracted → AES-GCM decrypted with the shared key\n"
                            "  4. Hidden FILE → saved to disk, path shown in the Files tab log\n"
                            "  5. Hidden TEXT → displayed in the Files tab log\n\n"
                            "Security: Without the shared key, the extracted LSBs look like\n"
                            "random noise — AES-256 ciphertext is computationally indistinguishable\n"
                            "from random data.\n\n"
                            "Requires:  pip install pillow",
                            id="steg-info"
                        )
                        yield Rule()
                        with Vertical(classes="st-field"):
                            yield Label("Cover image path  (JPG, PNG, BMP, TIFF, WebP …)")
                            yield Input(placeholder="/home/user/photo.jpg  or  photo.png", id="steg-cover")
                        yield Label("What to hide", classes="muted")
                        yield Select([("Hide a file","file"),("Hide a text message","msg")], id="steg-sel", value="file")
                        with Vertical(classes="st-field"):
                            yield Label("File to hide  (enter full path)")
                            yield Input(placeholder="/home/user/document.pdf", id="steg-file")
                        with Vertical(classes="st-field"):
                            yield Label("Message to hide  (type it here)")
                            yield Input(placeholder="Type your secret message …", id="steg-msg-inp")
                        yield Label("To: (select peer in sidebar)", id="steg-to")
                        yield Button("🖼  Embed & Send to selected peer", id="btn-steg", variant="primary")
                        yield Label("", id="steg-out")

                with TabPane("👥 Peers", id="tab-peers"):
                    with Vertical(id="peers-wrap"):
                        yield Label("Online peers", classes="card-title")
                        yield RichLog(id="peers-log", auto_scroll=False, markup=True)
                        with Vertical(id="alias-section"):
                            yield Label("Aliases", classes="card-title")
                            yield Label("Save a short name for a peer ID so you can use it everywhere.", classes="muted")
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
            asyncio.get_event_loop().call_later(0.4, lambda: asyncio.create_task(self._do_connect()))

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

    async def on_show_accept_modal(self, msg: ShowAcceptModal):
        if msg.future.done(): return
        try:
            result = await self.push_screen_wait(
                AcceptModal(msg.from_name, msg.filename, msg.size_str, msg.tid)
            )
            msg.future.set_result(bool(result))
        except Exception:
            if not msg.future.done(): msg.future.set_result(False)

    # ── tick ──────────────────────────────────────────────────

    async def _tick(self):
        if not self._client or not self.connected: return
        await self._update_sidebar(); self._draw_peers_log()

    # ── sidebar ───────────────────────────────────────────────

    async def _update_sidebar(self):
        if not self._client: return
        current = dict(self._client.peers)
        id2al   = {v: k for k, v in self._aliases.items()}
        desired: dict[str, str] = {}
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
                sb = self._q("#statusbar", Label)
                if sb: sb.update(f"⬡  Selected: {pname} [{pid}]  — type and press Send")
            else: w.update("← Click a peer in the sidebar to chat")
        txt = self._peer_display()
        for sel in ("#f-to","#steg-to"):
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
        if   bid == "btn-connect":    self._read_settings(); await self._do_connect()
        elif bid == "btn-disconnect": await self._disconnect()
        elif bid == "btn-csend":      await self._send_chat()
        elif bid == "btn-fsend":      await self._send_file()
        elif bid == "btn-steg":       await self._send_steg()
        elif bid == "btn-save-alias": self._save_alias()

    async def on_input_submitted(self, e):
        if e.input.id == "chat-inp": await self._send_chat()

    def _read_settings(self):
        self._relay = self._val("#i-relay"); self._secret = self._val("#i-secret")
        self._name  = self._val("#i-name") or "peer"; self._fp = self._val("#i-fp")
        self._knock = self._val("#i-knock"); self._proxy = self._val("#i-proxy")
        self._use_tor = self._sw("#sw-tor"); self._use_steg = self._sw("#sw-steg")
        self._auto_accept = self._sw("#sw-aa")
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
            self._stg_msg("Starting Tor (up to 60 s) …")
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
            use_steg=self._use_steg, knock_ports=knock_ports, auto_accept=self._auto_accept,
        )

        app_ref = self

        # ── Transfer accept modal bridge ───────────────────────────────────────
        async def tui_prompt_accept(tid, from_name, filename, size_bytes):
            if app_ref._auto_accept: return True
            size_str = (
                f"{size_bytes/(1024*1024):.1f} MB" if size_bytes > 1_048_576
                else f"{size_bytes//1024} KB"       if size_bytes > 1024
                else f"{size_bytes} B"
            )
            loop   = asyncio.get_event_loop()
            future = loop.create_future()
            app_ref.post_message(ShowAcceptModal(from_name, filename, size_str, tid, future))
            try:    return await asyncio.wait_for(future, timeout=35)
            except: return False

        self._client._prompt_accept = tui_prompt_accept

        # ── Steg result callback ───────────────────────────────────────────────
        # Called by _receive_file after successful steg extraction.
        # Routes the result to the Files tab log so user knows where the file is.
        def on_steg_received(saved_path, size, from_name, steg_type, message_text=None):
            ts = datetime.now().strftime("%H:%M")
            if steg_type == "msg":
                line = (
                    f"[{ts}] [bold magenta]🖼 STEG MSG[/bold magenta] "
                    f"from [cyan]{from_name}[/cyan]:\n"
                    f"  [italic]\"{message_text}\"[/italic]"
                )
            else:
                line = (
                    f"[{ts}] [bold magenta]🖼 STEG FILE[/bold magenta] "
                    f"from [cyan]{from_name}[/cyan]  "
                    f"([green]{size} bytes[/green])\n"
                    f"  Saved → [bold]{saved_path}[/bold]"
                )
            app_ref.post_message(XferLog(line, is_steg=True))
            # Switch to Files tab so user sees it immediately
            app_ref.call_later(lambda: app_ref._go("tab-files"))

        self._client._on_steg_received = on_steg_received

        # ── xfer status callback ───────────────────────────────────────────────
        def on_xfer_status(msg_str, is_err):
            ts   = datetime.now().strftime("%H:%M")
            col  = "red" if is_err else "green"
            line = f"[{ts}] [{col}]{msg_str}[/{col}]"
            app_ref.post_message(XferLog(line))

        self._client._on_xfer_status = on_xfer_status

        try:
            await self._client.connect()
        except Exception as ex:
            self._stg_msg(f"Failed: {ex}", err=True); self._client = None; return

        self.connected = True
        w = self._q("#myid-val", Label)
        if w: w.update(self._client.my_id or "—")
        self._stg_msg(f"Connected ✓  id = {self._client.my_id}  — click a peer in the sidebar")
        self._msg_task = asyncio.create_task(self._intercept_callbacks())

    async def _disconnect(self):
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

    # ── intercept client callbacks ────────────────────────────

    async def _intercept_callbacks(self):
        """
        Replace _receive_message and _receive_file with TUI-aware versions.
        Uses post_message (safe from any async context) to route to the UI.
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
            # orig_file handles: accept prompt, download, steg extract, save
            # _on_steg_received and _on_xfer_status callbacks post messages to TUI
            await orig_file(meta)
            # For normal (non-steg) files, add a log line here
            if not meta.get("steg", False):
                from_name = meta.get("from_name","?")
                fname     = meta.get("display_name","file")
                size      = meta.get("size",0)
                ts        = datetime.now().strftime("%H:%M")
                line = f"[{ts}] [cyan]↓ {from_name}[/cyan]: [bold]{fname}[/bold]  ({size} B)"
                app_ref.post_message(XferLog(line))

        self._client._receive_message = intercept_msg
        self._client._receive_file    = intercept_file

        while self.connected and self._client:
            await asyncio.sleep(5.0)

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

    # ── steg send ─────────────────────────────────────────────

    async def _send_steg(self):
        if not self._check_ready(): return
        cover = self._val("#steg-cover")
        sel_w = self._q("#steg-sel", Select)
        mode  = sel_w.value if sel_w else "file"
        out   = self._q("#steg-out", Label)

        def st(m, err=False):
            if out: out.update(("[red]" if err else "") + m + ("[/red]" if err else ""))

        if not cover:                  st("⚠  Enter a cover image path"); return
        if not os.path.isfile(cover):  st(f"⚠  Cover not found: {cover}"); return

        if mode == "file":
            fp = self._val("#steg-file")
            if not fp or not os.path.isfile(fp): st("⚠  Enter a valid file path to hide"); return
            payload = open(fp,"rb").read(); label = os.path.basename(fp)
        else:
            txt = self._val("#steg-msg-inp")
            if not txt: st("⚠  Enter a message to hide"); return
            payload = txt.encode(); label = "message"

        st(f"Encrypting + embedding via Pillow LSB …")
        try:
            await self._client.send_steg(self.selected_peer, cover, payload, label=label)
            st(f"[green]✓ Sent hidden {label} to {self._peer_display()}[/green]")
        except Exception as ex:
            st(f"✗ {ex}", err=True)

    # ── aliases ───────────────────────────────────────────────

    def _save_alias(self):
        name = self._val("#inp-alias-name"); pid = self._val("#inp-alias-id")
        if not name or not pid: return
        self._aliases[name] = pid; save_aliases(self._aliases)
        self._draw_alias_log()
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

    # Named _check_ready NOT _ready — Textual has an internal _ready() coroutine;
    # shadowing it causes: TypeError: object bool can't be used in 'await' expression
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

    ap = argparse.ArgumentParser(description="Secure Tunnel TUI")
    ap.add_argument("--relay",       default="")
    ap.add_argument("--secret",      default="")
    ap.add_argument("--name",        default="peer")
    ap.add_argument("--port",        default=4001, type=int)
    ap.add_argument("--fingerprint", default="")
    ap.add_argument("--knock-ports", default="", dest="knock_ports")
    ap.add_argument("--tor",         action="store_true")
    ap.add_argument("--proxy",       default="")
    ap.add_argument("--steg",        action="store_true")
    ap.add_argument("--auto-accept", action="store_true", dest="auto_accept")
    args = ap.parse_args()
    TunnelApp(args).run()

if __name__ == "__main__":
    main()
