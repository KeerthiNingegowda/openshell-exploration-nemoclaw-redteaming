"""Terminal UI application.

Translated from ``crates/openshell-tui/src/app.rs`` (3000 lines) using the
``textual`` library in place of Rust's ``ratatui`` + ``crossterm``.

The Rust ``App`` is a single large struct holding: the active screen
(Splash/Dashboard/Sandbox), the focused panel, an input mode (Normal/Command),
the gateway/provider/sandbox lists, and an ``OpenShellClient`` gRPC handle. It
renders each frame from that state and mutates it in ``handle_key``.

``textual`` inverts control: instead of a manual draw loop we declare widgets and
react to events. This port keeps the same *state model* (screens, focus, lists)
and the same key semantics, wired into a :class:`textual.app.App`. The gRPC data
loading is a clearly-marked stub — the UI renders whatever lists it is given.

Rust patterns:
- ``enum Screen`` / ``enum Focus`` / ``enum InputMode`` -> :class:`enum.Enum`.
- ``handle_key(&mut self, key)`` -> textual ``on_key`` / action methods.
- ``OpenShellClient<...>`` -> a stubbed data source (:class:`GatewayData`).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto

from .theme import Theme, ThemeMode, detect


class Screen(Enum):
    SPLASH = auto()  # boot screen on startup
    DASHBOARD = auto()  # gateway + provider + sandbox lists
    SANDBOX = auto()  # single-sandbox detail + logs


class InputMode(Enum):
    NORMAL = auto()
    COMMAND = auto()  # ":"-prefixed command line


class Focus(Enum):
    # Dashboard panels
    GATEWAYS = auto()
    PROVIDERS = auto()
    SANDBOXES = auto()
    # Sandbox screen panels
    SANDBOX_POLICY = auto()
    SANDBOX_LOGS = auto()
    SANDBOX_DRAFT = auto()


class LogSourceFilter(Enum):
    ALL = auto()
    GATEWAY = auto()
    SANDBOX = auto()

    def next(self) -> "LogSourceFilter":
        return {
            LogSourceFilter.ALL: LogSourceFilter.GATEWAY,
            LogSourceFilter.GATEWAY: LogSourceFilter.SANDBOX,
            LogSourceFilter.SANDBOX: LogSourceFilter.ALL,
        }[self]


@dataclass
class LogLine:
    """Structured log line from the server (Rust ``LogLine``)."""

    timestamp_ms: int
    level: str
    source: str  # "gateway" or "sandbox"
    target: str
    message: str
    fields: dict[str, str] = field(default_factory=dict)


@dataclass
class GatewayData:
    """Snapshot of gateway state the UI renders.

    Stands in for the live ``OpenShellClient`` gRPC handle in Rust. A real
    implementation would refresh these from ``ListSandboxes`` / ``ListProviders``.
    """

    gateway_name: str = "default"
    endpoint: str = ""
    gateways: list[str] = field(default_factory=list)
    provider_names: list[str] = field(default_factory=list)
    sandbox_names: list[str] = field(default_factory=list)
    sandbox_phases: list[str] = field(default_factory=list)


@dataclass
class AppState:
    """Pure state model mirroring the Rust ``App`` struct (UI-framework-agnostic).

    Kept separate from the textual widget tree so the navigation logic is
    testable and matches ``app.rs`` closely.
    """

    running: bool = True
    screen: Screen = Screen.SPLASH
    input_mode: InputMode = InputMode.NORMAL
    focus: Focus = Focus.SANDBOXES
    command_input: str = ""
    theme: Theme = field(default_factory=Theme.dark)
    status_text: str = ""
    data: GatewayData = field(default_factory=GatewayData)

    gateway_selected: int = 0
    provider_selected: int = 0
    sandbox_selected: int = 0

    log_filter: LogSourceFilter = LogSourceFilter.ALL

    # ---- navigation (Rust ``handle_key`` in Normal mode) -----------------
    def dismiss_splash(self) -> None:
        if self.screen is Screen.SPLASH:
            self.screen = Screen.DASHBOARD

    def cycle_focus(self) -> None:
        """Tab across dashboard panels (Rust focus rotation)."""
        if self.screen is Screen.DASHBOARD:
            order = [Focus.GATEWAYS, Focus.PROVIDERS, Focus.SANDBOXES]
            idx = order.index(self.focus) if self.focus in order else 0
            self.focus = order[(idx + 1) % len(order)]

    def move_selection(self, delta: int) -> None:
        """j/k or arrow movement within the focused list."""
        if self.focus is Focus.GATEWAYS:
            self.gateway_selected = _clamp(self.gateway_selected + delta, self.data.gateways)
        elif self.focus is Focus.PROVIDERS:
            self.provider_selected = _clamp(self.provider_selected + delta, self.data.provider_names)
        elif self.focus is Focus.SANDBOXES:
            self.sandbox_selected = _clamp(self.sandbox_selected + delta, self.data.sandbox_names)

    def enter_command_mode(self) -> None:
        self.input_mode = InputMode.COMMAND
        self.command_input = ""

    def quit(self) -> None:
        self.running = False


def _clamp(value: int, seq: list) -> int:
    if not seq:
        return 0
    return max(0, min(value, len(seq) - 1))


# ---------------------------------------------------------------------------
# textual integration
# ---------------------------------------------------------------------------

try:
    from textual.app import App, ComposeResult
    from textual.binding import Binding
    from textual.widgets import DataTable, Footer, Header, Static

    _TEXTUAL_AVAILABLE = True
except ImportError:  # pragma: no cover - textual optional at import time
    _TEXTUAL_AVAILABLE = False
    App = object  # type: ignore


if _TEXTUAL_AVAILABLE:

    class OpenShellTui(App):  # type: ignore[misc]
        """textual App rendering :class:`AppState`.

        Key bindings mirror the Rust TUI: ``q`` quits, ``tab`` cycles focus,
        ``j``/``k`` move the selection, ``:`` enters command mode.
        """

        CSS = """
        Screen { background: $background; }
        #status { color: $text-muted; }
        """

        BINDINGS = [
            Binding("q", "quit", "Quit"),
            Binding("tab", "cycle_focus", "Focus"),
            Binding("j", "move_down", "Down"),
            Binding("k", "move_up", "Up"),
            Binding("colon", "command", "Command"),
        ]

        def __init__(self, mode: ThemeMode = ThemeMode.AUTO, data: GatewayData | None = None):
            super().__init__()
            self.state = AppState(theme=detect(mode), data=data or GatewayData())
            # Skip splash immediately in this port; Rust auto-dismisses after a timer.
            self.state.dismiss_splash()

        def compose(self) -> "ComposeResult":
            yield Header(show_clock=True)
            self._sandbox_table = DataTable(id="sandboxes")
            self._sandbox_table.add_columns("NAME", "PHASE")
            self._refresh_sandbox_table()
            yield self._sandbox_table
            yield Static(self.state.status_text or "connected", id="status")
            yield Footer()

        def _refresh_sandbox_table(self) -> None:
            self._sandbox_table.clear()
            names = self.state.data.sandbox_names
            phases = self.state.data.sandbox_phases
            for i, name in enumerate(names):
                phase = phases[i] if i < len(phases) else ""
                self._sandbox_table.add_row(name, phase)

        # ---- actions (map to AppState mutations) -------------------------
        def action_quit(self) -> None:  # type: ignore[override]
            self.state.quit()
            self.exit()

        def action_cycle_focus(self) -> None:
            self.state.cycle_focus()

        def action_move_down(self) -> None:
            self.state.move_selection(1)

        def action_move_up(self) -> None:
            self.state.move_selection(-1)

        def action_command(self) -> None:
            self.state.enter_command_mode()


def run(mode: ThemeMode = ThemeMode.AUTO, data: GatewayData | None = None) -> None:
    """Launch the TUI (Rust ``main``/``run`` entry point).

    Loading live data requires the OpenShell gRPC client; pass a prepared
    :class:`GatewayData` to render a static snapshot for demos/tests.
    """
    if not _TEXTUAL_AVAILABLE:  # pragma: no cover
        raise RuntimeError("the 'textual' package is required to run the TUI (pip install textual)")
    OpenShellTui(mode=mode, data=data).run()
