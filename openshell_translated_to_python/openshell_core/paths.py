"""Path utilities: XDG dirs, permission helpers, lexical normalization.

Translated from ``crates/openshell-core/src/paths.rs``.

Rust returns ``miette::Result<PathBuf>``; here we return :class:`pathlib.Path`
and raise :class:`~openshell_core.error.ConfigError` when required env vars are
missing. The Unix-only permission helpers (``0o700``/``0o600`` chmod) are
no-ops on non-Unix platforms, exactly as the ``#[cfg(unix)]`` gates in Rust.
"""

from __future__ import annotations

import os
from pathlib import Path, PurePosixPath

from .error import ConfigError


def _env_dir(var: str, *fallback: str) -> Path:
    """Return ``$var`` if set, else ``$HOME`` joined with ``fallback``."""
    value = os.environ.get(var)
    if value:
        return Path(value)
    home = os.environ.get("HOME")
    if not home:
        raise ConfigError("HOME is not set")
    return Path(home, *fallback)


def xdg_config_dir() -> Path:
    """``$XDG_CONFIG_HOME`` or ``$HOME/.config``."""
    return _env_dir("XDG_CONFIG_HOME", ".config")


def openshell_config_dir() -> Path:
    return xdg_config_dir() / "openshell"


def xdg_state_dir() -> Path:
    return _env_dir("XDG_STATE_HOME", ".local", "state")


def openshell_state_dir() -> Path:
    return xdg_state_dir() / "openshell"


def xdg_data_dir() -> Path:
    return _env_dir("XDG_DATA_HOME", ".local", "share")


def create_dir_restricted(path: Path) -> None:
    """Create ``path`` (and parents) with owner-only perms (``0o700``) on Unix."""
    path.mkdir(parents=True, exist_ok=True)
    set_dir_owner_only(path)


def set_dir_owner_only(path: Path) -> None:
    if os.name == "posix":  # Rust: #[cfg(unix)]
        os.chmod(path, 0o700)


def set_file_owner_only(path: Path) -> None:
    if os.name == "posix":
        os.chmod(path, 0o600)


def ensure_parent_dir_restricted(path: Path) -> None:
    if path.parent and str(path.parent) not in ("", "."):
        create_dir_restricted(path.parent)


def is_file_permissions_too_open(path: Path) -> bool:
    """True if the file is group/other readable/writable/executable.

    Always False on non-Unix (matches the Rust ``#[cfg(unix)]`` gate).
    """
    if os.name != "posix":
        return False
    try:
        mode = os.stat(path).st_mode
    except OSError:
        return False
    return (mode & 0o077) != 0


def normalize_path(path: str) -> str:
    """Lexically normalize a path (no filesystem access, no symlink resolution).

    Collapses redundant separators and ``.`` components and strips trailing
    slashes. ``..`` is preserved verbatim — validation catches it separately,
    exactly like the Rust implementation.
    """
    p = PurePosixPath(path)
    parts: list[str] = []
    is_absolute = path.startswith("/")
    for part in p.parts:
        if part == "/":
            continue
        if part == ".":
            continue
        parts.append(part)  # ".." kept verbatim
    normalized = "/".join(parts)
    if is_absolute:
        normalized = "/" + normalized
    return normalized or "."
