"""openshell_cli — Python translation of the ``openshell-cli`` Rust crate.

- :mod:`openshell_cli.main` — command tree + dispatch (``src/main.rs``).
- :mod:`openshell_cli.sandbox_cmds` — sandbox create/connect/list/delete (``src/run.rs``).
- :mod:`openshell_cli.ssh` — SSH tunneling / proxy / config (``src/ssh.rs``).
"""

from . import main, sandbox_cmds, ssh

__all__ = ["main", "sandbox_cmds", "ssh"]
