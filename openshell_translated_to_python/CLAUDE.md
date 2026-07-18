# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this directory is

A **study-only Python translation** of [NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell) (Apache 2.0), originally written in Rust. The purpose is to make OpenShell's internal architecture legible in Python. It is not a runnable tool, not a security boundary, and must never be wired to real credentials or infrastructure.

The upstream Rust source lives at `/tmp/OpenShell/crates/` (cloned from `git@github.com:NVIDIA/OpenShell.git`) and is the reference for all translation work.

## Honest assessment of this translation

**Where it works well:** The pure logic modules — `secrets.py`, `policy.py`, `config.py`, `gpu.py` — translate nearly 1:1 and are genuinely easier to read in Python. The placeholder-rewriting security pattern and L7 policy rule model come through clearly. For learning *what* OpenShell does and *why*, these files are more approachable than the Rust originals.

**Where it falls short:** The translation loses the properties that make OpenShell actually safe. Rust's ownership model, borrow checker, and `unsafe` restrictions are what guarantee memory safety and prevent credential leaks at the type level — none of that carries over. The async driver code (`docker_driver.py`, `podman_driver.py`) captures the *shape* of the two-phase provisioning pattern but the stubs hollow out the most instructive parts: the actual Docker/Podman HTTP transport and the gRPC streaming relay. If you want to understand the hardest and most security-relevant code — the network proxy, VFIO passthrough, seccomp filtering — you have no choice but to read the Rust. This translation is a front door, not a substitute.

## Working preferences

**Never run or execute code during translation tasks.** Translate only — no smoke tests, no import checks, no `python -c` validation. If something can't be translated cleanly, mark it as a stub.

**Always confirm the target remote before pushing.** State the repo URL and wait for approval.

**Every `NotImplementedError` stub must include a `# Real implementation:` comment** with the exact Rust file path and line number, e.g.:
```python
# Real implementation:
#   crates/openshell-cli/src/run.rs:1960 — async fn sandbox_create
raise NotImplementedError("... see crates/openshell-cli/src/run.rs:1960")
```

**Every Python file must carry the SPDX header** (Apache 2.0 compliance):
```python
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# This file is a derivative work of NVIDIA OpenShell (https://github.com/NVIDIA/OpenShell),
# translated from Rust to Python for study purposes. Changes were made to the original.
```

## Architecture

Five packages, each mapping to one or more Rust crates:

| Package | Rust crate(s) | What it covers |
|---|---|---|
| `openshell_core/` | `openshell-core` | Config, auth, JWT, sandbox env protocol, secret placeholder resolution, provider credentials, policy structs, GPU CDI selection |
| `openshell_policy/` | `openshell-policy` | YAML policy parsing, L7 allow/deny rule model, provider policy composition |
| `openshell_cli/` | `openshell-cli` | CLI command tree, sandbox create/connect/list/delete, SSH config rendering |
| `openshell_drivers/` | `openshell-driver-docker`, `openshell-driver-podman` | `ComputeDriver` ABC, Docker/Podman sandbox lifecycle, container spec builder |
| `openshell_tui/` | `openshell-tui` | Terminal UI state machine and theme (ratatui → textual) |

**Key architectural pattern — secrets never leave the gateway:** `openshell_core/secrets.py` (`secrets.rs`) is the most security-critical module. Provider env vars are replaced with opaque placeholders (`openshell:resolve:env:KEY`) in the child environment. The `SecretResolver` in the network supervisor rewrites outgoing HTTP headers back to real values just before forwarding upstream — agents only ever see placeholders.

**Two-phase async provisioning (drivers):** `docker_driver.py` and `podman_driver.py` follow the Rust pattern of returning immediately after reserving a pending record, then spawning a background task (`asyncio.create_task` / `tokio::spawn`) for image pull → token write → container create → start.

**Policy layering:** `openshell_policy/compose.py` shows how provider base policies are stacked beneath user sandbox policies. `openshell_policy/policy.py` is the YAML schema and L7 matcher.

## Translation conventions

| Rust | Python |
|---|---|
| `Result<T, E>` | return `T` or `raise` |
| `Option<T>` | `T \| None` |
| `struct` | `@dataclass` |
| `enum` | `enum.Enum` |
| `trait` | `abc.ABC` |
| `Arc<Mutex<T>>` | `asyncio.Lock` |
| `tokio` async | `asyncio` |
| `tonic` gRPC | `grpcio` (stubbed where generated stubs needed) |
| `ratatui` | `textual` |
| Linux syscalls (VFIO, seccomp, nix) | `NotImplementedError` + platform note |

Each module docstring maps to its `.rs` source file and explains the translation choices.
