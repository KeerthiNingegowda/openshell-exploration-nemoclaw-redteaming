# OpenShell — Python Translation (Study Reference Only)

> **This is a study reference, not a runnable security tool.**
>
> This directory contains a Python translation of the internals of
> [NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell) for the sole purpose
> of **reading and understanding** how OpenShell works. It must not be used as
> an actual sandbox, security policy enforcer, credential manager, or any
> component in a real system. The security properties of the original Rust
> implementation — memory safety, privilege isolation, verified TLS, hardened
> process boundaries — do not carry over to this translation.
>
> For production use, install the real OpenShell binary from the upstream repo.

---

## Why this exists

OpenShell is written in Rust, which can be harder to read for developers more
familiar with Python. This translation exists so you can study the architecture,
the security design decisions, and the internal data flow in a language that is
easier to annotate and reason about line-by-line.

Every module has a docstring pointing back to the originating `.rs` source file
and calling out the Rust → Python translation choices inline.

---

## Files converted and why

### `openshell_core/` — from `crates/openshell-core/`

The shared library used by almost every other crate. Translated because it
contains the most educational material about how OpenShell's security model is
structured.

| File | Source `.rs` | Why translated |
|---|---|---|
| `config.py` | `config.rs` | Shows how driver type is auto-detected (Docker/Podman/K8s socket probing), TLS config, OIDC/JWT settings |
| `auth.py` | `auth.rs` | Edge auth header injection — how API keys/tokens are forwarded to the gateway |
| `jwt.py` | `jwt.rs` | Minimal JWT `exp` field decoding without full verification — illustrates the trust boundary |
| `sandbox_env.py` | `sandbox_env.rs` | The env-var protocol constants that sandboxes use to discover the proxy, gateway, and credentials |
| `secrets.py` | `secrets.rs` | **Security-critical (study only):** placeholder resolver that rewrites `{{SECRET}}` tokens in config into actual credentials in HTTP headers. Do not wire this to real secrets. |
| `provider_credentials.py` | `provider_credentials.rs` | Credential generation ring with locking — how short-lived sandbox credentials are rotated |
| `policy.py` | `policy.rs` | Sandbox policy structs and their proto conversion — the data model for what a policy is |
| `error.py` | `error.rs` | Custom error hierarchy, mirrors the `thiserror` enum variants |
| `paths.py` | `paths.rs` | Platform-aware config/data/log path resolution (`~/.config/openshell`, etc.) |
| `metadata.py` | `metadata.rs` | Sandbox metadata attached to every container (labels, annotations) |
| `image.py` | `image.rs` | Container image name normalization and registry resolution |
| `gpu.py` | `gpu.rs` | CDI (Container Device Interface) GPU inventory parsing and round-robin device selection |
| `time.py` | `time.rs` | Timestamp utilities |
| `forward_check.py` | `forward.rs` | Checks whether a port-forward request is permitted |

### `openshell_policy/` — from `crates/openshell-policy/`

The L7 policy engine. Translated because understanding how allow/deny rules are
parsed and matched is central to understanding OpenShell's network security model.

| File | Source `.rs` | Why translated |
|---|---|---|
| `policy.py` | `lib.rs` | YAML policy file parsing, the `AllowRule`/`DenyRule` data model, glob/method matching |
| `compose.py` | `compose.rs` | How provider-level base policies are layered beneath user-defined sandbox policies |

### `openshell_cli/` — from `crates/openshell-cli/`

The user-facing command-line interface. Translated to show the full command
surface and how each subcommand maps to gRPC calls against the gateway.

| File | Source `.rs` | Why translated |
|---|---|---|
| `main.py` | `main.rs` | Top-level argparse tree mirroring the `clap` command structure |
| `sandbox_cmds.py` | `run.rs` | `sandbox create`, `connect`, `list`, `delete` — argument models and handler logic |
| `ssh.py` | `ssh.rs` | Hardened SSH command construction, SSH config file rendering and host-alias upsert |

### `openshell_drivers/` — from `crates/openshell-driver-docker/` and `crates/openshell-driver-podman/`

The compute drivers that translate abstract sandbox operations into container
runtime API calls. Translated to show the two-phase provisioning pattern and how
container specs are built.

| File | Source `.rs` | Why translated |
|---|---|---|
| `base.py` | _(trait from core)_ | `ComputeDriver` abstract base class — the interface every driver implements |
| `docker_driver.py` | `openshell-driver-docker/src/lib.rs` | Docker Engine HTTP API calls, two-phase async provisioning with locks |
| `podman_driver.py` | `openshell-driver-podman/src/driver.rs` | Podman libpod socket driver |
| `podman_container.py` | `openshell-driver-podman/src/container.rs` | Podman container spec builder (mounts, env, networking, resource limits) |

### `openshell_tui/` — from `crates/openshell-tui/`

The terminal dashboard. Translated to show the UI state machine and navigation
model, using Python's `textual` library in place of Rust's `ratatui`.

| File | Source `.rs` | Why translated |
|---|---|---|
| `app.py` | `app.rs` | `AppState` model, screen navigation, key bindings, sandbox/provider list views |
| `theme.py` | `theme.rs` | NVIDIA-branded color palette and widget styles |

---

## Translation conventions

| Rust | Python |
|---|---|
| `Result<T, E>` | return `T` or `raise` an exception |
| `Option<T>` | `T \| None` |
| `enum` | `enum.Enum` |
| `struct` | `@dataclass` |
| `trait` | `abc.ABC` / `typing.Protocol` |
| `Arc<Mutex<T>>` / `RwLock` | `threading.Lock` / `asyncio.Lock` |
| `tokio` async | `asyncio` |
| `tonic` gRPC | `grpcio` (interfaces; stubs where generated code is needed) |
| `ratatui` TUI | `textual` |
| Linux-only syscalls (VFIO/seccomp/nix) | stubbed with `NotImplementedError` + platform note |

---

## What is real logic vs. stubs

**Faithful translations (readable logic):** secret placeholder resolution,
YAML policy parsing and the L7 rule model, GPU CDI inventory, path
normalization, JWT `exp` decoding, auth-header injection, image resolution,
driver detection, SSH config rendering, TUI state/navigation model, CLI command
tree.

**Clearly-marked stubs** (`raise NotImplementedError`): anything requiring
generated gRPC stubs (live gateway RPCs), live container-runtime HTTP sockets
(Docker Engine / Podman), or host-privileged operations (VFIO, seccomp, network
namespace setup). Each stub has a comment pointing to the originating Rust
function.

---

## What this is NOT

- Not a working sandbox runtime
- Not a security boundary of any kind
- Not a replacement for the upstream Python SDK (`python/openshell/`)
- Not tested for correctness against the real gateway protocol

Study the code. Read the comments. Then go read the original Rust.
