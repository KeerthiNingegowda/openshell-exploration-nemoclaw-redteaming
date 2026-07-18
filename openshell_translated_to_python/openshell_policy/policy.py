# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# This file is a derivative work of NVIDIA OpenShell (https://github.com/NVIDIA/OpenShell),
# translated from Rust to Python for study purposes. Changes were made to the original.

"""Sandbox policy YAML parsing and L7 allow/deny rules.

Translated from ``crates/openshell-policy/src/lib.rs`` (3400 lines in Rust).

The Rust module defines serde types that are the single canonical representation
of the YAML policy schema, used for both parsing (YAML->proto) and serialization
(proto->YAML). This Python port models those same schema types as dataclasses
and provides :func:`parse_sandbox_policy` / :func:`serialize_sandbox_policy`
using PyYAML.

The focus is the network policy / L7 layer that is OpenShell's security core:
- ``NetworkPolicyRule`` = a named rule with endpoints and (optional) binaries.
- ``NetworkEndpoint`` = a host/port/path with L7 ``allow`` and ``deny_rules``.
- ``L7Allow`` / ``L7DenyRule`` = method/path/command/query/params matchers.
- ``L7QueryMatcher`` = a single glob or an ``any: [...]`` glob list.

Rust patterns:
- ``#[serde(untagged)] enum QueryMatcherDef { Glob(String), Any(...) }`` ->
  we parse either a bare string (glob) or ``{any: [...]}`` at load time.
- ``Result<SandboxPolicy>`` -> returns the dataclass or raises.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

try:
    import yaml  # PyYAML — Rust uses serde_yml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore


# ---- L7 matchers ----------------------------------------------------------


@dataclass
class L7QueryMatcher:
    """A single ``glob`` OR an ``any`` list of globs (exactly one is set).

    Rust ``L7QueryMatcher { glob: String, any: Vec<String> }`` — an empty
    ``any`` means the ``glob`` form is in use.
    """

    glob: str = ""
    any: list[str] = field(default_factory=list)

    @classmethod
    def from_yaml(cls, value: Any) -> "L7QueryMatcher":
        # Short form: ``repo: "NVIDIA/*"``.
        if isinstance(value, str):
            return cls(glob=value)
        # Expanded form: ``repo: { any: ["NVIDIA/*", "openai/*"] }``.
        if isinstance(value, dict) and "any" in value:
            return cls(any=list(value["any"]))
        raise ValueError(f"invalid query matcher: {value!r}")

    def to_yaml(self) -> Any:
        return {"any": self.any} if self.any else self.glob


@dataclass
class L7Allow:
    """L7 allow matcher. Empty string / list fields mean "unconstrained"."""

    method: str = ""
    path: str = ""
    command: str = ""
    operation_type: str = ""
    operation_name: str = ""
    fields: list[str] = field(default_factory=list)
    query: dict[str, L7QueryMatcher] = field(default_factory=dict)
    params: dict[str, L7QueryMatcher] = field(default_factory=dict)

    @classmethod
    def from_yaml(cls, d: dict) -> "L7Allow":
        return cls(
            method=d.get("method", ""),
            path=d.get("path", ""),
            command=d.get("command", ""),
            operation_type=d.get("operation_type", ""),
            operation_name=d.get("operation_name", ""),
            fields=list(d.get("fields", [])),
            query={k: L7QueryMatcher.from_yaml(v) for k, v in d.get("query", {}).items()},
            # ``tool`` and ``params`` are flattened into the params map in Rust;
            # we keep params directly for clarity.
            params={k: L7QueryMatcher.from_yaml(v) for k, v in d.get("params", {}).items()},
        )


# L7DenyRule has the same shape as L7Allow in this schema.
L7DenyRule = L7Allow


@dataclass
class L7Rule:
    """A single L7 rule wrapping an ``allow`` matcher (Rust ``L7RuleDef``)."""

    allow: L7Allow


# ---- Endpoints & network rules --------------------------------------------


@dataclass
class NetworkEndpoint:
    host: str = ""
    path: str = ""
    port: int = 0
    ports: list[int] = field(default_factory=list)
    protocol: str = ""
    tls: str = ""
    enforcement: str = ""
    access: str = ""
    rules: list[L7Rule] = field(default_factory=list)  # L7 allow rules
    allowed_ips: list[str] = field(default_factory=list)
    deny_rules: list[L7DenyRule] = field(default_factory=list)
    allow_encoded_slash: bool = False
    websocket_credential_rewrite: bool = False
    request_body_credential_rewrite: bool = False

    @classmethod
    def from_yaml(cls, d: dict) -> "NetworkEndpoint":
        return cls(
            host=d.get("host", ""),
            path=d.get("path", ""),
            port=int(d.get("port", 0)),
            ports=[int(p) for p in d.get("ports", [])],
            protocol=d.get("protocol", ""),
            tls=d.get("tls", ""),
            enforcement=d.get("enforcement", ""),
            access=d.get("access", ""),
            rules=[L7Rule(allow=L7Allow.from_yaml(r["allow"])) for r in d.get("rules", [])],
            allowed_ips=list(d.get("allowed_ips", [])),
            deny_rules=[L7DenyRule.from_yaml(r) for r in d.get("deny_rules", [])],
            allow_encoded_slash=d.get("allow_encoded_slash", False),
            websocket_credential_rewrite=d.get("websocket_credential_rewrite", False),
            request_body_credential_rewrite=d.get("request_body_credential_rewrite", False),
        )


@dataclass
class NetworkBinary:
    path: str


@dataclass
class NetworkPolicyRule:
    name: str = ""
    endpoints: list[NetworkEndpoint] = field(default_factory=list)
    binaries: list[NetworkBinary] = field(default_factory=list)

    @classmethod
    def from_yaml(cls, name: str, d: dict) -> "NetworkPolicyRule":
        return cls(
            name=d.get("name", "") or name,
            endpoints=[NetworkEndpoint.from_yaml(e) for e in d.get("endpoints", [])],
            binaries=[NetworkBinary(path=b["path"]) for b in d.get("binaries", [])],
        )


# ---- Static policy sections -----------------------------------------------


@dataclass
class FilesystemDef:
    include_workdir: bool = False
    read_only: list[str] = field(default_factory=list)
    read_write: list[str] = field(default_factory=list)


@dataclass
class ProcessDef:
    run_as_user: str = ""
    run_as_group: str = ""


@dataclass
class LandlockDef:
    compatibility: str = ""


@dataclass
class SandboxPolicy:
    """Parsed sandbox policy (the proto-equivalent produced from YAML).

    ``network_policies`` is a name-keyed map, matching the Rust
    ``BTreeMap<String, NetworkPolicyRule>``.
    """

    version: int = 0
    filesystem: FilesystemDef | None = None
    landlock: LandlockDef | None = None
    process: ProcessDef | None = None
    network_policies: dict[str, NetworkPolicyRule] = field(default_factory=dict)


def parse_sandbox_policy(yaml_text: str) -> SandboxPolicy:
    """Parse policy YAML into a :class:`SandboxPolicy` (Rust ``parse_sandbox_policy``)."""
    if yaml is None:  # pragma: no cover
        raise RuntimeError("PyYAML is required to parse policies (pip install pyyaml)")
    raw = yaml.safe_load(yaml_text) or {}
    fs = raw.get("filesystem_policy")
    ll = raw.get("landlock")
    proc = raw.get("process")
    return SandboxPolicy(
        version=int(raw.get("version", 0)),
        filesystem=FilesystemDef(
            include_workdir=fs.get("include_workdir", False),
            read_only=list(fs.get("read_only", [])),
            read_write=list(fs.get("read_write", [])),
        )
        if fs
        else None,
        landlock=LandlockDef(compatibility=ll.get("compatibility", "")) if ll else None,
        process=ProcessDef(
            run_as_user=proc.get("run_as_user", ""),
            run_as_group=proc.get("run_as_group", ""),
        )
        if proc
        else None,
        network_policies={
            name: NetworkPolicyRule.from_yaml(name, rule)
            for name, rule in raw.get("network_policies", {}).items()
        },
    )


def serialize_sandbox_policy(policy: SandboxPolicy) -> str:
    """Serialize a :class:`SandboxPolicy` back to canonical YAML.

    Inverse of :func:`parse_sandbox_policy`; uses the canonical field names
    (``filesystem_policy``, not ``filesystem``) so output round-trips.
    """
    if yaml is None:  # pragma: no cover
        raise RuntimeError("PyYAML is required to serialize policies")
    out: dict[str, Any] = {"version": policy.version}
    if policy.filesystem:
        out["filesystem_policy"] = {
            "include_workdir": policy.filesystem.include_workdir,
            "read_only": policy.filesystem.read_only,
            "read_write": policy.filesystem.read_write,
        }
    if policy.landlock:
        out["landlock"] = {"compatibility": policy.landlock.compatibility}
    if policy.process:
        out["process"] = {
            "run_as_user": policy.process.run_as_user,
            "run_as_group": policy.process.run_as_group,
        }
    if policy.network_policies:
        out["network_policies"] = {
            name: _rule_to_yaml(rule) for name, rule in policy.network_policies.items()
        }
    return yaml.safe_dump(out, sort_keys=False)


def _rule_to_yaml(rule: NetworkPolicyRule) -> dict:
    d: dict[str, Any] = {}
    if rule.name:
        d["name"] = rule.name
    if rule.endpoints:
        d["endpoints"] = [_endpoint_to_yaml(e) for e in rule.endpoints]
    if rule.binaries:
        d["binaries"] = [{"path": b.path} for b in rule.binaries]
    return d


def _endpoint_to_yaml(e: NetworkEndpoint) -> dict:
    d: dict[str, Any] = {}
    for key in ("host", "path", "protocol", "tls", "enforcement", "access"):
        if getattr(e, key):
            d[key] = getattr(e, key)
    if e.port:
        d["port"] = e.port
    if e.ports:
        d["ports"] = e.ports
    if e.rules:
        d["rules"] = [{"allow": _allow_to_yaml(r.allow)} for r in e.rules]
    if e.deny_rules:
        d["deny_rules"] = [_allow_to_yaml(r) for r in e.deny_rules]
    if e.allowed_ips:
        d["allowed_ips"] = e.allowed_ips
    return d


def _allow_to_yaml(a: L7Allow) -> dict:
    d: dict[str, Any] = {}
    for key in ("method", "path", "command", "operation_type", "operation_name"):
        if getattr(a, key):
            d[key] = getattr(a, key)
    if a.fields:
        d["fields"] = a.fields
    if a.query:
        d["query"] = {k: v.to_yaml() for k, v in a.query.items()}
    if a.params:
        d["params"] = {k: v.to_yaml() for k, v in a.params.items()}
    return d