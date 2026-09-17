# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# This file is a derivative work of NVIDIA OpenShell (https://github.com/NVIDIA/OpenShell),
# translated from Rust to Python for study purposes. Changes were made to the original.

"""Policy layer composition helpers.

Translated from ``crates/openshell-policy/src/compose.rs``.

Composes an effective sandbox policy from a user-authored base policy plus a set
of provider policy layers. Provider rules are stored under a reserved
``_provider_*`` key namespace so they can be identified and stripped later
without disturbing user-authored network rules.
"""

from __future__ import annotations

from dataclasses import dataclass

from .policy import NetworkPolicyRule, SandboxPolicy

PROVIDER_RULE_NAME_PREFIX = "_provider_"


@dataclass
class ProviderPolicyLayer:
    rule_name: str
    rule: NetworkPolicyRule


def is_provider_rule_name(rule_name: str) -> bool:
    return rule_name.startswith(PROVIDER_RULE_NAME_PREFIX)


def generated_rule_name(host: str, port: int) -> str:
    """Deterministic rule name for a single host:port (Rust ``merge::generated_rule_name``).

    ``.`` and ``-`` become ``_``; any remaining non-alphanumeric/underscore chars
    are dropped. e.g. ``("api.github.com", 443)`` -> ``allow_api_github_com_443``.
    """
    replaced = host.replace(".", "_").replace("-", "_")
    sanitized = "".join(c for c in replaced if c.isalnum() or c == "_")
    return f"allow_{sanitized}_{port}"


def canonicalize_advisor_add_rule(
    base_policy: SandboxPolicy,
    effective_policy: SandboxPolicy,
    requested_rule_name: str,
    incoming_rule: NetworkPolicyRule,
) -> tuple[str, NetworkPolicyRule]:
    """Canonicalize an advisor-proposed single-endpoint add-rule.

    When the incoming rule is a single endpoint with exactly one host and one
    port (and at least one binary), upstream folds it onto the deterministic
    :func:`generated_rule_name` and merges with any existing contract for that
    host:port. Anything else is returned unchanged. The full contract-merge
    logic is summarized here.

    Real implementation:
      crates/openshell-policy/src/merge.rs — canonicalize_advisor_add_rule
    """
    endpoints = getattr(incoming_rule, "endpoints", []) or []
    binaries = getattr(incoming_rule, "binaries", []) or []
    if len(endpoints) != 1 or not binaries:
        return requested_rule_name, incoming_rule
    endpoint = endpoints[0]
    host = (getattr(endpoint, "host", "") or "").strip()
    ports = getattr(endpoint, "ports", []) or []
    if not host or len(ports) != 1:
        return requested_rule_name, incoming_rule
    return generated_rule_name(host, ports[0]), incoming_rule


def provider_rule_name(provider_name: str) -> str:
    """Sanitize a provider name into a reserved ``_provider_<slug>`` key.

    Non-alphanumeric/underscore chars become ``_``; the result is lowercased and
    trimmed of leading/trailing underscores. Empty -> ``_provider_unnamed``.
    """
    sanitized = "".join(
        c.lower() if (c.isalnum() and c.isascii()) or c == "_" else "_"
        for c in provider_name
    ).strip("_")
    if not sanitized:
        return f"{PROVIDER_RULE_NAME_PREFIX}unnamed"
    return f"{PROVIDER_RULE_NAME_PREFIX}{sanitized}"


def strip_provider_rule_names(policy: SandboxPolicy) -> bool:
    """Remove all reserved ``_provider_*`` rules in place. Returns True if any removed."""
    before = len(policy.network_policies)
    policy.network_policies = {
        k: v for k, v in policy.network_policies.items() if not is_provider_rule_name(k)
    }
    return len(policy.network_policies) != before


def _unique_provider_rule_key(policy: SandboxPolicy, preferred: str) -> str:
    """Find an unused key: ``preferred``, then ``preferred_2``, ``_3`` ..."""
    if preferred not in policy.network_policies:
        return preferred
    suffix = 2
    while True:
        candidate = f"{preferred}_{suffix}"
        if candidate not in policy.network_policies:
            return candidate
        suffix += 1


def compose_effective_policy(
    source_policy: SandboxPolicy, provider_layers: list[ProviderPolicyLayer]
) -> SandboxPolicy:
    """Compose an effective policy = base policy + provider layers.

    Existing keys are never overwritten; a numeric suffix disambiguates provider
    rule-name collisions. The source policy is not mutated (a shallow-ish copy of
    ``network_policies`` is made, matching Rust's ``clone``).
    """
    import copy

    effective = copy.deepcopy(source_policy)
    for layer in provider_layers:
        key = _unique_provider_rule_key(effective, layer.rule_name)
        rule = copy.deepcopy(layer.rule)
        if not rule.name:
            rule.name = key
        effective.network_policies[key] = rule
    return effective