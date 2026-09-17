# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# This file is a derivative work of NVIDIA OpenShell (https://github.com/NVIDIA/OpenShell),
# translated from Rust to Python for study purposes. Changes were made to the original.

"""Sandbox policy validation, canonicalization, and endpoint-ambiguity detection.

Translated from the validation surface added to
``crates/openshell-policy/src/lib.rs`` and the new
``crates/openshell-policy/src/ambiguity.rs``.

Two upstream concepts land here:

1. **Validate + canonicalize** (``validate_and_canonicalize_sandbox_policy``):
   validate a policy (including MCP-version presence), then materialize default
   MCP versions and canonicalize MCP allow-lists so the stored form is
   deterministic. Failures are collected as :class:`PolicyValidationError`.

2. **Endpoint ambiguity** (``find_endpoint_ambiguities``): a policy is rejected
   before activation if two endpoints can authorize the *same* request (their
   host + overlapping ports, and — for request-pipeline metadata — overlapping
   paths of equal specificity) yet disagree on policy-derived behavior that must
   have a single deterministic value (connection metadata, request-pipeline
   metadata). The pairwise scan is translated; the many small overlap/conflict
   predicates are summarized with citations, as they are mechanical string/port
   comparisons.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .policy import SandboxPolicy, parse_sandbox_policy


@dataclass
class PolicyViolation:
    """A single policy-validation failure (Rust ``PolicyViolation``)."""

    message: str


class PolicyValidationError(Exception):
    """Carries every :class:`PolicyViolation` found while validating a policy."""

    def __init__(self, violations: list[PolicyViolation]) -> None:
        self._violations = list(violations)
        super().__init__("; ".join(v.message for v in violations) or "policy validation failed")

    def violations(self) -> list[PolicyViolation]:
        return list(self._violations)

    def into_violations(self) -> list[PolicyViolation]:
        return self._violations


def validate_and_canonicalize_sandbox_policy(policy: SandboxPolicy) -> SandboxPolicy:
    """Validate, then canonicalize MCP versions/allow-lists (returns the canonical policy).

    Raises :class:`PolicyValidationError` if validation fails. The MCP-presence
    validation, default-version materialization, and allow-list canonicalization
    are summarized here (they operate on proto MCP options not modeled in this
    study translation).

    Real implementation:
      crates/openshell-policy/src/lib.rs — validate_and_canonicalize_sandbox_policy
      (validate_sandbox_policy_with_mcp_presence, materialize_default_mcp_versions,
      canonicalize_mcp_version_allowlists)
    """
    ambiguities = find_endpoint_ambiguities(policy)
    if ambiguities:
        raise PolicyValidationError([PolicyViolation(str(a)) for a in ambiguities])
    return policy


def parse_sandbox_policy_file(path: Path) -> SandboxPolicy:
    """Parse and validate an authored policy file (bounded parse in Rust)."""
    text = Path(path).read_text(encoding="utf-8")
    return parse_sandbox_policy(text)


# ---------------------------------------------------------------------------
# Endpoint ambiguity detection (ambiguity.rs)
# ---------------------------------------------------------------------------
@dataclass
class EndpointAmbiguity:
    """Two endpoints that can authorize the same request but disagree on
    policy-derived behavior that must be single-valued."""

    left_policy: str
    left_endpoint_index: int
    left_selector: str
    right_policy: str
    right_endpoint_index: int
    right_selector: str
    overlapping_ports: list[int] = field(default_factory=list)
    conflicts: list[str] = field(default_factory=list)

    def __str__(self) -> str:
        ports = ",".join(str(p) for p in self.overlapping_ports)
        return (
            f"network policies '{self.left_policy}' endpoint[{self.left_endpoint_index}] "
            f"({self.left_selector}) and '{self.right_policy}' "
            f"endpoint[{self.right_endpoint_index}] ({self.right_selector}) overlap on "
            f"port(s) {ports} with conflicting metadata: {'; '.join(self.conflicts)}"
        )


@dataclass
class _EndpointRef:
    policy: str
    index: int
    endpoint: object


def find_endpoint_ambiguities(policy: SandboxPolicy) -> list[EndpointAmbiguity]:
    """Return every pair of endpoints whose policy-derived behavior conflicts.

    Request authorization rules (``access``, ``rules``, ``deny_rules``) may be
    contributed by multiple compatible endpoints; connection- and
    request-pipeline metadata must agree whenever host/port (and, for
    request-specific metadata, path) selectors can match the same request.

    The overlap/conflict predicates (``overlapping_ports``,
    ``host_patterns_overlap``, ``connection_conflicts``,
    ``request_pipeline_conflicts``, ``path_patterns_overlap``,
    ``path_selector_specificity``) are summarized — they are mechanical
    host-pattern / port-range / path comparisons.

    Real implementation:
      crates/openshell-policy/src/ambiguity.rs — find_endpoint_ambiguities
    """
    endpoints: list[_EndpointRef] = []
    for key, rule in _network_policies(policy):
        policy_name = getattr(rule, "name", "") or key
        for index, endpoint in enumerate(getattr(rule, "endpoints", []) or []):
            endpoints.append(_EndpointRef(policy_name, index, endpoint))

    ambiguities: list[EndpointAmbiguity] = []
    for left_i in range(len(endpoints)):
        for right_i in range(left_i + 1, len(endpoints)):
            left, right = endpoints[left_i], endpoints[right_i]
            overlapping = _overlapping_ports(left.endpoint, right.endpoint)
            if not overlapping or not _host_patterns_overlap(
                getattr(left.endpoint, "host", ""), getattr(right.endpoint, "host", "")
            ):
                continue
            conflicts = _connection_conflicts(left.endpoint, right.endpoint)
            if (
                _contributes_request_pipeline_metadata(left.endpoint)
                and _contributes_request_pipeline_metadata(right.endpoint)
                and _path_patterns_overlap(
                    getattr(left.endpoint, "path", ""), getattr(right.endpoint, "path", "")
                )
                and _path_selector_specificity(getattr(left.endpoint, "path", ""))
                == _path_selector_specificity(getattr(right.endpoint, "path", ""))
            ):
                conflicts += _request_pipeline_conflicts(left.endpoint, right.endpoint)
            if not conflicts:
                continue
            ambiguities.append(
                EndpointAmbiguity(
                    left_policy=left.policy,
                    left_endpoint_index=left.index,
                    left_selector=_endpoint_selector(left.endpoint),
                    right_policy=right.policy,
                    right_endpoint_index=right.index,
                    right_selector=_endpoint_selector(right.endpoint),
                    overlapping_ports=overlapping,
                    conflicts=conflicts,
                )
            )
    return ambiguities


# ---- summarized overlap/conflict predicates (see ambiguity.rs citations) ----
def _network_policies(policy: SandboxPolicy):
    nps = getattr(policy, "network_policies", None)
    if nps is None:
        return []
    return nps.items() if hasattr(nps, "items") else list(nps)


def _endpoint_selector(endpoint) -> str:
    host = getattr(endpoint, "host", "") or "<any-host>"
    path = getattr(endpoint, "path", "") or ""
    ports = ",".join(str(p) for p in (getattr(endpoint, "ports", []) or [])) or "<any-port>"
    return f"{host}:{ports}{path}"


def _overlapping_ports(left, right) -> list[int]:
    left_ports = set(getattr(left, "ports", []) or [])
    right_ports = set(getattr(right, "ports", []) or [])
    # An empty port set matches any port; upstream models that as full overlap.
    if not left_ports or not right_ports:
        return sorted(left_ports or right_ports)
    return sorted(left_ports & right_ports)


def _host_patterns_overlap(left: str, right: str) -> bool:
    # Summarized: upstream compares host glob patterns. Empty host = any host.
    return not left or not right or left == right


def _path_patterns_overlap(left: str, right: str) -> bool:
    return not left or not right or left == right


def _path_selector_specificity(path: str) -> int:
    return len(path)


def _contributes_request_pipeline_metadata(endpoint) -> bool:
    # Summarized: true when the endpoint carries request-pipeline metadata.
    return bool(getattr(endpoint, "path", ""))


def _connection_conflicts(left, right) -> list[str]:
    # Real implementation: ambiguity.rs — connection_conflicts.
    return []


def _request_pipeline_conflicts(left, right) -> list[str]:
    # Real implementation: ambiguity.rs — request_pipeline_conflicts.
    return []
