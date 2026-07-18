# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# This file is a derivative work of NVIDIA OpenShell (https://github.com/NVIDIA/OpenShell),
# translated from Rust to Python for study purposes. Changes were made to the original.

"""openshell_policy — Python translation of the ``openshell-policy`` Rust crate.

YAML sandbox policy parsing/serialization and the L7 allow/deny rule model
(``crates/openshell-policy/src/lib.rs``), plus provider policy-layer composition
(``crates/openshell-policy/src/compose.rs``).
"""

from .compose import (
    PROVIDER_RULE_NAME_PREFIX,
    ProviderPolicyLayer,
    compose_effective_policy,
    is_provider_rule_name,
    provider_rule_name,
    strip_provider_rule_names,
)
from .policy import (
    L7Allow,
    L7DenyRule,
    L7QueryMatcher,
    L7Rule,
    NetworkEndpoint,
    NetworkPolicyRule,
    SandboxPolicy,
    parse_sandbox_policy,
    serialize_sandbox_policy,
)

__all__ = [
    "L7Allow",
    "L7DenyRule",
    "L7QueryMatcher",
    "L7Rule",
    "NetworkEndpoint",
    "NetworkPolicyRule",
    "SandboxPolicy",
    "parse_sandbox_policy",
    "serialize_sandbox_policy",
    "PROVIDER_RULE_NAME_PREFIX",
    "ProviderPolicyLayer",
    "compose_effective_policy",
    "is_provider_rule_name",
    "provider_rule_name",
    "strip_provider_rule_names",
]