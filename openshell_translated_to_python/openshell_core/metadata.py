# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# This file is a derivative work of NVIDIA OpenShell (https://github.com/NVIDIA/OpenShell),
# translated from Rust to Python for study purposes. Changes were made to the original.

"""Object metadata accessors for Kubernetes-style resources.

Translated from ``crates/openshell-core/src/metadata.rs``.

Rust defines traits (``ObjectId``, ``ObjectName``, ``ObjectLabels``,
``GetResourceVersion``, ``SetResourceVersion``) and implements them for each
proto resource type (``Sandbox``, ``Provider``, ``SshSession`` ...). Every impl
just reaches into the object's optional ``metadata`` sub-message.

Python doesn't need per-type impls: duck typing lets one set of free functions
work for any object that carries a ``metadata`` (with ``id``/``name``/``labels``/
``resource_version``) and optional ``status``. We expose the traits as
:class:`typing.Protocol` classes for documentation, plus these accessors.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class HasMetadata(Protocol):
    metadata: Any  # object with .id, .name, .labels, .resource_version


# ---- Trait-equivalent free functions --------------------------------------
# Rust: ``self.metadata.as_ref().map_or("", |m| m.id.as_str())`` — an absent
# metadata yields the empty string / zero, which we reproduce with getattr.


def object_id(obj: Any) -> str:
    meta = getattr(obj, "metadata", None)
    return getattr(meta, "id", "") if meta is not None else ""


def object_name(obj: Any) -> str:
    meta = getattr(obj, "metadata", None)
    return getattr(meta, "name", "") if meta is not None else ""


def object_labels(obj: Any) -> dict[str, str] | None:
    meta = getattr(obj, "metadata", None)
    if meta is None:
        return None
    labels = getattr(meta, "labels", None)
    return dict(labels) if labels is not None else None


def get_resource_version(obj: Any) -> int:
    meta = getattr(obj, "metadata", None)
    return getattr(meta, "resource_version", 0) if meta is not None else 0


def set_resource_version(obj: Any, version: int) -> None:
    meta = getattr(obj, "metadata", None)
    if meta is not None:
        meta.resource_version = version


# ---- Sandbox-specific helpers (Rust ``impl Sandbox``) ---------------------


def sandbox_phase(sandbox: Any) -> int:
    status = getattr(sandbox, "status", None)
    return getattr(status, "phase", 0) if status is not None else 0


def sandbox_current_policy_version(sandbox: Any) -> int:
    status = getattr(sandbox, "status", None)
    return getattr(status, "current_policy_version", 0) if status is not None else 0