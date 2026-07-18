# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# This file is a derivative work of NVIDIA OpenShell (https://github.com/NVIDIA/OpenShell),
# translated from Rust to Python for study purposes. Changes were made to the original.

"""Shared GPU resource requirement helpers.

Translated from ``crates/openshell-core/src/gpu.rs``.

Covers CDI (Container Device Interface) NVIDIA GPU inventory normalization and
the concurrency-safe round-robin default selector used by the Docker and Podman
drivers when a sandbox requests one or more GPUs.

Rust patterns:
- ``RwLock<State>`` + ``AtomicUsize`` cursor -> :class:`threading.Lock` guarding
  mutable state and an integer cursor.
- ``Result<Vec<String>, CdiGpuSelectionError>`` -> returns a list or raises
  :class:`CdiGpuSelectionError`.
- ``Option<u32>`` GPU counts -> ``int | None``.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

from .config import CDI_GPU_DEVICE_ALL

_CDI_NVIDIA_GPU_PREFIX = "nvidia.com/gpu="
_CDI_NVIDIA_GPU_ALL_SUFFIX = "all"


# ---- Request helpers (operate on proto-like resource requirement objects) --


def sandbox_gpu_requested(resources) -> bool:
    """True if the sandbox resource requirements request a GPU."""
    return resources is not None and getattr(resources, "gpu", None) is not None


def sandbox_gpu_count(resources) -> int | None:
    """Requested sandbox GPU count, if specified."""
    if resources is None:
        return None
    gpu = getattr(resources, "gpu", None)
    return getattr(gpu, "count", None) if gpu is not None else None


def effective_driver_gpu_count(gpu) -> int | None:
    """Effective driver GPU count. Absent count -> 1. Raises on explicit 0."""
    if gpu is None:
        return None
    count = getattr(gpu, "count", None)
    if count is None:
        count = 1
    if count == 0:
        raise ValueError("gpu count must be greater than 0")
    return count


class CdiGpuSelectionError(Exception):
    """CDI GPU selection failed (Rust ``CdiGpuSelectionError``)."""


class NoAvailableDevices(CdiGpuSelectionError):
    pass


class AllDevicesDefaultUnsupported(CdiGpuSelectionError):
    pass


class InsufficientDevices(CdiGpuSelectionError):
    def __init__(self, requested: int, available: int) -> None:
        self.requested = requested
        self.available = available
        super().__init__(
            f"requested {requested} GPU device(s) but only {available} available"
        )


def _cdi_nvidia_gpu_suffix(device_id: str) -> str | None:
    if device_id.startswith(_CDI_NVIDIA_GPU_PREFIX):
        return device_id[len(_CDI_NVIDIA_GPU_PREFIX) :]
    return None


@dataclass
class CdiGpuInventory:
    """Normalized CDI GPU inventory used by local container drivers.

    Only ``nvidia.com/gpu=*`` device IDs are retained; the list is sorted and
    de-duplicated on construction (matching the Rust ``new``).
    """

    device_ids: list[str]

    @classmethod
    def new(cls, device_ids) -> "CdiGpuInventory":
        filtered = sorted(
            {
                d.strip()
                for d in device_ids
                if d.strip().startswith(_CDI_NVIDIA_GPU_PREFIX)
            }
        )
        return cls(device_ids=filtered)

    def is_empty(self) -> bool:
        return not self.device_ids

    def default_device_family(self, allow_all_devices: bool) -> list[str]:
        """Return the orderable family of default-selectable devices.

        Preference order (from Rust):
        1. numerically-indexed ``nvidia.com/gpu=<n>`` devices, sorted by index;
        2. otherwise named (non-``all``) devices, sorted lexically;
        3. otherwise the ``all`` sentinel (only if ``allow_all_devices``).
        """
        indexed: list[tuple[int, str]] = []
        for device_id in self.device_ids:
            suffix = _cdi_nvidia_gpu_suffix(device_id)
            if suffix is None:
                continue
            try:
                indexed.append((int(suffix), device_id))
            except ValueError:
                continue
        if indexed:
            indexed.sort(key=lambda t: (t[0], t[1]))
            return [d for _, d in indexed]

        named = [
            d
            for d in self.device_ids
            if (s := _cdi_nvidia_gpu_suffix(d)) is not None
            and s != _CDI_NVIDIA_GPU_ALL_SUFFIX
        ]
        if named:
            return sorted(named)

        if any(d == CDI_GPU_DEVICE_ALL for d in self.device_ids):
            if not allow_all_devices:
                raise AllDevicesDefaultUnsupported()
            return [CDI_GPU_DEVICE_ALL]

        raise NoAvailableDevices()


class CdiGpuDefaultSelector:
    """Concurrency-safe default CDI GPU selector with a round-robin cursor.

    ``peek_device_ids`` returns the next devices without advancing;
    ``next_device_ids`` advances the cursor. Both raise
    :class:`InsufficientDevices` when fewer devices are available than requested.
    """

    def __init__(self, inventory: CdiGpuInventory, allow_all_devices: bool) -> None:
        self._lock = threading.Lock()
        self._inventory = inventory
        self._allow_all_devices = allow_all_devices
        self._next = 0  # round-robin cursor (Rust AtomicUsize)

    def refresh(self, inventory: CdiGpuInventory, allow_all_devices: bool) -> None:
        with self._lock:
            self._inventory = inventory
            self._allow_all_devices = allow_all_devices

    def device_ids(self) -> list[str]:
        with self._lock:
            return list(self._inventory.device_ids)

    def peek_device_ids(self, count: int) -> list[str]:
        return self._selected(count, consume=False)

    def next_device_ids(self, count: int) -> list[str]:
        return self._selected(count, consume=True)

    def _selected(self, count: int, consume: bool) -> list[str]:
        with self._lock:
            devices = self._inventory.default_device_family(self._allow_all_devices)
            available = len(devices)
            if count > available:
                raise InsufficientDevices(requested=count, available=available)
            base = self._next
            if consume:
                self._next += count
            return [devices[(base + offset) % available] for offset in range(count)]