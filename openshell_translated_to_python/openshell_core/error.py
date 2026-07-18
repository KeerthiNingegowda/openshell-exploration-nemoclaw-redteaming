"""Common error types for OpenShell.

Translated from ``crates/openshell-core/src/error.rs``.

Rust uses ``thiserror``/``miette`` enums with a ``Result<T, Error>`` alias.
In Python we model each Rust error variant as an exception subclass. Rust
functions that return ``Result<T, Error>`` become Python functions that either
return ``T`` or ``raise`` the corresponding exception.
"""

from __future__ import annotations

from enum import Enum


class OpenShellError(Exception):
    """Base for all OpenShell errors (the Rust ``Error`` enum).

    Each Rust variant (``Config``, ``Io``, ``Tls`` ...) maps to a subclass so
    ``except`` clauses can discriminate on variant the way a Rust ``match`` on
    the enum would.
    """

    code = "openshell::error"


class ConfigError(OpenShellError):
    """``Error::Config`` — configuration error."""

    code = "openshell::config"


class IoError(OpenShellError):
    """``Error::Io`` — wraps an underlying OS/IO error (``#[from] io::Error``)."""

    code = "openshell::io"


class TlsError(OpenShellError):
    code = "openshell::tls"


class TransportError(OpenShellError):
    """``Error::Transport`` — gRPC transport error."""

    code = "openshell::transport"


class ExecutionError(OpenShellError):
    code = "openshell::execution"


class ProcessError(OpenShellError):
    code = "openshell::process"


class TimeoutError_(OpenShellError):  # noqa: N801 - mirror Rust variant name
    """``Error::Timeout``."""

    code = "openshell::timeout"

    def __init__(self, message: str = "operation timed out") -> None:
        super().__init__(message)


# Convenience constructors mirroring the Rust ``impl Error`` helpers.
def config(message: str) -> ConfigError:
    return ConfigError(f"configuration error: {message}")


def tls(message: str) -> TlsError:
    return TlsError(f"TLS error: {message}")


def transport(message: str) -> TransportError:
    return TransportError(f"transport error: {message}")


def execution(message: str) -> ExecutionError:
    return ExecutionError(f"execution error: {message}")


def process(message: str) -> ProcessError:
    return ProcessError(f"process error: {message}")


class ComputeDriverErrorKind(Enum):
    """Discriminant for :class:`ComputeDriverError` (Rust ``ComputeDriverError``).

    Both the Podman and Docker drivers map backend-specific errors into these
    variants before crossing crate boundaries. In Rust each variant converts to
    a ``tonic::Status``; see :meth:`ComputeDriverError.to_grpc_status`.
    """

    ALREADY_EXISTS = "already_exists"
    INVALID_ARGUMENT = "invalid_argument"
    PRECONDITION = "failed_precondition"
    MESSAGE = "internal"


class ComputeDriverError(OpenShellError):
    """Error shared by all compute driver implementations."""

    def __init__(self, kind: ComputeDriverErrorKind, message: str | None = None) -> None:
        self.kind = kind
        if kind is ComputeDriverErrorKind.ALREADY_EXISTS:
            message = message or "sandbox already exists"
        super().__init__(message or kind.value)

    @classmethod
    def already_exists(cls) -> "ComputeDriverError":
        return cls(ComputeDriverErrorKind.ALREADY_EXISTS)

    @classmethod
    def invalid_argument(cls, message: str) -> "ComputeDriverError":
        return cls(ComputeDriverErrorKind.INVALID_ARGUMENT, message)

    @classmethod
    def precondition(cls, message: str) -> "ComputeDriverError":
        return cls(ComputeDriverErrorKind.PRECONDITION, message)

    @classmethod
    def message(cls, message: str) -> "ComputeDriverError":
        return cls(ComputeDriverErrorKind.MESSAGE, message)

    def to_grpc_status(self):
        """Equivalent of ``impl From<ComputeDriverError> for tonic::Status``.

        Returns a ``(grpc.StatusCode, str)`` pair. Kept dependency-free so the
        module imports without ``grpcio`` installed.
        """
        try:
            import grpc  # type: ignore

            code_map = {
                ComputeDriverErrorKind.ALREADY_EXISTS: grpc.StatusCode.ALREADY_EXISTS,
                ComputeDriverErrorKind.INVALID_ARGUMENT: grpc.StatusCode.INVALID_ARGUMENT,
                ComputeDriverErrorKind.PRECONDITION: grpc.StatusCode.FAILED_PRECONDITION,
                ComputeDriverErrorKind.MESSAGE: grpc.StatusCode.INTERNAL,
            }
            return code_map[self.kind], str(self)
        except ImportError:  # pragma: no cover - grpcio optional
            return self.kind.value, str(self)
