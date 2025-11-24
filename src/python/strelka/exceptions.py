from __future__ import annotations
from typing import Any, ClassVar

from .util.timeout import BaseTimeout


__all__ = (
    "ConfigError",
    "DistributionTimeout",
    "RequestTimeout",
    "ScannerException",
    "ScannerTimeout",
)


class ConfigError(ValueError):
    """Raised when a confuguration value is invalid."""

    config_path: str
    config_value: str
    config_format: str

    def __init__(self, path: str, value: Any, format: str) -> None:
        super().__init__(
            f"backend config option {path} has invalid value: expected "
            f"{format}, but got {value!r}"
        )
        self.config_path = path
        self.config_value = value
        self.config_format = format


class ScannerException(Exception):
    DEFAULT_MESSAGE: ClassVar = "an unknown exception occurred during scanning"

    message: str

    def __init__(self, message: str = DEFAULT_MESSAGE) -> None:
        self.message = message
        super().__init__(self.message)


class RequestTimeout(BaseTimeout):
    pass


class DistributionTimeout(BaseTimeout):
    pass


class ScannerTimeout(BaseTimeout):
    pass
