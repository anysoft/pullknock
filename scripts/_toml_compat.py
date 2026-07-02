"""Compatibility import for TOML parsing across supported Python versions."""

from __future__ import annotations

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib

__all__ = ["tomllib"]
