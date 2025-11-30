"""Backward compatibility shim for the legacy RSA core module."""

from rsa_cryptanalysis.core.rsa_cipher import RSACipher  # noqa: F401

__all__ = ["RSACipher"]
