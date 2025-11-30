"""Backward compatibility shim for generate_rsa_keypair utility."""

from rsa_cryptanalysis.core.keygen import KeyPair, generate_rsa_keypair  # noqa: F401

__all__ = ["KeyPair", "generate_rsa_keypair"]
