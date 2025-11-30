"""Utilities for generating and serialising RSA key pairs."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Tuple

from Crypto.PublicKey import RSA


@dataclass
class KeyPair:
    """Container holding a freshly generated RSA key pair."""

    public_key: RSA.RsaKey
    private_key: RSA.RsaKey

    def as_pem(self) -> Tuple[str, str]:
        return (
            self.public_key.export_key().decode("utf-8"),
            self.private_key.export_key().decode("utf-8"),
        )


def generate_rsa_keypair(key_size: int = 3072, output_dir: str | None = "keys") -> KeyPair:
    """Generate an RSA key pair and optionally persist it to disk."""

    key = RSA.generate(key_size)
    key_pair = KeyPair(public_key=key.publickey(), private_key=key)

    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        with open(os.path.join(output_dir, "public_key.pem"), "wb") as public_file:
            public_file.write(key_pair.public_key.export_key())
        with open(os.path.join(output_dir, "private_key.pem"), "wb") as private_file:
            private_file.write(key_pair.private_key.export_key())

    return key_pair


__all__ = ["KeyPair", "generate_rsa_keypair"]
