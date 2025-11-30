"""RSA cipher utilities wrapping PyCryptodome primitives."""

from __future__ import annotations

import base64
import logging
import os
import time
from typing import Dict, Tuple, Union

from Crypto.Cipher import PKCS1_OAEP, PKCS1_v1_5
from Crypto.Hash import SHA3_256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

logger = logging.getLogger(__name__)


class RSACipher:
    """High-level helper around RSA key generation and crypto operations."""

    def __init__(self, key_size: int = 3072) -> None:
        self.key_size = key_size
        self._validate_key_size()

    def _validate_key_size(self) -> None:
        if self.key_size < 2048:
            raise ValueError("Key size must be at least 2048 bits for security")

    @staticmethod
    def generate_keypair(key_size: int = 3072, e: int = 16777217) -> Tuple[RSA.RsaKey, RSA.RsaKey]:
        start_time = time.time()
        key = RSA.generate(key_size, e=e)
        duration = time.time() - start_time
        logger.info("Generated %s-bit RSA keypair with e=%s in %.2fs", key_size, e, duration)
        return key.publickey(), key

    def save_keys(self, public_key: RSA.RsaKey, private_key: RSA.RsaKey, key_dir: str = "keys") -> None:
        try:
            os.makedirs(key_dir, exist_ok=True)
            public_key_path = os.path.join(key_dir, "public_key.pem")
            private_key_path = os.path.join(key_dir, "private_key.pem")

            with open(public_key_path, "wb") as public_file:
                public_file.write(public_key.export_key("PEM"))

            with open(private_key_path, "wb") as private_file:
                private_file.write(private_key.export_key("PEM"))
        except Exception as exc:
            logger.error("Error saving keys: %s", exc)
            raise

    @staticmethod
    def load_keys(key_dir: str = "keys") -> Tuple[RSA.RsaKey, RSA.RsaKey]:
        try:
            with open(os.path.join(key_dir, "public_key.pem"), "rb") as public_file:
                public_key = RSA.import_key(public_file.read())

            with open(os.path.join(key_dir, "private_key.pem"), "rb") as private_file:
                private_key = RSA.import_key(private_file.read())

            return public_key, private_key
        except Exception as exc:
            logger.error("Error loading keys: %s", exc)
            raise

    def encrypt_message(self, message: str, public_key: RSA.RsaKey) -> str:
        try:
            cipher = PKCS1_v1_5.new(public_key)
            message_bytes = message.encode("utf-8")
            encrypted = cipher.encrypt(message_bytes)
            return base64.b64encode(encrypted).decode()
        except Exception as exc:
            logger.error("Encryption error: %s", exc)
            raise

    def decrypt_message(self, ciphertext: str, private_key: RSA.RsaKey) -> str:
        try:
            cipher = PKCS1_v1_5.new(private_key)
            encrypted = base64.b64decode(ciphertext)
            decrypted = cipher.decrypt(encrypted, None)
            return decrypted.decode("utf-8")
        except Exception as exc:
            logger.error("Decryption error: %s", exc)
            raise

    def sign_message(self, message: str, private_key: Union[RSA.RsaKey, Dict]) -> str:
        try:
            key = self._coerce_private_key(private_key)
            digest = SHA3_256.new(message.encode("utf-8"))
            signature = pkcs1_15.new(key).sign(digest)
            return base64.b64encode(signature).decode()
        except Exception as exc:
            logger.error("Signing error: %s", exc)
            raise

    def verify_signature(self, message: str, signature: str, public_key: Union[RSA.RsaKey, Dict]) -> bool:
        try:
            key = self._coerce_public_key(public_key)
            signature_bytes = base64.b64decode(signature)
            digest = SHA3_256.new(message.encode("utf-8"))
            pkcs1_15.new(key).verify(digest, signature_bytes)
            return True
        except Exception as exc:  # broad to return False on validation errors
            logger.info("Signature verification failed: %s", exc)
            return False

    @staticmethod
    def _coerce_private_key(private_key: Union[RSA.RsaKey, Dict]) -> RSA.RsaKey:
        if isinstance(private_key, RSA.RsaKey):
            return private_key
        required_fields = {"n", "e", "d", "p", "q"}
        missing = required_fields.difference(private_key)
        if missing:
            raise ValueError(f"Private key dict missing fields: {', '.join(sorted(missing))}")
        components = tuple(int(private_key[field]) for field in ["n", "e", "d", "p", "q"])
        return RSA.construct(components)

    @staticmethod
    def _coerce_public_key(public_key: Union[RSA.RsaKey, Dict]) -> RSA.RsaKey:
        if isinstance(public_key, RSA.RsaKey):
            return public_key
        required_fields = {"n", "e"}
        missing = required_fields.difference(public_key)
        if missing:
            raise ValueError(f"Public key dict missing fields: {', '.join(sorted(missing))}")
        components = tuple(int(public_key[field]) for field in ["n", "e"])
        return RSA.construct(components)


__all__ = ["RSACipher"]
