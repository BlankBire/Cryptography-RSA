"""Helper utilities for padding oracle simulations."""

from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA


def simulate_padding_oracle(private_key: RSA.RsaKey, ciphertext: bytes) -> bool:
    """Simulate a PKCS#1 v1.5 padding oracle response."""

    cipher = PKCS1_v1_5.new(private_key)
    try:
        cipher.decrypt(ciphertext, None)
        return True
    except ValueError as exc:
        return "Padding is not correct." not in str(exc)
    except Exception:
        return False
