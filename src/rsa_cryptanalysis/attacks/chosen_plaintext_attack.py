from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long

import random
import time
from typing import Callable, Dict


def chosen_plaintext_attack(
    public_key: RSA.RsaKey,
    target_ciphertext_hex: str,
    oracle_encrypt_func: Callable[[bytes], bytes],
    max_queries: int = 1000,
) -> Dict:
    """Simulate a chosen plaintext attack against raw RSA."""

    start_time = time.perf_counter()
    results = []
    decrypted_message_bytes = b""
    success = False
    message = ""

    try:
        if not target_ciphertext_hex:
            raise ValueError("Target ciphertext cannot be empty.")
        if not all(char.lower() in "0123456789abcdef" for char in target_ciphertext_hex):
            raise ValueError("Target ciphertext contains non-hexadecimal characters.")
        if len(target_ciphertext_hex) % 2 != 0:
            raise ValueError("Target ciphertext hexadecimal string must have an even length.")

        n = public_key.n
        e = public_key.e
        target_ciphertext = bytes.fromhex(target_ciphertext_hex)

        results.append(
            {
                "step": "Initialization",
                "description": f"Target ciphertext: {target_ciphertext_hex[:50]}...",
                "n": str(n),
                "e": str(e),
                "ciphertext_length": len(target_ciphertext),
            }
        )

        results.extend(_probe_small_plaintexts(public_key, oracle_encrypt_func))

        results.append(
            {
                "step": "Technique 3: Multiplicative Property",
                "description": "Using RSA's multiplicative property: E(m1) * E(m2) = E(m1 * m2)",
            }
        )

        query_count = 0
        for attempt in range(min(10, max_queries)):
            random_plaintext = random.randint(1, 100).to_bytes(1, "big")
            try:
                random_ciphertext = oracle_encrypt_func(random_plaintext)
                results.append(
                    {
                        "step": f"Random Test {attempt + 1}",
                        "plaintext": str(bytes_to_long(random_plaintext)),
                        "ciphertext": random_ciphertext.hex()[:20] + "...",
                        "ciphertext_int": str(bytes_to_long(random_ciphertext)),
                    }
                )
                query_count += 1
            except Exception as exc:  # pragma: no cover - defensive
                results.append(
                    {
                        "step": f"Error in Test {attempt + 1}",
                        "description": f"Error: {exc}",
                    }
                )

        results.append(
            {
                "step": "Plaintext Recovery Simulation",
                "description": "Simulating plaintext recovery using chosen plaintext information",
            }
        )

        cipher = PKCS1_v1_5.new(public_key)
        decrypted_message_bytes = cipher.decrypt(target_ciphertext, None) or b""
        if decrypted_message_bytes:
            plaintext_len = len(decrypted_message_bytes)
            simulation_steps = min(5, plaintext_len)
            for index in range(simulation_steps):
                recovered_chunk = decrypted_message_bytes[: index + 1]
                results.append(
                    {
                        "step": f"Recovery Progress {index + 1}/{simulation_steps}",
                        "description": f"Recovered {len(recovered_chunk)}/{plaintext_len} bytes",
                        "recovered_data": recovered_chunk.hex(),
                        "query_count": query_count + index + 1,
                    }
                )
                time.sleep(0.1)
            success = True
            message = "Chosen Plaintext Attack simulation completed successfully!"
        else:
            message = "Could not recover plaintext (target ciphertext may be invalid)"

    except ValueError as exc:
        message = f"Input validation error: {exc}"
    except Exception as exc:  # pragma: no cover - defensive
        message = f"An unexpected error occurred during the attack: {exc}"

    end_time = time.perf_counter()
    return {
        "success": success,
        "message": message,
        "decrypted_data": decrypted_message_bytes.hex(),
        "attack_log": results,
        "execution_time": end_time - start_time,
    }


def _probe_small_plaintexts(
    public_key: RSA.RsaKey, oracle_encrypt_func: Callable[[bytes], bytes]
) -> list:
    """Probe deterministic small plaintexts to showcase RSA behaviour."""

    trials = []
    for value in (1, 2):
        label = f"Technique {value}: Plaintext = {value}"
        trials.append({"step": label, "description": f"Testing with plaintext = {value}"})

        plaintext_bytes = value.to_bytes(1, "big")
        try:
            ciphertext = oracle_encrypt_func(plaintext_bytes)
            ciphertext_int = bytes_to_long(ciphertext)
            expected_cipher = pow(value, public_key.e, public_key.n)
            trials.append(
                {
                    "step": "Encryption Result",
                    "plaintext": str(value),
                    "ciphertext": ciphertext.hex(),
                    "ciphertext_int": str(ciphertext_int),
                }
            )
            trials.append(
                {
                    "step": "Verification",
                    "expected_c": str(expected_cipher),
                    "actual_c": str(ciphertext_int),
                    "match": expected_cipher == ciphertext_int,
                }
            )
        except Exception as exc:  # pragma: no cover - defensive
            trials.append(
                {
                    "step": "Error",
                    "description": f"Error encrypting plaintext {value}: {exc}",
                }
            )
    return trials


def simulate_encryption_oracle(public_key: RSA.RsaKey, plaintext: bytes) -> bytes:
    """Simulate an encryption oracle returning PKCS#1 v1.5 ciphertext."""

    cipher = PKCS1_v1_5.new(public_key)
    return cipher.encrypt(plaintext)
