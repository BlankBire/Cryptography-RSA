from Crypto.Cipher import PKCS1_OAEP, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, long_to_bytes

import random
import time
from typing import Dict

from .padding_oracle import simulate_padding_oracle


def padding_oracle_attack(private_key: RSA.RsaKey, ciphertext_hex: str, max_queries: int = 1000) -> Dict:
    """Simulate a padding oracle attack against PKCS#1 v1.5."""

    start_time = time.perf_counter()
    results = []
    decrypted_message_bytes = b""
    success = False
    message = ""

    try:
        if not ciphertext_hex:
            raise ValueError("Ciphertext cannot be empty.")
        if not all(char.lower() in "0123456789abcdef" for char in ciphertext_hex):
            raise ValueError("Ciphertext contains non-hexadecimal characters.")
        if len(ciphertext_hex) % 2 != 0:
            raise ValueError("Ciphertext hexadecimal string must have an even length.")

        n = private_key.n
        e = private_key.e
        public_key = private_key.publickey()
        target_ciphertext = bytes.fromhex(ciphertext_hex)

        try:
            cipher_v1_5_decrypt = PKCS1_v1_5.new(private_key)
            decrypted_result = cipher_v1_5_decrypt.decrypt(target_ciphertext, None)
            decrypted_message_bytes = decrypted_result or b""
        except ValueError as exc:
            message = (
                "Target ciphertext is not valid PKCS#1 v1.5 format or cannot be decrypted by oracle: "
                f"{exc}"
            )
            return _attack_result(False, message, decrypted_message_bytes, results, start_time)
        except Exception as exc:  # pragma: no cover - defensive
            message = f"An unexpected error occurred during initial decryption for simulation: {exc}"
            return _attack_result(False, message, decrypted_message_bytes, results, start_time)

        pow_bound = 2 ** (8 * (public_key.size_in_bytes() - 2))
        _ = pow_bound  # retained for documentation purposes

        s = 1
        initial_s_found = False
        query_count_s0 = 0

        while query_count_s0 < max_queries:
            test_s = random.randint(1, n - 1)
            modified_cipher = (bytes_to_long(target_ciphertext) * pow(test_s, e, n)) % n
            c_prime = long_to_bytes(modified_cipher, public_key.size_in_bytes())

            is_valid = simulate_padding_oracle(private_key, c_prime)
            query_count_s0 += 1
            results.append(
                {
                    "step": "Finding initial s",
                    "s_value": str(test_s),
                    "modified_ciphertext": c_prime.hex(),
                    "padding_valid": is_valid,
                    "query_count": query_count_s0,
                }
            )
            if is_valid:
                s = test_s
                initial_s_found = True
                break

        if not initial_s_found:
            message = "Max queries reached while finding initial s. Attack failed."
        else:
            simulation_steps = max(1, len(decrypted_message_bytes) // 2)
            simulation_steps = min(simulation_steps, 5)
            plaintext_len = len(decrypted_message_bytes)
            chunk_size = max(1, plaintext_len // simulation_steps)

            for index in range(simulation_steps):
                end_idx = min((index + 1) * chunk_size, plaintext_len)
                recovered_chunk = decrypted_message_bytes[:end_idx]
                results.append(
                    {
                        "step": f"Simulated Decryption (Progress {index + 1}/{simulation_steps})",
                        "description": (
                            "Recovered "
                            f"{len(recovered_chunk)}/{plaintext_len} bytes: {recovered_chunk.hex()}"
                        ),
                        "recovered_plaintext_partial": recovered_chunk.hex(),
                        "query_count": query_count_s0 + index + 1,
                    }
                )
                time.sleep(0.05)

            success = True
            message = (
                "Simulated Padding Oracle Attack completed successfully! "
                "(Note: simplified simulation for demonstration.)"
            )

    except ValueError as exc:
        message = f"Input validation error: {exc}"
    except Exception as exc:  # pragma: no cover - defensive
        message = f"An unexpected error occurred during the attack simulation: {exc}"

    return _attack_result(success, message, decrypted_message_bytes, results, start_time)


def _attack_result(success: bool, message: str, plaintext: bytes, results: list, start_time: float) -> Dict:
    return {
        "success": success,
        "message": message,
        "decrypted_data": plaintext.hex(),
        "attack_log": results,
        "execution_time": time.perf_counter() - start_time,
    }
