import logging
import math
import random
import time
from typing import Dict, List, Tuple, Union

from sympy import integer_nthroot, nextprime
from sympy.ntheory.modular import crt

logger = logging.getLogger(__name__)


def hastad_attack(public_key: Union[Dict, Tuple], ciphertexts: List[Dict] | None = None) -> Dict:
    start_time = time.time()
    try:
        if isinstance(public_key, dict):
            n = int(public_key["n"])
            e = int(public_key["e"])
        else:
            n = int(public_key[0])
            e = int(public_key[1])

        logger.info("Starting Hastad attack on RSA key with n=%s, e=%s", n, e)

        if ciphertexts is None:
            logger.info("No ciphertexts provided, generating test data")
            ciphertexts = _generate_test_ciphertexts(n, e)

        moduli: List[int] = []
        remainders: List[int] = []
        for ciphertext in ciphertexts:
            if isinstance(ciphertext, dict):
                moduli.append(int(ciphertext["n"]))
                remainders.append(int(ciphertext["c"]))
            else:
                moduli.append(int(ciphertext[0]))
                remainders.append(int(ciphertext[1]))

        if len(moduli) < e:
            return {
                "success": False,
                "message": f"Not enough ciphertexts (need {e}, got {len(moduli)})",
                "execution_time": time.time() - start_time,
            }

        if not _are_coprime(moduli):
            return {
                "success": False,
                "message": "Hastad attack failed: Moduli are not pairwise coprime",
                "execution_time": time.time() - start_time,
            }

        result = crt(moduli, remainders)
        if result is None:
            return {
                "success": False,
                "message": "Hastad attack failed: No solution found",
                "execution_time": time.time() - start_time,
            }

        message_value = int(result[0])
        recovered = _find_eth_root(message_value, e)
        if recovered is None:
            return {
                "success": False,
                "message": "Hastad attack failed: Could not recover message",
                "execution_time": time.time() - start_time,
            }

        try:
            message_text = _int_to_text(recovered)
            return {
                "success": True,
                "decrypted_message": recovered,
                "message_text": message_text,
                "message": "Hastad attack successful",
                "execution_time": time.time() - start_time,
            }
        except ValueError:
            return {
                "success": True,
                "decrypted_message": recovered,
                "message": "Hastad attack successful (numeric message)",
                "execution_time": time.time() - start_time,
            }
    except Exception as exc:  # pragma: no cover - defensive
        logger.error("Error in Hastad attack: %s", exc)
        return {
            "success": False,
            "message": f"Error in Hastad attack: {exc}",
            "execution_time": time.time() - start_time,
        }


def _are_coprime(numbers: List[int]) -> bool:
    for index, value in enumerate(numbers):
        for other in numbers[index + 1 :]:
            if math.gcd(value, other) != 1:
                return False
    return True


def _int_to_text(value: int) -> str:
    bytes_data = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return bytes_data.decode("utf-8")


def _generate_test_ciphertexts(n: int, e: int, num_ciphertexts: int = 3) -> List[Dict]:
    message = random.randint(1, 1000)
    ciphertexts: List[Dict] = []
    moduli: List[int] = []

    for _ in range(num_ciphertexts):
        while True:
            p_candidate = nextprime(random.randint(2**512, 2**513))
            q_candidate = nextprime(random.randint(2**512, 2**513))
            modulus = int(p_candidate * q_candidate)
            if all(math.gcd(modulus, existing) == 1 for existing in moduli):
                moduli.append(modulus)
                break
        ciphertexts.append({"n": modulus, "c": pow(message, e, modulus)})

    return ciphertexts


def _find_eth_root(value: int, exponent: int) -> Union[int, None]:
    try:
        root, is_exact = integer_nthroot(value, exponent)
        return int(root) if is_exact else None
    except Exception as exc:  # pragma: no cover - defensive
        logger.error("Error finding e-th root: %s", exc)
        return None


def generate_test_example() -> Dict:
    message = 123
    exponent = 3
    ciphertexts: List[Dict[str, str]] = []
    moduli: List[int] = []

    p1 = nextprime(random.randint(2**100, 2**101))
    q1 = nextprime(random.randint(2**100, 2**101))
    n1 = int(p1 * q1)
    moduli.append(n1)
    c1 = pow(message, exponent, n1)
    ciphertexts.append({"n": str(n1), "c": str(c1)})

    while True:
        p2 = nextprime(random.randint(2**100, 2**101))
        q2 = nextprime(random.randint(2**100, 2**101))
        n2 = int(p2 * q2)
        if math.gcd(n2, n1) == 1:
            moduli.append(n2)
            c2 = pow(message, exponent, n2)
            ciphertexts.append({"n": str(n2), "c": str(c2)})
            break

    while True:
        p3 = nextprime(random.randint(2**100, 2**101))
        q3 = nextprime(random.randint(2**100, 2**101))
        n3 = int(p3 * q3)
        if math.gcd(n3, n1) == 1 and math.gcd(n3, moduli[1]) == 1:
            c3 = pow(message, exponent, n3)
            ciphertexts.append({"n": str(n3), "c": str(c3)})
            break

    return {
        "public_key": {"n": str(n1), "e": str(exponent)},
        "ciphertexts": ciphertexts,
        "original_message": message,
    }
