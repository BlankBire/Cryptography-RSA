import logging
import math
import time
from typing import Dict, Tuple, Union

from sympy import Rational, integer_nthroot
from sympy.ntheory.continued_fraction import continued_fraction, continued_fraction_convergents
from sympy.ntheory.primetest import isprime

logger = logging.getLogger(__name__)


def wiener_attack(public_key: Union[Dict, Tuple]) -> Dict:
    start_time = time.time()
    try:
        if isinstance(public_key, dict):
            n = int(public_key["n"])
            e = int(public_key["e"])
        else:
            n = int(public_key[0])
            e = int(public_key[1])

        logger.info("Starting Wiener attack on RSA key with n=%s, e=%s", n, e)

        vulnerable_d = _check_wiener_vulnerability(n, e)
        if vulnerable_d:
            logger.info("Key is vulnerable to Wiener attack")
            k = (e * vulnerable_d - 1) // n
            phi = (e * vulnerable_d - 1) // k
            factors = _find_factors(n, phi)
            if factors:
                return _success_response(n, e, vulnerable_d, factors, start_time)

        fractions = continued_fraction(Rational(e, n))
        convergents = list(continued_fraction_convergents(fractions))
        logger.info("Generated %s convergents", len(convergents))

        for convergent in convergents:
            if hasattr(convergent, "numerator") and hasattr(convergent, "denominator"):
                k = int(convergent.numerator)
                d = int(convergent.denominator)
            else:  # pragma: no cover - sympy versions differences
                k, d = map(int, convergent)

            if k == 0 or (e * d - 1) % k != 0:
                continue

            phi = (e * d - 1) // k
            factors = _find_factors(n, phi)
            if factors:
                logger.info("Found private key and factors")
                return _success_response(n, e, d, factors, start_time)

        logger.info("Wiener attack failed - no valid private key found")
        return {
            "success": False,
            "message": "Wiener attack failed - no valid private key found",
            "execution_time": time.time() - start_time,
        }
    except Exception as exc:  # pragma: no cover - defensive
        logger.error("Error in Wiener attack: %s", exc)
        return {
            "success": False,
            "message": f"Error in Wiener attack: {exc}",
            "execution_time": time.time() - start_time,
        }


def _success_response(n: int, e: int, d: int, factors: Dict[str, int], start_time: float) -> Dict:
    return {
        "success": True,
        "private_key": {"n": n, "e": e, "d": d},
        "factors": factors,
        "message": "Wiener attack successful - found private key and factors",
        "execution_time": time.time() - start_time,
    }


def _check_wiener_vulnerability(n: int, e: int) -> Union[int, None]:
    try:
        n_4th_root, _ = integer_nthroot(n, 4)
        d_bound = int((1 / 3) * n_4th_root)

        convergents = list(continued_fraction_convergents(Rational(e, n)))
        for convergent in convergents[:10]:
            if hasattr(convergent, "denominator"):
                d_candidate = int(convergent.denominator)
                if d_candidate < d_bound and (e * d_candidate - 1) % convergent.numerator == 0:
                    return d_candidate
        return None
    except Exception as exc:  # pragma: no cover - defensive
        logger.error("Error checking Wiener vulnerability: %s", exc)
        return None


def _find_factors(n: int, phi: int) -> Union[Dict[str, int], None]:
    try:
        a = 1
        b = -(n - phi + 1)
        c = n
        delta = b * b - 4 * a * c
        if delta <= 0:
            return None

        sqrt_delta = math.isqrt(delta)
        if sqrt_delta * sqrt_delta != delta:
            return None

        p = (-b + sqrt_delta) // (2 * a)
        q = (-b - sqrt_delta) // (2 * a)

        if p * q == n and isprime(p) and isprime(q):
            return {"p": int(p), "q": int(q)}
        return None
    except Exception as exc:  # pragma: no cover - defensive
        logger.error("Error finding factors: %s", exc)
        return None
