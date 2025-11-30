import logging
import math
import random
import time
from typing import Dict, List, Tuple

logger = logging.getLogger(__name__)


def trial_division(n: int) -> Tuple[int, int] | Tuple[None, None]:
    for divisor in range(2, int(math.isqrt(n)) + 1):
        if n % divisor == 0:
            return divisor, n // divisor
    return None, None


def fermat_factor(n: int) -> Tuple[int, int] | Tuple[None, None]:
    if n % 2 == 0:
        return 2, n // 2

    a = math.isqrt(n)
    if a * a < n:
        a += 1

    while True:
        b2 = a * a - n
        b = math.isqrt(b2)
        if b * b == b2:
            p = a - b
            q = a + b
            if p * q == n:
                return p, q
        a += 1
        if a - math.isqrt(n) > 1_000_000:
            return None, None


def pollards_rho(n: int) -> Tuple[int, int] | Tuple[None, None]:
    if n % 2 == 0:
        return 2, n // 2

    def f(x: int) -> int:
        return (x * x + 1) % n

    x, y, d = 2, 2, 1
    while d == 1:
        x = f(x)
        y = f(f(y))
        d = math.gcd(abs(x - y), n)
    if d == n:
        return None, None
    return d, n // d


def quadratic_sieve(n: int, smoothness_bound: int = 1000) -> Tuple[int, int] | Tuple[None, None]:
    if n % 2 == 0:
        return 2, n // 2

    relations = []
    x = int(math.isqrt(n)) + 1

    while len(relations) < smoothness_bound:
        y = x * x - n
        if y > 0:
            factors = _factor_smooth(y, smoothness_bound)
            if factors:
                relations.append((x, factors))
        x += 1

    matrix = _build_matrix(relations)
    solution = _solve_matrix(matrix)

    if solution:
        x_val = 1
        y_val = 1
        for index, bit in enumerate(solution):
            if bit:
                x_val = (x_val * relations[index][0]) % n
                y_val = (y_val * relations[index][1]) % n

        p = math.gcd(x_val + y_val, n)
        if p not in (1, n):
            return p, n // p

    return None, None


def elliptic_curve_method(n: int, max_curves: int = 100) -> Tuple[int, int] | Tuple[None, None]:
    if n % 2 == 0:
        return 2, n // 2

    for _ in range(max_curves):
        a = random.randrange(1, n)
        b = random.randrange(1, n)
        x = random.randrange(1, n)
        y = random.randrange(1, n)

        for multiplier in range(2, 1000):
            try:
                x, y = _ec_multiply(x, y, a, b, n, multiplier)
                factor = math.gcd(x, n)
                if factor not in (1, n):
                    return factor, n // factor
            except Exception:  # pragma: no cover - defensive
                continue

    return None, None


def _factor_smooth(n: int, bound: int) -> List[int]:
    factors: List[int] = []
    for prime_candidate in range(2, bound + 1):
        while n % prime_candidate == 0:
            factors.append(prime_candidate)
            n //= prime_candidate
    if n == 1:
        return factors
    return []


def _build_matrix(relations: List[Tuple[int, List[int]]]) -> List[List[int]]:
    primes = sorted({factor for relation in relations for factor in relation[1]})
    matrix: List[List[int]] = []
    for _, factors in relations:
        row = [0] * len(primes)
        for factor in factors:
            row[primes.index(factor)] = 1
        matrix.append(row)
    return matrix


def _solve_matrix(matrix: List[List[int]]) -> List[int]:
    if not matrix:
        return []

    rows = len(matrix)
    cols = len(matrix[0])

    for i in range(rows):
        pivot = -1
        for j in range(i, rows):
            if matrix[j][i] == 1:
                pivot = j
                break

        if pivot == -1:
            continue

        matrix[i], matrix[pivot] = matrix[pivot], matrix[i]

        for j in range(rows):
            if j != i and matrix[j][i] == 1:
                for k in range(cols):
                    matrix[j][k] ^= matrix[i][k]

    solution = [0] * rows
    for i in range(rows):
        if matrix[i][i] == 1:
            solution[i] = 1

    return solution


def _ec_multiply(x: int, y: int, a: int, b: int, n: int, k: int) -> Tuple[int, int]:
    if k == 1:
        return x, y

    if k % 2 == 0:
        x, y = _ec_multiply(x, y, a, b, n, k // 2)
        return _ec_add(x, y, x, y, a, b, n)

    x1, y1 = _ec_multiply(x, y, a, b, n, k - 1)
    return _ec_add(x, y, x1, y1, a, b, n)


def _ec_add(x1: int, y1: int, x2: int, y2: int, a: int, b: int, n: int) -> Tuple[int, int]:
    if x1 == x2 and y1 == y2:
        if y1 == 0:
            return 0, 0
        slope = (3 * x1 * x1 + a) * pow(2 * y1, -1, n) % n
    else:
        if x1 == x2:
            return 0, 0
        slope = (y2 - y1) * pow(x2 - x1, -1, n) % n

    x3 = (slope * slope - x1 - x2) % n
    y3 = (slope * (x1 - x3) - y1) % n
    return x3, y3


def factorize(n: int, method: str = "auto") -> Dict:
    start_time = time.time()
    try:
        chosen_method = method
        if method == "auto":
            if n < 10 ** 6:
                chosen_method = "trial"
            elif n < 10 ** 12:
                chosen_method = "pollard"
            elif n < 10 ** 50:
                chosen_method = "fermat"
            else:
                chosen_method = "quadratic"

        logger.info("Using %s method to factor %s", chosen_method, n)

        if chosen_method == "trial":
            factors = trial_division(n)
        elif chosen_method == "fermat":
            factors = fermat_factor(n)
        elif chosen_method == "pollard":
            factors = pollards_rho(n)
        elif chosen_method == "quadratic":
            factors = quadratic_sieve(n)
        elif chosen_method == "ecm":
            factors = elliptic_curve_method(n)
        else:
            return {
                "success": False,
                "message": f"Unknown method: {method}",
                "execution_time": time.time() - start_time,
            }

        p, q = factors if factors != (None, None) else (None, None)
        if p and q:
            return {
                "success": True,
                "factors": {"p": p, "q": q},
                "method": chosen_method,
                "execution_time": time.time() - start_time,
            }
        return {
            "success": False,
            "message": f"Failed to factor n using {chosen_method}",
            "execution_time": time.time() - start_time,
        }
    except Exception as exc:  # pragma: no cover - defensive
        return {
            "success": False,
            "message": f"Error in factorization: {exc}",
            "execution_time": time.time() - start_time,
        }
