import math
import random
import time
from typing import Dict, Union, Tuple, List
import logging

logger = logging.getLogger(__name__)

def trial_division(n):
    """
    Phân tích nhân tử bằng phương pháp thử từng ước số từ 2 đến sqrt(n).
    Chỉ dùng được cho số nhỏ (n < 10^6).
    """
    for i in range(2, int(math.isqrt(n)) + 1):
        if n % i == 0:
            return i, n // i
    return None, None

def fermat_factor(n):
    """
    Phân tích nhân tử bằng phương pháp Fermat.
    Giả định rằng n = p * q với p ≈ q
    (hiệu p - q nhỏ).
    """
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
        if a - math.isqrt(n) > 1000000:  # giới hạn bước tránh lặp vô hạn
            return None, None

def pollards_rho(n):
    """
    Phân tích nhân tử bằng thuật toán Pollard's Rho.
    Hiệu quả với n nhỏ hoặc vừa.
    """
    if n % 2 == 0:
        return 2, n // 2

    def f(x): return (x * x + 1) % n

    x, y, d = 2, 2, 1
    while d == 1:
        x = f(x)
        y = f(f(y))
        d = math.gcd(abs(x - y), n)
    if d == n:
        return None, None
    return d, n // d

def quadratic_sieve(n: int, smoothness_bound: int = 1000) -> Tuple[int, int]:
    """
    Phân tích nhân tử bằng phương pháp Quadratic Sieve.
    Hiệu quả với số lớn (n > 10^50).
    
    Args:
        n: Số cần phân tích
        smoothness_bound: Giới hạn độ mịn cho các số
        
    Returns:
        Tuple (p, q) chứa các thừa số nguyên tố
    """
    if n % 2 == 0:
        return 2, n // 2
        
    # Tạo ma trận quan hệ
    relations = []
    x = int(math.isqrt(n)) + 1
    
    while len(relations) < smoothness_bound:
        y = x * x - n
        if y > 0:
            factors = _factor_smooth(y, smoothness_bound)
            if factors:
                relations.append((x, factors))
        x += 1
        
    # Giải hệ phương trình tuyến tính
    matrix = _build_matrix(relations)
    solution = _solve_matrix(matrix)
    
    if solution:
        # Tính các thừa số
        x = 1
        y = 1
        for i, bit in enumerate(solution):
            if bit:
                x = (x * relations[i][0]) % n
                y = (y * relations[i][1]) % n
                
        p = math.gcd(x + y, n)
        if p != 1 and p != n:
            return p, n // p
            
    return None, None

def elliptic_curve_method(n: int, max_curves: int = 100) -> Tuple[int, int]:
    """
    Phân tích nhân tử bằng phương pháp Elliptic Curve Method (ECM).
    Hiệu quả với số có thừa số nhỏ.
    
    Args:
        n: Số cần phân tích
        max_curves: Số đường cong tối đa thử
        
    Returns:
        Tuple (p, q) chứa các thừa số nguyên tố
    """
    if n % 2 == 0:
        return 2, n // 2
        
    for _ in range(max_curves):
        # Chọn tham số ngẫu nhiên cho đường cong
        a = random.randrange(1, n)
        b = random.randrange(1, n)
        
        # Tạo điểm P trên đường cong
        x = random.randrange(1, n)
        y = random.randrange(1, n)
        
        # Tính bội của điểm P
        for i in range(2, 1000):
            try:
                x, y = _ec_multiply(x, y, a, b, n, i)
                p = math.gcd(x, n)
                if p != 1 and p != n:
                    return p, n // p
            except:
                continue
                
    return None, None

def _factor_smooth(n: int, bound: int) -> List[int]:
    """
    Phân tích n thành các thừa số nhỏ hơn bound.
    """
    factors = []
    for p in range(2, bound + 1):
        while n % p == 0:
            factors.append(p)
            n //= p
    if n == 1:
        return factors
    return []

def _build_matrix(relations: List[Tuple[int, List[int]]]) -> List[List[int]]:
    """
    Xây dựng ma trận từ các quan hệ.
    """
    # Tạo tập các số nguyên tố
    primes = set()
    for _, factors in relations:
        primes.update(factors)
    primes = sorted(list(primes))
    
    # Xây dựng ma trận
    matrix = []
    for _, factors in relations:
        row = [0] * len(primes)
        for p in factors:
            row[primes.index(p)] = 1
        matrix.append(row)
        
    return matrix

def _solve_matrix(matrix: List[List[int]]) -> List[int]:
    """
    Giải hệ phương trình tuyến tính trên trường GF(2).
    """
    if not matrix:
        return []
        
    rows = len(matrix)
    cols = len(matrix[0])
    
    # Gaussian elimination
    for i in range(rows):
        # Tìm hàng có 1 ở cột i
        pivot = -1
        for j in range(i, rows):
            if matrix[j][i] == 1:
                pivot = j
                break
                
        if pivot == -1:
            continue
            
        # Hoán đổi hàng
        matrix[i], matrix[pivot] = matrix[pivot], matrix[i]
        
        # Khử các hàng khác
        for j in range(rows):
            if j != i and matrix[j][i] == 1:
                for k in range(cols):
                    matrix[j][k] ^= matrix[i][k]
                    
    # Tìm nghiệm
    solution = [0] * rows
    for i in range(rows):
        if matrix[i][i] == 1:
            solution[i] = 1
            
    return solution

def _ec_multiply(x: int, y: int, a: int, b: int, n: int, k: int) -> Tuple[int, int]:
    """
    Tính k lần điểm P(x,y) trên đường cong elliptic.
    """
    if k == 1:
        return x, y
        
    if k % 2 == 0:
        x, y = _ec_multiply(x, y, a, b, n, k // 2)
        return _ec_add(x, y, x, y, a, b, n)
    else:
        x1, y1 = _ec_multiply(x, y, a, b, n, k - 1)
        return _ec_add(x, y, x1, y1, a, b, n)

def _ec_add(x1: int, y1: int, x2: int, y2: int, a: int, b: int, n: int) -> Tuple[int, int]:
    """
    Cộng hai điểm trên đường cong elliptic.
    """
    if x1 == x2 and y1 == y2:
        # P + P
        if y1 == 0:
            return 0, 0
        m = (3 * x1 * x1 + a) * pow(2 * y1, -1, n) % n
    else:
        # P + Q
        if x1 == x2:
            return 0, 0
        m = (y2 - y1) * pow(x2 - x1, -1, n) % n
        
    x3 = (m * m - x1 - x2) % n
    y3 = (m * (x1 - x3) - y1) % n
    return x3, y3

def factorize(n: int, method: str = 'auto') -> Dict:
    """
    Phân tích thừa số n thành p * q.
    
    Args:
        n: Số cần phân tích
        method: Phương pháp phân tích ('trial', 'fermat', 'pollard', 'quadratic', 'ecm', 'auto')
        
    Returns:
        Dict chứa kết quả phân tích
    """
    start_time = time.time()
    
    try:
        if method == 'auto':
            # Chọn phương pháp dựa trên kích thước của n
            if n < 10**6:
                method = 'trial'
            elif n < 10**12:
                method = 'pollard'
            elif n < 10**50:
                method = 'fermat'
            else:
                method = 'quadratic'
        
        logger.info(f"Using {method} method to factor {n}")
        
        if method == 'trial':
            p, q = trial_division(n)
        elif method == 'fermat':
            p, q = fermat_factor(n)
        elif method == 'pollard':
            p, q = pollards_rho(n)
        elif method == 'quadratic':
            p, q = quadratic_sieve(n)
        elif method == 'ecm':
            p, q = elliptic_curve_method(n)
        else:
            return {
                'success': False,
                'message': f'Unknown method: {method}',
                'execution_time': time.time() - start_time
            }
        
        if p and q:
            return {
                'success': True,
                'factors': {
                    'p': p,
                    'q': q
                },
                'method': method,
                'execution_time': time.time() - start_time
            }
        else:
            return {
                'success': False,
                'message': f'Failed to factor n using {method}',
                'execution_time': time.time() - start_time
            }
            
    except Exception as e:
        return {
            'success': False,
            'message': f'Error in factorization: {str(e)}',
            'execution_time': time.time() - start_time
        }
