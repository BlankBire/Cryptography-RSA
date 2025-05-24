import math
import random

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

def is_prime(n):
    """
    Kiểm tra n có phải số nguyên tố không.
    Dùng Miller-Rabin đơn giản với số nhỏ.
    """
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False

    # Viết n - 1 dưới dạng 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        d //= 2
        r += 1

    for _ in range(5):  # chạy 5 vòng thử
        a = random.randrange(2, n - 2)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True
