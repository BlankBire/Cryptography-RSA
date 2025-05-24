import os
import math

def save_pem(filename, data):
    with open(filename, 'wb') as f:
        f.write(data)

def load_pem(filename):
    if not os.path.exists(filename):
        raise FileNotFoundError(f"File not found: {filename}")
    with open(filename, 'rb') as f:
        return f.read()

def str_to_bytes(s):
    return s.encode('utf-8')

def bytes_to_str(b):
    return b.decode('utf-8')

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def is_prime(n):
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False
    for i in range(3, int(math.sqrt(n)) + 1, 2):
        if n % i == 0:
            return False
    return True
