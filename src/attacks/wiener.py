from sympy import Rational
from sympy.ntheory.continued_fraction import continued_fraction_convergents
from sympy.ntheory.primetest import isprime

def wiener_attack(public_key):
    """
    Thực hiện tấn công Wiener trên RSA
    public_key: tuple (n, e) với n là modulus và e là public exponent
    """
    n = int(public_key[0])  # Chuyển đổi sang int
    e = int(public_key[1])  # Chuyển đổi sang int
    
    # Tìm các convergent của e/n
    convergents = list(continued_fraction_convergents(Rational(e, n)))
    
    for convergent in convergents:
        # convergent có thể là Rational hoặc tuple
        if hasattr(convergent, 'numerator') and hasattr(convergent, 'denominator'):
            k = int(convergent.numerator)  # Chuyển đổi sang int
            d = int(convergent.denominator)  # Chuyển đổi sang int
        else:
            k, d = map(int, convergent)
        if k == 0:
            continue
            
        # Kiểm tra xem d có phải là private key không
        if d > 0 and (e * d - 1) % k == 0:
            phi = (e * d - 1) // k
            
            # Giải phương trình bậc 2 để tìm p và q
            # x^2 - (n - phi + 1)x + n = 0
            b = n - phi + 1
            c = n
            
            # Tính delta = b^2 - 4c
            delta = b * b - 4 * c
            
            if delta >= 0:
                # Tính nghiệm
                p = (b + int(delta ** 0.5)) // 2
                q = (b - int(delta ** 0.5)) // 2
                
                if p * q == n and isprime(p) and isprime(q):
                    return {
                        'success': True,
                        'private_key': {
                            'n': n,
                            'd': d
                        },
                        'factors': {
                            'p': p,
                            'q': q
                        }
                    }
    
    return {
        'success': False,
        'message': 'Wiener attack failed'
    } 