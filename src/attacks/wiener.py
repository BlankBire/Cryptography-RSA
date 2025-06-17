from sympy import Rational
from sympy.ntheory.continued_fraction import continued_fraction_convergents, continued_fraction
from sympy.ntheory.primetest import isprime
import logging
import time
from typing import Dict, Union, Tuple
import gmpy2

logger = logging.getLogger(__name__)

def wiener_attack(public_key: Union[Dict, Tuple]) -> Dict:
    """
    Perform Wiener's attack on RSA.
    
    This attack exploits the fact that if d < (1/3) * n^(1/4), then the private key d
    can be recovered from the public key (n, e) using continued fractions.
    
    Args:
        public_key: Either a dict containing 'n' and 'e' or a tuple (n, e)
        
    Returns:
        Dict containing:
            - success: bool indicating if attack was successful
            - private_key: dict containing recovered private key components
            - factors: dict containing prime factors p and q
            - message: str describing the result
            - execution_time: float indicating time taken
    """
    start_time = time.time()
    
    try:
        # Extract n and e from public key
        if isinstance(public_key, dict):
            n = int(public_key['n'])
            e = int(public_key['e'])
        else:
            n = int(public_key[0])
            e = int(public_key[1])
            
        logger.info(f"Starting Wiener attack on RSA key with n={n}, e={e}")
        
        # Check if key is vulnerable to Wiener attack
        if d := _check_wiener_vulnerability(n, e):
            logger.info("Key is vulnerable to Wiener attack")
            # Tìm phi từ d
            k = (e * d - 1) // n
            phi = (e * d - 1) // k
            
            # Tìm p và q
            factors = _find_factors(n, phi)
            if factors:
                return {
                    'success': True,
                    'private_key': {
                        'n': n,
                        'e': e,
                        'd': d
                    },
                    'factors': factors,
                    'message': 'Wiener attack successful - found private key and factors',
                    'execution_time': time.time() - start_time
                }
            
        # If not vulnerable, try continued fraction method
        cf = continued_fraction(Rational(e, n))
        convergents = list(continued_fraction_convergents(cf))
        logger.info(f"Generated {len(convergents)} convergents")
        
        for convergent in convergents:
            # Extract k and d from convergent
            if hasattr(convergent, 'numerator') and hasattr(convergent, 'denominator'):
                k = int(convergent.numerator)
                d = int(convergent.denominator)
            else:
                k, d = map(int, convergent)
                
            if k == 0 or (e * d - 1) % k != 0:
                continue
                
            # Check if d is a valid private key
            phi = (e * d - 1) // k
            factors = _find_factors(n, phi)
                
            # Solve quadratic equation to find p and q
            if factors:
                logger.info("Found private key and factors")
                return {
                    'success': True,
                    'private_key': {
                        'n': n,
                        'e': e,
                        'd': d
                    },
                    'factors': factors,
                    'message': 'Wiener attack successful - found private key and factors',
                    'execution_time': time.time() - start_time
                }
        
        logger.info("Wiener attack failed - no valid private key found")
        return {
            'success': False,
            'message': 'Wiener attack failed - no valid private key found',
            'execution_time': time.time() - start_time
        }
        
    except Exception as e:
        logger.error(f"Error in Wiener attack: {str(e)}")
        return {
            'success': False,
            'message': f'Error in Wiener attack: {str(e)}',
            'execution_time': time.time() - start_time
        }

def _check_wiener_vulnerability(n: int, e: int) -> Union[int, None]:
    """
    Check if RSA key is vulnerable to Wiener attack using the condition d < (1/3) * n^(1/4).
    
    Args:
        n: RSA modulus
        e: Public exponent
        
    Returns:
        Private key d if vulnerable, None otherwise
    """
    try:
        # Calculate upper bound for d using n^(1/4)
        n_4th_root = int(gmpy2.root(n, 4)[0])  # Sử dụng gmpy2.root cho số lớn
        d_bound = int((1/3) * n_4th_root)
        
        # Try to find d using continued fractions
        convergents = list(continued_fraction_convergents(Rational(e, n)))
        
        for convergent in convergents[:10]:  # Check first 10 convergents
            if hasattr(convergent, 'denominator'):
                d = int(convergent.denominator)
                if d < d_bound and (e * d - 1) % convergent.numerator == 0:
                    return d
                    
        return None
        
    except Exception as e:
        logger.error(f"Error checking Wiener vulnerability: {str(e)}")
        return None

def _find_factors(n: int, phi: int) -> Union[Dict, None]:
    """
    Find prime factors p and q of n using phi(n).
    
    Args:
        n: RSA modulus
        phi: Euler's totient function value
        
    Returns:
        Dict containing p and q if found, None otherwise
    """
    try:
        # Giải phương trình bậc 2: x^2 - (n - phi + 1)x + n = 0
        # với x1 = p, x2 = q
        a = 1
        b = -(n - phi + 1)
        c = n

        # Tính delta = b^2 - 4ac
        delta = b * b - 4 * a * c
        
        # Kiểm tra delta có dương không
        if delta <= 0:
            return None
            
        # Kiểm tra delta có phải số chính phương không
        sqrt_delta = int(gmpy2.isqrt(delta))  # Sử dụng gmpy2.isqrt cho số lớn
        if sqrt_delta * sqrt_delta != delta:
            return None

        # Tính p và q
        p = (-b + sqrt_delta) // (2 * a)
        q = (-b - sqrt_delta) // (2 * a)

        # Kiểm tra p và q có phải là số nguyên tố không
        if p * q == n and isprime(p) and isprime(q):
            return {'p': p, 'q': q}
        return None
        
    except Exception as e:
        logger.error(f"Error finding factors: {str(e)}")
        return None