from sympy import mod_inverse
from sympy.ntheory.modular import crt
import logging
import time
from typing import Dict, Union, Tuple, List
import gmpy2
import random

logger = logging.getLogger(__name__)

def hastad_attack(public_key: Union[Dict, Tuple], 
                 ciphertexts: List[Dict] = None) -> Dict:
    """
    Perform Hastad's broadcast attack on RSA.
    
    This attack exploits the fact that if the same message is encrypted with the same
    small public exponent e to different recipients, then the message can be recovered
    using the Chinese Remainder Theorem.
    
    Args:
        public_key: Either a dict containing 'n' and 'e' or a tuple (n, e)
        ciphertexts: List of dicts containing 'n' and 'c' for each ciphertext.
                    If None, generates test ciphertexts.
        
    Returns:
        Dict containing:
            - success: bool indicating if attack was successful
            - decrypted_message: int containing the recovered message
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
            
        logger.info(f"Starting Hastad attack on RSA key with n={n}, e={e}")
        
        # Generate test ciphertexts if none provided
        if ciphertexts is None:
            logger.info("No ciphertexts provided, generating test data")
            ciphertexts = _generate_test_ciphertexts(n, e)
            
        # Extract moduli and remainders
        moduli = []
        remainders = []
        
        for ct in ciphertexts:
            if isinstance(ct, dict):
                moduli.append(int(ct['n']))
                remainders.append(int(ct['c']))
            else:
                moduli.append(int(ct[0]))
                remainders.append(int(ct[1]))
                
        logger.info(f"Processing {len(moduli)} ciphertexts")
        
        # Check if we have enough ciphertexts
        if len(moduli) < e:
            logger.warning(f"Not enough ciphertexts (need {e}, got {len(moduli)})")
            return {
                'success': False,
                'message': f'Not enough ciphertexts (need {e}, got {len(moduli)})',
                'execution_time': time.time() - start_time
            }
            
        # Check if moduli are pairwise coprime
        if not _are_coprime(moduli):
            logger.warning("Moduli are not pairwise coprime")
            return {
                'success': False,
                'message': 'Hastad attack failed: Moduli are not pairwise coprime',
                'execution_time': time.time() - start_time
            }
            
        # Use Chinese Remainder Theorem to find message
        result = crt(moduli, remainders)
        if result is None:
            logger.info("No solution found using CRT")
            return {
                'success': False,
                'message': 'Hastad attack failed: No solution found',
                'execution_time': time.time() - start_time
            }
            
        m, _ = result
        m = int(m)
        
        # Try to recover the original message
        try:
            # Try to find e-th root
            message = _find_eth_root(m, e)
            if message is not None:
                # Try to convert message to text
                try:
                    message_text = _int_to_text(message)
                    logger.info("Successfully recovered message")
                    return {
                        'success': True,
                        'decrypted_message': message,
                        'message_text': message_text,
                        'message': 'Hastad attack successful',
                        'execution_time': time.time() - start_time
                    }
                except:
                    # If conversion fails, return numeric message
                    return {
                        'success': True,
                        'decrypted_message': message,
                        'message': 'Hastad attack successful (numeric message)',
                        'execution_time': time.time() - start_time
                    }
        except Exception as e:
            logger.error(f"Error finding e-th root: {str(e)}")
            
        logger.info("Attack failed - could not recover message")
        return {
            'success': False,
            'message': 'Hastad attack failed: Could not recover message',
            'execution_time': time.time() - start_time
        }
        
    except Exception as e:
        logger.error(f"Error in Hastad attack: {str(e)}")
        return {
            'success': False,
            'message': f'Error in Hastad attack: {str(e)}',
            'execution_time': time.time() - start_time
        }

def _are_coprime(numbers: List[int]) -> bool:
    """
    Check if numbers are pairwise coprime.
    
    Args:
        numbers: List of numbers to check
        
    Returns:
        True if numbers are pairwise coprime, False otherwise
    """
    for i in range(len(numbers)):
        for j in range(i + 1, len(numbers)):
            if gmpy2.gcd(numbers[i], numbers[j]) != 1:
                return False
    return True

def _int_to_text(n: int) -> str:
    """
    Convert integer to text.
    
    Args:
        n: Integer to convert
        
    Returns:
        Text representation of integer
    """
    try:
        # Try to convert to bytes then to text
        bytes_data = n.to_bytes((n.bit_length() + 7) // 8, 'big')
        return bytes_data.decode('utf-8')
    except:
        raise ValueError("Cannot convert integer to text")

def _generate_test_ciphertexts(n: int, e: int, 
                             num_ciphertexts: int = 3) -> List[Dict]:
    """
    Generate test ciphertexts for Hastad attack.
    
    Args:
        n: RSA modulus
        e: Public exponent
        num_ciphertexts: Number of ciphertexts to generate
        
    Returns:
        List of dicts containing test ciphertexts
    """
    try:
        # Generate a random message
        message = random.randint(1, 1000)
        logger.info(f"Generated test message: {message}")
        
        # Generate ciphertexts
        ciphertexts = []
        moduli = []
        
        for i in range(num_ciphertexts):
            # Generate a different modulus for each ciphertext
            while True:
                p = gmpy2.next_prime(random.randint(2**512, 2**513))
                q = gmpy2.next_prime(random.randint(2**512, 2**513))
                n_i = p * q
                
                # Check if n_i is coprime with all previous moduli
                is_coprime = True
                for prev_n in moduli:
                    if gmpy2.gcd(n_i, prev_n) != 1:
                        is_coprime = False
                        break
                        
                if is_coprime:
                    moduli.append(n_i)
                    break
            
            # Encrypt message
            c = pow(message, e, n_i)
            ciphertexts.append({
                'n': n_i,
                'c': c
            })
            
        return ciphertexts
        
    except Exception as e:
        logger.error(f"Error generating test ciphertexts: {str(e)}")
        raise

def _find_eth_root(m: int, e: int) -> Union[int, None]:
    """
    Find the e-th root of m.
    
    Args:
        m: Number to find root of
        e: Exponent
        
    Returns:
        e-th root if found, None otherwise
    """
    try:
        # Try to find e-th root using gmpy2
        root = gmpy2.root(m, e)
        if isinstance(root, tuple) and root[1]:  # Check if root is exact
            return int(root[0])
        elif isinstance(root, (int, float)):  # Handle single value return
            return int(root)
            
        # If not exact, try binary search
        low = 0
        high = m
        
        while low <= high:
            mid = (low + high) // 2
            power = pow(mid, e)
            
            if power == m:
                return mid
            elif power < m:
                low = mid + 1
            else:
                high = mid - 1
                
        return None
        
    except Exception as e:
        logger.error(f"Error finding e-th root: {str(e)}")
        return None

def generate_test_example() -> Dict:
    """
    Generate a complete test example for Hastad attack.
    
    Returns:
        Dict containing:
            - public_key: dict with n and e
            - ciphertexts: list of dicts with n and c
            - original_message: the original message used
    """
    try:
        # Generate a small message
        message = 123
        e = 3  # Small public exponent
        
        # Generate 3 coprime moduli
        moduli = []
        ciphertexts = []
        
        # First modulus
        p1 = gmpy2.next_prime(random.randint(2**100, 2**101))
        q1 = gmpy2.next_prime(random.randint(2**100, 2**101))
        n1 = p1 * q1
        moduli.append(n1)
        c1 = pow(message, e, n1)
        ciphertexts.append({
            'n': str(n1),
            'c': str(c1)
        })
        
        # Second modulus
        while True:
            p2 = gmpy2.next_prime(random.randint(2**100, 2**101))
            q2 = gmpy2.next_prime(random.randint(2**100, 2**101))
            n2 = p2 * q2
            if gmpy2.gcd(n2, n1) == 1:
                moduli.append(n2)
                c2 = pow(message, e, n2)
                ciphertexts.append({
                    'n': str(n2),
                    'c': str(c2)
                })
                break
        
        # Third modulus
        while True:
            p3 = gmpy2.next_prime(random.randint(2**100, 2**101))
            q3 = gmpy2.next_prime(random.randint(2**100, 2**101))
            n3 = p3 * q3
            if gmpy2.gcd(n3, n1) == 1 and gmpy2.gcd(n3, n2) == 1:
                moduli.append(n3)
                c3 = pow(message, e, n3)
                ciphertexts.append({
                    'n': str(n3),
                    'c': str(c3)
                })
                break
        
        return {
            'public_key': {
                'n': str(n1),  # Use first modulus as public key
                'e': str(e)
            },
            'ciphertexts': ciphertexts,
            'original_message': message
        }
        
    except Exception as e:
        logger.error(f"Error generating test example: {str(e)}")
        raise 