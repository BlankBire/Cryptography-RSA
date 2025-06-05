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
                logger.info("Successfully recovered message")
                return {
                    'success': True,
                    'decrypted_message': message,
                    'message': 'Hastad attack successful',
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
        for i in range(num_ciphertexts):
            # Generate a different modulus for each ciphertext
            p = gmpy2.next_prime(random.randint(2**512, 2**513))
            q = gmpy2.next_prime(random.randint(2**512, 2**513))
            n_i = p * q
            
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
        if root[1]:  # Check if root is exact
            return int(root[0])
            
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