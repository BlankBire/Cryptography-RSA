from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, PKCS1_v1_5
import time
import random
from typing import Dict, List, Optional
from Crypto.Util.number import bytes_to_long, long_to_bytes
import math

def chosen_plaintext_attack(public_key: RSA.RsaKey, target_ciphertext_hex: str, 
                           oracle_encrypt_func, max_queries: int = 1000) -> Dict:
    """
    Mô phỏng Chosen Plaintext Attack chống lại RSA.
    
    Trong cuộc tấn công này, kẻ tấn công có thể:
    1. Chọn các plaintext và nhận được ciphertext tương ứng
    2. Sử dụng thông tin này để phục hồi plaintext gốc
    
    Args:
        public_key (RSA.RsaKey): RSA public key.
        target_ciphertext_hex (str): Bản mã mục tiêu (hexadecimal string).
        oracle_encrypt_func: Hàm oracle để mã hóa plaintext được chọn.
        max_queries (int): Số lượng truy vấn tối đa đến oracle.

    Returns:
        Dict: Chứa kết quả tấn công, bao gồm bản rõ được giải mã
              và các bước trong quá trình tấn công.
    """
    start_time = time.perf_counter()
    results = []
    decrypted_message_bytes = b''
    success = False
    message = ""

    try:
        # Input validation
        if not target_ciphertext_hex:
            raise ValueError("Target ciphertext cannot be empty.")
        if not all(c.lower() in '0123456789abcdef' for c in target_ciphertext_hex):
            raise ValueError("Target ciphertext contains non-hexadecimal characters.")
        if len(target_ciphertext_hex) % 2 != 0:
            raise ValueError("Target ciphertext hexadecimal string must have an even length.")

        # Get n and e from public key
        n = public_key.n
        e = public_key.e
        
        target_ciphertext = bytes.fromhex(target_ciphertext_hex)
        target_ciphertext_int = bytes_to_long(target_ciphertext)
        
        # Step 0: Giải mã thực tế để so sánh (trong thực tế, kẻ tấn công không biết điều này)
        # Đây chỉ là để demo và so sánh kết quả
        actual_decrypted_message_bytes: bytes = b''
        try:
            # Sử dụng private key để giải mã (chỉ để demo)
            # Trong thực tế, kẻ tấn công không có private key
            cipher_v1_5_decrypt = PKCS1_v1_5.new(public_key)
            decrypted_result = cipher_v1_5_decrypt.decrypt(target_ciphertext, None)
            if decrypted_result is not None:
                actual_decrypted_message_bytes = decrypted_result
            else:
                actual_decrypted_message_bytes = b''
        except Exception:
            actual_decrypted_message_bytes = b''

        results.append({
            "step": "Initialization",
            "description": f"Target ciphertext: {target_ciphertext_hex[:50]}...",
            "n": str(n),
            "e": str(e),
            "ciphertext_length": len(target_ciphertext)
        })

        # Bước 1: Tấn công bằng cách sử dụng plaintext đặc biệt
        # Chúng ta sẽ sử dụng một số kỹ thuật khác nhau
        
        # Kỹ thuật 1: Sử dụng plaintext = 1
        results.append({
            "step": "Technique 1: Plaintext = 1",
            "description": "Testing with plaintext = 1 to understand encryption pattern"
        })
        
        plaintext_1 = b'\x01'  # Plaintext = 1
        try:
            ciphertext_1 = oracle_encrypt_func(plaintext_1)
            ciphertext_1_int = bytes_to_long(ciphertext_1)
            
            results.append({
                "step": "Encryption Result",
                "plaintext": "1",
                "ciphertext": ciphertext_1.hex(),
                "ciphertext_int": str(ciphertext_1_int)
            })
            
            # Tính toán: c1 = 1^e mod n = 1
            expected_c1 = pow(1, e, n)
            results.append({
                "step": "Verification",
                "expected_c1": str(expected_c1),
                "actual_c1": str(ciphertext_1_int),
                "match": expected_c1 == ciphertext_1_int
            })
            
        except Exception as e:
            results.append({
                "step": "Error",
                "description": f"Error encrypting plaintext 1: {str(e)}"
            })

        # Kỹ thuật 2: Sử dụng plaintext = 2
        results.append({
            "step": "Technique 2: Plaintext = 2",
            "description": "Testing with plaintext = 2"
        })
        
        plaintext_2 = b'\x02'  # Plaintext = 2
        try:
            ciphertext_2 = oracle_encrypt_func(plaintext_2)
            ciphertext_2_int = bytes_to_long(ciphertext_2)
            
            results.append({
                "step": "Encryption Result",
                "plaintext": "2",
                "ciphertext": ciphertext_2.hex(),
                "ciphertext_int": str(ciphertext_2_int)
            })
            
            # Tính toán: c2 = 2^e mod n
            expected_c2 = pow(2, e, n)
            results.append({
                "step": "Verification",
                "expected_c2": str(expected_c2),
                "actual_c2": str(ciphertext_2_int),
                "match": expected_c2 == ciphertext_2_int
            })
            
        except Exception as e:
            results.append({
                "step": "Error",
                "description": f"Error encrypting plaintext 2: {str(e)}"
            })

        # Kỹ thuật 3: Tấn công bằng cách sử dụng multiplicative property
        # Nếu m1 * m2 = m_target, thì c1 * c2 = c_target
        results.append({
            "step": "Technique 3: Multiplicative Property",
            "description": "Using RSA's multiplicative property: E(m1) * E(m2) = E(m1 * m2)"
        })
        
        # Tìm các plaintext có thể nhân với nhau để tạo ra plaintext mục tiêu
        # Đây là một kỹ thuật phức tạp hơn
        query_count = 0
        
        # Thử một số plaintext ngẫu nhiên để tìm pattern
        for i in range(min(10, max_queries)):
            random_plaintext = random.randint(1, 100).to_bytes(1, 'big')
            try:
                random_ciphertext = oracle_encrypt_func(random_plaintext)
                random_ciphertext_int = bytes_to_long(random_ciphertext)
                random_plaintext_int = bytes_to_long(random_plaintext)
                
                results.append({
                    "step": f"Random Test {i+1}",
                    "plaintext": str(random_plaintext_int),
                    "ciphertext": random_ciphertext.hex()[:20] + "...",
                    "ciphertext_int": str(random_ciphertext_int)
                })
                
                query_count += 1
                
                # Kiểm tra xem có thể tìm thấy plaintext mục tiêu không
                # (Đây là một mô phỏng đơn giản)
                
            except Exception as e:
                results.append({
                    "step": f"Error in Test {i+1}",
                    "description": f"Error: {str(e)}"
                })
        
        # Bước 4: Mô phỏng phục hồi plaintext
        # Trong thực tế, đây sẽ là một thuật toán phức tạp
        results.append({
            "step": "Plaintext Recovery Simulation",
            "description": "Simulating plaintext recovery using chosen plaintext information"
        })
        
        # Mô phỏng việc phục hồi từng phần của plaintext
        if actual_decrypted_message_bytes:
            plaintext_len = len(actual_decrypted_message_bytes)
            simulation_steps = min(5, plaintext_len)
            
            for i in range(simulation_steps):
                recovered_chunk = actual_decrypted_message_bytes[:i+1]
                results.append({
                    "step": f"Recovery Progress {i+1}/{simulation_steps}",
                    "description": f"Recovered {len(recovered_chunk)}/{plaintext_len} bytes",
                    "recovered_data": recovered_chunk.hex(),
                    "query_count": query_count + i + 1
                })
                time.sleep(0.1)  # Simulate processing time
            
            decrypted_message_bytes = actual_decrypted_message_bytes
            success = True
            message = "Chosen Plaintext Attack simulation completed successfully!"
        else:
            success = False
            message = "Could not recover plaintext (target ciphertext may be invalid)"

    except ValueError as ve:
        message = f"Input validation error: {str(ve)}"
        success = False
    except Exception as e:
        message = f"An unexpected error occurred during the attack: {str(e)}"
        success = False

    end_time = time.perf_counter()
    return {
        "success": success,
        "message": message,
        "decrypted_data": decrypted_message_bytes.hex(),
        "attack_log": results,
        "execution_time": end_time - start_time
    }

def simulate_encryption_oracle(public_key: RSA.RsaKey, plaintext: bytes) -> bytes:
    """
    Mô phỏng một encryption oracle.
    Trong thực tế, đây có thể là một server cho phép kẻ tấn công mã hóa plaintext.
    
    Args:
        public_key (RSA.RsaKey): RSA public key.
        plaintext (bytes): Plaintext cần mã hóa.
        
    Returns:
        bytes: Ciphertext được mã hóa.
    """
    cipher = PKCS1_v1_5.new(public_key)
    return cipher.encrypt(plaintext) 