from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, PKCS1_v1_5
import time
import random
from typing import Dict, List, Optional
from Crypto.Util.number import bytes_to_long, long_to_bytes

def cca_oracle(ciphertext, private_key):
    """
    Oracle cho attacker biết ciphertext có hợp lệ hay không khi giải mã.
    Đây là cơ sở cho CCA (Chosen Ciphertext Attack).
    """
    cipher = PKCS1_OAEP.new(private_key)
    try:
        plaintext = cipher.decrypt(ciphertext)
        return True  # giải mã thành công (ciphertext hợp lệ)
    except ValueError:
        return False  # lỗi giải mã (ciphertext không hợp lệ)

def simulate_cca_attack(ciphertext, private_key, public_key):
    """
    Mô phỏng một cuộc tấn công CCA cơ bản: attacker thay đổi ciphertext
    và dùng oracle để thu thập thông tin từ phản hồi.
    """
    print("[📡] Simulating Chosen Ciphertext Attack (CCA)...")

    # Đổi từng bit một của ciphertext và hỏi oracle
    valid_count = 0
    for i in range(len(ciphertext)):
        for bit in range(8):
            modified = bytearray(ciphertext)
            modified[i] ^= (1 << bit)
            if cca_oracle(bytes(modified), private_key):
                valid_count += 1

    print(f"[🔍] Valid modified ciphertexts: {valid_count}")
    return valid_count

# --- Simulated Padding Oracle ---
def simulate_padding_oracle(private_key: RSA.RsaKey, ciphertext: bytes) -> bool:
    """
    Mô phỏng một padding oracle.
    Nó sẽ giải mã bản mã và kiểm tra xem padding PKCS#1 v1.5 có hợp lệ không.
    Trả về True nếu padding hợp lệ, False nếu không.
    """
    cipher = PKCS1_v1_5.new(private_key)
    try:
        # Thử giải mã. Nếu padding không hợp lệ, Crypto.Cipher sẽ raise ValueError.
        # Sentinel (random string) được sử dụng để bắt lỗi giải mã không phải là padding.
        # Ở đây, chúng ta chỉ quan tâm đến lỗi padding.
        cipher.decrypt(ciphertext, None) # None sentinel sẽ raise ValueError nếu padding sai
        return True # Giải mã thành công với padding hợp lệ
    except ValueError as e:
        # Kiểm tra xem lỗi có phải do padding không hợp lệ hay không.
        # Trong một oracle thực tế, lỗi này sẽ được báo hiệu ra ngoài.
        # Ở đây, chúng ta đơn giản trả về False.
        # Nếu lỗi là "Padding is not correct." thì đó là lỗi padding.
        # Các lỗi khác có thể là ciphertext không hợp lệ.
        if "Padding is not correct." in str(e):
            return False
        else:
            # Lỗi không phải do padding, có thể do bản mã quá ngắn hoặc không đúng định dạng.
            # Trong một cuộc tấn công thực tế, kẻ tấn công cũng sẽ phân biệt được điều này.
            # Ở đây, chúng ta coi nó là không hợp lệ cho mục đích của oracle.
            return False
    except Exception:
        # Bất kỳ lỗi giải mã nào khác
        return False

# --- Padding Oracle Attack Logic ---
def padding_oracle_attack(private_key: RSA.RsaKey, ciphertext_hex: str, max_queries: int = 1000) -> Dict:
    """
    Mô phỏng Padding Oracle Attack chống lại RSA PKCS#1 v1.5.
    
    Args:
        private_key (RSA.RsaKey): RSA private key.
        ciphertext_hex (str): Bản mã mục tiêu (hexadecimal string).
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
        # Input validation for ciphertext_hex
        if not ciphertext_hex:
            raise ValueError("Ciphertext cannot be empty.")
        if not all(c.lower() in '0123456789abcdef' for c in ciphertext_hex):
            raise ValueError("Ciphertext contains non-hexadecimal characters.")
        if len(ciphertext_hex) % 2 != 0:
            raise ValueError("Ciphertext hexadecimal string must have an even length.")

        # Get n and e from private key
        n = private_key.n
        e = private_key.e
        public_key = private_key.publickey()

        target_ciphertext = bytes.fromhex(ciphertext_hex)

        # Step 0: Perform actual decryption of the target_ciphertext for demonstration purposes.
        # In a real attack, this is what the attacker is trying to find.
        actual_decrypted_message_bytes = b''
        try:
            cipher_v1_5_decrypt = PKCS1_v1_5.new(private_key)
            # The `None` sentinel causes `decrypt` to raise ValueError on padding error, which our oracle expects.
            actual_decrypted_message_bytes = cipher_v1_5_decrypt.decrypt(target_ciphertext, None)
        except ValueError as ve:
            message = f"Target ciphertext is not valid PKCS#1 v1.5 format or cannot be decrypted by oracle: {ve}"
            success = False
            # Return early if the target ciphertext itself is not valid for the oracle
            return {
                "success": success,
                "message": message,
                "decrypted_data": actual_decrypted_message_bytes.hex(),
                "attack_log": results,
                "execution_time": time.perf_counter() - start_time
            }
        except Exception as e:
            message = f"An unexpected error occurred during initial decryption for simulation: {str(e)}"
            success = False
            return {
                "success": success,
                "message": message,
                "decrypted_data": actual_decrypted_message_bytes.hex(),
                "attack_log": results,
                "execution_time": time.perf_counter() - start_time
            }

        B = 2**(8 * (public_key.size_in_bytes() - 2)) # Theo PKCS#1 v1.5 padding rules
        
        # Bước 1: Tìm s0
        # Đây là bước đơn giản nhất, trong đó chúng ta tìm s0 sao cho
        # c' = (c * s0^e) mod n có padding hợp lệ.
        # Với mục đích demo, chúng ta sẽ làm đơn giản hóa bước này.
        # Trong tấn công thực tế, bước này là phức tạp.
        # Giả định một s0 để bắt đầu tìm kiếm
        s = 1 # Kẻ tấn công sẽ lặp qua các giá trị s
        initial_s_found = False
        query_count_s0 = 0
        while query_count_s0 < max_queries:
            test_s = random.randint(1, n - 1)
            c_prime = long_to_bytes((bytes_to_long(target_ciphertext) * pow(test_s, e, n)) % n, public_key.size_in_bytes())
            
            is_valid = simulate_padding_oracle(private_key, c_prime)
            query_count_s0 += 1
            results.append({
                "step": "Finding initial s",
                "s_value": str(test_s),
                "modified_ciphertext": c_prime.hex(),
                "padding_valid": is_valid,
                "query_count": query_count_s0
            })
            if is_valid:
                s = test_s
                initial_s_found = True
                break
            
        if not initial_s_found:
            message = "Max queries reached while finding initial s. Attack failed."
            success = False
        else:
            # Bước 2 & 3: Mô phỏng tìm kiếm M (bản rõ)
            # Thay vì thuật toán phức tạp, chúng ta sẽ mô phỏng việc phục hồi từng phần
            # của bản rõ thực tế (actual_decrypted_message_bytes).
            simulation_steps = max(1, len(actual_decrypted_message_bytes) // 2) # Divide into at least 2 chunks
            if simulation_steps > 5: # Limit steps to avoid very long logs
                simulation_steps = 5

            plaintext_len = len(actual_decrypted_message_bytes)
            chunk_size = max(1, plaintext_len // simulation_steps)

            for i in range(simulation_steps):
                start_idx = i * chunk_size
                end_idx = min((i + 1) * chunk_size, plaintext_len)
                recovered_chunk = actual_decrypted_message_bytes[:end_idx]

                results.append({
                    "step": f"Simulated Decryption (Progress {i+1}/{simulation_steps})",
                    "description": f"Recovered {len(recovered_chunk)}/{plaintext_len} bytes: {recovered_chunk.hex()}",
                    "recovered_plaintext_partial": recovered_chunk.hex(),
                    "query_count": query_count_s0 + i + 1 # Continue query count
                })
                time.sleep(0.05) # Simulate some work

            success = True
            message = "Simulated Padding Oracle Attack completed successfully! (Note: This is a simplified simulation for demo purposes)."
            decrypted_message_bytes = actual_decrypted_message_bytes # Set the final decrypted_data to the actual plaintext

    except ValueError as ve:
        message = f"Input validation error: {str(ve)}"
        success = False
    except Exception as e:
        message = f"An unexpected error occurred during the attack simulation: {str(e)}"
        success = False

    end_time = time.perf_counter()
    return {
        "success": success,
        "message": message,
        "decrypted_data": decrypted_message_bytes.hex(),
        "attack_log": results,
        "execution_time": end_time - start_time
    }
