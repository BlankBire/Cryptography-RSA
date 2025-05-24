import time
import random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto import Random

def simulate_decryption_time(private_key, ciphertext):
    """
    Mô phỏng thời gian giải mã phụ thuộc vào khóa.
    Giải mã và đo thời gian thực hiện.
    """
    cipher = PKCS1_v1_5.new(private_key)
    start = time.perf_counter()
    sentinel = Random.new().read(15)
    cipher.decrypt(ciphertext, sentinel)
    end = time.perf_counter()
    return end - start

def timing_attack(private_key, public_key, trials=100):
    """
    Mô phỏng attack bằng cách phân tích thời gian giải mã.
    Có thể tiết lộ thông tin về khóa bí mật.
    (Chỉ là giả lập - không thực hiện attack thực tế)
    """
    results = []
    cipher = PKCS1_v1_5.new(public_key)

    for _ in range(trials):
        plaintext = random.getrandbits(64).to_bytes(8, 'big')
        ciphertext = cipher.encrypt(plaintext)
        duration = simulate_decryption_time(private_key, ciphertext)
        results.append(duration)

    avg_time = sum(results) / len(results)
    print(f"[⏱] Average decryption time over {trials} trials: {avg_time:.8f} seconds")
    return results

def simulate_timing_attack(n, e):
    """
    Giao diện mô phỏng timing attack theo đúng format run_attacks.py cần.
    Tạo key RSA ngẫu nhiên và đo thời gian giải mã.
    """
    key = RSA.generate(2048)
    private_key = key
    public_key = key.publickey()

    print("[⏱] Simulating decryption timing...")
    results = timing_attack(private_key, public_key, trials=10)

    # Ghi log kết quả
    log = "\n".join([f"Trial {i+1}: {t:.8f} seconds" for i, t in enumerate(results)])
    avg = sum(results) / len(results)
    log += f"\n\n[Avg] {avg:.8f} seconds"

    return log
