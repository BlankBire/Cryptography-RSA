from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

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
