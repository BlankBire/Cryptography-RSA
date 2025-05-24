from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import os

def load_keys(key_dir='keys'):
    """
    Đọc khóa từ thư mục chỉ định.
    """
    with open(os.path.join(key_dir, 'public_key.pem'), 'rb') as f:
        public_key = RSA.import_key(f.read())

    with open(os.path.join(key_dir, 'private_key.pem'), 'rb') as f:
        private_key = RSA.import_key(f.read())

    return public_key, private_key

def encrypt_message(message: str, public_key):
    """
    Mã hóa chuỗi message bằng khóa công khai.
    """
    cipher = PKCS1_OAEP.new(public_key)
    encrypted = cipher.encrypt(message.encode())
    return encrypted

def decrypt_message(ciphertext: bytes, private_key):
    """
    Giải mã ciphertext bằng khóa riêng.
    """
    cipher = PKCS1_OAEP.new(private_key)
    decrypted = cipher.decrypt(ciphertext)
    return decrypted.decode()

def sign_message(message: str, private_key):
    """
    Tạo chữ ký số từ thông điệp bằng khóa riêng.
    """
    h = SHA256.new(message.encode())
    signature = pkcs1_15.new(private_key).sign(h)
    return signature

def verify_signature(message: str, signature: bytes, public_key):
    """
    Kiểm tra chữ ký số bằng khóa công khai.
    """
    h = SHA256.new(message.encode())
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

# DEMO nhanh nếu chạy trực tiếp file
if __name__ == "__main__":
    pub_key, priv_key = load_keys()

    msg = "RSA is cool!"

    print("\n🔐 Original message:", msg)

    encrypted = encrypt_message(msg, pub_key)
    print("🔒 Encrypted (hex):", encrypted.hex())

    decrypted = decrypt_message(encrypted, priv_key)
    print("🔓 Decrypted:", decrypted)

    signature = sign_message(msg, priv_key)
    print("🖋 Signature (hex):", signature.hex())

    valid = verify_signature(msg, signature, pub_key)
    print("✅ Signature valid?" if valid else "❌ Signature invalid")
