from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import os
import json

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

def sign_message(message: str, private_key_dict):
    """
    Tạo chữ ký số từ thông điệp bằng khóa riêng.
    private_key_dict: dict chứa các thành phần của private key (n, d, p, q)
    """
    try:
        # Tạo đối tượng RSA key từ PEM
        with open('keys/private_key.pem', 'rb') as f:
            key = RSA.import_key(f.read())
        
        h = SHA256.new(message.encode())
        signature = pkcs1_15.new(key).sign(h)
        return signature.hex()  # Chuyển sang hex để dễ truyền qua JSON
    except Exception as e:
        print(f"Error in sign_message: {str(e)}")
        raise

def verify_signature(message: str, signature_hex: str, public_key_dict):
    """
    Kiểm tra chữ ký số bằng khóa công khai.
    public_key_dict: dict chứa các thành phần của public key (n, e)
    """
    try:
        # Tạo đối tượng RSA key từ PEM
        with open('keys/public_key.pem', 'rb') as f:
            key = RSA.import_key(f.read())
        
        h = SHA256.new(message.encode())
        try:
            pkcs1_15.new(key).verify(h, bytes.fromhex(signature_hex))
            return True
        except (ValueError, TypeError):
            return False
    except Exception as e:
        print(f"Error in verify_signature: {str(e)}")
        raise

# DEMO nhanh nếu chạy trực tiếp file
if __name__ == "__main__":
    pub_key, priv_key = load_keys()

    msg = "RSA is cool!"

    print("\n🔐 Original message:", msg)

    encrypted = encrypt_message(msg, pub_key)
    print("🔒 Encrypted (hex):", encrypted.hex())

    decrypted = decrypt_message(encrypted, priv_key)
    print("🔓 Decrypted:", decrypted)

    # Tạo dict chứa private key
    priv_key_dict = {
        'n': priv_key.n,
        'd': priv_key.d,
        'p': priv_key.p,
        'q': priv_key.q
    }
    
    signature = sign_message(msg, priv_key_dict)
    print("🖋 Signature (hex):", signature)

    # Tạo dict chứa public key
    pub_key_dict = {
        'n': pub_key.n,
        'e': pub_key.e
    }
    
    valid = verify_signature(msg, signature, pub_key_dict)
    print("✅ Signature valid?" if valid else "❌ Signature invalid")
