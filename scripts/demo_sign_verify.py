from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
import os

# Đường dẫn
KEY_DIR = "keys"
DATA_FILE = "data/plaintext_samples.txt"
RESULT_FILE = "results/signatures.txt"

def load_keys():
    with open(os.path.join(KEY_DIR, "private_key.pem"), "rb") as f:
        private_key = RSA.import_key(f.read())
    with open(os.path.join(KEY_DIR, "public_key.pem"), "rb") as f:
        public_key = RSA.import_key(f.read())
    return private_key, public_key

def read_plaintext():
    with open(DATA_FILE, "r", encoding="utf-8") as f:
        return f.read().strip()

def sign_message(private_key, message):
    h = SHA256.new(message.encode())
    signature = pkcs1_15.new(private_key).sign(h)
    return signature

def verify_signature(public_key, message, signature):
    h = SHA256.new(message.encode())
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

def save_signature(signature):
    with open(RESULT_FILE, "wb") as f:
        f.write(signature)

if __name__ == "__main__":
    print("[🔐] Demo ký và xác minh chữ ký RSA...")
    
    private_key, public_key = load_keys()
    message = read_plaintext()
    
    signature = sign_message(private_key, message)
    verified = verify_signature(public_key, message, signature)
    
    save_signature(signature)

    print(f"[📝] Message: {message}")
    print(f"[✔] Signature created and saved to {RESULT_FILE}")
    print(f"[✅] Verification result: {'SUCCESS' if verified else 'FAILURE'}")
