import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), '../src'))
from keygen import generate_rsa_keypair

if __name__ == "__main__":
    print("[🔑] Generating RSA key pair (2048 bits)...")
    generate_rsa_keypair(2048)
