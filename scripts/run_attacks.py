import sys
import os
from Crypto.PublicKey import RSA
sys.path.append(os.path.join(os.path.dirname(__file__), '../src'))
from attacks import factorization, timing_attack, cca_attack
# Load private key
with open('keys/private_key.pem', 'rb') as f:
    key_data = f.read()
rsa_key = RSA.import_key(key_data)

# -------------------- DỮ LIỆU MẪU --------------------
rsa_n = 8051  # ví dụ: n = 83 * 97
e = 65537

# -------------------- 1. FACTORIZATION ATTACK --------------------
print("[🔍] Running factorization attacks...")

methods = {
    "Trial Division": factorization.trial_division,
    "Fermat": factorization.fermat_factor,
    "Pollard's Rho": factorization.pollards_rho
}

with open("results/factorization_log.txt", "w") as f:
    for name, method in methods.items():
        f.write(f"=== {name} ===\n")
        p, q = method(rsa_n)
        if p and q:
            f.write(f"Success: n = {p} * {q}\n")
        else:
            f.write("Failed to factorize.\n")
        f.write("\n")

print("[✔] Factorization results saved to results/factorization_log.txt")

# -------------------- 2. TIMING ATTACK --------------------
print("[⏱] Simulating timing attack...")

timing_result = timing_attack.simulate_timing_attack(rsa_n, e)

with open("results/timing_attack_result.txt", "w") as f:
    f.write("=== Timing Attack Simulation ===\n")
    f.write(str(timing_result) + "\n")

print("[✔] Timing attack result saved to results/timing_attack_result.txt")

# -------------------- 3. CCA ATTACK --------------------
print("[💣] Running CCA attack simulation...")

# Mã hóa một thông điệp làm ciphertext
from Crypto.Cipher import PKCS1_OAEP
cipher = PKCS1_OAEP.new(rsa_key.publickey())
plaintext = b'Test message for CCA attack'
ciphertext = cipher.encrypt(plaintext)

private_key = rsa_key
public_key = rsa_key.publickey()

cca_result = cca_attack.simulate_cca_attack(ciphertext, private_key, public_key)

with open("results/cca_output.txt", "w") as f:
    f.write("=== CCA Attack Simulation ===\n")
    f.write(f"Original plaintext: {plaintext}\n")
    f.write(f"CCA attack valid modified ciphertexts count: {cca_result}\n")

print("[✔] CCA attack result saved to results/cca_output.txt")

