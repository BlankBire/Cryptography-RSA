from Crypto.PublicKey import RSA
import os

def generate_rsa_keypair(key_size=3072, output_dir='keys'):
    """
    Tạo cặp khóa RSA và trả về dạng dict.
    """
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    key = RSA.generate(key_size)
    
    # Lấy các thành phần của khóa
    n = key.n
    e = key.e
    d = key.d
    p = key.p
    q = key.q
    
    # Tạo dict chứa public key và private key
    public_key = {
        'n': n,
        'e': e
    }
    
    private_key = {
        'n': n,
        'd': d,
        'p': p,
        'q': q
    }
    
    # Lưu khóa vào file (tùy chọn)
    private_key_pem = key.export_key()
    public_key_pem = key.publickey().export_key()

    with open(os.path.join(output_dir, 'private_key.pem'), 'wb') as priv_file:
        priv_file.write(private_key_pem)

    with open(os.path.join(output_dir, 'public_key.pem'), 'wb') as pub_file:
        pub_file.write(public_key_pem)

    print(f"[✔] Generated RSA key pair with {key_size} bits and saved to '{output_dir}'.")
    
    return public_key, private_key

if __name__ == "__main__":
    generate_rsa_keypair(3072)  # Bạn có thể đổi thành 1024 hoặc 4096 nếu muốn
