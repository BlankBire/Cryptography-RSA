from Crypto.PublicKey import RSA
import os

def generate_rsa_keypair(key_size=2048, output_dir='keys'):
    """
    Tạo cặp khóa RSA và lưu vào thư mục output_dir.
    """
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    key = RSA.generate(key_size)

    private_key = key.export_key()
    public_key = key.publickey().export_key()

    with open(os.path.join(output_dir, 'private_key.pem'), 'wb') as priv_file:
        priv_file.write(private_key)

    with open(os.path.join(output_dir, 'public_key.pem'), 'wb') as pub_file:
        pub_file.write(public_key)

    print(f"[✔] Generated RSA key pair with {key_size} bits and saved to '{output_dir}'.")

if __name__ == "__main__":
    generate_rsa_keypair(2048)  # Bạn có thể đổi thành 1024 hoặc 4096 nếu muốn
