import os
import pytest
from Crypto.PublicKey import RSA
import keygen

@pytest.fixture(scope="module")
def cleanup_keys():
    # Thư mục lưu khóa tạm thời cho test
    test_dir = 'test_keys'
    if os.path.exists(test_dir):
        # Xóa nếu tồn tại trước đó
        for f in os.listdir(test_dir):
            os.remove(os.path.join(test_dir, f))
        os.rmdir(test_dir)
    yield test_dir
    # Cleanup sau test
    if os.path.exists(test_dir):
        for f in os.listdir(test_dir):
            os.remove(os.path.join(test_dir, f))
        os.rmdir(test_dir)

def test_generate_rsa_keypair_creates_files(cleanup_keys):
    output_dir = cleanup_keys
    keygen.generate_rsa_keypair(1024, output_dir)

    priv_path = os.path.join(output_dir, 'private_key.pem')
    pub_path = os.path.join(output_dir, 'public_key.pem')

    assert os.path.exists(priv_path), "Private key file not created"
    assert os.path.exists(pub_path), "Public key file not created"

    # Kiểm tra file private key có thể load được
    with open(priv_path, 'rb') as f:
        priv_key = RSA.import_key(f.read())
    assert priv_key.has_private(), "Private key loaded is not private"

    # Kiểm tra file public key có thể load được
    with open(pub_path, 'rb') as f:
        pub_key = RSA.import_key(f.read())
    assert not pub_key.has_private(), "Public key loaded is not public"

def test_generate_rsa_keypair_key_size(cleanup_keys):
    output_dir = cleanup_keys
    key_size = 2048
    keygen.generate_rsa_keypair(key_size, output_dir)
    
    priv_path = os.path.join(output_dir, 'private_key.pem')
    with open(priv_path, 'rb') as f:
        priv_key = RSA.import_key(f.read())
    assert priv_key.size_in_bits() == key_size, f"Key size is not {key_size}"
