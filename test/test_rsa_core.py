import pytest
import rsa_core

@pytest.fixture(scope="module")
def keys():
    return rsa_core.load_keys()

def test_encrypt_decrypt(keys):
    public_key, private_key = keys
    message = "Hello Cryptography!"
    
    encrypted = rsa_core.encrypt_message(message, public_key)
    decrypted = rsa_core.decrypt_message(encrypted, private_key)

    assert decrypted == message, "Decrypted message does not match original"

def test_sign_verify(keys):
    public_key, private_key = keys
    message = "Sign this message"

    signature = rsa_core.sign_message(message, private_key)
    valid = rsa_core.verify_signature(message, signature, public_key)

    assert valid is True, "Signature verification failed"

def test_invalid_signature(keys):
    public_key, private_key = keys
    message = "Original message"
    tampered_message = "Tampered message"

    signature = rsa_core.sign_message(message, private_key)
    valid = rsa_core.verify_signature(tampered_message, signature, public_key)

    assert valid is False, "Tampered message should not pass signature verification"
