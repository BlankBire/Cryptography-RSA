from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256, SHA3_256
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import os
import json
import logging
import time
from typing import Dict, Tuple, Union, Optional
import base64

logger = logging.getLogger(__name__)

class RSACipher:
    def __init__(self, key_size: int = 2048):
        """
        Initialize RSA cipher with specified key size.
        Args:
            key_size: Size of RSA key in bits (default: 2048)
        """
        self.key_size = key_size
        self._validate_key_size()

    def _validate_key_size(self):
        """Validate key size is secure."""
        if self.key_size < 2048:
            raise ValueError("Key size must be at least 2048 bits for security")

    @staticmethod
    def generate_keypair(key_size: int = 3072, e: int = 16777217) -> Tuple[RSA.RsaKey, RSA.RsaKey]:
        """
        Generate a new RSA key pair.
        Args:
            key_size: Size of RSA key in bits
            e: Public exponent (default: 16777217)
        Returns:
            Tuple of (public_key, private_key)
        """
        start_time = time.time()
        key = RSA.generate(key_size, e=e)
        duration = time.time() - start_time
        logger.info(f"Generated {key_size}-bit RSA keypair with e={e} in {duration:.2f}s")
        return key.publickey(), key

    def save_keys(self, public_key: RSA.RsaKey, private_key: RSA.RsaKey, 
                 key_dir: str = 'keys') -> None:
        """
        Save RSA keys to files.
        Args:
            public_key: RSA public key
            private_key: RSA private key
            key_dir: Directory to save keys
        """
        try:
            # Create directory if it doesn't exist
            os.makedirs(key_dir, exist_ok=True)
            
            # Get full paths for key files
            public_key_path = os.path.join(key_dir, 'public_key.pem')
            private_key_path = os.path.join(key_dir, 'private_key.pem')
            
            logger.info(f"Saving public key to: {public_key_path}")
            logger.info(f"Saving private key to: {private_key_path}")
            
            # Save public key
            with open(public_key_path, 'wb') as f:
                f.write(public_key.export_key('PEM'))
            logger.info("Public key saved successfully")
            
            # Save private key without password protection
            with open(private_key_path, 'wb') as f:
                f.write(private_key.export_key('PEM'))
            logger.info("Private key saved successfully")
            
        except Exception as e:
            logger.error(f"Error saving keys: {str(e)}")
            raise

    @staticmethod
    def load_keys(key_dir: str = 'keys') -> Tuple[RSA.RsaKey, RSA.RsaKey]:
        """
        Load RSA keys from files.
        Args:
            key_dir: Directory containing key files
        Returns:
            Tuple of (public_key, private_key)
        """
        try:
            with open(os.path.join(key_dir, 'public_key.pem'), 'rb') as f:
                public_key = RSA.import_key(f.read())

            with open(os.path.join(key_dir, 'private_key.pem'), 'rb') as f:
                private_key = RSA.import_key(f.read())

            return public_key, private_key
        except Exception as e:
            logger.error(f"Error loading keys: {str(e)}")
            raise

    def encrypt_message(self, message: str, public_key: RSA.RsaKey) -> str:
        """
        Encrypt message using RSA-OAEP.
        Args:
            message: Message to encrypt
            public_key: RSA public key
        Returns:
            Base64 encoded encrypted message
        """
        try:
            # Use OAEP padding for better security
            cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA3_256)
            
            # Convert message to bytes using UTF-8 encoding
            try:
                message_bytes = message.encode('utf-8')
            except UnicodeEncodeError:
                logger.error("Message contains characters that cannot be encoded as UTF-8")
                raise ValueError("Message contains characters that cannot be encoded as UTF-8")

            # Encrypt the message bytes directly
            encrypted = cipher.encrypt(message_bytes)
            
            # Return base64 encoded result
            return base64.b64encode(encrypted).decode()
        except Exception as e:
            logger.error(f"Encryption error: {str(e)}")
            raise

    def decrypt_message(self, ciphertext: str, private_key: RSA.RsaKey) -> str:
        """
        Decrypt message using RSA-OAEP.
        Args:
            ciphertext: Base64 encoded encrypted message
            private_key: RSA private key
        Returns:
            Decrypted message
        """
        try:
            # Create cipher with OAEP padding
            cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA3_256)
            
            # Decode base64 ciphertext
            encrypted = base64.b64decode(ciphertext)
            
            # Decrypt the message
            decrypted = cipher.decrypt(encrypted)
            
            # Convert bytes back to string
            return decrypted.decode('utf-8')
        except Exception as e:
            logger.error(f"Decryption error: {str(e)}")
            raise

    def sign_message(self, message: str, private_key: Union[RSA.RsaKey, Dict]) -> str:
        """
        Sign message using RSA-PSS.
        Args:
            message: Message to sign
            private_key: RSA private key or dict containing key components
        Returns:
            Base64 encoded signature
        """
        try:
            if isinstance(private_key, dict):
                # Create RSA key from components
                key = RSA.construct((
                    private_key['n'],
                    private_key['e'],
                    private_key['d'],
                    private_key['p'],
                    private_key['q']
                ))
            else:
                key = private_key

            # Use SHA3-256 for better security
            h = SHA3_256.new(message.encode())
            signature = pkcs1_15.new(key).sign(h)
            return base64.b64encode(signature).decode()
        except Exception as e:
            logger.error(f"Signing error: {str(e)}")
            raise

    def verify_signature(self, message: str, signature: str, 
                        public_key: Union[RSA.RsaKey, Dict]) -> bool:
        """
        Verify RSA signature.
        Args:
            message: Original message
            signature: Base64 encoded signature
            public_key: RSA public key or dict containing key components
        Returns:
            True if signature is valid, False otherwise
        """
        logger.info(f"Attempting to verify signature for message (truncated): {message[:50]}...")
        logger.info(f"Signature (truncated): {signature[:50]}...")
        
        try:
            if isinstance(public_key, dict):
                logger.info(f"Reconstructing public key from dict: n={public_key.get('n')} e={public_key.get('e')}")
                # Ensure key components are present and castable to int
                if 'n' not in public_key or 'e' not in public_key:
                     logger.error("Public key dict missing 'n' or 'e'.")
                     return False # Trả về False thay vì ném lỗi nếu key dict sai
                try:
                    n_int = int(public_key['n'])
                    e_int = int(public_key['e'])
                except ValueError:
                     logger.error("Public key components 'n' or 'e' cannot be cast to int.")
                     return False # Trả về False nếu không cast được

                # Create RSA key from components
                key = RSA.construct((n_int, e_int))
            else:
                logger.info("Using public key object directly.")
                key = public_key

            logger.info("Public key reconstructed successfully.")

            # Decode signature
            try:
                signature_bytes = base64.b64decode(signature)
                logger.info(f"Signature decoded to bytes (length: {len(signature_bytes)}).")
            except (ValueError, TypeError, base64.binascii.Error) as e:
                 logger.error(f"Base64 decoding failed for signature: {str(e)}")
                 return False # Trả về False nếu decode Base64 lỗi

            # Encode message
            try:
                 message_bytes = message.encode('utf-8')
                 logger.info(f"Message encoded to bytes (length: {len(message_bytes)}).")
            except UnicodeEncodeError:
                 logger.error("Message contains characters that cannot be encoded as UTF-8 for verification")
                 return False # Trả về False nếu encode message lỗi

            h = SHA3_256.new(message_bytes)
            logger.info("Hash created.")
            try:
                # Thực hiện xác thực
                pkcs1_15.new(key).verify(h, signature_bytes)
                logger.info("Signature verification SUCCEEDED.")
                return True # Chỉ trả về True nếu verify thành công
            except (ValueError, TypeError) as e:
                # Trả về False nếu verify thất bại (chữ ký sai) hoặc lỗi format
                logger.info(f"Signature verification FAILED: {str(e)}")
                return False
        except Exception as e:
            # Log các lỗi khác (ví dụ: key không hợp lệ sau khi reconstruct)
            logger.error(f"Unexpected error during verification: {str(e)}")
            # Không raise ngoại lệ để server trả về 400 thay vì 500, dễ debug hơn
            return False # Trả về False cho mọi lỗi không mong muốn

# Example usage
if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    # Create RSA cipher instance
    rsa = RSACipher(key_size=2048)
    
    # Generate new key pair
    public_key, private_key = rsa.generate_keypair()
    
    # Save keys
    rsa.save_keys(public_key, private_key)
    
    # Test message
    message = "Hello, RSA!"
    print(f"\nOriginal message: {message}")
    
    # Encrypt and decrypt
    encrypted = rsa.encrypt_message(message, public_key)
    print(f"Encrypted (base64): {encrypted}")
    
    decrypted = rsa.decrypt_message(encrypted, private_key)
    print(f"Decrypted: {decrypted}")
    
    # Sign and verify
    signature = rsa.sign_message(message, private_key)
    print(f"Signature (base64): {signature}")
    
    is_valid = rsa.verify_signature(message, signature, public_key)
    print(f"Signature valid: {is_valid}")
