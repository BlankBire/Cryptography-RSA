from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from rsa_core import RSACipher
from keygen import generate_rsa_keypair
import json
import logging
from functools import wraps
import time
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os
from datetime import datetime
from Crypto.PublicKey import RSA
import base64
from Crypto.Util.number import getPrime, inverse, GCD

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('server.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__, template_folder='templates')
CORS(app)

# Initialize RSA cipher and key storage
rsa = None
server_keys = None  # Store server's RSA keys

def get_rsa_cipher():
    global rsa
    if rsa is None:
        rsa = RSACipher(key_size=3072)
    return rsa

def initialize_server_keys():
    global server_keys
    try:
        rsa_cipher = get_rsa_cipher()
        public_key, private_key = rsa_cipher.generate_keypair(3072, 16777217)  # 3072 bits with e=16777217
        
        server_keys = {
            'public_key': public_key,
            'private_key': private_key
        }
        
        # Log key information
        logger.info("Server keys generated successfully:")
        logger.info(f"Key size: 3072 bits")
        logger.info(f"Public exponent (e): 16777217")
        logger.info(f"Public Key (n): {public_key.n}")
        logger.info(f"Private Key (d): {private_key.d}")
        logger.info(f"Private Key (p): {private_key.p}")
        logger.info(f"Private Key (q): {private_key.q}")
        
    except Exception as e:
        logger.error(f"Error generating server keys: {str(e)}")
        raise

# Initialize server keys on startup
initialize_server_keys()

# Configure rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Security headers middleware
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

def log_request(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        start_time = time.time()
        response = f(*args, **kwargs)
        duration = time.time() - start_time
        # Handle both response object and (response, status) tuple
        status = response.status_code if hasattr(response, 'status_code') else response[1] if isinstance(response, tuple) and len(response) > 1 else 'unknown'
        logger.info(f"Request: {request.method} {request.path} - Duration: {duration:.2f}s - Status: {status}")
        return response
    return decorated_function

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/api/generate-keys', methods=['POST'])
@limiter.limit("10 per minute")
@log_request
def generate_keys():
    try:
        if not server_keys:
            raise ValueError("Server keys not initialized")
            
        # Convert keys to dict format
        public_key_dict = {
            'n': str(server_keys['public_key'].n),
            'e': str(server_keys['public_key'].e)
        }
        
        private_key_dict = {
            'n': str(server_keys['private_key'].n),
            'e': str(server_keys['private_key'].e),
            'd': str(server_keys['private_key'].d),
            'p': str(server_keys['private_key'].p),
            'q': str(server_keys['private_key'].q)
        }
        
        # Save keys to .pem files
        keys_dir = 'keys'
        os.makedirs(keys_dir, exist_ok=True)

        # Save public key
        public_pem_path = os.path.join(keys_dir, 'public.pem')
        with open(public_pem_path, 'wb') as f:
            f.write(server_keys['public_key'].export_key(format='PEM'))
        logger.info(f"Public key saved to {public_pem_path}")

        # Save private key
        private_pem_path = os.path.join(keys_dir, 'private.pem')
        with open(private_pem_path, 'wb') as f:
            f.write(server_keys['private_key'].export_key(format='PEM'))
        logger.info(f"Private key saved to {private_pem_path}")

        logger.info("Sending keys to client")
        return jsonify({
            'public_key': public_key_dict,
            'private_key': private_key_dict,
            'timestamp': datetime.utcnow().isoformat()
        })
    except ValueError as ve:
        logger.error(f"Validation error in generate_keys: {str(ve)}")
        return jsonify({'error': str(ve)}), 400
    except Exception as e:
        logger.error(f"Error in generate_keys: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/sign', methods=['POST'])
@limiter.limit("100 per minute")
@log_request
def sign_message():
    try:
        data = request.get_json()
        if not data or 'message' not in data:
            raise ValueError("Missing required fields")
            
        message = data['message']
        
        if not server_keys:
            raise ValueError("Server keys not initialized")
            
        rsa_cipher = get_rsa_cipher()
        signature = rsa_cipher.sign_message(message, server_keys['private_key'])
        
        logger.info(f"Message signed successfully:")
        logger.info(f"Original message: {message}")
        logger.info(f"Signature: {signature}")
        
        return jsonify({
            'signature': signature,
            'timestamp': datetime.utcnow().isoformat()
        })
    except ValueError as ve:
        logger.error(f"Validation error in sign_message: {str(ve)}")
        return jsonify({'error': str(ve)}), 400
    except Exception as e:
        logger.error(f"Error in sign_message: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/verify', methods=['POST'])
@limiter.limit("100 per minute")
@log_request
def verify_signature():
    try:
        data = request.get_json()
        if not data or 'message' not in data or 'signature' not in data:
            raise ValueError("Missing required fields")
            
        message = data['message']
        signature = data['signature']
        
        if not server_keys:
            raise ValueError("Server keys not initialized")
            
        rsa_cipher = get_rsa_cipher()
        is_valid = rsa_cipher.verify_signature(message, signature, server_keys['public_key'])
        
        logger.info(f"Signature verification result: {is_valid}")
        logger.info(f"Message: {message}")
        logger.info(f"Signature: {signature}")
        
        return jsonify({
            'is_valid': is_valid,
            'timestamp': datetime.utcnow().isoformat()
        })
    except ValueError as ve:
        logger.error(f"Validation error in verify_signature: {str(ve)}")
        return jsonify({'error': str(ve)}), 400
    except Exception as e:
        logger.error(f"Error in verify_signature: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/attack', methods=['POST'])
@limiter.limit("5 per minute")
@log_request
def perform_attack():
    try:
        data = request.get_json()
        if not data or 'attack_type' not in data or 'public_key' not in data:
            raise ValueError("Missing required fields")
            
        attack_type = data['attack_type']
        public_key = data['public_key']
        
        if attack_type == 'wiener':
            from attacks.wiener import wiener_attack
            result = wiener_attack(public_key)
        elif attack_type == 'hastad':
            from attacks.hastad import hastad_attack
            result = hastad_attack(public_key)
        else:
            raise ValueError("Invalid attack type")
            
        logger.info(f"Attack {attack_type} performed successfully")
        return jsonify({
            'result': result,
            'timestamp': datetime.utcnow().isoformat()
        })
    except ValueError as ve:
        logger.error(f"Validation error in perform_attack: {str(ve)}")
        return jsonify({'error': str(ve)}), 400
    except Exception as e:
        logger.error(f"Error in perform_attack: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/encrypt', methods=['POST'])
@limiter.limit("100 per minute")
@log_request
def encrypt_message():
    try:
        data = request.get_json()
        if not data or 'message' not in data or 'public_key' not in data:
            raise ValueError("Missing required fields")
        message = data['message']
        public_key_dict = data['public_key']
        
        # Convert all key fields to int (handle string from JSON)
        for k in ['n', 'e']:
            public_key_dict[k] = int(public_key_dict[k])
            
        # Create RSA key object from components
        public_key = RSA.construct((
            public_key_dict['n'],
            public_key_dict['e']
        ))
        
        rsa_cipher = get_rsa_cipher()
        encrypted = rsa_cipher.encrypt_message(message, public_key)
        
        # Save ciphertext to file
        ciphertext_dir = 'data'
        os.makedirs(ciphertext_dir, exist_ok=True)
        ciphertext_path = os.path.join(ciphertext_dir, 'ciphertext_samples.txt')
        with open(ciphertext_path, 'w') as f: # Changed to 'w' for write (overwrite)
            f.write(f"{encrypted}\n")
        logger.info(f"Ciphertext saved to {ciphertext_path}")

        # Automatically decrypt the message using server's private key
        try:
            decrypted = rsa_cipher.decrypt_message(encrypted, server_keys['private_key'])
            logger.info(f"Message encrypted and decrypted successfully:")
            logger.info(f"Original message: {message}")
            logger.info(f"Encrypted: {encrypted}")
            logger.info(f"Decrypted: {decrypted}")
        except Exception as e:
            logger.error(f"Error during automatic decryption: {str(e)}")
        
        return jsonify({
            'encrypted': encrypted,
            'timestamp': datetime.utcnow().isoformat()
        })
    except ValueError as ve:
        logger.error(f"Validation error in encrypt_message: {str(ve)}")
        return jsonify({'error': str(ve)}), 400
    except Exception as e:
        logger.error(f"Error in encrypt_message: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/save-ciphertext', methods=['POST'])
@limiter.limit("100 per minute")
@log_request
def save_ciphertext():
    try:
        data = request.get_json()
        if not data or 'ciphertext' not in data:
            raise ValueError("Missing ciphertext data")
        
        ciphertext = data['ciphertext']
        ciphertext_path = os.path.join('data', 'ciphertext_samples.txt')
        
        # Save ciphertext to file
        with open(ciphertext_path, 'w') as f:
            f.write(ciphertext)
        
        logger.info(f"Ciphertext saved to {ciphertext_path}")
        return jsonify({
            'success': True,
            'timestamp': datetime.utcnow().isoformat()
        })
    except Exception as e:
        logger.error(f"Error saving ciphertext: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/factorization')
def factorization_page():
    return render_template('factorization.html')

@app.route('/api/factorize', methods=['POST'])
@limiter.limit("5 per minute")
@log_request
def factorize():
    try:
        data = request.get_json()
        if not data or 'n' not in data:
            raise ValueError("Missing required field 'n'")
            
        n = int(data['n'])
        method = data.get('method', 'auto')
        
        from attacks.factorization import factorize
        result = factorize(n, method)
        
        logger.info(f"Factorization completed for n={n} using method={method}")
        return jsonify(result)
        
    except ValueError as ve:
        logger.error(f"Validation error in factorize: {str(ve)}")
        return jsonify({'error': str(ve)}), 400
    except Exception as e:
        logger.error(f"Error in factorize: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/timing-attack', methods=['POST'])
@limiter.limit("5 per minute")
@log_request
def timing_attack():
    try:
        data = request.get_json()
        if not data or 'n' not in data or 'e' not in data:
            raise ValueError("Missing required fields: n and e")
            
        n = int(data['n'])
        e = int(data['e'])
        trials = int(data.get('trials', 10))  # Default to 10 trials if not specified
        
        from attacks.timing_attack import simulate_timing_attack
        result = simulate_timing_attack(n, e, trials)
        
        logger.info(f"Timing attack completed successfully with {trials} trials")
        return jsonify({
            'success': True,
            'statistics': result['statistics'],
            'results': result['results'],
            'execution_time': result['execution_time'],
            'inference': result.get('inference'),
            'timestamp': datetime.utcnow().isoformat()
        })
    except ValueError as ve:
        logger.error(f"Validation error in timing_attack: {str(ve)}")
        return jsonify({'success': False, 'message': str(ve)}), 400
    except Exception as e:
        logger.error(f"Error in timing_attack: {str(e)}")
        return jsonify({'success': False, 'message': 'Internal server error'}), 500

@app.route('/api/cca-attack', methods=['POST'])
@limiter.limit("5 per minute")
@log_request
def cca_attack():
    try:
        data = request.get_json()
        if not data or 'ciphertext' not in data:
            raise ValueError("Missing required field: ciphertext")
            
        ciphertext_b64 = data.get('ciphertext')

        if not ciphertext_b64:
            raise ValueError("Missing ciphertext")

        # Sử dụng server's private key
        if not server_keys:
            raise ValueError("Server keys not initialized")
            
        private_key = server_keys['private_key']
            
        # Decode Base64 ciphertext to bytes, then convert to hex string
        try:
            ciphertext_bytes = base64.b64decode(ciphertext_b64)
            ciphertext_hex = ciphertext_bytes.hex()
        except Exception as e:
            raise ValueError(f"Invalid Base64 ciphertext: {e}")

        from attacks.cca_attack import padding_oracle_attack
        result = padding_oracle_attack(private_key, ciphertext_hex)
        
        logger.info(f"CCA attack performed successfully")
        return jsonify({
            'result': result,
            'timestamp': datetime.utcnow().isoformat()
        })
    except ValueError as ve:
        logger.error(f"Validation error in cca_attack: {str(ve)}")
        return jsonify({'error': str(ve)}), 400
    except Exception as e:
        logger.error(f"Error in cca_attack: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500
    
@app.route('/api/wiener-attack', methods=['POST'])
@limiter.limit("5 per minute")
@log_request
def wiener_attack_api():
    try:
        data = request.get_json()
        if not data or 'n' not in data or 'e' not in data:
            raise ValueError("Missing required fields: n and e")
        n = int(data['n'])
        e = int(data['e'])
        from attacks.wiener import wiener_attack
        result = wiener_attack({'n': n, 'e': e})
        logger.info("Wiener attack completed")
        return jsonify({
            'success': result.get('success', False),
            'result': result,
            'timestamp': datetime.utcnow().isoformat()
        })
    except ValueError as ve:
        logger.error(f"Validation error in wiener_attack: {str(ve)}")
        return jsonify({'success': False, 'message': str(ve)}), 400
    except Exception as e:
        logger.error(f"Error in wiener_attack: {str(e)}")
        return jsonify({'success': False, 'message': 'Internal server error'}), 500
    
@app.route('/api/generate-small-wiener-key', methods=['GET'])
@limiter.limit("5 per minute")
@log_request
def generate_small_wiener_key():
    import random
    # Sinh khóa nhỏ dễ bị Wiener Attack (ví dụ n ~ 256 bit, d nhỏ)
    # 1. Sinh p, q nhỏ (~64 bit để n ~ 128 bit → dễ bị tấn công)
    while True:
        p = getPrime(64)
        q = getPrime(64)
        n = p * q
        phi = (p - 1) * (q - 1)
        n_4th = int(n ** 0.25)

        # 2. Chọn d nhỏ hơn (1/3)*n^(1/4) (cố tình để Wiener attack được)
        d_bound = int((1/3) * n_4th)
        if d_bound < 1000:
            continue
        d = random.randint(1000, d_bound)

        # 3. Tính e = d⁻¹ mod phi
        if GCD(d, phi) == 1:
            try:
                e = inverse(d, phi)
                if 1 < e < n:
                    return jsonify({
                    'n': str(n),
                    'e': str(e),
                    'd': str(d)
                    })                    
            except ValueError:
                continue
    
@app.route('/api/get-signed-message', methods=['GET'])
@limiter.limit("100 per minute")
@log_request
def get_signed_message():
    try:
        if not server_keys:
            raise ValueError("Server keys not initialized")
            
        # Generate a random message
        message = f"Server message at {datetime.utcnow().isoformat()}"
        
        # Sign the message with server's private key
        rsa_cipher = get_rsa_cipher()
        signature = rsa_cipher.sign_message(message, server_keys['private_key'])
        
        logger.info(f"Generated and signed message:")
        logger.info(f"Message: {message}")
        logger.info(f"Signature: {signature}")
        
        return jsonify({
            'message': message,
            'signature': signature,
            'timestamp': datetime.utcnow().isoformat()
        })
    except ValueError as ve:
        logger.error(f"Validation error in get_signed_message: {str(ve)}")
        return jsonify({'error': str(ve)}), 400
    except Exception as e:
        logger.error(f"Error in get_signed_message: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/attacks/hastad', methods=['POST'])
@limiter.limit("5 per minute")
@log_request
def hastad_attack_api():
    try:
        data = request.get_json()
        if not data or 'public_key' not in data:
            raise ValueError("Missing required fields")
            
        public_key = data['public_key']
        ciphertexts = data.get('ciphertexts')  # Optional
        
        from attacks.hastad import hastad_attack
        result = hastad_attack(public_key, ciphertexts)
        
        logger.info(f"Hastad attack completed")
        return jsonify(result)
        
    except ValueError as ve:
        logger.error(f"Validation error in hastad_attack_api: {str(ve)}")
        return jsonify({'error': str(ve)}), 400
    except Exception as e:
        logger.error(f"Error in hastad_attack_api: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/generate-hastad-example', methods=['GET'])
@limiter.limit("5 per minute")
@log_request
def generate_hastad_example():
    try:
        from attacks.hastad import generate_test_example
        example = generate_test_example()
        
        logger.info(f"Generated Hastad test example with message: {example['original_message']}")
        return jsonify(example)
        
    except Exception as e:
        logger.error(f"Error generating Hastad example: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    # Create necessary directories
    os.makedirs('keys', exist_ok=True)
    os.makedirs('results', exist_ok=True)
    
    # Run the Flask app
    app.run(host='0.0.0.0', port=4444, debug=True) 