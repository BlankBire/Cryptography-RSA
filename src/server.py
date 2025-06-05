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

# Initialize RSA cipher
rsa = RSACipher(key_size=3072)

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
        data = request.get_json()
        bits = data.get('bits', 3072)
        
        # Generate new key pair
        public_key, private_key = rsa.generate_keypair(bits)
        
        # Save keys
        rsa.save_keys(public_key, private_key)
        
        # Convert keys to dict format for JSON response
        public_key_dict = {
            'n': str(public_key.n),
            'e': str(public_key.e)
        }
        
        private_key_dict = {
            'n': str(private_key.n),
            'd': str(private_key.d),
            'p': str(private_key.p),
            'q': str(private_key.q)
        }
        
        logger.info(f"Generated new RSA keypair with {bits} bits")
        
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
        if not data or 'message' not in data or 'private_key' not in data:
            raise ValueError("Missing required fields")
        message = data['message']
        private_key = data['private_key']
        # Convert all key fields to int (handle string from JSON)
        for k in ['n', 'e', 'd', 'p', 'q']:
            private_key[k] = int(private_key[k])
        signature = rsa.sign_message(message, private_key)
        logger.info(f"Message signed successfully")
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
        if not data or 'message' not in data or 'signature' not in data or 'public_key' not in data:
            raise ValueError("Missing required fields")
        message = data['message']
        signature = data['signature']
        public_key = data['public_key']
        # Convert all key fields to int (handle string from JSON)
        for k in ['n', 'e']:
            public_key[k] = int(public_key[k])
        is_valid = rsa.verify_signature(message, signature, public_key)
        logger.info(f"Signature verification result: {is_valid}")
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

if __name__ == '__main__':
    # Create necessary directories
    os.makedirs('logs', exist_ok=True)
    os.makedirs('keys', exist_ok=True)
    
    # Run the server
    app.run(
        host='0.0.0.0',
        port=4444,
        debug=False,  # Disable debug mode in production
        #ssl_context='adhoc'  # Enable HTTPS
    ) 