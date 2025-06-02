from flask import Flask, request, jsonify
from flask_cors import CORS
from rsa_core import sign_message as rsa_sign, verify_signature as rsa_verify
from keygen import generate_rsa_keypair
import json

app = Flask(__name__)
CORS(app)

# Khởi tạo RSA instance
#rsa = RSA()

@app.route('/api/generate-keys', methods=['POST'])
def generate_keys():
    try:
        data = request.get_json()
        bits = data.get('bits', 1024)
        public_key, private_key = generate_rsa_keypair(bits)
        return jsonify({
            'public_key': public_key,
            'private_key': private_key
        })
    except Exception as e:
        print(f"Error in generate_keys: {str(e)}")
        return jsonify({'error': str(e)}), 400

@app.route('/api/sign', methods=['POST'])
def sign_message():
    try:
        data = request.get_json()
        message = data['message']
        private_key = data['private_key']
        
        # Không cần chuyển đổi vì private_key đã là dict
        signature = rsa_sign(message, private_key)
        return jsonify({'signature': signature})
    except Exception as e:
        print(f"Error in sign_message: {str(e)}")
        return jsonify({'error': str(e)}), 400

@app.route('/api/verify', methods=['POST'])
def verify_signature():
    try:
        data = request.get_json()
        message = data['message']
        signature = data['signature']
        public_key = data['public_key']
        
        # Không cần chuyển đổi vì public_key đã là dict
        is_valid = rsa_verify(message, signature, public_key)
        return jsonify({'is_valid': is_valid})
    except Exception as e:
        print(f"Error in verify_signature: {str(e)}")
        return jsonify({'error': str(e)}), 400

@app.route('/api/attack', methods=['POST'])
def perform_attack():
    try:
        data = request.get_json()
        attack_type = data['attack_type']
        public_key = data['public_key']
        
        # Chuyển đổi public key từ dict sang tuple cho các hàm tấn công
        public_key_tuple = (public_key['n'], public_key['e'])
        
        if attack_type == 'wiener':
            from attacks.wiener import wiener_attack
            result = wiener_attack(public_key_tuple)
        elif attack_type == 'hastad':
            from attacks.hastad import hastad_attack
            result = hastad_attack(public_key_tuple)
        else:
            return jsonify({'error': 'Invalid attack type'}), 400
            
        return jsonify(result)
    except Exception as e:
        print(f"Error in perform_attack: {str(e)}")
        return jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    app.run(debug=True, port=4444) 