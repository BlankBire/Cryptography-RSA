# filepath: attack_server.py
from flask import Flask, request, jsonify
import sys
import os
from Crypto.PublicKey import RSA
sys.path.append(os.path.join(os.path.dirname(__file__), '../src'))
from attacks import factorization, timing_attack, cca_attack
import base64

app = Flask(__name__)

@app.route('/factorize', methods=['POST'])
def factorize():
    n = int(request.json['n'])
    method = request.json.get('method', 'trial')
    if method == 'trial':
        p, q = factorization.trial_division(n)
    elif method == 'fermat':
        p, q = factorization.fermat_factor(n)
    elif method == 'pollard':
        p, q = factorization.pollards_rho(n)
    else:
        return jsonify({'error': 'Unknown method'}), 400
    return jsonify({'p': p, 'q': q})

@app.route('/timing', methods=['POST'])
def timing():
    # Giả lập attack, không thực hiện attack thực tế
    n = int(request.json['n'])
    e = int(request.json['e'])
    result = timing_attack.simulate_timing_attack(n, e)
    return jsonify({'result': result})

@app.route('/cca', methods=['POST'])
def cca():
    # Nhận ciphertext (base64), private_key (PEM), public_key (PEM)
    ciphertext = base64.b64decode(request.json['ciphertext'])
    priv_key = RSA.import_key(request.json['private_key'].encode())
    pub_key = RSA.import_key(request.json['public_key'].encode())
    count = cca_attack.simulate_cca_attack(ciphertext, priv_key, pub_key)
    return jsonify({'valid_count': count})

if __name__ == '__main__':
    app.run(port=5000, debug=True)