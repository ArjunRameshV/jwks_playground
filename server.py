import base64
import json
import glob
import os

from cryptography.hazmat.primitives import serialization
from datetime import datetime, timedelta
from flask import Flask, abort, jsonify
from jwt import PyJWK, PyJWKSet, encode
from markupsafe import escape

app = Flask(__name__)

def load_public_keys(root_dir="keys"):
    public_keys = []
    for dirpath, dirnames, _ in os.walk(root_dir):
        for dirname in dirnames:
            subdir_path = os.path.join(dirpath, dirname)
            with open(f"{subdir_path}/public_key.pem", "rb") as f:
                public_key = serialization.load_pem_public_key(f.read())
                key_id = int(dirname)
                public_keys.append((key_id, public_key))

    return public_keys

def public_key_to_jwk(key_id, public_key):
    numbers = public_key.public_numbers()
    e = base64.urlsafe_b64encode(numbers.e.to_bytes(3, 'big')).decode('utf-8').rstrip('=')
    n = base64.urlsafe_b64encode(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, 'big')).decode('utf-8').rstrip('=')
    jwk = {
        "kty": "RSA",
        "use": "sig",
        "kid": key_id,
        "alg": "RS256",
        "n": n,
        "e": e,
    }
    return jwk

@app.route('/jwks-endpoint', methods=['GET'])
def jwks():
    public_keys = load_public_keys()

    # convert public key to JWK
    jwks = {"keys": [public_key_to_jwk(key_id, key) for key_id, key in public_keys]}
    return jwks

@app.route('/generate_encoded_message/<int:key_id>')
def encoded_message(key_id):
    try:
        with open(f"keys/{key_id}/private_key.pem", "rb") as f:
            private_key = f.read()
    except Exception:
        print(f"key_id: {key_id} not found")
        abort(404)

    # Create a JWT
    payload = {
        "sub": "1234567890",
        "name": "John Doe",
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(minutes=1)
    }

    token = encode(payload, private_key, algorithm="RS256")
    return jsonify({"encoded_body": token})


if __name__ == "__main__":
    app.run(host="localhost", port=5050, debug=True)
