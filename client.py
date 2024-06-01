import base64
import json
import requests
import argparse
import jwt

from jwt.exceptions import InvalidTokenError, PyJWTError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from requests.exceptions import RequestException, JSONDecodeError, Timeout, HTTPError

BASE_ENDPOINT = "http://localhost:5050"
JWK_ENDPOINT = f"{BASE_ENDPOINT}/jwks-endpoint"
JWT_BASE_ENDPOINT = f"{BASE_ENDPOINT}/generate_encoded_message"

def fetch_jwt_token(jwt_endpoint):
    try:
        resp = requests.get(jwt_endpoint, timeout=2)
        resp.raise_for_status()
    except (RequestException, JSONDecodeError, Timeout, HTTPError) as e:
        raise Exception(e)
    
    return resp.json()

def fetch_jwks(jwk_endpoint):
    try:
        resp = requests.get(jwk_endpoint, timeout=2)
        resp.raise_for_status()
        return resp.json()
    except (RequestException, JSONDecodeError, Timeout) as e:
        print(f"Exception:{e}")

def generate_rsa_public_key(key):
    try:
        n = int.from_bytes(base64.urlsafe_b64decode(key["n"] + "=="), byteorder="big")
        e = int.from_bytes(base64.urlsafe_b64decode(key["e"] + "=="), byteorder="big")
        public_numbers = rsa.RSAPublicNumbers(e, n)
        public_key = public_numbers.public_key(default_backend())
        return public_key
    except Exception as e:
        print(f"Exception when getting pub key: {e}")

def construct_public_key_pem(jwt_kid, jwks):
    public_key = next((key for key in jwks["keys"] if key["kid"] == jwt_kid), None)
    if public_key is None:
        raise ValueError("No matching public key")
    
    if public_key["kty"] == "RSA":
        rsa_public_key = generate_rsa_public_key(public_key)
    else:
        raise ValueError("Unsupported key type")
    
    public_key_pem = rsa_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return public_key_pem

def decode_jwt(jwt_token, public_key):
    try:
        # Decode the JWT token using the current PEM certificate
        decoded_token = jwt.decode(jwt_token, public_key, algorithms=['RS256'])
    except jwt.ExpiredSignatureError:
        print("Token has expired")
    except jwt.InvalidTokenError:
        print("Token Invalid")
    
    return decoded_token
    

def main(key_id):
    # Get the JWT Token
    jwt_resp = fetch_jwt_token(f"{JWT_BASE_ENDPOINT}/{key_id}")
    
    jwt_token = jwt_resp.get("encoded_body")
    # Get the Token Header
    try:
        unverified_header = jwt.get_unverified_header(jwt_token)
    except PyJWTError as e:
        raise ValueError(f"Unable to get the JWT header: {e}")
    
    # Find matching key
    kid = unverified_header.get("kid")
    if not kid:
        raise ValueError("JWT does not contain 'kid' header")

    # Get the Json Web Key Set (JWKS)
    jwks = fetch_jwks(JWK_ENDPOINT)

    # Get the public key
    public_key = construct_public_key_pem(kid, jwks)

    decoded_message = decode_jwt(jwt_token, public_key)
    print("The decoded message is:")
    print(json.dumps(decoded_message, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="JWKS Client")
    parser.add_argument("--key_id", type=int, default=0, help="Key ID used to generate jwt token")
    args = parser.parse_args()

    try:
        main(args.key_id)
    except Exception as e:
        print(f"ERROR: {e}")