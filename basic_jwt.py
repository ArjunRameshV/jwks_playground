import jwt
from datetime import datetime, timedelta

# Load private key
with open("keys/0/private_key.pem", "rb") as f:
    private_key = f.read()

# Create a JWT
payload = {
    "sub": "1234567890",
    "name": "John Doe",
    "iat": datetime.utcnow(),
    "exp": datetime.utcnow() + timedelta(minutes=1)
}

token = jwt.encode(payload, private_key, algorithm="RS256")
print(f"JWT: {token}")

# Load public key
with open("keys/0/public_key.pem", "rb") as f:
    public_key = f.read()

# Decode the JWT
decoded = jwt.decode(token, public_key, algorithms=["RS256"])
print(f"Decoded JWT: {decoded}")