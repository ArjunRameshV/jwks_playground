import argparse
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from pathlib import Path

def generate_rsa_key_pair(key_size=2048):
    # Generate the private key
    private_key = rsa.generate_private_key(
        public_exponent=65537, # the recommended value as per cryptography docs
        key_size=key_size
    )

    public_key = private_key.public_key()
    return private_key, public_key

def save_rsa_keys(key, filename, is_private):
    if is_private:
        key_bytes = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    else:
        key_bytes = key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    file = Path(filename)
    file.parent.mkdir(parents=True, exist_ok=True)
    file.write_bytes(key_bytes)

def main(key_size, num_keys, output_dir):
    for i in range(num_keys):
        private_key, public_key = generate_rsa_key_pair(key_size)

        private_key_filename = f"{output_dir}/{i}/private_key.pem"
        public_key_filename = f"{output_dir}/{i}/public_key.pem"

        save_rsa_keys(private_key, private_key_filename, True)
        save_rsa_keys(public_key, public_key_filename, False)

        print(f"Generated key pair {i} and saved to {private_key_filename} and {public_key_filename}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate and store RSA key pairs")
    parser.add_argument("--key_size", type=int, default=2048, help="Size of RSA key to generate")
    parser.add_argument("--num_keys", type=int, default=1, help="Number of key pairs to generate")
    parser.add_argument("--output_dir", type=str, default="keys", help="Directory to save generated keys")
    args = parser.parse_args()

    main(args.key_size, args.num_keys, args.output_dir)