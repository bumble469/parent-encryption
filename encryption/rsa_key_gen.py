from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os
from dotenv import load_dotenv
load_dotenv()

def generate_rsa_keys(key_size=2048):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    public_key = private_key.public_key()

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_key_pem, public_key_pem

private_key_pem, public_key_pem = generate_rsa_keys()

key_folder_path = os.getenv('FOLDER_PATH')  
private_key_file = os.getenv('RSA_PRIVATE_KEY')  
public_key_file = os.getenv('RSA_PUBLIC_KEY')

os.makedirs(key_folder_path, exist_ok=True)

private_key_path = os.path.join(key_folder_path, private_key_file)
public_key_path = os.path.join(key_folder_path, public_key_file)

with open(private_key_path, 'wb') as private_file:
    private_file.write(private_key_pem)

with open(public_key_path, 'wb') as public_file:
    public_file.write(public_key_pem)

print(f"Keys saved to '{key_folder_path}'")
