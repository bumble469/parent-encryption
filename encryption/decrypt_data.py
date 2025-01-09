import os
import math
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Helper function to get absolute paths
def get_absolute_path(relative_path):
    base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, relative_path)

# Load RSA private key
def load_rsa_private_key(pem_file):
    with open(get_absolute_path(pem_file), 'rb') as key_file:
        private_key_pem = key_file.read()
        private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    return private_key

# Decrypt the AES key using RSA private key
def decrypt_aes_key(rsa_private_key, encrypted_aes_key):
    aes_key = rsa_private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return aes_key

# Decrypt the intervals using RSA private key
def decrypt_intervals(rsa_private_key, encrypted_intervals_hex):
    encrypted_intervals = bytes.fromhex(encrypted_intervals_hex)
    intervals_decrypted = rsa_private_key.decrypt(
        encrypted_intervals,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    intervals = list(map(int, intervals_decrypted.decode('utf-8').split(',')))
    return intervals

# Reverse the shuffle operation
def reverse_shuffle(shuffled_data, intervals):
    sum_intervals = sum(intervals)
    len_intervals = len(intervals)
    palindrome_sum = sum_intervals
    reverse = 0
    while palindrome_sum > 0:
        digit = palindrome_sum % 10
        reverse = reverse * 10 + digit
        palindrome_sum = palindrome_sum // 10
    new_len = math.ceil(sum_intervals / len_intervals)
    shuffle_value = math.floor((sum_intervals * new_len) / reverse)
    shuffled_data_list = list(shuffled_data)
    for i in range(len(shuffled_data_list) - 1, -1, -1):
        new_index = (i + shuffle_value) % len(shuffled_data_list)
        shuffled_data_list[new_index], shuffled_data_list[i] = shuffled_data_list[i], shuffled_data_list[new_index]
    original_data = ''.join(shuffled_data_list)
    return original_data

# Extract AES data from mixed data
def extract_aes_data(mixed_data, intervals):
    original_data = []
    for i in range(len(mixed_data)):
        if i not in intervals:
            original_data.append(mixed_data[i])
    return ''.join(original_data)

# Decrypt the data using the AES key
def decrypt_data(aes_key, encrypted_data):
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted_data

# Main function
def main():
    rsa_private_key = load_rsa_private_key(os.getenv('RSA_PRIVATE_KEY'))

    # Load mixed encrypted data
    with open(get_absolute_path('encryption/mixed_encrypted_data.txt'), 'r') as data_file:
        mixed_data = data_file.read().strip()

    # Separate encrypted intervals and AES data
    encrypted_intervals_hex = mixed_data[:512]
    mixed_aes_data = mixed_data[512:]

    # Decrypt intervals
    intervals = decrypt_intervals(rsa_private_key, encrypted_intervals_hex)

    # Reverse shuffle operation
    deshuffled_data = reverse_shuffle(mixed_aes_data, intervals)

    # Extract AES data
    encrypted_aes_data_hex = extract_aes_data(deshuffled_data, intervals)
    encrypted_aes_data = bytes.fromhex(encrypted_aes_data_hex)

    # Load encrypted AES key
    with open(get_absolute_path('encryption/encrypted_aes_key.bin'), 'rb') as key_file:
        encrypted_aes_key = key_file.read()

    # Decrypt AES key
    aes_key = decrypt_aes_key(rsa_private_key, encrypted_aes_key)

    # Decrypt data
    decrypted_data = decrypt_data(aes_key, encrypted_aes_data)

    # Display decrypted data
    print("Decrypted data:", decrypted_data.decode('utf-8'))

if __name__ == "__main__":
    main()
