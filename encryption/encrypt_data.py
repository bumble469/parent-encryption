import os
import random
import string
import math
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

BASE_DIR = os.getcwd()

def get_absolute_path(relative_path):
    """Get the absolute path for a given relative path."""
    return os.path.join(BASE_DIR, relative_path)

def load_rsa_public_key(pem_file):
    """Load an RSA public key from a PEM file."""
    try:
        with open(get_absolute_path(pem_file), 'rb') as key_file:
            public_key_pem = key_file.read()
            public_key = serialization.load_pem_public_key(public_key_pem)
        return public_key
    except FileNotFoundError:
        raise FileNotFoundError(f"Public key file not found at {get_absolute_path(pem_file)}")

def generate_aes_key():
    """Generate a random AES key."""
    return os.urandom(32)

def encrypt_aes_key(rsa_public_key, aes_key):
    """Encrypt the AES key using the RSA public key."""
    return rsa_public_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def encrypt_data(aes_key, data):
    """Encrypt data using AES encryption."""
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    if isinstance(data, str):
        data = data.encode('utf-8')
    encrypted_data = encryptor.update(data) + encryptor.finalize()
    return iv + encrypted_data

def generate_random_characters(length):
    """Generate a string of random characters."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def generate_insertion_intervals(data_length):
    """Generate random insertion intervals for mixing data."""
    intervals = []
    interval_position = random.randint(3, 56)
    if interval_position < data_length:
        intervals.append(interval_position)
    else:
        intervals.append(data_length - 1)
    return set(intervals)

def mix_with_intervals(encrypted_aes, random_chars, intervals):
    """Mix random characters with encrypted data based on intervals."""
    result = []
    random_char_index = 0
    encrypted_index = 0

    for i in range(len(encrypted_aes) + len(random_chars)):
        if encrypted_index < len(encrypted_aes) and i in intervals:
            if random_char_index < len(random_chars):
                result.append(random_chars[random_char_index])
                random_char_index += 1
        elif encrypted_index < len(encrypted_aes):
            result.append(encrypted_aes[encrypted_index])
            encrypted_index += 1

    return ''.join(result)

def shuffle_data_based_on_intervals(mixed_data, intervals):
    """Shuffle the mixed data based on intervals."""
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
    mixed_data_list = list(mixed_data)
    for i in range(len(mixed_data_list)):
        new_index = (i + shuffle_value) % len(mixed_data_list)
        mixed_data_list[i], mixed_data_list[new_index] = mixed_data_list[new_index], mixed_data_list[i]
    
    shuffled_data = ''.join(mixed_data_list)
    return shuffled_data

def encrypt_intervals(rsa_public_key, intervals):
    """Encrypt intervals using the RSA public key."""
    interval_string = ','.join(map(str, intervals)).encode('utf-8')
    return rsa_public_key.encrypt(
        interval_string,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def encrypt_message(message, public_key_path=os.getenv('RSA_PUBLIC_KEY')):
    """Encrypt a message with multiple layers of security."""
    rsa_public_key = load_rsa_public_key(public_key_path)
    aes_key = generate_aes_key()
    encrypted_aes_key = encrypt_aes_key(rsa_public_key, aes_key)
    encrypted_aes_data = encrypt_data(aes_key, message)
    encrypted_aes_data_hex = encrypted_aes_data.hex()

    num_insertions = random.randint(math.ceil(len(encrypted_aes_data_hex) * 0.04), math.ceil(len(encrypted_aes_data_hex) * 0.1))
    random_chars = generate_random_characters(num_insertions)

    intervals = generate_insertion_intervals(len(encrypted_aes_data_hex))

    mixed_data = mix_with_intervals(encrypted_aes_data_hex, random_chars, intervals)

    shuffled_mixed_data = shuffle_data_based_on_intervals(mixed_data, intervals)

    encrypted_intervals = encrypt_intervals(rsa_public_key, intervals)

    # Ensure encryption directory exists
    os.makedirs(get_absolute_path('encryption'), exist_ok=True)

    with open(get_absolute_path('encryption/encrypted_aes_key.bin'), 'wb') as key_file:
        key_file.write(encrypted_aes_key)
    with open(get_absolute_path('encryption/mixed_encrypted_data.txt'), 'w') as data_file:
        data_file.write(shuffled_mixed_data)

    return ({
        "encrypted_aes_data": encrypted_aes_data_hex,
        "random_chars": random_chars,
        "intervals": intervals,
        "mixed_data": mixed_data,
        "shuffled_mixed_data": shuffled_mixed_data,
        "encrypted_intervals": encrypted_intervals.hex(),
        "final_message": shuffled_mixed_data,
        "encrypted_aes_key": encrypted_aes_key.hex()
    })
