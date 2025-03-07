from quart import Quart, request, jsonify
import os
from dotenv import load_dotenv
from concurrent.futures import ThreadPoolExecutor
import asyncio
from quart_cors import cors
from multiprocessing import cpu_count
from encryption.encrypt_data import (
    encrypt_data, generate_aes_key, encrypt_aes_key,
    generate_random_characters, mix_with_intervals,
    load_rsa_public_key, encrypt_intervals, shuffle_data_based_on_intervals, generate_insertion_intervals
)
from encryption.decrypt_data import (
    load_rsa_private_key, decrypt_aes_key, decrypt_data,
    extract_aes_data, decrypt_intervals, reverse_shuffle
)

load_dotenv()
app = Quart(__name__)
allowed_origins = os.getenv("ALLOWED_ORIGINS", "").split(",")
app = cors(app, allow_origin=allowed_origins)
executor = ThreadPoolExecutor(max_workers=min(cpu_count(), 8))

async def run_in_executor(func, *args):
    try:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(executor, func, *args)
    except Exception as e:
        print(f"Error in executor: {e}")
        raise

@app.before_serving
async def startup():
    print("Application is starting up...")

@app.after_serving
async def shutdown():
    print("Shutting down executor...")
    executor.shutdown(wait=False)

@app.route('/wakeup', methods=['GET'])
def wakeup():
    return jsonify({"status": "ok"})

@app.route('/encrypt', methods=['POST'])
async def encrypt_route():
    data = (await request.get_json()).get('data', '')
    if not data or not isinstance(data, str):
        return jsonify({"error": "Invalid data format"}), 400
    else:
        data = data.encode() 
    public_key_path = '/etc/secrets/rsa_public_key.pem'
    rsa_public_key = load_rsa_public_key(public_key_path)

    aes_key = await run_in_executor(generate_aes_key)
    encrypted_data = await run_in_executor(encrypt_data, aes_key, data)
    encrypted_aes_key = await run_in_executor(encrypt_aes_key, rsa_public_key, aes_key)
    
    intervals = await run_in_executor(generate_insertion_intervals, len(encrypted_data.hex()))
    encrypted_intervals = await run_in_executor(encrypt_intervals, rsa_public_key, intervals)
    random_chars = await run_in_executor(generate_random_characters, len(encrypted_data))
    mixed_data = await run_in_executor(mix_with_intervals, encrypted_data.hex(), random_chars, intervals)
    shuffled_mixed_data = await run_in_executor(shuffle_data_based_on_intervals, mixed_data, intervals)
    
    final_message = encrypted_intervals.hex() + shuffled_mixed_data

    return jsonify({
        "encrypted_aes_key": encrypted_aes_key.hex(),
        "final_data": final_message
    })

@app.route('/decrypt', methods=['POST'])
async def decrypt_route():
    private_key_path = '/etc/secrets/rsa_private_key.pem'
    rsa_private_key = load_rsa_private_key(private_key_path)

    request_data = await request.get_json()
    shuffled_mixed_data = request_data.get('encrypted_data', '')
    encrypted_aes_key = bytes.fromhex(request_data.get('encrypted_aes_key', ''))

    encrypted_intervals = shuffled_mixed_data[:512]
    shuffled_mixed_data = shuffled_mixed_data[512:]

    intervals = await run_in_executor(decrypt_intervals, rsa_private_key, encrypted_intervals)
    deshuffled_mixed_data = await run_in_executor(reverse_shuffle, shuffled_mixed_data, intervals)
    encrypted_aes_data_hex = await run_in_executor(extract_aes_data, deshuffled_mixed_data, intervals)
    encrypted_aes_data = bytes.fromhex(encrypted_aes_data_hex)
    aes_key = await run_in_executor(decrypt_aes_key, rsa_private_key, encrypted_aes_key)
    decrypted_data = await run_in_executor(decrypt_data, aes_key, encrypted_aes_data)
    
    return jsonify({
        "decrypted_data": decrypted_data.decode('utf-8')
    })

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, port=5000)
