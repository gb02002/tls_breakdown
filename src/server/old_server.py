import json
import random
import socket
from base64 import b64decode, b64encode

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519, ec

import src.crypto_utils.connection as connection_utils
from src.crypto_utils.connection import SERVER_SIGNING_PRIVKEY
from src.crypto_utils.keys import generate_key_pair, derive_shared_secret, derive_master_secret, split_traffic_keys, \
    calculate_transcript_hash, AEAD_decrypt, HMAC, parse_finished, encode_finished, AEAD_encrypt
from src.crypto_utils.logging_module import instantiate_logger
from src.crypto_utils.messaging import decrypt_message, encrypt_message, deserialize_encrypted, serialize_encrypted, \
    hkdf_extract, hkdf_expand

logger = instantiate_logger("server")

def create_server(port: int, host: str) -> socket.socket:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    for i in range(10):
        try:
            server.bind((host, port+i))
            logger.outside(f"Server is up, port: {port}")
            break
        except OSError:
            pass
    else:
        raise OSError("Chose different port range")
    server.listen()
    return server

def process_ClientHello(request_bytes: bytes):
    payload = json.loads(request_bytes.decode())
    supported_groups = payload["supported_groups"]
    client_keys = payload["key_share"]
    client_random_str = payload["random"]
    client_random_bytes = b64decode(client_random_str)

    chosen_group = random.choice(supported_groups)

    for group, pub_b64 in client_keys:
        if group == chosen_group:
            client_pub_bytes = b64decode(pub_b64)
            break
    else:
        raise Exception("No matching client public key for chosen group")

    if chosen_group == "secp256r1":
        client_pub_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), client_pub_bytes)
    elif chosen_group == "X25519":
        client_pub_key = x25519.X25519PublicKey.from_public_bytes(client_pub_bytes)
    else:
        raise Exception("no client_pub_key")

    server_priv, server_pub = generate_key_pair(chosen_group)
    server_pub_bytes = server_pub.public_bytes(
        encoding=serialization.Encoding.X962 if chosen_group == "secp256r1" else serialization.Encoding.Raw,
        format=serialization.PublicFormat.UncompressedPoint if chosen_group == "secp256r1" else serialization.PublicFormat.Raw
    )

    server_random_bytes = random.randbytes(32)
    message_to_sign = server_pub_bytes + client_random_bytes + server_random_bytes
    signature = SERVER_SIGNING_PRIVKEY.sign(message_to_sign)

    # Также можешь отдать клиенту `public_encryption_bytes`
    # pub_signature_key = SERVER_SIGNING_PRIVKEY.public_key()
    # # public_encryption_bytes = pub_signature_key.public_bytes(
    # #     encoding=serialization.Encoding.Raw,
    # #     format=serialization.PublicFormat.Raw
    # # )

    # ServerHello payload
    server_hello = {
        "selected_group": chosen_group,
        "server_key_share": b64encode(server_pub_bytes).decode(),
        "random": b64encode(server_random_bytes).decode(),
        "signature": b64encode(signature).decode()
    }

    shared_secret = derive_shared_secret(server_priv, client_pub_key, chosen_group)
    return server_hello, shared_secret, server_random_bytes, client_random_bytes

def server_main():
    server = create_server(
        port=connection_utils.SERVER_PORT, host=connection_utils.SERVER_HOST
    )

    while True:
        client = None
        try:
            client, addr = server.accept()
            logger.inside(f"[+] Accepted connection from {addr[0]}:{addr[1]}")

            client_hello_raw = client.recv(4096)
            response, shared_sec, server_random, client_random = process_ClientHello(client_hello_raw)
            response_raw = json.dumps(response).encode()
            logger.inside(f"Calculated response: {response}")
            logger.inside(f"Calculated shared_key: {shared_sec}")

            logger.inside("ServerHello: %s", response)
            logger.outside("ServerHello raw: %s", response_raw)

            client.send(response_raw)

            # Master secret
            salt_zero = b'\x00' * 32
            early_secret = hkdf_extract(salt_zero, b"")
            handshake_secret = hkdf_extract(early_secret, shared_sec)

            # Transcript hash
            transcript_hash = calculate_transcript_hash(client_hello_raw, response_raw)

            # client_handshake_traffic_secret
            client_hs_secret = hkdf_expand(handshake_secret, b"c hs traffic" + transcript_hash)
            client_write_key = hkdf_expand(client_hs_secret, b"key", 16)
            client_write_iv = hkdf_expand(client_hs_secret, b"iv", 12)

            # Считаем server_hs_secret
            server_hs_secret = hkdf_expand(handshake_secret, b"s hs traffic" + transcript_hash)
            server_write_key = hkdf_expand(server_hs_secret, b"key", 16)
            server_write_iv = hkdf_expand(server_hs_secret, b"iv", 12)

            # Формируем и шифруем server Finished
            verify_data = HMAC(server_hs_secret, transcript_hash)
            finished_msg = encode_finished(verify_data)
            encrypted_finished = AEAD_encrypt(server_write_key, server_write_iv, finished_msg)
            logger.inside("Server FINISHED to send: %s", verify_data)
            client.send(encrypted_finished)
            logger.outside("Encrypted server FINISHED: %s", encrypted_finished)

            # 6. Расшифровка Finished
            encrypted_client_finished = client.recv(4096)
            finished_plain = AEAD_decrypt(client_write_key, client_write_iv, encrypted_client_finished)
            verify_expected = HMAC(client_hs_secret, transcript_hash)
            verify_received = parse_finished(finished_plain)
            assert parse_finished(verify_received) == verify_expected, "Server Finished verification failed"
            logger.inside("FINISHED is calculated successfully [+]: %s", verify_received)

            # # Создаем master secret
            # master_secret = derive_master_secret(shared_secret=shared_sec, client_random=client_random,
            #                                      server_random=server_random)
            # cwk, swk = split_traffic_keys(master_secret=master_secret)
            # logger.inside("cwk: %s, swk: %s, master: %s", cwk, swk, master_secret)

            # New master and app secrets

            master_secret = hkdf_extract(handshake_secret, b"")
            client_app_traffic_secret = hkdf_expand(master_secret, b"c ap traffic" + transcript_hash, 32)
            server_app_traffic_secret = hkdf_expand(master_secret, b"s ap traffic" + transcript_hash, 32)

            # --- Получаем ключи и IV ---
            client_app_key = hkdf_expand(client_app_traffic_secret, b"key", length=16)
            client_app_iv = hkdf_expand(client_app_traffic_secret, b"iv", length=12)

            server_app_key = hkdf_expand(server_app_traffic_secret, b"key", 16)
            server_app_iv = hkdf_expand(server_app_traffic_secret, b"iv", 12)

            # --- Получаем зашифрованное сообщение от клиента(application layer) ---
            req_raw = client.recv(4096)
            logger.outside("Raw request: %s", req_raw)
            plaintext = AEAD_decrypt(client_app_key, client_app_iv, req_raw)
            logger.inside("Decrypted request: %s", plaintext)
            logger.inside("Decrypted decoded request: %s", plaintext.decode())
            # decrypted = decrypt_message(ciphertext=ciphertext, key=cwk, iv=iv, tag=tag)
            # logger.inside("Client said: %s", decrypted.decode())

            # --- Отправляем зашифрованный ответ ---
            # response_cipher, response_iv, response_tag = encrypt_message(b"Hello, client!", server_app_key)
            response = AEAD_encrypt(key=server_app_key, iv=server_app_iv, plaintext=b'Hello, client!')
            # response_message_payload = serialize_encrypted(ciphertext=response_cipher, nonce=response_iv, tag=response_tag)

            # response_raw = json.dumps(response_message_payload).encode()
            client.send(response)

            # logger.inside("Response: %s", response_message_payload)
            logger.outside("Response mitm sees: %s", response)
            logger.outside(f"Sent encrypted reply")

        except Exception as e:
            logger.inside("Error:", e)
        finally:
            if client:
                client.close()


if __name__ == "__main__":
    try:
        server_main()
    except KeyboardInterrupt:
        print("Keyboard interrupt")
    finally:
        print("Server is down!")
