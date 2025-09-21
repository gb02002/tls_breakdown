import json
import socket
from base64 import b64encode, b64decode

from random import randbytes
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePublicKey,
    SECP256R1,
    ECDH,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

import src.crypto_utils.connection as connection_utils
from src.crypto_utils.keys import (
    generate_key_pair,
    calculate_transcript_hash,
    encode_finished,
    AEAD_encrypt,
    HMAC,
    AEAD_decrypt,
    parse_finished,
)
from src.crypto_utils.logging_module import instantiate_logger
from src.crypto_utils.messaging import hkdf_extract, hkdf_expand

logger = instantiate_logger("client")


def ClientHello():
    random = randbytes(32)
    payload: dict[str, Any] = {
        "version": "1.3",
        "supported_groups": ["secp256r1", "X25519"],
        "key_share": [],
        "random": b64encode(random).decode(),
    }

    privates = {}
    for group in payload["supported_groups"]:
        priv, pub = generate_key_pair(group)
        pub_bytes = pub.public_bytes(
            encoding=serialization.Encoding.X962
            if group == "secp256r1"
            else serialization.Encoding.Raw,
            format=serialization.PublicFormat.UncompressedPoint
            if group == "secp256r1"
            else serialization.PublicFormat.Raw,
        )
        payload["key_share"].append((group, b64encode(pub_bytes).decode()))
        privates[group] = priv

    return payload, privates, random


def process_ServerHello(private_key: dict, request: dict, client_random: bytes):
    chosen_group = request["selected_group"]
    server_key_b64 = request["server_key_share"]
    server_random_str = request["random"]
    signature = b64decode(request["signature"])

    message = b64decode(server_key_b64) + client_random + b64decode(server_random_str)

    try:
        connection_utils.SERVER_SIGNING_PUBKEY.verify(signature, message)
        logger.inside("Server signature verified[+]")
    except Exception as e:
        logger.inside("Server signature failed[!]: %s", e)
        raise

    server_pub_bytes = b64decode(server_key_b64)
    server_random_bytes = b64decode(server_random_str)

    if chosen_group == "X25519":
        server_pub_key = X25519PublicKey.from_public_bytes(server_pub_bytes)
        shared_secret = private_key["X25519"].exchange(server_pub_key)

    elif chosen_group == "secp256r1":
        server_pub_key = EllipticCurvePublicKey.from_encoded_point(
            SECP256R1(), server_pub_bytes
        )
        shared_secret = private_key["secp256r1"].exchange(ECDH(), server_pub_key)

    else:
        raise ValueError(f"Unsupported group: {chosen_group}")

    return shared_secret, server_random_bytes


def create_client(port: int, host: str) -> socket.socket:
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    for i in range(10):
        try:
            client.connect((host, port))
            break
        except OSError:
            pass
    else:
        raise OSError("Not able to find our server")
    return client


def client_main():
    client = create_client(
        port=connection_utils.SERVER_PORT,
        host=connection_utils.SERVER_HOST,
    )
    logger.inside("We are connected")

    client_payload, client_keys, client_random = ClientHello()
    client_hello_to_send = json.dumps(client_payload).encode()

    logger.outside("Client_payload: %s", client_payload)
    logger.outside("Raw data to send: %s", client_hello_to_send)
    client.send(client_hello_to_send)

    server_hello_bytes = client.recv(4096)
    logger.outside("Server response: %s\n", server_hello_bytes)
    response_str = server_hello_bytes.decode()
    logger.outside("Server decoded response: %s\n", response_str)

    server_finished_enc = client.recv(4096)

    server_hello = json.loads(response_str)
    our_shared_secret, server_random = process_ServerHello(
        client_keys, server_hello, client_random
    )
    logger.inside("shared: %s, server_random: %s", our_shared_secret, server_random)

    # --- (1) Early Secret ---
    salt_zero = b"\x00" * 32
    early_secret = hkdf_extract(salt_zero, b"")  # <- no PSK

    # --- (2) Handshake Secret ---
    handshake_secret = hkdf_extract(early_secret, our_shared_secret)

    # --- (3) Transcript Hash на данный момент (ClientHello + ServerHello) ---
    transcript_hash = calculate_transcript_hash(
        client_hello_to_send, server_hello_bytes
    )

    # --- (4) Handshake traffic secrets ---
    client_hs_traffic_secret = hkdf_expand(
        handshake_secret, b"c hs traffic" + transcript_hash
    )
    server_hs_traffic_secret = hkdf_expand(
        handshake_secret, b"s hs traffic" + transcript_hash
    )

    # --- (5) Traffic keys для расшифровки Finished от сервера ---
    server_write_key = hkdf_expand(server_hs_traffic_secret, b"key", 16)
    server_write_iv = hkdf_expand(server_hs_traffic_secret, b"iv", 12)

    # --- (6) Ждём Server Finished ---
    server_finished_plain = AEAD_decrypt(
        server_write_key, server_write_iv, server_finished_enc
    )

    # Проверка Server Finished
    expected_verify_data = HMAC(server_hs_traffic_secret, transcript_hash)
    assert parse_finished(server_finished_plain) == expected_verify_data, (
        "Server Finished verification failed"
    )
    logger.inside(
        "FINISHED from server completed successfully [+]: %s", expected_verify_data
    )

    # --- (7) Traffic keys для отправки Client Finished ---
    client_write_key = hkdf_expand(client_hs_traffic_secret, b"key", 16)
    client_write_iv = hkdf_expand(client_hs_traffic_secret, b"iv", 12)

    # --- (8) Отправка Client Finished ---
    verify_data = HMAC(client_hs_traffic_secret, transcript_hash)
    finished_msg = encode_finished(verify_data)
    encrypted_finished = AEAD_encrypt(client_write_key, client_write_iv, finished_msg)
    client.send(encrypted_finished)

    # --- (9) Master secret ---
    master_secret = hkdf_extract(handshake_secret, b"")

    # --- (10) Application traffic secrets ---
    client_app_secret = hkdf_expand(master_secret, b"c ap traffic" + transcript_hash)
    server_app_secret = hkdf_expand(master_secret, b"s ap traffic" + transcript_hash)

    # --- (11) Application traffic keys ---
    client_app_key = hkdf_expand(client_app_secret, b"key", 16)
    client_app_iv = hkdf_expand(client_app_secret, b"iv", 12)
    server_app_key = hkdf_expand(server_app_secret, b"key", 16)
    server_app_iv = hkdf_expand(server_app_secret, b"iv", 12)

    # --- Шлём зашифрованное сообщение ---
    message_to_send = input("Type your message: ").encode()
    ciphertext = AEAD_encrypt(client_app_key, client_app_iv, message_to_send)
    logger.outside("Encrypted data: %s", ciphertext)
    client.send(ciphertext)

    # # --- Шлём зашифрованное сообщение ---
    # message_to_send = input("Type ur msg: ").encode()
    # cipher, iv, tag = encrypt_message(message_to_send, cwk) # Тут у нас пока испльзуется старый cwk, напрямую рассчитанный из shared->master
    # message_payload = serialize_encrypted(ciphertext=cipher, nonce=iv, tag=tag)
    # client.send(json.dumps(message_payload).encode())
    # logger.outside(f"Sent encrypted: {client_payload}")

    # --- Получаем зашифрованный ответ ---
    response = client.recv(4096)
    plaintext = AEAD_decrypt(key=server_app_key, iv=server_app_iv, ciphertext=response)
    logger.inside("Server_reply: %s", plaintext.decode())


if __name__ == "__main__":
    try:
        client_main()
    except KeyboardInterrupt:
        pass


# This is old version
#     logger.inside("shared: %s, server_random: %s", our_shared_secret, server_random)
#
#     # Тут мы создаем early-secret
#     salt_zero = b'\x00' * 32  # 0-хэш
#     early_secret = hkdf_extract(salt_zero, b"")  # если нет PSK
#
#     # Handshake secret
#     handshake_secret = hkdf_extract(early_secret, our_shared_secret)
#     transcript_hash = calculate_transcript_hash(client_hello_to_send, server_hello_bytes)
#
#     # --- Waiting for server Finished
#     server_Finished = client.recv(4096)
#
#     # --- Новый вариант hs и мастер секрктов
#     client_hs_secret = hkdf_expand(handshake_secret, b"c hs traffic" + transcript_hash)
#     server_hs_secret = hkdf_expand(handshake_secret, b"s hs traffic" + transcript_hash)
#     verify_data = HMAC(client_hs_secret, transcript_hash)
#     finished_msg = encode_finished(verify_data)
#     encrypted_finished = AEAD_encrypt(client_write_key, client_write_iv, finished_msg)
#
#     client.send(encrypted_finished)
#
#     # --- Вот тут мы уже создаем мастер-секрет ---
#     master_secret = derive_master_secret(shared_secret=our_shared_secret, client_random=client_random, server_random=server_random)
#     cwk, swk = split_traffic_keys(master_secret=master_secret)
#     logger.inside(f"cwk: {cwk}, swk: {swk}, master_key: {master_secret}")
#     master_secret = hkdf_extract(handshake_secret, b"")  # extract with empty salt again
#
#     # --- Новый вариант cwk и swk
#     client_write_key = hkdf_expand(client_hs_secret, b"key", 16)
#     client_write_iv = hkdf_expand(client_hs_secret, b"iv", 12)
#
#     # --- Шлём зашифрованное сообщение ---
#     message_to_send = input("Type ur msg: ").encode()
#     cipher, iv, tag = encrypt_message(message_to_send, cwk) # Тут у нас пока испльзуется старый cwk, напрямую рассчитанный из shared->master
