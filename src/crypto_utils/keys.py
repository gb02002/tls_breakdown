from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from hashlib import sha256

### THIS IS JUST A MESS. Half of funcs are not used

def generate_key_pair(group_name: str):
    if group_name == "secp256r1":
        priv = ec.generate_private_key(ec.SECP256R1())
        pub = priv.public_key()
    elif group_name == "X25519":
        priv = x25519.X25519PrivateKey.generate()
        pub = priv.public_key()
    else:
        raise ValueError(f"Unsupported group: {group_name}")
    return priv, pub


def derive_shared_secret(priv_key, pub_key, group):
    if group == "X25519":
        return priv_key.exchange(pub_key)
    elif group == "secp256r1":
        return priv_key.exchange(ec.ECDH(), pub_key)
    else:
        raise ValueError(f"Unsupported group for key exchange: {group}")

def derive_master_secret(shared_secret: bytes, client_random: bytes, server_random: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=client_random + server_random,
        info=b'tls13 handshake key expansion',
    )
    return hkdf.derive(shared_secret)

def split_traffic_keys(master_secret: bytes) -> tuple[bytes, bytes]:
    client_write_key = HKDF(
        algorithm=hashes.SHA256(),
        length=16,
        salt=None,
        info=b'client write key'
    ).derive(master_secret)

    server_write_key = HKDF(
        algorithm=hashes.SHA256(),
        length=16,
        salt=None,
        info=b'server write key'
    ).derive(master_secret)

    return client_write_key, server_write_key

def calculate_transcript_hash(*messages: bytes) -> bytes:
    hasher = sha256()
    for msg in messages:
        hasher.update(msg)
    return hasher.digest()

def AEAD_decrypt(key: bytes, iv: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(iv, ciphertext, aad)  # assumes tag is appended at the end

def HMAC(secret: bytes, data: bytes) -> bytes:
    h = hmac.HMAC(secret, hashes.SHA256())
    h.update(data)
    return h.finalize()

def parse_finished(msg: bytes) -> bytes:
    """
    Expects Finished message to be exactly the raw verify_data.
    """
    return msg

def encode_finished(verify_data: bytes) -> bytes:
    return verify_data

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def AEAD_encrypt(key: bytes, iv: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.encrypt(iv, plaintext, aad)
