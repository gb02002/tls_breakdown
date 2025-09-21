import base64
import json

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from os import urandom

from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand, HKDF


def encrypt_message(plaintext: bytes, key: bytes) -> tuple[bytes, bytes, bytes]:
    iv = urandom(12)  # 96 бит — стандарт для AES-GCM
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()

    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext, iv, encryptor.tag

def decrypt_message(ciphertext: bytes, key: bytes, iv: bytes, tag: bytes) -> bytes:
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()

    return decryptor.update(ciphertext) + decryptor.finalize()

def b64(x: bytes) -> str:
    return base64.b64encode(x).decode()

def b64decode_str(x: str) -> bytes:
    return base64.b64decode(x)

def deserialize_encrypted(payload: str) -> tuple[bytes, bytes, bytes]:
    data = json.loads(payload)
    return (
        b64decode_str(data["ciphertext"]),
        b64decode_str(data["nonce"]),
        b64decode_str(data["tag"]),
    )

def serialize_encrypted(ciphertext: bytes, nonce: bytes, tag: bytes) -> str:
    return json.dumps({
        "ciphertext": b64(ciphertext),
        "nonce": b64(nonce),
        "tag": b64(tag),
    })


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=None,
        backend=default_backend()
    )
    return hkdf.derive(ikm)

def hkdf_expand(prk: bytes, info: bytes, length: int = 32) -> bytes:
    hkdf = HKDFExpand(
        algorithm=hashes.SHA256(),
        length=length,
        info=info,
        backend=default_backend()
    )
    return hkdf.derive(prk)