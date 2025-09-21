from dataclasses import dataclass
from abc import ABC, abstractmethod

@dataclass
class TrafficKeys:
    """Encapsulates symmetric keys and state for encryption/decryption"""

    key: bytes
    iv: bytes
    seq: int = 0

    def next_nonce(self) -> bytes:
        nonce_int = int.from_bytes(self.iv, "big") ^ self.seq
        self.seq += 1
        return nonce_int.to_bytes(len(self.iv), "big")

@dataclass
class KeySchedule:
    """Responsible for HKDF logic and generation of all keys. Separates handshake and app-level"""

    early_secret: bytes
    handshake_secret: bytes
    master_secret: bytes
    handshake_keys: TrafficKeys
    app_keys: TrafficKeys

    @abstractmethod
    def derive_handshake_keys(self): ...

    @abstractmethod
    def derive_master_secret(self): ...

    @abstractmethod
    def derive_application_keys(self): ...

@dataclass
class HandshakeState(ABC):
    """Holds connection state"""
    random: bytes
    key_share: bytes
    shared_secret: bytes
    transcript_hash: bytes

class AEADContext(ABC):
    """AEAD operations, nonce rotation"""

    @abstractmethod
    def encrypt(self, plaintext: bytes) -> bytes: ...
    @abstractmethod
    def decrypt(self, ciphertext: bytes) -> bytes: ...