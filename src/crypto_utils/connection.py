from base64 import b64decode

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey, Ed25519PrivateKey

SERVER_PORT = 60002
SERVER_HOST = "localhost"

CLIENT_PORT = 12344
CLIENT_HOST = "localhost"

SERVER_SIGNING_PRIVKEY_B64 = "TDh79HPF23ELYBOV5dwDb8MhUQUzycMjaugQBdKqUyU="
SERVER_SIGNING_PRIVKEY = Ed25519PrivateKey.from_private_bytes(
    b64decode(SERVER_SIGNING_PRIVKEY_B64)
)

SERVER_SIGNING_PUBKEY_B64 = "A9WXZpxsU/5+Cm2cxKCMPLcElaQrjdwCPPKfUkBzFmM="
SERVER_SIGNING_PUBKEY = Ed25519PublicKey.from_public_bytes(
    b64decode(SERVER_SIGNING_PUBKEY_B64)
)