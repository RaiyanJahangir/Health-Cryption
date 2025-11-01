import os
from typing import Optional
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from nacl.public import PrivateKey as X25519PrivateKey, PublicKey as X25519PublicKey, SealedBox

# ----- symmetric (AES-GCM) -----
def scrypt_kdf(passphrase: str, salt: bytes, length: int = 32) -> bytes:
    kdf = Scrypt(salt=salt, length=length, n=2**14, r=8, p=1)
    return kdf.derive(passphrase.encode("utf-8"))

def aesgcm_encrypt(key: bytes, plaintext: bytes, aad: Optional[bytes] = None):
    aes = AESGCM(key)
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, plaintext, aad)
    return nonce, ct

def aesgcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: Optional[bytes] = None) -> bytes:
    aes = AESGCM(key)
    return aes.decrypt(nonce, ciphertext, aad)

def random_key32() -> bytes:
    return os.urandom(32)

# ----- asymmetric (X25519 sealed boxes) -----
def x25519_generate():
    priv = X25519PrivateKey.generate()
    pub = priv.public_key
    return priv, pub

def sealed_box_encrypt(pubkey_bytes: bytes, data: bytes) -> bytes:
    box = SealedBox(X25519PublicKey(pubkey_bytes))
    return box.encrypt(data)

def sealed_box_decrypt(privkey: X25519PrivateKey, sealed: bytes) -> bytes:
    box = SealedBox(privkey)
    return box.decrypt(sealed)

# Protect a doctor's private key with their password (scrypt -> AES-GCM)
def protect_privkey_with_password(priv: X25519PrivateKey, password: str):
    raw = bytes(priv)  # 32 bytes
    salt = os.urandom(16)
    k = scrypt_kdf(password, salt, 32)
    nonce, ct = aesgcm_encrypt(k, raw)
    return salt, nonce, ct

def unprotect_privkey_with_password(enc_priv: bytes, nonce: bytes, salt: bytes, password: str) -> X25519PrivateKey:
    k = scrypt_kdf(password, salt, 32)
    raw = aesgcm_decrypt(k, nonce, enc_priv)
    return X25519PrivateKey(raw)
