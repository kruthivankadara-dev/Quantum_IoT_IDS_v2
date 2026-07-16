import os
import json

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.primitives.hmac import HMAC


def derive_session_key(
    shared_secret: bytes,
    session_id: bytes
) -> bytes:
    """
    Derive a 256-bit AES session key
    from the ML-KEM shared secret.
    """

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"IoT-Edge-AES-Session" + session_id
    )

    return hkdf.derive(shared_secret)


def encrypt_packet(packet: dict,
                   session_key: bytes):

    aes = AESGCM(session_key)

    nonce = os.urandom(12)

    plaintext = json.dumps(packet).encode()

    ciphertext = aes.encrypt(
        nonce,
        plaintext,
        None
    )

    return nonce, ciphertext


def decrypt_packet(ciphertext: bytes,
                   nonce: bytes,
                   session_key: bytes):

    aes = AESGCM(session_key)

    plaintext = aes.decrypt(
        nonce,
        ciphertext,
        None
    )

    return json.loads(
        plaintext.decode()
    )

def generate_hmac(
    session_key,
    session_id,
    ciphertext
):

    h = HMAC(
        session_key,
        hashes.SHA256()
    )

    h.update(session_id.encode())
    h.update(ciphertext)

    return h.finalize()

def verify_hmac(
    session_key,
    session_id,
    ciphertext,
    received_tag
):

    h = HMAC(
        session_key,
        hashes.SHA256()
    )

    h.update(session_id.encode())
    h.update(ciphertext)

    try:
        h.verify(received_tag)
        return True
    except Exception:
        return False