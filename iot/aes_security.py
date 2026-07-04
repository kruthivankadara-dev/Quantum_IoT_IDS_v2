import os
import json

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


AES_KEY = b"0123456789abcdef0123456789abcdef"


def encrypt_packet(packet):

    packet_json = json.dumps(
        packet
    ).encode()

    aes = AESGCM(
        AES_KEY
    )

    nonce = os.urandom(
        12
    )

    ciphertext = aes.encrypt(
        nonce,
        packet_json,
        None
    )

    return {

        "ciphertext":
        ciphertext.hex(),

        "nonce":
        nonce.hex()
    }


def decrypt_packet(
    ciphertext_hex,
    nonce_hex
):

    aes = AESGCM(
        AES_KEY
    )

    ciphertext = bytes.fromhex(
        ciphertext_hex
    )

    nonce = bytes.fromhex(
        nonce_hex
    )

    plaintext = aes.decrypt(
        nonce,
        ciphertext,
        None
    )

    return json.loads(
        plaintext.decode()
    )