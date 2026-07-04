'''
import oqs

print("liboqs imported successfully!")

print("\nAvailable KEMs:")
print(
    oqs.get_enabled_kem_mechanisms()
)

print("\nAvailable Signatures:")
print(
    oqs.get_enabled_sig_mechanisms()
)'''

import oqs

print("="*60)
print("        ML-KEM-512 TEST")
print("="*60)

with oqs.KeyEncapsulation("ML-KEM-512") as server:

    public_key = server.generate_keypair()

    print("\nPublic Key Generated")
    print("Length :", len(public_key), "bytes")

    with oqs.KeyEncapsulation("ML-KEM-512") as client:

        ciphertext, client_secret = client.encap_secret(public_key)

        print("\nEncapsulation Successful")
        print("Ciphertext :", len(ciphertext), "bytes")

    server_secret = server.decap_secret(ciphertext)

    print("\nDecapsulation Successful")

    if client_secret == server_secret:
        print("\nShared Secret Match")
        print("SUCCESS")
    else:
        print("FAILED")


print("\n")
print("="*60)
print("        ML-DSA-65 TEST")
print("="*60)

message = b"Post Quantum IoT IDS"

with oqs.Signature("ML-DSA-65") as signer:

    public_key = signer.generate_keypair()

    signature = signer.sign(message)

    print("\nSignature Generated")
    print("Signature Size :", len(signature), "bytes")

    with oqs.Signature("ML-DSA-65") as verifier:

        if verifier.verify(message, signature, public_key):
            print("\nSignature Verified")
            print("SUCCESS")
        else:
            print("FAILED")