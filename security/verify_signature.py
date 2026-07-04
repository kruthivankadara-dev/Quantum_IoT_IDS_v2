import oqs

def verify_packet(
    encrypted_packet,
    signature,
    public_key
):

    verifier = oqs.Signature(
        "ML-DSA-65"
    )

    return verifier.verify(
        encrypted_packet,
        signature,
        public_key
    )