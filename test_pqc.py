import oqs

print("liboqs imported successfully!")

print("\nAvailable KEMs:")
print(
    oqs.get_enabled_kem_mechanisms()
)

print("\nAvailable Signatures:")
print(
    oqs.get_enabled_sig_mechanisms()
)