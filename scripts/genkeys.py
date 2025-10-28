#!/usr/bin/env python3

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
import os
import struct

def generate_ed25519_keypair(save_to_files=True, private_key_file="private_key.pem",
                           public_key_file="public_key.pem", password=None):
    """
    Generate Ed25519 keypair and optionally save to files
    """
    # Generate keys
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    # Serialize private key
    if password:
        encryption = serialization.BestAvailableEncryption(password.encode())
    else:
        encryption = serialization.NoEncryption()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption
    )

    # Serialize public key
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Save to files
    if save_to_files:
        with open(private_key_file, 'wb') as f:
            f.write(private_pem)
        with open(public_key_file, 'wb') as f:
            f.write(public_pem)
        print(f"Keys saved to {private_key_file} and {public_key_file}")

    return private_key, public_key

# Generate without password
private_rootkey, public_rootkey = generate_ed25519_keypair(private_key_file="private_rootkey.pem",
                                                   public_key_file="public_rootkey.pem")
private_key, public_key = generate_ed25519_keypair(private_key_file="private_key.pem",
                                                   public_key_file="public_key.pem")

# Get raw bytes of the public key
public_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)

# Sign the public key message using the rootkey

signature = private_rootkey.sign(public_bytes)

# Create a struct for the signed pubkey

USECBOOT_SIGN_TAG_ED25519 =	0x10
USECBOOT_PKEY_TAG = 0x20
USECBOOT_SIGN_TAG = USECBOOT_SIGN_TAG_ED25519
sigtlv_fmt = '< B B I 64s'
sigtlv_fmt_size = struct.calcsize(sigtlv_fmt)
pkey_sigtlv = struct.pack(sigtlv_fmt,
    USECBOOT_SIGN_TAG,
    sigtlv_fmt_size,
    len(public_bytes),
    bytes(signature)
    )

pkeytlv_fmt = f'< B B 32s {sigtlv_fmt_size}s'
pkeytlv_fmt_size = struct.calcsize(pkeytlv_fmt)
pkeytlv = struct.pack(pkeytlv_fmt,
    USECBOOT_PKEY_TAG,
    pkeytlv_fmt_size,
    public_bytes,
    pkey_sigtlv)

with open("signedpkey.bin", 'wb') as f:
    f.write(pkeytlv)

print("Created signed pubkey data")