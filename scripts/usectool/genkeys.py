#!/usr/bin/env python3

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from usectool.defines import *
import os
import struct
import click

def load_private_key_from_file(private_key_file, password=None):
    """
    Load private key from PEM file
    """
    with open(private_key_file, 'rb') as f:
        private_key_data = f.read()

    if password:
        private_key = serialization.load_pem_private_key(
            private_key_data,
            password=password.encode()
        )
    else:
        private_key = serialization.load_pem_private_key(
            private_key_data,
            password=None
        )

    return private_key

def generate_ed25519_keypair(
    private_key_file="private_key.pem",
    public_key_file="public_key.pem",
    password=None
):
    """
    Generate Ed25519 keypair and save to files
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
    with open(private_key_file, 'wb') as f:
        f.write(private_pem)
    with open(public_key_file, 'wb') as f:
        f.write(public_pem)

    return private_key, public_key

def create_signed_public_key(
    private_rootkey,
    public_key,
    output_file="signed_pkey.bin"
):
    """
    Create signed public key binary file
    """
    # Get raw bytes of the public key
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    # Sign the public key message using the rootkey
    signature = private_rootkey.sign(public_bytes)

    # Create a struct for the signed pubkey
    sigtlv_fmt = '> B B I 64s'
    sigtlv_fmt_size = struct.calcsize(sigtlv_fmt)
    pkey_sigtlv = struct.pack(
        sigtlv_fmt,
        USECBOOT_SIGN_TAG,
        sigtlv_fmt_size,
        len(public_bytes),
        bytes(signature)
    )

    pkeytlv_fmt = f'> B B 32s {sigtlv_fmt_size}s'
    pkeytlv_fmt_size = struct.calcsize(pkeytlv_fmt)
    pkeytlv = struct.pack(
        pkeytlv_fmt,
        USECBOOT_PKEY_TAG,
        pkeytlv_fmt_size,
        public_bytes,
        pkey_sigtlv
    )

    with open(output_file, 'wb') as f:
        f.write(pkeytlv)

    return output_file

@click.command()
@click.argument('filename')
@click.option('--root-key', '-r', help='Path to existing root private key file for signing')
@click.option('--root-key-password', '-p', help='Password for root private key')
@click.option('--password', '-w', help='Password for new private key encryption')
@click.option('--output-dir', '-o', default='.', help='Output directory for generated files')
@click.option('--signed-output', '-s', default='signed_pkey.bin', help='Output filename for signed public key')
def main(filename, root_key, root_key_password, password, output_dir, signed_output):
    """
    Generate Ed25519 keypair. If --root-key is specified, sign the new public key with the provided root key.
    """
    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)

    # Generate regular keypair
    private_key_file = os.path.join(output_dir, f"{filename}_private.pem")
    public_key_file = os.path.join(output_dir, f"{filename}_public.pem")

    click.echo(f"Generating keypair: {filename}")
    private_key, public_key = generate_ed25519_keypair(
        private_key_file=private_key_file,
        public_key_file=public_key_file,
        password=password
    )

    click.echo(f"✓ Private key saved to: {private_key_file}")
    click.echo(f"✓ Public key saved to: {public_key_file}")

    if root_key:
        # Load existing root private key
        if not os.path.exists(root_key):
            click.echo(f"❌ Error: Root key file not found: {root_key}")
            return 1

        click.echo(f"Loading root key from: {root_key}")
        try:
            private_rootkey = load_private_key_from_file(
                private_key_file=root_key,
                password=root_key_password
            )
            click.echo("✓ Root key loaded successfully")
        except Exception as e:
            click.echo(f"❌ Error loading root key: {e}")
            return 1

        # Create signed public key
        signed_pkey_file = os.path.join(output_dir, signed_output)
        signed_file = create_signed_public_key(
            private_rootkey=private_rootkey,
            public_key=public_key,
            output_file=signed_pkey_file
        )

        click.echo(f"✓ Signed public key saved to: {signed_file}")
        click.echo("✓ Key generation completed with signed public key")
    else:
        click.echo("✓ Key generation completed")

if __name__ == '__main__':
    main()