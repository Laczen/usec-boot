#!/usr/bin/env python3

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from pathlib import Path
import click
import textwrap

def pem_pubkey_to_hex(pem_file_path):
    # Load public key from PEM file
    with open(pem_file_path, 'rb') as f:
        public_key = serialization.load_pem_public_key(f.read())

    # Extract raw bytes (32 bytes for Ed25519)
    raw_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    return raw_bytes

def bytes_to_hexstring(byte_data):
    hex_str = ''.join(f"\\x{b:02x}" for b in byte_data)
    lines = textwrap.wrap(hex_str, width=76, break_long_words=True, break_on_hyphens=False)
    return '\t"' + '" \\\n\t"'.join(lines) + '"'

@click.command()
@click.argument('pem_file', type=click.Path(exists=True, file_okay=True, dir_okay=False))
@click.option('--output', '-o', default='root_pkey.h', help='Output header file name')
@click.option('--define-name', '-d', default='USECBOOT_ROOTPKEY', help='C preprocessor define name')
def main(pem_file, output, define_name):
    """
    Convert a PEM public key file to a C header file with hex representation.

    PEM_FILE: Path to the PEM format public key file
    """
    try:
        hex_key = bytes_to_hexstring(pem_pubkey_to_hex(pem_file))

        with open(output, 'w') as f:
            f.write('/*\n * Automatically generated - do not change\n */\n')
            f.write(f'#ifndef {define_name}_H_\n')
            f.write(f'#define {define_name}_H_\n\n')
            f.write(f'#define {define_name} \\\n')
            f.write(hex_key)
            f.write('\n\n')
            f.write(f'#endif /* {define_name}_H_ */\n')

        click.echo(f"✓ Header file generated: {output}")

    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)

if __name__ == '__main__':
    main()