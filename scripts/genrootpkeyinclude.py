#!/usr/bin/env python3

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from pathlib import Path
import sys
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

filename = sys.argv[1]
filepath = Path(sys.argv[1])

if filepath.is_file():
    hex_key = bytes_to_hexstring(pem_pubkey_to_hex(filename))

    with open('root_pkey.h', 'w') as f:
        f.write('/*\n * Automatically generated - do not change\n */\n')
        f.write('#ifndef USECBOOT_ROOTPKEY_H_\n#define USECBOOT_ROOTPKEY_H_\n')
        f.write('#define USECBOOT_ROOTPKEY \\\n')
        f.write(hex_key)
        f.write('\n')
        f.write('#endif /* USECBOOT_ROOTPKEY_H_ */\n')
else :
    print("ERROR: {filename} does not exist")