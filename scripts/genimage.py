#!/usr/bin/env python3

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
import struct

def load_private_key(filename, password=None):
    with open(filename, 'rb') as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=password.encode() if password else None
        )
    return private_key

def sha512_hash(data):
    digest = hashes.Hash(hashes.SHA512())
    digest.update(data)
    return digest.finalize()

hdrsize = 512
USECBOOT_SIGN_TAG_ED25519 =	0x10
USECBOOT_MAGIC_TAG =	0x00
USECBOOT_END_TAG = 0xFF
USECBOOT_MAGIC = 0x55534543
USECBOOT_SIGN_TAG = USECBOOT_SIGN_TAG_ED25519
USECBOOT_HASH_TAG =	0x21

def gen_firmware():
    private_key = load_private_key('private_key.pem')

    with open('image1.bin','rb') as f:
        firmware = f.read()

    ihash = sha512_hash(firmware[hdrsize:])
    hashtlv_fmt = '< B B I I 64s'
    hashtlv_size = struct.calcsize(hashtlv_fmt)
    hashtlv = struct.pack(hashtlv_fmt,
        USECBOOT_HASH_TAG,
        hashtlv_size,
        hdrsize,
        len(firmware) - hdrsize,
        ihash)

    hdr = hashtlv
    with open('signedpkey.bin','rb') as f:
        signedpkey = f.read()

    hdr += signedpkey
    signature = private_key.sign(hdr)
    sigtlv_fmt = '< B B I 64s'
    sigtlv_fmt_size = struct.calcsize(sigtlv_fmt)
    sigtlv = struct.pack(sigtlv_fmt,
        USECBOOT_SIGN_TAG,
        sigtlv_fmt_size,
        len(hdr),
        bytes(signature)
    )

    hdr += sigtlv
    data = bytearray(firmware)
    data[0:len(hdr)] = hdr
    with open('signed_image.bin', 'wb') as f:
        f.write(data)

gen_firmware()
