#!/usr/bin/env python3
"""
Example user script for adding custom TLVs to the firmware header
"""

import struct

def add_custom_tlvs(header_data):
    """
    Add custom TLVs to the header before signing

    Args:
        header_data: Current header data as bytes

    Returns:
        Updated header data with custom TLVs appended
    """

    # Example: Add a version TLV
    version_major = 1
    version_minor = 2
    version_patch = 3
    version_fmt = '< B B B B H'  # tag, length, major, minor, patch
    version_tlv = struct.pack(
        version_fmt,
        0x01,  # Custom tag for version
        struct.calcsize(version_fmt),
        version_major,
        version_minor,
        version_patch
    )

    # Append custom TLVs to header
    header_data += version_tlv

    return header_data