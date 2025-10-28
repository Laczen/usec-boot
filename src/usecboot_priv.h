/*
 * Copyright (c) 2024 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * usec-boot provides routines to build a simple secure bootloader,
 * this header provides the private interface and structures.
 */

#ifndef INCLUDE_USECBOOT_PRIV_H_
#define INCLUDE_USECBOOT_PRIV_H_

#if defined(STRUCT_PACKED)
#undef STRUCT_PACKED
#endif

#define STRUCT_PACKED struct __attribute__((__packed__))

/* TAGS 0x10..0x1f are reserved for signatures */
#define USECBOOT_SIGN_TAG_ED25519	0x10

/* The signature tag defines the used pubkey and hashes to keep the
 * bootloader size small. There is no need to support multiple tags
 * for the stored hashes and pubkeys. Let us defined the used tags
 */
#define USECBOOT_MAGIC_TAG	0x00
#define USECBOOT_END_TAG	0xFF
#define USECBOOT_MAGIC		0x55534543 /* USEC */
#define USECBOOT_SIGN_TAG	USECBOOT_SIGN_TAG_ED25519
#define USECBOOT_PKEY_TAG	0x20
#define USECBOOT_HASH_TAG	0x21

#if USECBOOT_SIGN_TAG == USECBOOT_SIGN_TAG_ED25519
#define USECBOOT_HASH_SIZE 64
#define USECBOOT_PKEY_SIZE 32
#define USECBOOT_SIGN_SIZE 64
#endif

#include <stdint.h>

STRUCT_PACKED usecboot_tlv_hdr {
	uint8_t tag;
	uint8_t len;
};

STRUCT_PACKED usecboot_magic_tlv {
	struct usecboot_tlv_hdr hdr;
	uint32_t magic;
};

STRUCT_PACKED usecboot_hash_tlv {
	struct usecboot_tlv_hdr hdr;
	uint32_t offset;
	uint32_t msg_size;
	uint8_t hash[USECBOOT_HASH_SIZE];
};

/* The message that is signed is prepending the signature tlv, the message
 * length is determined by msg_size.
 */
STRUCT_PACKED usecboot_signature_tlv {
	struct usecboot_tlv_hdr hdr;
	uint32_t msg_size;
	uint8_t signature[USECBOOT_SIGN_SIZE];
};

STRUCT_PACKED usecboot_pubkey_tlv {
	struct usecboot_tlv_hdr hdr;
	uint8_t pubkey[USECBOOT_PKEY_SIZE];
	struct usecboot_signature_tlv signature;
};

#ifdef CONFIG_USECBOOT_LOG
#define USECBOOT_LOG(arg) usecboot_log(arg)
#else
#define USECBOOT_LOG(arg) ((void)0)
#endif

#endif /* INCLUDE_USECBOOT_PRIV_H_ */