#include <stdbool.h>
#include "../ext/monocypher/monocypher-ed25519.h"
#include "usecboot.h"
#include "usecboot_priv.h"
#include "usecboot_rootpubkey.h"

#ifndef CONFIG_USECBOOT_MAX_HDRSIZE
#define CONFIG_USECBOOT_MAX_HDRSIZE 1024
#endif
#ifndef CONFIG_USECBOOT_MAX_REJECTED_PKEY
#define CONFIG_USECBOOT_MAX_REJECTED_PKEY 0
#endif

/* To reduce stack usage we define one static buffer to use when reading data,
 * select its size to be equal to the maximum header sign to allow validating
 * the header signature.
 */
static uint8_t msg[CONFIG_USECBOOT_MAX_HDRSIZE];

void usecboot_wipe(void *secret, size_t size)
{
	volatile uint8_t *v_secret = (uint8_t *)secret;

	for (size_t i = 0; i < size; i++) {
		v_secret[i] = 0U;
	}
}

int usecboot_cmp(const void *d1, const void *d2, size_t size)
{
	const uint8_t *p1 = d1;
	const uint8_t *p2 = d2;
	uint8_t result = 0;

	for (size_t i = 0; i < size; i++) {
		result |= p1[i] ^ p2[i];
	}

    	return (result == 0) ? 0 : 1;
}

void usecboot_memcpy(void *d1, const void *d2, size_t size)
{
	uint8_t *p1 = d1;
	const uint8_t *p2 = d2;

	for (size_t i = 0; i < size; i++) {
		p1[i] = p2[i];
	}
}

/* To get a specific tlv: fill in the tlv header of a pointer to the
 * desired tlv with the TAG and the size and call usecboot_get_tlv
 */
int usecboot_get_tlv(const struct usecboot_slot *slot,
		     void *tlv, uint32_t *pos)
{
	struct usecboot_tlv_hdr *hdr = (struct usecboot_tlv_hdr *)tlv;
	struct usecboot_tlv_hdr wlk;
	uint32_t rdpos = 0;
	int rc = 0;

	while (true) {
		if (rdpos >= CONFIG_USECBOOT_MAX_HDRSIZE) {
			rc = -USECBOOTERR_ENOENT;
			goto err_out;
		}

		rc = slot->api->read(slot, rdpos, (void *)&wlk, sizeof(wlk));
		if (rc != USECBOOTERR_NONE) {
			goto err_out;
		}

		if ((wlk.tag == hdr->tag) && (wlk.len == hdr->len)) {
			break;
		}

		rdpos += wlk.len;
	}

	if (pos != NULL) {
		*pos = rdpos;
	}

	return slot->api->read(slot, rdpos, tlv, wlk.len);
err_out:
	return rc;
}

static int usecboot_get_pubkey(const struct usecboot_slot *slot,
			struct usecboot_pubkey_tlv *pktlv)
{
	uint32_t pos = 0;
	int rc;

	pktlv->hdr.tag = USECBOOT_PKEY_TAG;
	pktlv->hdr.len = sizeof(struct usecboot_pubkey_tlv);

	rc = usecboot_get_tlv(slot, pktlv, &pos);

	if (rc == -USECBOOTERR_ENOENT) {
		/* set the pubkey to the root pubkey */
		usecboot_memcpy(pktlv->pubkey, usecboot_rootpubkey,
			        USECBOOT_PKEY_SIZE);
		goto ok_out;
	}

	if ((rc != USECBOOTERR_NONE) ||
	    (pktlv->signature.msg_size != USECBOOT_PKEY_SIZE)) {
		goto err_out;
	}

#if CONFIG_USECBOOT_MAX_REJECTED_PKEY != 0
	/* Is the pubkey on the list of rejected pubkeys ? */
	for (uint32_t i = 0U; i < CONFIG_USECBOOT_MAX_REJECTED_PKEY; i++) {
		rc = usecboot_get_rejected_pubkey(i, msg, USECBOOT_PKEY_SIZE);
		if (rc == USECBOOTERR_ENOENT) {
			break;
		}

		if (usecboot_cmp(rejpk, pktlv->pubkey, sizeof(rejpk)) == 0) {
			/* The pubkey has been rejected */
			goto err_out;
		}
	}
#endif

	rc = slot->api->read(slot, pos - pktlv->signature.msg_size, (void *)msg,
			     pktlv->signature.msg_size);

	if (rc != USECBOOTERR_NONE) {
		goto err_out;
	}

	rc = crypto_ed25519_check(pktlv->signature.signature, pktlv->pubkey, msg,
				  pktlv->signature.msg_size);
	if (rc != 0) {
		goto err_out;
	}

ok_out:
	return USECBOOTERR_NONE;
err_out:
	return -USECBOOTERR_EFAULT;
}

static int usecboot_signature_ok(const struct usecboot_slot *slot)
{
	struct usecboot_pubkey_tlv pktlv;
	struct usecboot_signature_tlv sigtlv = {
		.hdr.tag = USECBOOT_SIGN_TAG,
		.hdr.len = sizeof(sigtlv),
	};
	uint32_t pos;
	int rc;

	rc = usecboot_get_pubkey(slot, &pktlv);
	if (rc != USECBOOTERR_NONE) {
		goto err_out;
	}

	rc = usecboot_get_tlv(slot, &sigtlv, &pos);
	if ((rc != USECBOOTERR_NONE) || (sigtlv.msg_size > pos) ||
	    (sigtlv.msg_size > sizeof(msg))) {
		goto err_out;
	}

	rc = slot->api->read(slot, pos - sigtlv.msg_size, (void *)msg,
			     sigtlv.msg_size);

	if (rc != USECBOOTERR_NONE) {
		goto err_out;
	}

	rc = crypto_ed25519_check(sigtlv.signature, pktlv.pubkey, msg,
				  sigtlv.msg_size);
	if (rc != 0) {
		goto err_out;
	}

	return USECBOOTERR_NONE;
err_out:
	return -USECBOOTERR_EFAULT;
}

int usecboot_hash_ok(const struct usecboot_slot *slot)
{
	struct usecboot_hash_tlv hashtlv = {
		.hdr.tag = USECBOOT_HASH_TAG,
		.hdr.len = sizeof(hashtlv),
	};
	crypto_sha512_ctx ctx;
	uint8_t hash[USECBOOT_HASH_SIZE];
	uint32_t off;
	size_t len;
	int rc;

	rc = usecboot_get_tlv(slot, &hashtlv, NULL);

	if (rc != USECBOOTERR_NONE) {
		goto err_out;
	}

	off = hashtlv.offset;
	len = hashtlv.msg_size;
	crypto_sha512_init(&ctx);
	while (len != 0) {
		const size_t rdlen = len < sizeof(msg) ? len : sizeof(msg);

		rc = slot->api->read(slot, off, (void *)msg, rdlen);
		if (rc != USECBOOTERR_NONE) {
			break;
		}

		crypto_sha512_update(&ctx, msg, rdlen);
		off += rdlen;
		len -= rdlen;
	}

	crypto_sha512_final (&ctx, hash);

	if (rc != USECBOOTERR_NONE) {
		goto err_out;
	}

	if (usecboot_cmp(hash, hashtlv.hash, USECBOOT_HASH_SIZE) != 0) {
		goto err_out;
	}

	return USECBOOTERR_NONE;
err_out:
	return -USECBOOTERR_EFAULT;
}

int usecboot_brdy(const struct usecboot_slot *slot)
{
	if ((slot->state != USECBOOTSS_INIT) ||
	    (usecboot_signature_ok(slot) != USECBOOTERR_NONE) ||
	    (usecboot_hash_ok(slot) != USECBOOTERR_NONE)) {
		return -USECBOOTERR_EFAULT;
	}

	return USECBOOTERR_NONE;
}

void usecboot_boot(void)
{
	uint8_t idx = 0;
	struct usecboot_slot slot;

	while (true) {
		usecboot_wipe(&slot, sizeof(slot));

		if (usecboot_get_slot(idx, &slot) != 0) {
			break;
		}

		if ((slot.api->init != NULL) &&
		    (slot.api->read != NULL) &&
		    (slot.api->boot != NULL))
		{
			slot.state = USECBOOTSS_PREP;
		} else {
			usecboot_wipe(&slot, sizeof(slot));
		}

		if ((slot.state = USECBOOTSS_PREP) &&
		    (slot.api->init(&slot) == 0)) {
			slot.state = USECBOOTSS_INIT;
		} else {
			usecboot_wipe(&slot, sizeof(slot));
		}

		if ((slot.state == USECBOOTSS_INIT) &&
		    (usecboot_brdy(&slot) == 0)) {
			slot.state = USECBOOTSS_BRDY;
		} else {
			usecboot_wipe(&slot, sizeof(slot));
		}

		if (slot.state == USECBOOTSS_BRDY) {
			slot.api->boot(&slot);
		}

		if (slot.api->clean != NULL) {
			slot.api->clean(&slot);
		}

		idx++;
	}
}