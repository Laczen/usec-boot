#include <stdint.h>
#include <stddef.h>

/* BLAKE2s Constants */
static const uint32_t blake2s_iv[8] = {
	0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
	0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
};

static const uint8_t blake2s_sigma[10][16] = {
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
	{11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
	{7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
	{9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
	{2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
	{12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
	{13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
	{6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
	{10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0}
};

typedef struct {
	uint32_t h[8];		/* Chaining state */
	uint32_t t[2];		/* Counter: t[0] = low, t[1] = high */
	uint32_t f[2];		/* Finalization flags */
	uint8_t buf[64];	/* Input buffer */
	size_t buflen;		/* Bytes in buffer */
	size_t outlen;		/* Output length in bytes */
} blake2s_ctx;

/* Portable little-endian load */
static inline uint32_t load32_le(const uint8_t *src)
{
	return (uint32_t)src[0] | ((uint32_t)src[1] << 8) |
	       ((uint32_t)src[2] << 16) | ((uint32_t)src[3] << 24);
}

/* Portable little-endian store */
static inline void store32_le(uint8_t *dst, uint32_t w)
{
	dst[0] = (uint8_t)(w);
	dst[1] = (uint8_t)(w >> 8);
	dst[2] = (uint8_t)(w >> 16);
	dst[3] = (uint8_t)(w >> 24);
}

/* Secure wipe */
static void crypto_wipe(void *secret, size_t size)
{
	volatile uint8_t *v_secret = (uint8_t *)secret;

	for (size_t i = 0; i < size; i++) {
		v_secret[i] = 0U;
	}
}

/* Constant time wipe */
/* 32-bit optimized rotation */
static inline uint32_t rotr32(uint32_t x, uint32_t n)
{
	return (x >> n) | (x << (32 - n));
}

/* 32-bit optimized G mix function */
static inline void g32(uint32_t *v, int a, int b, int c, int d, uint32_t x,
		       uint32_t y)
{
	v[a] = v[a] + v[b] + x;
	v[d] = rotr32(v[d] ^ v[a], 16);
	v[c] = v[c] + v[d];
	v[b] = rotr32(v[b] ^ v[c], 12);
	v[a] = v[a] + v[b] + y;
	v[d] = rotr32(v[d] ^ v[a], 8);
	v[c] = v[c] + v[d];
	v[b] = rotr32(v[b] ^ v[c], 7);
}

/* Compression function optimized for 32-bit */
static void blake2s_compress(blake2s_ctx *ctx, int last)
{
	uint32_t v[16], m[16];
	int i;

	/* Pre-load message words - aligned access helps on 32-bit */
	for (i = 0; i < 16; i++) {
		m[i] = load32_le(&ctx->buf[i * 4]);
	}

    	/* Initialize work vector */
	for (i = 0; i < 8; i++) {
		v[i] = ctx->h[i];
		v[i + 8] = blake2s_iv[i];
	}

    	/* Low 32 bits of counter */
	v[12] ^= ctx->t[0];
	/* High 32 bits of counter */
	v[13] ^= ctx->t[1];

	/* Last block flag */
	if (last) {
		v[14] = ~v[14];
	}

	/* 10 rounds of mixing */
	for (i = 0; i < 10; i++) {
		const uint8_t *s = blake2s_sigma[i];

		/* Column round */
		g32(v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
		g32(v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
		g32(v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
		g32(v, 3, 7, 11, 15, m[s[6]], m[s[7]]);

		/* Diagonal round */
		g32(v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
		g32(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
		g32(v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
		g32(v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
	}

	/* Update chain values */
	for (i = 0; i < 8; i++) {
		ctx->h[i] ^= v[i] ^ v[i + 8];
	}
}

/* Initialize context with specified output length and key*/
static void blake2s_init_key(blake2s_ctx *ctx, size_t outlen,
			     const void *key, size_t keylen)
{
	/* clamp parameters */
	outlen = (outlen < 32U) ? outlen : 32U;
	keylen = (keylen < 32U) ? keylen : 32U;

	ctx->outlen = outlen;
	ctx->buflen = 0;
	ctx->t[0] = 0;
	ctx->t[1] = 0;
	ctx->f[0] = 0;
	ctx->f[1] = 0;

	/* Initialize state with IV */
	for (int i = 0; i < 8; i++) {
		ctx->h[i] = blake2s_iv[i];
	}

	/* Set parameter block: digest length, key length, fanout=1, depth=1 */
	ctx->h[0] ^= 0x01010000 ^ (ctx->outlen << 8) ^ (keylen << 16);

	/* Process key if provided */
	if (key != NULL && keylen > 0) {
		/* Pad key to full block in buffer */
		for (size_t i = 0; i < 64; i++) {
			ctx->buf[i] = (i < keylen) ? ((const uint8_t *)key)[i] : 0;
		}

		/* Update counter */
		ctx->t[0] += 64;
		if (ctx->t[0] < 64) ctx->t[1]++;

		/* Compress key block */
		blake2s_compress(ctx, 0);
		ctx->buflen = 0;
	}
}

void blake2s_init(void *vctx, size_t outlen)
{
	blake2s_ctx *ctx = (blake2s_ctx *)vctx;

	blake2s_init_key(ctx, outlen, NULL, 0U);
}

void blake2s_keyedinit(void *vctx, size_t outlen, const void *key,
		       size_t keylen)
{
	blake2s_ctx *ctx = (blake2s_ctx *)vctx;

	blake2s_init_key(ctx, outlen, key, keylen);
}

/* Update with new data */
void blake2s_update(void *vctx, const void *in, size_t inlen)
{
	blake2s_ctx *ctx = (blake2s_ctx *)vctx;
	const uint8_t *data = (const uint8_t *)in;
	size_t fill;

	while (inlen > 0) {
		if (ctx->buflen == 64) { /* Buffer full, compress it */
			ctx->t[0] += 64;
			if (ctx->t[0] < 64) { /* Carry*/
				ctx->t[1]++;
			}

			blake2s_compress(ctx, 0);
            		ctx->buflen = 0;
        	}

		fill = 64 - ctx->buflen;
		if (fill > inlen) {
			fill = inlen;
		}

		for (size_t i = 0U; i < fill; i++) {
			ctx->buf[i + ctx->buflen] = data[i];
		}

		ctx->buflen += fill;
		data += fill;
		inlen -= fill;
	}
}

/* Finish */
static void blake2s_finish(blake2s_ctx *ctx, uint8_t *out)
{
	/* Increment counter for final block */
	ctx->t[0] += ctx->buflen;
	if (ctx->t[0] < ctx->buflen) { /* Carry */
		ctx->t[1]++;
	}

	/* Pad remaining space in buffer with zeros */
	for (size_t i = 0U; i < 64 - ctx->buflen; i++) {
		ctx->buf[i + ctx->buflen] = 0;
	}

	/* Compress final block */
	blake2s_compress(ctx, 1);

	/* Output hash in little-endian */
	for (size_t i = 0; i < 8; i++) {
		store32_le(&out[i * 4], ctx->h[i]);
	}
}

/* Finalize and output hash */
void blake2s_final(void *vctx, void *out)
{
	blake2s_ctx *ctx = (blake2s_ctx *)vctx;
	uint8_t *result = (uint8_t *)out;
	uint8_t tmp[32];

	blake2s_finish(ctx, tmp);

	/* Output the hash (little-endian) */
	for (size_t i = 0; i < ctx->outlen; i++) {
		result[i] = tmp[i];
	}

	/* Clear sensitive data */
	crypto_wipe(ctx, sizeof(blake2s_ctx));
}

/* Finalize and cmp */
int blake2s_finalcmp(void *vctx, const void *cmp)
{
	blake2s_ctx *ctx = (blake2s_ctx *)vctx;
	const uint8_t *exp = (const uint8_t *)cmp;
	uint8_t tmp[32];
	uint8_t rv = 0U;

	blake2s_finish(ctx, tmp);

	for (size_t i = 0; i < ctx->outlen; i++) {
		rv |= tmp[i] ^ exp[i];
	}

	/* Clear sensitive data */
	crypto_wipe(ctx, sizeof(blake2s_ctx));

	return (rv == 0) ? 0 : 1;
}