#include "platform.h"

#define SHA_DIGEST_LENGTH 20

typedef struct
{
	uint32_t total[2];          /*!< number of bytes processed  */
	uint32_t state[5];          /*!< intermediate digest state  */
	unsigned char buffer[64];   /*!< data block being processed */

	unsigned char ipad[64];     /*!< HMAC: inner padding        */
	unsigned char opad[64];     /*!< HMAC: outer padding        */
}
sha1_context;

__device__ void sha1_init(sha1_context *ctx)
{
    memset(ctx, 0, sizeof(sha1_context));
}

__device__ void sha1_free(sha1_context *ctx)
{
    if (ctx == NULL)
        return;

    zeroize(ctx, sizeof(sha1_context));
}

/*
 * SHA-1 context setup
 */
__device__ void sha1_starts(sha1_context *ctx)
{
    ctx->total[0] = 0;
    ctx->total[1] = 0;

    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xC3D2E1F0;
}

__device__ void sha1_process(sha1_context *ctx, const unsigned char data[64])
{
    uint32_t temp, W[16], A, B, C, D, E;

    GET_UINT32_BE(W[ 0], data,  0);
    GET_UINT32_BE(W[ 1], data,  4);
    GET_UINT32_BE(W[ 2], data,  8);
    GET_UINT32_BE(W[ 3], data, 12);
    GET_UINT32_BE(W[ 4], data, 16);
    GET_UINT32_BE(W[ 5], data, 20);
    GET_UINT32_BE(W[ 6], data, 24);
    GET_UINT32_BE(W[ 7], data, 28);
    GET_UINT32_BE(W[ 8], data, 32);
    GET_UINT32_BE(W[ 9], data, 36);
    GET_UINT32_BE(W[10], data, 40);
    GET_UINT32_BE(W[11], data, 44);
    GET_UINT32_BE(W[12], data, 48);
    GET_UINT32_BE(W[13], data, 52);
    GET_UINT32_BE(W[14], data, 56);
    GET_UINT32_BE(W[15], data, 60);

#define R(t)                                            \
(                                                       \
    temp = W[(t -  3) & 0x0F] ^ W[(t - 8) & 0x0F] ^ \
           W[(t - 14) & 0x0F] ^ W[  t       & 0x0F],  \
    (W[t & 0x0F] = S(temp,1))                         \
)

#define O(a,b,c,d,e,x)                                  \
{                                                       \
    e += S(a,5) + F(b,c,d) + K + x; b = S(b,30);        \
}

    A = ctx->state[0];
    B = ctx->state[1];
    C = ctx->state[2];
    D = ctx->state[3];
    E = ctx->state[4];

#define F(x,y,z) (z ^ (x & (y ^ z)))
#define K 0x5A827999

    O(A, B, C, D, E, W[0]  );
    O(E, A, B, C, D, W[1]  );
    O(D, E, A, B, C, W[2]  );
    O(C, D, E, A, B, W[3]  );
    O(B, C, D, E, A, W[4]  );
    O(A, B, C, D, E, W[5]  );
    O(E, A, B, C, D, W[6]  );
    O(D, E, A, B, C, W[7]  );
    O(C, D, E, A, B, W[8]  );
    O(B, C, D, E, A, W[9]  );
    O(A, B, C, D, E, W[10]);
    O(E, A, B, C, D, W[11]);
    O(D, E, A, B, C, W[12]);
    O(C, D, E, A, B, W[13]);
    O(B, C, D, E, A, W[14]);
    O(A, B, C, D, E, W[15]);
    O(E, A, B, C, D, R(16));
    O(D, E, A, B, C, R(17));
    O(C, D, E, A, B, R(18));
    O(B, C, D, E, A, R(19));

#undef K
#undef F

#define F(x,y,z) (x ^ y ^ z)
#define K 0x6ED9EBA1

    O(A, B, C, D, E, R(20));
    O(E, A, B, C, D, R(21));
    O(D, E, A, B, C, R(22));
    O(C, D, E, A, B, R(23));
    O(B, C, D, E, A, R(24));
    O(A, B, C, D, E, R(25));
    O(E, A, B, C, D, R(26));
    O(D, E, A, B, C, R(27));
    O(C, D, E, A, B, R(28));
    O(B, C, D, E, A, R(29));
    O(A, B, C, D, E, R(30));
    O(E, A, B, C, D, R(31));
    O(D, E, A, B, C, R(32));
    O(C, D, E, A, B, R(33));
    O(B, C, D, E, A, R(34));
    O(A, B, C, D, E, R(35));
    O(E, A, B, C, D, R(36));
    O(D, E, A, B, C, R(37));
    O(C, D, E, A, B, R(38));
    O(B, C, D, E, A, R(39));

#undef K
#undef F

#define F(x,y,z) ((x & y) | (z & (x | y)))
#define K 0x8F1BBCDC

    O(A, B, C, D, E, R(40));
    O(E, A, B, C, D, R(41));
    O(D, E, A, B, C, R(42));
    O(C, D, E, A, B, R(43));
    O(B, C, D, E, A, R(44));
    O(A, B, C, D, E, R(45));
    O(E, A, B, C, D, R(46));
    O(D, E, A, B, C, R(47));
    O(C, D, E, A, B, R(48));
    O(B, C, D, E, A, R(49));
    O(A, B, C, D, E, R(50));
    O(E, A, B, C, D, R(51));
    O(D, E, A, B, C, R(52));
    O(C, D, E, A, B, R(53));
    O(B, C, D, E, A, R(54));
    O(A, B, C, D, E, R(55));
    O(E, A, B, C, D, R(56));
    O(D, E, A, B, C, R(57));
    O(C, D, E, A, B, R(58));
    O(B, C, D, E, A, R(59));

#undef K
#undef F

#define F(x,y,z) (x ^ y ^ z)
#define K 0xCA62C1D6

    O(A, B, C, D, E, R(60));
    O(E, A, B, C, D, R(61));
    O(D, E, A, B, C, R(62));
    O(C, D, E, A, B, R(63));
    O(B, C, D, E, A, R(64));
    O(A, B, C, D, E, R(65));
    O(E, A, B, C, D, R(66));
    O(D, E, A, B, C, R(67));
    O(C, D, E, A, B, R(68));
    O(B, C, D, E, A, R(69));
    O(A, B, C, D, E, R(70));
    O(E, A, B, C, D, R(71));
    O(D, E, A, B, C, R(72));
    O(C, D, E, A, B, R(73));
    O(B, C, D, E, A, R(74));
    O(A, B, C, D, E, R(75));
    O(E, A, B, C, D, R(76));
    O(D, E, A, B, C, R(77));
    O(C, D, E, A, B, R(78));
    O(B, C, D, E, A, R(79));

#undef K
#undef F

    ctx->state[0] += A;
    ctx->state[1] += B;
    ctx->state[2] += C;
    ctx->state[3] += D;
    ctx->state[4] += E;
}

/*
 * SHA-1 process buffer
 */
__device__ void sha1_update(sha1_context *ctx, const unsigned char *input, size_t ilen)
{
    size_t fill;
    uint32_t left;

    if (ilen == 0)
        return;

    left = ctx->total[0] & 0x3F;
    fill = 64 - left;

    ctx->total[0] += (uint32_t) ilen;
    ctx->total[0] &= 0xFFFFFFFF;

    if (ctx->total[0] < (uint32_t) ilen)
        ctx->total[1]++;

    if (left && ilen >= fill)
    {
        memcpy((void *) (ctx->buffer + left), input, fill);
        sha1_process(ctx, ctx->buffer);
        input += fill;
        ilen  -= fill;
        left = 0;
    }

    while(ilen >= 64)
    {
        sha1_process(ctx, input);
        input += 64;
        ilen  -= 64;
    }

    if (ilen > 0)
        memcpy((void *) (ctx->buffer + left), input, ilen);
}

__device__ static const unsigned char sha1_padding[64] =
{
 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/*
 * SHA-1 final digest
 */
__device__ void sha1_finish(sha1_context *ctx, unsigned char output[20])
{
    uint32_t last, padn;
    uint32_t high, low;
    unsigned char msglen[8];

    high = (ctx->total[0] >> 29)
         | (ctx->total[1] <<  3);
    low  = (ctx->total[0] <<  3);

    PUT_UINT32_BE(high, msglen, 0);
    PUT_UINT32_BE(low,  msglen, 4);

    last = ctx->total[0] & 0x3F;
    padn = (last < 56) ? (56 - last) : (120 - last);

    sha1_update(ctx, sha1_padding, padn);
    sha1_update(ctx, msglen, 8);

    PUT_UINT32_BE(ctx->state[0], output,  0);
    PUT_UINT32_BE(ctx->state[1], output,  4);
    PUT_UINT32_BE(ctx->state[2], output,  8);
    PUT_UINT32_BE(ctx->state[3], output, 12);
    PUT_UINT32_BE(ctx->state[4], output, 16);
}

/*
 * output = SHA-1(input buffer)
 */
__device__ void sha1(const unsigned char *input, size_t ilen, unsigned char output[20])
{
    sha1_context ctx;

    sha1_init(&ctx);
    sha1_starts(&ctx);
    sha1_update(&ctx, input, ilen);
    sha1_finish(&ctx, output);
    sha1_free(&ctx);
}


/*
 * SHA-1 HMAC context setup
 */
__device__ void sha1_hmac_starts(sha1_context *ctx, const unsigned char *key,
                       size_t keylen)
{
    size_t i;
    unsigned char sum[20];

    if (keylen > 64)
    {
        sha1(key, keylen, sum);
        keylen = 20;
        key = sum;
    }

    memset(ctx->ipad, 0x36, 64);
    memset(ctx->opad, 0x5C, 64);

    for (i = 0; i < keylen; i++)
    {
        ctx->ipad[i] = (unsigned char)(ctx->ipad[i] ^ key[i]);
        ctx->opad[i] = (unsigned char)(ctx->opad[i] ^ key[i]);
    }

    sha1_starts(ctx);
    sha1_update(ctx, ctx->ipad, 64);

    zeroize(sum, sizeof(sum));
}

/*
 * SHA-1 HMAC process buffer
 */
__device__ void sha1_hmac_update(sha1_context *ctx, const unsigned char *input,
                       size_t ilen)
{
    sha1_update(ctx, input, ilen);
}

/*
 * SHA-1 HMAC final digest
 */
__device__ void sha1_hmac_finish(sha1_context *ctx, unsigned char output[20])
{
    unsigned char tmpbuf[20];

    sha1_finish(ctx, tmpbuf);
    sha1_starts(ctx);
    sha1_update(ctx, ctx->opad, 64);
    sha1_update(ctx, tmpbuf, 20);
    sha1_finish(ctx, output);

    zeroize(tmpbuf, sizeof(tmpbuf));
}

/*
 * SHA1 HMAC context reset
 */
__device__ void sha1_hmac_reset(sha1_context *ctx)
{
    sha1_starts(ctx);
    sha1_update(ctx, ctx->ipad, 64);
}

/*
 * output = HMAC-SHA-1(hmac key, input buffer)
 */
__device__ void sha1_hmac(const unsigned char *key, size_t keylen,
                const unsigned char *input, size_t ilen,
                unsigned char output[20])
{
    sha1_context ctx;

    sha1_init(&ctx);
    sha1_hmac_starts(&ctx, key, keylen);
    sha1_hmac_update(&ctx, input, ilen);
    sha1_hmac_finish(&ctx, output);
    sha1_free(&ctx);
}