/*
 *  FIPS-180-2 compliant SHA-256 implementation
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */
/*
 *  The SHA-256 Secure Hash Standard was published by NIST in 2002.
 *
 *  http://csrc.nist.gov/publications/fips/fips180-2/fips180-2.pdf
 */
/*
 * Copyright 2019-2020 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_SHA256_C)

#include "mbedtls/sha256.h"
#include "mbedtls/platform_util.h"

#include <string.h>

#if defined(MBEDTLS_SELF_TEST)
#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_printf printf
#define mbedtls_calloc calloc
#define mbedtls_free   free
#endif /* MBEDTLS_PLATFORM_C */
#endif /* MBEDTLS_SELF_TEST */

#define SHA256_VALIDATE_RET(cond) MBEDTLS_INTERNAL_VALIDATE_RET(cond, MBEDTLS_ERR_SHA256_BAD_INPUT_DATA)
#define SHA256_VALIDATE(cond)     MBEDTLS_INTERNAL_VALIDATE(cond)

#if defined(MBEDTLS_SHA256_ALT)


/*
 * 32-bit integer manipulation macros (big endian)
 */
#ifndef GET_UINT32_BE
#define GET_UINT32_BE(n, b, i)                                                                              \
    do                                                                                                      \
    {                                                                                                       \
        (n) = ((uint32_t)(b)[(i)] << 24) | ((uint32_t)(b)[(i) + 1] << 16) | ((uint32_t)(b)[(i) + 2] << 8) | \
              ((uint32_t)(b)[(i) + 3]);                                                                     \
    } while (0)
#endif

#ifndef PUT_UINT32_BE
#define PUT_UINT32_BE(n, b, i)                     \
    do                                             \
    {                                              \
        (b)[(i)]     = (unsigned char)((n) >> 24); \
        (b)[(i) + 1] = (unsigned char)((n) >> 16); \
        (b)[(i) + 2] = (unsigned char)((n) >> 8);  \
        (b)[(i) + 3] = (unsigned char)((n));       \
    } while (0)
#endif

void mbedtls_sha256_init(mbedtls_sha256_context *ctx)
{
    SHA256_VALIDATE(ctx != NULL);

    (void)memset(ctx, 0, sizeof(mbedtls_sha256_context));
}

void mbedtls_sha256_free(mbedtls_sha256_context *ctx)
{
    if (ctx == NULL)
    {
        return;
    }
    mbedtls_platform_zeroize(ctx, sizeof(mbedtls_sha256_context));
}

void mbedtls_sha256_clone(mbedtls_sha256_context *dst, const mbedtls_sha256_context *src)
{
    SHA256_VALIDATE(dst != NULL);
    SHA256_VALIDATE(src != NULL);

    *dst = *src;
}

/*
 * SHA-256 context setup
 */
int mbedtls_sha256_starts_ret(mbedtls_sha256_context *ctx, int is224)
{
    SHA256_VALIDATE_RET(ctx != NULL);
    SHA256_VALIDATE_RET(is224 == 0 || is224 == 1);
    int ret;
    sss_algorithm_t alg;
    if (is224 == 1)
    {
        alg = kAlgorithm_SSS_SHA224;
    }
    else
    {
        alg = kAlgorithm_SSS_SHA256;
    }
    if (CRYPTO_InitHardware() != kStatus_Success)
    {
        ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    }
    else if (sss_sscp_digest_context_init(&ctx->ctx, &g_sssSession, alg, kMode_SSS_Digest) != kStatus_SSS_Success)
    {
        ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    }
    else if (sss_sscp_digest_init(&ctx->ctx) != kStatus_SSS_Success)
    {
        ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    }
    else
    {
        ret = 0;
    }
    return ret;
}

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
void mbedtls_sha256_starts(mbedtls_sha256_context *ctx, int is224)
{
    (void)mbedtls_sha256_starts_ret(ctx, is224);
}
#endif

#if !defined(MBEDTLS_SHA256_PROCESS_ALT)
static const uint32_t K[] = {
    0x428A2F98u, 0x71374491u, 0xB5C0FBCFu, 0xE9B5DBA5u, 0x3956C25Bu, 0x59F111F1u, 0x923F82A4u, 0xAB1C5ED5u,
    0xD807AA98u, 0x12835B01u, 0x243185BEu, 0x550C7DC3u, 0x72BE5D74u, 0x80DEB1FEu, 0x9BDC06A7u, 0xC19BF174u,
    0xE49B69C1u, 0xEFBE4786u, 0x0FC19DC6u, 0x240CA1CCu, 0x2DE92C6Fu, 0x4A7484AAu, 0x5CB0A9DCu, 0x76F988DAu,
    0x983E5152u, 0xA831C66Du, 0xB00327C8u, 0xBF597FC7u, 0xC6E00BF3u, 0xD5A79147u, 0x06CA6351u, 0x14292967u,
    0x27B70A85u, 0x2E1B2138u, 0x4D2C6DFCu, 0x53380D13u, 0x650A7354u, 0x766A0ABBu, 0x81C2C92Eu, 0x92722C85u,
    0xA2BFE8A1u, 0xA81A664Bu, 0xC24B8B70u, 0xC76C51A3u, 0xD192E819u, 0xD6990624u, 0xF40E3585u, 0x106AA070u,
    0x19A4C116u, 0x1E376C08u, 0x2748774Cu, 0x34B0BCB5u, 0x391C0CB3u, 0x4ED8AA4Au, 0x5B9CCA4Fu, 0x682E6FF3u,
    0x748F82EEu, 0x78A5636Fu, 0x84C87814u, 0x8CC70208u, 0x90BEFFFAu, 0xA4506CEBu, 0xBEF9A3F7u, 0xC67178F2u,
};

#define SHR(x, n)  (((x)&0xFFFFFFFFU) >> (n))
#define ROTR(x, n) (SHR(x, n) | ((x) << (32 - (n))))

#define S0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3))
#define S1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10))

#define S2(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define S3(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))

#define F0(x, y, z) (((x) & (y)) | ((z) & ((x) | (y))))
#define F1(x, y, z) ((z) ^ ((x) & ((y) ^ (z))))

#define R(t) (W[t] = S1(W[(t)-2]) + W[(t)-7] + S0(W[(t)-15]) + W[(t)-16])

#define P(a, b, c, d, e, f, g, h, x, K)                      \
    do                                                       \
    {                                                        \
        temp1 = (h) + S3(e) + F1((e), (f), (g)) + (K) + (x); \
        temp2 = S2(a) + F0((a), (b), (c));                   \
        (d) += temp1;                                        \
        (h) = temp1 + temp2;                                 \
    } while (0)

int mbedtls_internal_sha256_process(mbedtls_sha256_context *ctx, const unsigned char data[64])
{
    uint32_t temp1, temp2, W[64];
    uint32_t A[8];
    unsigned int i;

    SHA256_VALIDATE_RET(ctx != NULL);
    SHA256_VALIDATE_RET((const unsigned char *)data != NULL);

    for (i = 0; i < 8u; i++)
    {
        A[i] = ctx->state[i];
    }

#if defined(MBEDTLS_SHA256_SMALLER)
    for (i = 0; i < 64; i++)
    {
        if (i < 16)
            GET_UINT32_BE(W[i], data, 4 * i);
        else
            R(i);

        P(A[0], A[1], A[2], A[3], A[4], A[5], A[6], A[7], W[i], K[i]);

        temp1 = A[7];
        A[7]  = A[6];
        A[6]  = A[5];
        A[5]  = A[4];
        A[4]  = A[3];
        A[3]  = A[2];
        A[2]  = A[1];
        A[1]  = A[0];
        A[0]  = temp1;
    }
#else  /* MBEDTLS_SHA256_SMALLER */
    for (i = 0; i < 16; i++)
        GET_UINT32_BE(W[i], data, 4 * i);

    for (i = 0; i < 16; i += 8)
    {
        P(A[0], A[1], A[2], A[3], A[4], A[5], A[6], A[7], W[i + 0], K[i + 0]);
        P(A[7], A[0], A[1], A[2], A[3], A[4], A[5], A[6], W[i + 1], K[i + 1]);
        P(A[6], A[7], A[0], A[1], A[2], A[3], A[4], A[5], W[i + 2], K[i + 2]);
        P(A[5], A[6], A[7], A[0], A[1], A[2], A[3], A[4], W[i + 3], K[i + 3]);
        P(A[4], A[5], A[6], A[7], A[0], A[1], A[2], A[3], W[i + 4], K[i + 4]);
        P(A[3], A[4], A[5], A[6], A[7], A[0], A[1], A[2], W[i + 5], K[i + 5]);
        P(A[2], A[3], A[4], A[5], A[6], A[7], A[0], A[1], W[i + 6], K[i + 6]);
        P(A[1], A[2], A[3], A[4], A[5], A[6], A[7], A[0], W[i + 7], K[i + 7]);
    }

    for (i = 16; i < 64; i += 8)
    {
        P(A[0], A[1], A[2], A[3], A[4], A[5], A[6], A[7], R(i + 0), K[i + 0]);
        P(A[7], A[0], A[1], A[2], A[3], A[4], A[5], A[6], R(i + 1), K[i + 1]);
        P(A[6], A[7], A[0], A[1], A[2], A[3], A[4], A[5], R(i + 2), K[i + 2]);
        P(A[5], A[6], A[7], A[0], A[1], A[2], A[3], A[4], R(i + 3), K[i + 3]);
        P(A[4], A[5], A[6], A[7], A[0], A[1], A[2], A[3], R(i + 4), K[i + 4]);
        P(A[3], A[4], A[5], A[6], A[7], A[0], A[1], A[2], R(i + 5), K[i + 5]);
        P(A[2], A[3], A[4], A[5], A[6], A[7], A[0], A[1], R(i + 6), K[i + 6]);
        P(A[1], A[2], A[3], A[4], A[5], A[6], A[7], A[0], R(i + 7), K[i + 7]);
    }
#endif /* MBEDTLS_SHA256_SMALLER */

    for (i = 0; i < 8u; i++)
    {
        ctx->state[i] += A[i];
    }

    return (0);
}

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
void mbedtls_sha256_process(mbedtls_sha256_context *ctx, const unsigned char data[64])
{
    (void)mbedtls_internal_sha256_process(ctx, data);
}
#endif
#endif /* !MBEDTLS_SHA256_PROCESS_ALT */

/*
 * SHA-256 process buffer
 */
int mbedtls_sha256_update_ret(mbedtls_sha256_context *ctx, const unsigned char *input, size_t ilen)
{
    int ret;
    if (CRYPTO_InitHardware() != kStatus_Success)
    {
        ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    }
    else if (sss_sscp_digest_update(&ctx->ctx, (uint8_t *)(uintptr_t)input, ilen) != kStatus_SSS_Success)
    {
        ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    }
    else
    {
        ret = 0;
    }
    return ret;
}

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
void mbedtls_sha256_update(mbedtls_sha256_context *ctx, const unsigned char *input, size_t ilen)
{
    (void)mbedtls_sha256_update_ret(ctx, input, ilen);
}
#endif

/*
 * SHA-256 final digest
 */
int mbedtls_sha256_finish_ret(mbedtls_sha256_context *ctx, unsigned char output[32])
{
    int ret;
    size_t len = ctx->ctx.digestFullLen;
    if (CRYPTO_InitHardware() != kStatus_Success)
    {
        ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    }
    else if (sss_sscp_digest_finish(&ctx->ctx, output, &len) != kStatus_SSS_Success)
    {
        ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    }
    else
    {
        ret = 0;
    }
    (void)sss_sscp_digest_context_free(&ctx->ctx);
    return ret;
}

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
void mbedtls_sha256_finish(mbedtls_sha256_context *ctx, unsigned char output[32])
{
    (void)mbedtls_sha256_finish_ret(ctx, output);
}
#endif
#endif /* MBEDTLS_SHA256_ALT */

#if defined(NXP_MBEDTLS_SHA256_ALT)
/*
 * output = SHA-256( input buffer )
 */
int mbedtls_sha256_ret(const unsigned char *input, size_t ilen, unsigned char output[32], int is224)
{
    sss_sscp_digest_t dctx;
    sss_algorithm_t alg;
    int ret;
    size_t size = 32u;
    if (is224 == 1)
    {
        alg = kAlgorithm_SSS_SHA224;
    }
    else
    {
        alg = kAlgorithm_SSS_SHA256;
    }
    if (CRYPTO_InitHardware() != kStatus_Success)
    {
        ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    }
    else if (sss_sscp_digest_context_init(&dctx, &g_sssSession, alg, kMode_SSS_Digest) != kStatus_SSS_Success)
    {
        ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    }
    else
    {
         sss_status_t st;
         st = sss_sscp_digest_one_go(&dctx, input, ilen, output, &size);
         ret = (st == kStatus_SSS_Success) ? 0 : MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
         (void)sss_sscp_digest_context_free(&dctx);
    }
    return ret;
}

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
void mbedtls_sha256(const unsigned char *input, size_t ilen, unsigned char output[32], int is224)
{
    (void)mbedtls_sha256_ret(input, ilen, output, is224);
}
#endif
#endif /* NXP_MBEDTLS_SHA256_ALT */

#endif /* MBEDTLS_SHA256_C */
