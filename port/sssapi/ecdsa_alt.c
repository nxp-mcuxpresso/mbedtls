/*
 *  Elliptic curve DSA
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
 * Copyright 2019-2021 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*
 * References:
 *
 * SEC1 http://www.secg.org/index.php?action=secg,docs_secg
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif
#if defined(MBEDTLS_ECDSA_C)

#include "sss_crypto.h"

#include "mbedtls/ecdsa.h"
#include "mbedtls/asn1write.h"

#include <string.h>

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc calloc
#define mbedtls_free   free
#endif
#include "sss_crypto.h"
#include "mbedtls/platform_util.h"

/* Parameter validation macros based on platform_util.h */
#define ECDSA_VALIDATE_RET(cond) MBEDTLS_INTERNAL_VALIDATE_RET(cond, MBEDTLS_ERR_ECP_BAD_INPUT_DATA)
#define ECDSA_VALIDATE(cond)     MBEDTLS_INTERNAL_VALIDATE(cond)

#define ECDSA_RS_ECP NULL

#define ECDSA_BUDGET(ops) /* no-op; for compatibility */

#define ECDSA_RS_ENTER(SUB) (void) rs_ctx
#define ECDSA_RS_LEAVE(SUB) (void) rs_ctx

/* Used as values s and n of mbedtls_mpi object to indicate that P contain pointer to key object. */
#define MBEDTLS_ECDSA_MPI_S_HAVE_OBJECT (155)
#define MBEDTLS_ECDSA_MPI_N_HAVE_OBJECT (1u)

#if defined(MBEDTLS_ECDSA_SIGN_ALT) || defined(MBEDTLS_ECDSA_VERIFY_ALT)
static int mbedtls_ecdsa_verify_digest_len(const size_t pbits,
                                           size_t *digestLen,
                                           sss_algorithm_t *alg)
{
    int ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    switch (pbits) {
        case 224:
            *alg = kAlgorithm_SSS_ECDSA_SHA224;
            *digestLen = 28U;
            ret  = 0;
            break;
        case 256:
            *alg = kAlgorithm_SSS_ECDSA_SHA256;
            *digestLen = 32U;
            ret  = 0;
            break;
        case 384:
            *alg = kAlgorithm_SSS_ECDSA_SHA384;
            *digestLen = 48U;
            ret  = 0;
            break;
        case 521:
            *alg = kAlgorithm_SSS_ECDSA_SHA512;
            *digestLen = 64U;
            ret  = 0;
            break;
        default:
            ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
            break;
    }
    return ret;
}

static int mbedtls_ecdsa_verify_digest_align(const size_t digestLen,
                                             const size_t ecCoordinateSize,
                                             const uint8_t *digest,
                                             uint8_t alignedDigest[])
{
    if (digestLen < ecCoordinateSize) {
        size_t diff = ecCoordinateSize - digestLen;
        (void) memcpy(&alignedDigest[diff], digest, digestLen);
    } else {
        (void) memcpy(alignedDigest, digest, digestLen);
    }
    return 0;
}
#endif /* defined(MBEDTLS_ECDSA_SIGN_ALT) || defined(MBEDTLS_ECDSA_VERIFY_ALT) */

#if defined(MBEDTLS_ECDSA_SIGN_ALT)
/*
 * Compute ECDSA signature of a hashed message (SEC1 4.1.3)
 * Obviously, compared to SEC1 4.1.3, we skip step 4 (hash message)
 */
static int ecdsa_sign_restartable(mbedtls_ecp_group *grp,
                                  mbedtls_mpi *r,
                                  mbedtls_mpi *s,
                                  const mbedtls_mpi *d,
                                  const unsigned char *buf,
                                  size_t blen,
                                  int (*f_rng)(void *, unsigned char *, size_t),
                                  void *p_rng,
                                  mbedtls_ecdsa_restart_ctx *rs_ctx)
{
    int ret = 0;
    sss_sscp_asymmetric_t asyc;
    sss_sscp_object_t key = { 0 };
    sss_algorithm_t alg;
    size_t coordinateLen   = (grp->pbits + 7u) / 8u;
    size_t signatureSize   = 2u * coordinateLen;
    uint8_t *signature     = mbedtls_calloc(signatureSize, sizeof(uint8_t));
    uint8_t *alignedDigest = mbedtls_calloc(coordinateLen, sizeof(uint8_t));
    uint8_t *privateKey    = mbedtls_calloc(coordinateLen, sizeof(uint8_t));

    /* Fail cleanly on curves such as Curve25519 that can't be used for ECDSA */
    if (grp->N.p == NULL) {
        mbedtls_free(signature);
        mbedtls_free(alignedDigest);
        mbedtls_free(privateKey);
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
    if (CRYPTO_InitHardware() != kStatus_Success) {
        mbedtls_free(signature);
        mbedtls_free(alignedDigest);
        mbedtls_free(privateKey);
        return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    }
    /* Check if KEY is generated by ELE200 so mbedtls_mpi was initialized with key object. */
    /* If key is not from ELE200 load private key from system memory into ELE200*/
    if ((d->s != MBEDTLS_ECDSA_MPI_S_HAVE_OBJECT) && (d->n != MBEDTLS_ECDSA_MPI_N_HAVE_OBJECT)) {
        /* Key is loaded from memory into ELE200*/

        mbedtls_mpi_write_binary(d, privateKey, coordinateLen);

        if (sss_sscp_key_object_init(&key, &g_keyStore) != kStatus_SSS_Success) {
            mbedtls_free(signature);
            mbedtls_free(alignedDigest);
            mbedtls_free(privateKey);
            (void) SSS_KEY_OBJ_FREE(&key);
            return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
        }
        /* Allocate key handle */
#if (defined(KW45_A0_SUPPORT) && KW45_A0_SUPPORT)
        if (sss_sscp_key_object_allocate_handle(&key,
                                                0x0u,
                                                kSSS_KeyPart_Private,
                                                kSSS_CipherType_EC_NIST_P,
                                                coordinateLen,
                                                SSS_PUBLIC_KEY_PART_EXPORTABLE) !=
            kStatus_SSS_Success)
#else
        if (sss_sscp_key_object_allocate_handle(&key,
                                                0x0u,
                                                kSSS_KeyPart_Private,
                                                kSSS_CipherType_EC_NIST_P,
                                                coordinateLen,
                                                SSS_KEYPROP_OPERATION_ASYM) != kStatus_SSS_Success)
#endif
        {
            mbedtls_free(signature);
            mbedtls_free(alignedDigest);
            mbedtls_free(privateKey);
            (void) SSS_KEY_OBJ_FREE(&key);
            return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
        }

        if (SSS_KEY_STORE_SET_KEY(&key, (const uint8_t *) privateKey, coordinateLen, grp->pbits,
                                  kSSS_KeyPart_Private) !=
            kStatus_SSS_Success) {
            mbedtls_free(signature);
            mbedtls_free(alignedDigest);
            mbedtls_free(privateKey);
            (void) SSS_KEY_OBJ_FREE(&key);
            return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
        }
    }

    ret = mbedtls_ecdsa_verify_digest_len(grp->pbits, &blen, &alg);
    if (ret != 0) {
        mbedtls_free(signature);
        mbedtls_free(alignedDigest);
        mbedtls_free(privateKey);
        (void) SSS_KEY_OBJ_FREE(&key);
        return ret;
    }

    ret = mbedtls_ecdsa_verify_digest_align(blen,
                                            coordinateLen,
                                            (const uint8_t *) buf,
                                            alignedDigest);
    if (ret != 0) {
        mbedtls_free(signature);
        mbedtls_free(alignedDigest);
        mbedtls_free(privateKey);
        (void) SSS_KEY_OBJ_FREE(&key);
        return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    }

    if ((d->s == MBEDTLS_ECDSA_MPI_S_HAVE_OBJECT) && (d->n == MBEDTLS_ECDSA_MPI_N_HAVE_OBJECT)) {
        /* Key is from ELE200 */
        ret =
            sss_sscp_asymmetric_context_init(&asyc,
                                             &g_sssSession,
                                             (sss_sscp_object_t *) (uintptr_t) d->p,
                                             alg,
                                             kMode_SSS_Sign);
        if (ret != kStatus_SSS_Success) {
            mbedtls_free(signature);
            mbedtls_free(alignedDigest);
            mbedtls_free(privateKey);
            (void) sss_sscp_asymmetric_context_free(&asyc);
            (void) SSS_KEY_OBJ_FREE(&key);
            return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
        }
    } else {
        /* Key is loaded from memory */
        ret = sss_sscp_asymmetric_context_init(&asyc, &g_sssSession, &key, alg, kMode_SSS_Sign);
        if (ret != kStatus_SSS_Success) {
            mbedtls_free(signature);
            mbedtls_free(alignedDigest);
            mbedtls_free(privateKey);
            (void) sss_sscp_asymmetric_context_free(&asyc);
            (void) SSS_KEY_OBJ_FREE(&key);
            return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
        }
    }

    if (sss_sscp_asymmetric_sign_digest(&asyc, alignedDigest, blen, signature, &signatureSize) !=
        kStatus_SSS_Success) {
    } else if ((ret = mbedtls_mpi_read_binary(r, signature, coordinateLen)) != 0) {
    } else if ((ret = mbedtls_mpi_read_binary(s, &signature[coordinateLen], coordinateLen)) != 0) {
    } else {
        ret = 0;
    }
    (void) sss_sscp_asymmetric_context_free(&asyc);

    /* Free object key only when key from memory has been used*/
    if ((d->s != MBEDTLS_ECDSA_MPI_S_HAVE_OBJECT) && (d->n != MBEDTLS_ECDSA_MPI_N_HAVE_OBJECT)) {
        (void) SSS_KEY_OBJ_FREE(&key);
    }
    mbedtls_free(alignedDigest);
    mbedtls_free(signature);
    mbedtls_free(privateKey);
    return ret;
}

#if defined(MBEDTLS_ECDSA_ALT)
/*
 * Initialize context
 */
void mbedtls_ecdsa_init(mbedtls_ecdsa_context *ctx)
{
    ECDSA_VALIDATE(ctx != NULL);
    ctx->isKeyInitialized = false;
    mbedtls_ecp_keypair_init((mbedtls_ecp_keypair *) ctx);
}

/*
 * Free context
 */
void mbedtls_ecdsa_free(mbedtls_ecdsa_context *ctx)
{
    if (ctx == NULL) {
        return;
    }
    if (ctx->isKeyInitialized) {
        (void) SSS_KEY_OBJ_FREE(&ctx->key);
    }
    mbedtls_ecp_group_free(&ctx->grp);
    mbedtls_ecp_point_free(&ctx->Q);

}

int mbedtls_ecdsa_from_keypair(mbedtls_ecdsa_context *ctx, const mbedtls_ecp_keypair *key)
{
    int ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    ECDSA_VALIDATE_RET(ctx != NULL);
    ECDSA_VALIDATE_RET(key != NULL);

    if ((ret = mbedtls_ecp_group_copy(&ctx->grp, &key->grp)) != 0 ||
        (ret = mbedtls_ecp_copy(&ctx->Q, &key->Q)) != 0) {
        mbedtls_ecdsa_free(ctx);
        return ret;
    }

    size_t keyLen     = (ctx->grp.pbits + 7u) / 8u;
    size_t keyBitsLen = ctx->grp.pbits;

    mbedtls_ecdsa_context *pKey = (mbedtls_ecdsa_context *) key;

    if ((pKey->d.s == MBEDTLS_ECDSA_MPI_S_HAVE_OBJECT) &&
        (pKey->d.n == MBEDTLS_ECDSA_MPI_N_HAVE_OBJECT)) {
        /* The key was generated with ELE200 and must be loaded into ecdsa context.*/
        ctx->d.s = MBEDTLS_ECDSA_MPI_S_HAVE_OBJECT;
        ctx->d.n = MBEDTLS_ECDSA_MPI_N_HAVE_OBJECT;
        ctx->key = pKey->key;
//      ctx->d.p = (mbedtls_mpi_uint *)(uintptr_t)&pKey->key;
        ctx->d.p = (mbedtls_mpi_uint *) (uintptr_t) &ctx->key;

        /* We don't want to free the key in ecdsa free */
        ctx->isKeyInitialized = false;

        ret      = 0;
    }
    /* Check if we actually have a private key to load, for ecdsa verify it is not needed */
    else if (key->d.p != NULL) {
        /* Key is loaded from file into ELE200*/
        uint8_t privateKey[32];
        mbedtls_mpi_write_binary(&key->d, privateKey, 32);

        if (CRYPTO_InitHardware() != kStatus_Success) {
            return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
        }

        if (ctx->isKeyInitialized == false) {
            if (sss_sscp_key_object_init(&ctx->key, &g_keyStore) != kStatus_SSS_Success) {
                (void) SSS_KEY_OBJ_FREE(&ctx->key);
                return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
            }
            /* Allocate key handle */
#if (defined(KW45_A0_SUPPORT) && KW45_A0_SUPPORT)
            else if (sss_sscp_key_object_allocate_handle(&ctx->key,
                                                         0x0u,
                                                         kSSS_KeyPart_Private,
                                                         kSSS_CipherType_EC_NIST_P,
                                                         keyLen,
                                                         SSS_PUBLIC_KEY_PART_EXPORTABLE) !=
                     kStatus_SSS_Success)
#else
            else if (sss_sscp_key_object_allocate_handle(&ctx->key,
                                                         0x0u,
                                                         kSSS_KeyPart_Private,
                                                         kSSS_CipherType_EC_NIST_P,
                                                         keyLen,
                                                         SSS_KEYPROP_OPERATION_ASYM) !=
                     kStatus_SSS_Success)
#endif
            {
                (void) SSS_KEY_OBJ_FREE(&ctx->key);
                return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
            } else {
                ctx->isKeyInitialized = true;
            }
        }
        if ((ret =
                 SSS_KEY_STORE_SET_KEY(&ctx->key, (const uint8_t *) privateKey, keyLen, keyBitsLen,
                                       kSSS_KeyPart_Private)) != kStatus_SSS_Success) {
            (void) SSS_KEY_OBJ_FREE(&ctx->key);
            return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
        } else {
            ctx->d.s = MBEDTLS_ECDSA_MPI_S_HAVE_OBJECT;
            ctx->d.n = MBEDTLS_ECDSA_MPI_N_HAVE_OBJECT;
            ctx->d.p = (mbedtls_mpi_uint *) (uintptr_t) &ctx->key;
            ret      = 0;
        }
    } else {
        /* Nothing left to do in this case but to return success */
        ret = 0;
    }
    return ret;
}

#endif /* MBEDTLS_ECDSA_ALT */

#if defined(MBEDTLS_ECDSA_GENKEY_ALT)
/*
 * Generate key pair
 */
int mbedtls_ecdsa_genkey(mbedtls_ecdsa_context *ctx,
                         mbedtls_ecp_group_id gid,
                         int (*f_rng)(void *, unsigned char *, size_t),
                         void *p_rng)
{
    int ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    ECDSA_VALIDATE_RET(ctx != NULL);
    ret = mbedtls_ecp_group_load(&ctx->grp, gid);
    if (ret != 0) {
        return ret;
    }
    size_t keyLen     = (ctx->grp.pbits + 7u) / 8u;
    size_t keyBitsLen = ctx->grp.pbits;

    size_t keySize    = SSS_ECP_KEY_SZ(keyLen); /* just 2 * key for A1 public key but 3 times for A0 */
    uint8_t *pubKey   = mbedtls_calloc(keySize, sizeof(uint8_t));
    if (CRYPTO_InitHardware() != kStatus_Success) {
        mbedtls_platform_zeroize(pubKey, keySize);
        mbedtls_free(pubKey);
        return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    }
    if (ctx->isKeyInitialized == false) {
        if (sss_sscp_key_object_init(&ctx->key, &g_keyStore) != kStatus_SSS_Success) {
            mbedtls_platform_zeroize(pubKey, keySize);
            mbedtls_free(pubKey);
            (void) SSS_KEY_OBJ_FREE(&ctx->key);
            return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
        }

        /* Allocate key handle */
#if (defined(KW45_A0_SUPPORT) && KW45_A0_SUPPORT)
        else if (sss_sscp_key_object_allocate_handle(&ctx->key,
                                                     0x0u,
                                                     kSSS_KeyPart_Pair,
                                                     kSSS_CipherType_EC_NIST_P,
                                                     keySize,
                                                     SSS_PUBLIC_KEY_PART_EXPORTABLE) !=
                 kStatus_SSS_Success)
#else
        else if (sss_sscp_key_object_allocate_handle(&ctx->key,
                                                     0x0u,
                                                     kSSS_KeyPart_Pair,
                                                     kSSS_CipherType_EC_NIST_P,
                                                     3u * keyLen,
                                                     SSS_KEYPROP_OPERATION_ASYM) !=
                 kStatus_SSS_Success)
#endif
        {
            mbedtls_platform_zeroize(pubKey, keySize);
            mbedtls_free(pubKey);
            (void) SSS_KEY_OBJ_FREE(&ctx->key);
            return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
        } else {
            ctx->isKeyInitialized = true;
        }
    }
    if (SSS_ECP_GENERATE_KEY(&ctx->key, keyBitsLen) != kStatus_SSS_Success) {
        ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    } else if (SSS_KEY_STORE_GET_PUBKEY(&ctx->key,
                                        pubKey,
                                        &keySize,
                                        &keyBitsLen) != kStatus_SSS_Success) {
        ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    } else if ((ret = mbedtls_mpi_read_binary(&ctx->Q.X, pubKey, keyLen)) != 0) {
    } else if ((ret = mbedtls_mpi_read_binary(&ctx->Q.Y, &pubKey[keyLen], keyLen)) != 0) {
    } else if ((ret = mbedtls_mpi_lset(&ctx->Q.Z, 1)) != 0) {
    } else {
        ctx->d.s = MBEDTLS_ECDSA_MPI_S_HAVE_OBJECT;
        ctx->d.n = MBEDTLS_ECDSA_MPI_N_HAVE_OBJECT;
        ctx->d.p = (mbedtls_mpi_uint *) (uintptr_t) &ctx->key;
        ret      = 0;
    }
    mbedtls_platform_zeroize(pubKey, keySize);
    mbedtls_free(pubKey);
    return ret;
}
#endif /* MBEDTLS_ECDSA_GENKEY_ALT */

/*
 * Compute ECDSA signature of a hashed message
 */
int mbedtls_ecdsa_sign(mbedtls_ecp_group *grp,
                       mbedtls_mpi *r,
                       mbedtls_mpi *s,
                       const mbedtls_mpi *d,
                       const unsigned char *buf,
                       size_t blen,
                       int (*f_rng)(void *, unsigned char *, size_t),
                       void *p_rng)
{
    ECDSA_VALIDATE_RET(grp != NULL);
    ECDSA_VALIDATE_RET(r != NULL);
    ECDSA_VALIDATE_RET(s != NULL);
    ECDSA_VALIDATE_RET(d != NULL);
    ECDSA_VALIDATE_RET(f_rng != NULL);
    ECDSA_VALIDATE_RET(buf != NULL || blen == 0);

    return ecdsa_sign_restartable(grp, r, s, d, buf, blen, f_rng, p_rng, NULL);
}
#endif /* MBEDTLS_ECDSA_SIGN_ALT */

#if defined(MBEDTLS_ECDSA_VERIFY_ALT)
/*
 * Verify ECDSA signature of hashed message (SEC1 4.1.4)
 * Obviously, compared to SEC1 4.1.3, we skip step 2 (hash message)
 */
static int ecdsa_verify_restartable(mbedtls_ecp_group *grp,
                                    const unsigned char *buf,
                                    size_t blen,
                                    const mbedtls_ecp_point *Q,
                                    const mbedtls_mpi *r,
                                    const mbedtls_mpi *s,
                                    mbedtls_ecdsa_restart_ctx *rs_ctx)
{
    int ret;
    /* Fail cleanly on curves such as Curve25519 that can't be used for ECDSA */
    if (grp->N.p == NULL) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
    size_t coordinateLen     = (grp->pbits + 7u) / 8u;
    size_t coordinateBitsLen = grp->pbits;
    size_t keySize           = SSS_ECP_KEY_SZ(coordinateLen);
    uint8_t *pubKey          = mbedtls_calloc(keySize, sizeof(uint8_t));
    sss_sscp_object_t ecdsaPublic = { 0 };
    sss_sscp_asymmetric_t asyc = { 0 };
    sss_algorithm_t alg;
    uint8_t *alignedDigest = mbedtls_calloc(coordinateLen, sizeof(uint8_t));
    if (CRYPTO_InitHardware() != kStatus_Success) {
        ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    } else if ((ret = mbedtls_ecdsa_verify_digest_len(grp->pbits, &blen, &alg)) != 0) {
    } else if (mbedtls_ecdsa_verify_digest_align(blen, coordinateLen, (const uint8_t *) buf,
                                                 alignedDigest) != 0) {
        ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    } else if ((ret = mbedtls_mpi_write_binary(&Q->X, pubKey, coordinateLen)) != 0) {
    } else if ((ret =
                    mbedtls_mpi_write_binary(&Q->Y, &pubKey[coordinateLen], coordinateLen)) != 0) {
    } else if (sss_sscp_key_object_init(&ecdsaPublic, &g_keyStore) != kStatus_SSS_Success) {
        ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    }
    /* Allocate key handle */
#if (defined(KW45_A0_SUPPORT) && KW45_A0_SUPPORT)
    else if (sss_sscp_key_object_allocate_handle(&ecdsaPublic,
                                                 0u,
                                                 kSSS_KeyPart_Pair,
                                                 kSSS_CipherType_EC_NIST_P,
                                                 keySize,
                                                 SSS_PUBLIC_KEY_PART_EXPORTABLE) !=
             kStatus_SSS_Success)
#else
    else if (sss_sscp_key_object_allocate_handle(&ecdsaPublic,
                                                 0u,
                                                 kSSS_KeyPart_Public,
                                                 kSSS_CipherType_EC_NIST_P,
                                                 keySize,
                                                 SSS_KEYPROP_OPERATION_ASYM) != kStatus_SSS_Success)
#endif
    {
        ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    } else if (SSS_KEY_STORE_SET_KEY(&ecdsaPublic, (const uint8_t *) pubKey, keySize,
                                     coordinateBitsLen,
                                     (uint32_t) kSSS_KeyPart_Public) != kStatus_SSS_Success) {
        ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    } else if ((ret = mbedtls_mpi_write_binary(r, pubKey, coordinateLen)) != 0) {
    } else if ((ret = mbedtls_mpi_write_binary(s, &pubKey[coordinateLen], coordinateLen)) != 0) {
    } else if (sss_sscp_asymmetric_context_init(&asyc, &g_sssSession, &ecdsaPublic, alg,
                                                kMode_SSS_Verify) !=
               kStatus_SSS_Success) {
        ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    } else if (sss_sscp_asymmetric_verify_digest(&asyc, alignedDigest, blen, pubKey,
                                                 coordinateLen * 2u) !=
               kStatus_SSS_Success) {
        ret = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    } else {
        ret = 0;
    }
    (void) SSS_KEY_OBJ_FREE(&ecdsaPublic);
    (void) sss_sscp_asymmetric_context_free(&asyc);
    mbedtls_platform_zeroize(pubKey, keySize);
    mbedtls_free(pubKey);
    mbedtls_platform_zeroize(alignedDigest, coordinateLen);
    mbedtls_free(alignedDigest);
    return ret;
}

/*
 * Verify ECDSA signature of hashed message
 */
int mbedtls_ecdsa_verify(mbedtls_ecp_group *grp,
                         const unsigned char *buf,
                         size_t blen,
                         const mbedtls_ecp_point *Q,
                         const mbedtls_mpi *r,
                         const mbedtls_mpi *s)
{
    ECDSA_VALIDATE_RET(grp != NULL);
    ECDSA_VALIDATE_RET(Q != NULL);
    ECDSA_VALIDATE_RET(r != NULL);
    ECDSA_VALIDATE_RET(s != NULL);
    ECDSA_VALIDATE_RET(buf != NULL || blen == 0);

    return ecdsa_verify_restartable(grp, buf, blen, Q, r, s, NULL);
}
#endif /* MBEDTLS_ECDSA_VERIFY_ALT */

#endif /* MBEDTLS_ECDSA_C */
