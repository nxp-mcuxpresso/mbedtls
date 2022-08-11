/*
 *  FIPS-197 compliant AES implementation
 *
 *  Copyright The Mbed TLS Contributors
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
 *  The AES block cipher was designed by Vincent Rijmen and Joan Daemen.
 *
 *  http://csrc.nist.gov/encryption/aes/rijndael/Rijndael.pdf
 *  http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
 */

/*
 * For HW integration change
 * Copyright 2022 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "common.h"

#if defined(MBEDTLS_AES_C)

#include <string.h>

#include "mbedtls/aes.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/platform.h"
#if defined(MBEDTLS_PADLOCK_C)
#include "mbedtls/padlock.h"
#endif
#if defined(MBEDTLS_AESNI_C)
#include "mbedtls/aesni.h"
#endif

#if defined(MBEDTLS_AES_ALT)
/* clang-format off */
/* Parameter validation macros based on platform_util.h */
#define AES_VALIDATE_RET( cond )    \
    MBEDTLS_INTERNAL_VALIDATE_RET( cond, MBEDTLS_ERR_AES_BAD_INPUT_DATA )
#define AES_VALIDATE( cond )        \
    MBEDTLS_INTERNAL_VALIDATE( cond )

void mbedtls_aes_init( mbedtls_aes_context *ctx )
{
    AES_VALIDATE( ctx != NULL );

    memset( ctx, 0, sizeof( mbedtls_aes_context ) );
}

void mbedtls_aes_free( mbedtls_aes_context *ctx )
{
    if( ctx == NULL )
        return;

    mbedtls_platform_zeroize( ctx, sizeof( mbedtls_aes_context ) );
}

/*
 * AES-ECB block encryption/decryption
 */
int mbedtls_aes_crypt_ecb( mbedtls_aes_context *ctx,
                           int mode,
                           const unsigned char input[16],
                           unsigned char output[16] )
{
    AES_VALIDATE_RET( ctx != NULL );
    AES_VALIDATE_RET( input != NULL );
    AES_VALIDATE_RET( output != NULL );
    AES_VALIDATE_RET( mode == MBEDTLS_AES_ENCRYPT ||
                      mode == MBEDTLS_AES_DECRYPT );

#if defined(MBEDTLS_AESNI_C) && defined(MBEDTLS_HAVE_X86_64)
    if( mbedtls_aesni_has_support( MBEDTLS_AESNI_AES ) )
        return( mbedtls_aesni_crypt_ecb( ctx, mode, input, output ) );
#endif

#if defined(MBEDTLS_PADLOCK_C) && defined(MBEDTLS_HAVE_X86)
    if( aes_padlock_ace )
    {
        if( mbedtls_padlock_xcryptecb( ctx, mode, input, output ) == 0 )
            return( 0 );

        // If padlock data misaligned, we just fall back to
        // unaccelerated mode
        //
    }
#endif

    if( mode == MBEDTLS_AES_ENCRYPT )
        return( mbedtls_internal_aes_encrypt( ctx, input, output ) );
    else
        return( mbedtls_internal_aes_decrypt( ctx, input, output ) );
}

#if defined(MBEDTLS_CIPHER_MODE_CFB)
/*
 * AES-CFB128 buffer encryption/decryption
 */
#if !defined(MBEDTLS_AES_CRYPT_CFB_ALT)
int mbedtls_aes_crypt_cfb128( mbedtls_aes_context *ctx,
                       int mode,
                       size_t length,
                       size_t *iv_off,
                       unsigned char iv[16],
                       const unsigned char *input,
                       unsigned char *output )
{
    int c;
    size_t n;

    AES_VALIDATE_RET( ctx != NULL );
    AES_VALIDATE_RET( mode == MBEDTLS_AES_ENCRYPT ||
                      mode == MBEDTLS_AES_DECRYPT );
    AES_VALIDATE_RET( iv_off != NULL );
    AES_VALIDATE_RET( iv != NULL );
    AES_VALIDATE_RET( input != NULL );
    AES_VALIDATE_RET( output != NULL );

    n = *iv_off;

    if( n > 15 )
        return( MBEDTLS_ERR_AES_BAD_INPUT_DATA );

    if( mode == MBEDTLS_AES_DECRYPT )
    {
        while( length-- )
        {
            if( n == 0 )
                mbedtls_aes_crypt_ecb( ctx, MBEDTLS_AES_ENCRYPT, iv, iv );

            c = *input++;
            *output++ = (unsigned char)( c ^ iv[n] );
            iv[n] = (unsigned char) c;

            n = ( n + 1 ) & 0x0F;
        }
    }
    else
    {
        while( length-- )
        {
            if( n == 0 )
                mbedtls_aes_crypt_ecb( ctx, MBEDTLS_AES_ENCRYPT, iv, iv );

            iv[n] = *output++ = (unsigned char)( iv[n] ^ *input++ );

            n = ( n + 1 ) & 0x0F;
        }
    }

    *iv_off = n;

    return( 0 );
}

/*
 * AES-CFB8 buffer encryption/decryption
 */
int mbedtls_aes_crypt_cfb8( mbedtls_aes_context *ctx,
                            int mode,
                            size_t length,
                            unsigned char iv[16],
                            const unsigned char *input,
                            unsigned char *output )
{
    unsigned char c;
    unsigned char ov[17];

    AES_VALIDATE_RET( ctx != NULL );
    AES_VALIDATE_RET( mode == MBEDTLS_AES_ENCRYPT ||
                      mode == MBEDTLS_AES_DECRYPT );
    AES_VALIDATE_RET( iv != NULL );
    AES_VALIDATE_RET( input != NULL );
    AES_VALIDATE_RET( output != NULL );
    while( length-- )
    {
        memcpy( ov, iv, 16 );
        mbedtls_aes_crypt_ecb( ctx, MBEDTLS_AES_ENCRYPT, iv, iv );

        if( mode == MBEDTLS_AES_DECRYPT )
            ov[16] = *input;

        c = *output++ = (unsigned char)( iv[0] ^ *input++ );

        if( mode == MBEDTLS_AES_ENCRYPT )
            ov[16] = c;

        memcpy( iv, ov + 1, 16 );
    }

    return( 0 );
}
#endif /* !MBEDTLS_AES_CRYPT_CFB_ALT */
#endif /* MBEDTLS_CIPHER_MODE_CFB */

#if defined(MBEDTLS_CIPHER_MODE_OFB)
/*
 * AES-OFB (Output Feedback Mode) buffer encryption/decryption
 */
int mbedtls_aes_crypt_ofb( mbedtls_aes_context *ctx,
                           size_t length,
                           size_t *iv_off,
                           unsigned char iv[16],
                           const unsigned char *input,
                           unsigned char *output )
{
    int ret = 0;
    size_t n;

    AES_VALIDATE_RET( ctx != NULL );
    AES_VALIDATE_RET( iv_off != NULL );
    AES_VALIDATE_RET( iv != NULL );
    AES_VALIDATE_RET( input != NULL );
    AES_VALIDATE_RET( output != NULL );

    n = *iv_off;

    if( n > 15 )
        return( MBEDTLS_ERR_AES_BAD_INPUT_DATA );

    while( length-- )
    {
        if( n == 0 )
        {
            ret = mbedtls_aes_crypt_ecb( ctx, MBEDTLS_AES_ENCRYPT, iv, iv );
            if( ret != 0 )
                goto exit;
        }
        *output++ =  *input++ ^ iv[n];

        n = ( n + 1 ) & 0x0F;
    }

    *iv_off = n;

exit:
    return( ret );
}
#endif /* MBEDTLS_CIPHER_MODE_OFB */

#if defined(MBEDTLS_CIPHER_MODE_CTR)
/*
 * AES-CTR buffer encryption/decryption
 */
#if !defined(MBEDTLS_AES_CRYPT_CTR_ALT)
int mbedtls_aes_crypt_ctr( mbedtls_aes_context *ctx,
                       size_t length,
                       size_t *nc_off,
                       unsigned char nonce_counter[16],
                       unsigned char stream_block[16],
                       const unsigned char *input,
                       unsigned char *output )
{
    int c, i;
    size_t n;

    AES_VALIDATE_RET( ctx != NULL );
    AES_VALIDATE_RET( nc_off != NULL );
    AES_VALIDATE_RET( nonce_counter != NULL );
    AES_VALIDATE_RET( stream_block != NULL );
    AES_VALIDATE_RET( input != NULL );
    AES_VALIDATE_RET( output != NULL );

    n = *nc_off;

    if ( n > 0x0F )
        return( MBEDTLS_ERR_AES_BAD_INPUT_DATA );

    while( length-- )
    {
        if( n == 0 ) {
            mbedtls_aes_crypt_ecb( ctx, MBEDTLS_AES_ENCRYPT, nonce_counter, stream_block );

            for( i = 16; i > 0; i-- )
                if( ++nonce_counter[i - 1] != 0 )
                    break;
        }
        c = *input++;
        *output++ = (unsigned char)( c ^ stream_block[n] );

        n = ( n + 1 ) & 0x0F;
    }

    *nc_off = n;

    return( 0 );
}
#endif /* !MBEDTLS_AES_CRYPT_CTR_ALT */
#endif /* MBEDTLS_CIPHER_MODE_CTR */
/* clang-format on */

/*          NXP_MBEDTLS_AES_ALT        */
#if defined(NXP_MBEDTLS_AES_ALT)
#include "sss_crypto.h"
/*
 * AES key schedule (encryption)
 */
int mbedtls_aes_setkey_enc(mbedtls_aes_context *ctx, const unsigned char *key, unsigned int keybits)
{
    AES_VALIDATE_RET(ctx != NULL);
    AES_VALIDATE_RET(key != NULL);

    switch (keybits)
    {
        case 128:
            ctx->keySize = 16;
            break;
        case 192:
            ctx->keySize = 24;
            break;
        case 256:
            ctx->keySize = 32;
            break;
        default:
            return (MBEDTLS_ERR_AES_INVALID_KEY_LENGTH);
    }

    memcpy(ctx->key, key, ctx->keySize);

    return (0);
}

/*
 * AES key schedule (decryption)
 */
int mbedtls_aes_setkey_dec(mbedtls_aes_context *ctx, const unsigned char *key, unsigned int keybits)
{
    return mbedtls_aes_setkey_enc(ctx, key, keybits);
}

/*
 * AES-ECB block encryption
 */
int mbedtls_internal_aes_encrypt(mbedtls_aes_context *ctx, const unsigned char input[16], unsigned char output[16])
{
    sss_sscp_symmetric_t aesCtx;
    sss_sscp_object_t sssKey;

    if ((sss_sscp_key_object_init(&sssKey, &g_keyStore)) != kStatus_SSS_Success)
    {
        return (MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED);
    }

    if ((SSS_KEY_ALLOCATE_HANDLE(&sssKey, 1u, /* key id */
                                 kSSS_KeyPart_Default, kSSS_CipherType_AES, ctx->keySize, SSS_KEYPROP_OPERATION_AES)) !=
        kStatus_SSS_Success)
    {
        (void)SSS_KEY_OBJ_FREE(&sssKey);
        return (MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED);
    }
    if ((SSS_KEY_STORE_SET_KEY(&sssKey, ctx->key, ctx->keySize, (ctx->keySize << 3), kSSS_KeyPart_Default)) !=
        kStatus_SSS_Success)
    {
        (void)SSS_KEY_OBJ_FREE(&sssKey);
        return (MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED);
    }

    if ((sss_sscp_symmetric_context_init(&aesCtx, &g_sssSession, &sssKey, kAlgorithm_SSS_AES_ECB, kMode_SSS_Encrypt)) !=
        kStatus_SSS_Success)
    {
        (void)SSS_KEY_OBJ_FREE(&sssKey);
        return (MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED);
    }

    /* RUN AES */
    if ((sss_sscp_cipher_one_go(&aesCtx, NULL, 0, input, output, 16)) != kStatus_SSS_Success)
    {
        
        (void)sss_sscp_symmetric_context_free(&aesCtx);
        (void)SSS_KEY_OBJ_FREE(&sssKey);
        return (MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED);
    }

    /* Free AES context whether AES operation succeeded or not */
    if (sss_sscp_symmetric_context_free(&aesCtx) != kStatus_SSS_Success)
    {
        return (MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED);
    }
    
    (void)SSS_KEY_OBJ_FREE(&sssKey);

    return 0;
}

/*
 * AES-ECB block decryption
 */
int mbedtls_internal_aes_decrypt(mbedtls_aes_context *ctx, const unsigned char input[16], unsigned char output[16])
{
    sss_sscp_symmetric_t aesCtx;
    sss_sscp_object_t sssKey;

    if ((sss_sscp_key_object_init(&sssKey, &g_keyStore)) != kStatus_SSS_Success)
    {
        return (MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED);
    }

    if ((SSS_KEY_ALLOCATE_HANDLE(&sssKey, 1u, /* key id */
                                 kSSS_KeyPart_Default, kSSS_CipherType_AES, ctx->keySize, SSS_KEYPROP_OPERATION_AES)) !=
        kStatus_SSS_Success)
    {
        (void)SSS_KEY_OBJ_FREE(&sssKey);
        return (MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED);
    }
    if ((SSS_KEY_STORE_SET_KEY(&sssKey, ctx->key, ctx->keySize, (ctx->keySize << 3), kSSS_KeyPart_Default)) !=
        kStatus_SSS_Success)
    {
        (void)SSS_KEY_OBJ_FREE(&sssKey);
        return (MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED);
    }

    if ((sss_sscp_symmetric_context_init(&aesCtx, &g_sssSession, &sssKey, kAlgorithm_SSS_AES_ECB, kMode_SSS_Decrypt)) !=
        kStatus_SSS_Success)
    {
        (void)SSS_KEY_OBJ_FREE(&sssKey);
        return (MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED);
    }

    /* RUN AES */
    if ((sss_sscp_cipher_one_go(&aesCtx, NULL, 0, input, output, 16)) != kStatus_SSS_Success)
    {
        
        (void)sss_sscp_symmetric_context_free(&aesCtx);
        (void)SSS_KEY_OBJ_FREE(&sssKey);
        return (MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED);
    }

    /* Free AES context whether AES operation succeeded or not */
    if (sss_sscp_symmetric_context_free(&aesCtx) != kStatus_SSS_Success)
    {
        
        (void)SSS_KEY_OBJ_FREE(&sssKey);
        return (MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED);
    }
    
    (void)SSS_KEY_OBJ_FREE(&sssKey);

    return 0;
}

#if defined(MBEDTLS_CIPHER_MODE_CBC)
/*
 * AES-CBC buffer encryption/decryption
 */
int mbedtls_aes_crypt_cbc(mbedtls_aes_context *ctx,
                          int mode,
                          size_t length,
                          unsigned char iv[16],
                          const unsigned char *input,
                          unsigned char *output)
{
    AES_VALIDATE_RET(ctx != NULL);
    AES_VALIDATE_RET(mode == MBEDTLS_AES_ENCRYPT || mode == MBEDTLS_AES_DECRYPT);
    AES_VALIDATE_RET(iv != NULL);
    AES_VALIDATE_RET(input != NULL);
    AES_VALIDATE_RET(output != NULL);

    if (length % 16)
        return (MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH);

    sss_sscp_symmetric_t aesCtx;
    sss_sscp_object_t sssKey;

    if ((sss_sscp_key_object_init(&sssKey, &g_keyStore)) != kStatus_SSS_Success)
    {
        return (MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED);
    }

    if ((SSS_KEY_ALLOCATE_HANDLE(&sssKey, 1u, /* key id */
                                 kSSS_KeyPart_Default, kSSS_CipherType_AES, ctx->keySize, SSS_KEYPROP_OPERATION_AES)) !=
        kStatus_SSS_Success)
    {
        return (MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED);
    }
    if ((SSS_KEY_STORE_SET_KEY(&sssKey, ctx->key, ctx->keySize, (ctx->keySize << 3), kSSS_KeyPart_Default)) !=
        kStatus_SSS_Success)
    {
        (void)SSS_KEY_OBJ_FREE(&sssKey);
        return (MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED);
    }

    if (mode == MBEDTLS_AES_DECRYPT)
    {
        uint8_t tmp[16];
        memcpy(tmp, input + length - 16, 16);

        if ((sss_sscp_symmetric_context_init(&aesCtx, &g_sssSession, &sssKey, kAlgorithm_SSS_AES_CBC,
                                             kMode_SSS_Decrypt)) != kStatus_SSS_Success)
        {
            return (MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED);
        }

        /* RUN AES */
        if ((sss_sscp_cipher_one_go(&aesCtx, iv, 16, input, output, 16)) != kStatus_SSS_Success)
        {
            return (MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED);
        }

        /* Free AES context it its init worked whether AES operation succeeded or not */
        if (sss_sscp_symmetric_context_free(&aesCtx) != kStatus_SSS_Success)
        {
            return (MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED);
        }

        memcpy(iv, tmp, 16);
    }
    else
    {
        if ((sss_sscp_symmetric_context_init(&aesCtx, &g_sssSession, &sssKey, kAlgorithm_SSS_AES_CBC,
                                             kMode_SSS_Encrypt)) != kStatus_SSS_Success)
        {
            return (MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED);
        }

        /* RUN AES */
        if ((sss_sscp_cipher_one_go(&aesCtx, iv, 16, input, output, 16)) != kStatus_SSS_Success)
        {
            return (MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED);
        }

        /* Free AES context it its init worked whether AES operation succeeded or not */
        if (sss_sscp_symmetric_context_free(&aesCtx) != kStatus_SSS_Success)
        {
            return (MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED);
        }

        memcpy(iv, output + length - 16, 16);
    }

    (void)SSS_KEY_OBJ_FREE(&sssKey);

    return 0;
}
#endif /* MBEDTLS_CIPHER_MODE_CBC */

#endif /* NXP_MBEDTLS_AES_ALT */
#endif /* MBEDTLS_AES_ALT */
#endif /* MBEDTLS_AES_C */
