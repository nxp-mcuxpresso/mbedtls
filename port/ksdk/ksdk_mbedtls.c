/*
* Copyright (c) 2015, Freescale Semiconductor, Inc.
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without modification,
* are permitted provided that the following conditions are met:
*
* o Redistributions of source code must retain the above copyright notice, this list
*   of conditions and the following disclaimer.
*
* o Redistributions in binary form must reproduce the above copyright notice, this
*   list of conditions and the following disclaimer in the documentation and/or
*   other materials provided with the distribution.
*
* o Neither the name of Freescale Semiconductor, Inc. nor the names of its
*   contributors may be used to endorse or promote products derived from this
*   software without specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
* ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
* ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

/******************************************************************************/
/*************************** DES **********************************************/
/******************************************************************************/

#if defined(MBEDTLS_DES_C)

#if defined (MBEDTLS_FREESCALE_LTC_DES) || defined (MBEDTLS_FREESCALE_MMCAU_DES)

#include "mbedtls/des.h"

#if defined (MBEDTLS_FREESCALE_MMCAU_DES)
    const unsigned char parityLookup[128] =
    {
        1,0,0,1,0,1,1,0,0,1,1,0,1,0,0,1,0,1,1,0,1,0,0,1,1,0,0,1,0,1,1,0,
        0,1,1,0,1,0,0,1,1,0,0,1,0,1,1,0,1,0,0,1,0,1,1,0,0,1,1,0,1,0,0,1,
        0,1,1,0,1,0,0,1,1,0,0,1,0,1,1,0,1,0,0,1,0,1,1,0,0,1,1,0,1,0,0,1,
        1,0,0,1,0,1,1,0,0,1,1,0,1,0,0,1,0,1,1,0,1,0,0,1,1,0,0,1,0,1,1,0
     };
#endif

/*
 * DES key schedule (56-bit, encryption)
 */
int mbedtls_des_setkey_enc( mbedtls_des_context *ctx, const unsigned char key[MBEDTLS_DES_KEY_SIZE] )
{
    int i;

#if defined (MBEDTLS_FREESCALE_LTC_DES) 
    for(i = 0 ;i< MBEDTLS_DES_KEY_SIZE ; i++)
    {
        ctx -> sk[i] = key[i];
    }
    ctx -> mode = MBEDTLS_DES_ENCRYPT;
#elif defined (MBEDTLS_FREESCALE_MMCAU_DES)
    /* fix key parity, if needed */
    for (i = 0; i < MBEDTLS_DES_KEY_SIZE; i++)
    {
       ctx -> sk[i] = ((key[i] & 0xFE) | parityLookup[key[i] >> 1]);
    }
#endif
    ctx -> mode = MBEDTLS_DES_ENCRYPT;

    return( 0 );
}

/*
 * DES key schedule (56-bit, decryption)
 */
int mbedtls_des_setkey_dec( mbedtls_des_context *ctx, const unsigned char key[MBEDTLS_DES_KEY_SIZE] )
{
    int i;
#if defined (MBEDTLS_FREESCALE_LTC_DES) 
    for(i = 0 ;i< MBEDTLS_DES_KEY_SIZE ; i++)
    {
        ctx -> sk[i] = key[i];
    }
#elif defined (MBEDTLS_FREESCALE_MMCAU_DES)
    /* fix key parity, if needed */
    for (i = 0; i < MBEDTLS_DES_KEY_SIZE; i++)
    {
       ctx -> sk[i] = ((key[i] & 0xFE) | parityLookup[key[i] >> 1]);
    }
#endif
    ctx -> mode = MBEDTLS_DES_DECRYPT ;
    return( 0 );
}

/*
 * Triple-DES key schedule (112-bit, encryption)
 */
int mbedtls_des3_set2key_enc( mbedtls_des3_context *ctx,
                      const unsigned char key[MBEDTLS_DES_KEY_SIZE * 2] )
{
    int i;
#if defined (MBEDTLS_FREESCALE_LTC_DES) 
    for(i = 0 ; i< MBEDTLS_DES_KEY_SIZE*2 ; i++)
    {
        ctx -> sk[i] = key[i];
    }
    for (i = MBEDTLS_DES_KEY_SIZE*2; i < MBEDTLS_DES_KEY_SIZE*3; i++)
    {
       ctx -> sk[i]= key[i-MBEDTLS_DES_KEY_SIZE*2];
    }
#elif defined (MBEDTLS_FREESCALE_MMCAU_DES)
    /* fix key parity, if needed */
    for (i = 0; i < MBEDTLS_DES_KEY_SIZE*2; i++)
    {
       ctx -> sk[i] = ((key[i] & 0xFE) | parityLookup[key[i] >> 1]);
    }
    for (i = MBEDTLS_DES_KEY_SIZE*2; i < MBEDTLS_DES_KEY_SIZE*3; i++)
    {
       ctx -> sk[i]= ((key[i-MBEDTLS_DES_KEY_SIZE*2] & 0xFE) | parityLookup[key[i-MBEDTLS_DES_KEY_SIZE*2] >> 1]);
    }
#endif
    ctx -> mode = MBEDTLS_DES_ENCRYPT;
    return( 0 );
}

/*
 * Triple-DES key schedule (112-bit, decryption)
 */
int mbedtls_des3_set2key_dec( mbedtls_des3_context *ctx,
                      const unsigned char key[MBEDTLS_DES_KEY_SIZE * 2] )
{
    int i;
#if defined (MBEDTLS_FREESCALE_LTC_DES) 
    for(i = 0 ;i < MBEDTLS_DES_KEY_SIZE*2 ; i++)
    {
        ctx -> sk[i] = key[i];
    }
    for (i = MBEDTLS_DES_KEY_SIZE*2; i < MBEDTLS_DES_KEY_SIZE*3; i++)
    {
       ctx -> sk[i]= key[i-MBEDTLS_DES_KEY_SIZE*2];
    }
#elif defined (MBEDTLS_FREESCALE_MMCAU_DES)
    /* fix key parity, if needed */
    for (i = 0; i < MBEDTLS_DES_KEY_SIZE*2; i++)
    {
       ctx -> sk[i] = ((key[i] & 0xFE) | parityLookup[key[i] >> 1]);
    }
    for (i = MBEDTLS_DES_KEY_SIZE*2; i < MBEDTLS_DES_KEY_SIZE*3; i++)
    {
       ctx -> sk[i]= ((key[i-MBEDTLS_DES_KEY_SIZE*2] & 0xFE) | parityLookup[key[i-MBEDTLS_DES_KEY_SIZE*2] >> 1]);
    }
#endif
    ctx -> mode = MBEDTLS_DES_DECRYPT ;
    return( 0 );
}

/*
 * Triple-DES key schedule (168-bit, encryption)
 */
int mbedtls_des3_set3key_enc( mbedtls_des3_context *ctx,
                      const unsigned char key[MBEDTLS_DES_KEY_SIZE * 3] )
{
    int i ;
#if defined (MBEDTLS_FREESCALE_LTC_DES) 
    for(i = 0 ;i < MBEDTLS_DES_KEY_SIZE*3 ; i++)
    {
        ctx -> sk[i] = key[i];
    }
#elif defined (MBEDTLS_FREESCALE_MMCAU_DES)
    /* fix key parity, if needed */
    for (i = 0; i < MBEDTLS_DES_KEY_SIZE*3; i++)
    {
       ctx -> sk[i] = ((key[i] & 0xFE) | parityLookup[key[i] >> 1]);
    }
#endif
    ctx -> mode = MBEDTLS_DES_ENCRYPT;
    return( 0 );
}

/*
 * Triple-DES key schedule (168-bit, decryption)
 */
int mbedtls_des3_set3key_dec( mbedtls_des3_context *ctx,
                      const unsigned char key[MBEDTLS_DES_KEY_SIZE * 3] )
{
#if defined (MBEDTLS_FREESCALE_LTC_DES)
    int i ;
    for(i = 0 ;i< MBEDTLS_DES_KEY_SIZE*3 ; i++)
    {
        ctx -> sk[i] = key[i];
    }
    ctx -> mode = MBEDTLS_DES_DECRYPT ;
#elif defined (MBEDTLS_FREESCALE_MMCAU_DES)
    int i ;
    /* fix key parity, if needed */
    for (i = 0; i < MBEDTLS_DES_KEY_SIZE*3; i++)
    {
       ctx -> sk[i] = ((key[i] & 0xFE) | parityLookup[key[i] >> 1]);
    }
    ctx -> mode = MBEDTLS_DES_DECRYPT;
#endif
    return( 0 );
}

/*
 * DES-ECB block encryption/decryption
 */
int mbedtls_des_crypt_ecb( mbedtls_des_context *ctx,
                    const unsigned char input[8],
                    unsigned char output[8] )
{
    uint8_t key[8];
    int i;

    for(i = 0 ; i < 8 ; i++)
    {
        key[i] = (uint8_t)ctx ->sk[i] ;
    }
#if defined(MBEDTLS_FREESCALE_LTC_DES)
    if(ctx -> mode == MBEDTLS_DES_ENCRYPT)
    {
        LTC_DES_encrypt_ecb( LTC_INSTANCE, input, output, 8, key) ;
    }
    else
    {
        LTC_DES_decrypt_ecb( LTC_INSTANCE, input, output, 8, key);
    }
#elif defined (MBEDTLS_FREESCALE_MMCAU_DES)
    if(ctx -> mode == MBEDTLS_DES_ENCRYPT)
    {
        cau_des_encrypt(input, key, output);
    }
    else
    {
        cau_des_decrypt(input, key, output);
    }    
#endif 
    return( 0 );
}

/*
 * 3DES-ECB block encryption/decryption
 */
int mbedtls_des3_crypt_ecb( mbedtls_des3_context *ctx,
                     const unsigned char input[8],
                     unsigned char output[8] )
{
    uint8_t key[24];
    int i;
    for(i = 0 ; i < 24 ; i++)
    {
        key[i] = (uint8_t)ctx ->sk[i] ;
    }
#if defined (MBEDTLS_FREESCALE_LTC_DES)
    if(ctx -> mode == MBEDTLS_DES_ENCRYPT)
    {
        LTC_DES3_encrypt_ecb(LTC_INSTANCE, input, output, 8, key, key + 8, key + 16);
    }
    else
    {
        LTC_DES3_decrypt_ecb(LTC_INSTANCE, input, output, 8, key, key + 8, key + 16);
    }
#elif defined (MBEDTLS_FREESCALE_MMCAU_DES)
    if(ctx -> mode == MBEDTLS_DES_ENCRYPT)
    {
        cau_des_encrypt(input, key, output);
        cau_des_decrypt(output, key + 8, output);
        cau_des_encrypt(output, key + 16, output);
    }
    else
    {
        cau_des_decrypt(input, key + 16 , output);
        cau_des_encrypt(output, key + 8, output);
        cau_des_decrypt(output, key , output);
    }    
#endif
    return( 0 );
}

#if defined(MBEDTLS_CIPHER_MODE_CBC)
/*
 * DES-CBC buffer encryption/decryption
 */
#if defined(MBEDTLS_FREESCALE_LTC_DES)
int mbedtls_des_crypt_cbc( mbedtls_des_context *ctx,
                    int mode,
                    size_t length,
                    unsigned char iv[8],
                    const unsigned char *input,
                    unsigned char *output )
{
    int i;
    unsigned char temp[8];

    uint8_t key[8];
    for(i = 0 ; i < 8 ; i++)
    {
        key[i] = (uint8_t)ctx ->sk[i] ;
    }

    if( length % 8 )
        return( MBEDTLS_ERR_DES_INVALID_INPUT_LENGTH );

    if( mode == MBEDTLS_DES_ENCRYPT )
    {
        LTC_DES_encrypt_cbc(LTC_INSTANCE, input, output, length, iv, key);
        memcpy( iv, output + length - 8, 8 );
    }
    else /* MBEDTLS_DES_DECRYPT */
    {
        memcpy( temp, input + length - 8, 8 );
        LTC_DES_decrypt_cbc(LTC_INSTANCE, input, output, length, iv, key) ;
        memcpy( iv, temp, 8 );
    }
    return( 0 );
}

/*
 * 3DES-CBC buffer encryption/decryption
 */
int mbedtls_des3_crypt_cbc( mbedtls_des3_context *ctx,
                     int mode,
                     size_t length,
                     unsigned char iv[8],
                     const unsigned char *input,
                     unsigned char *output )
{
    int i;
    unsigned char temp[8];

    if( length % 8 )
        return( MBEDTLS_ERR_DES_INVALID_INPUT_LENGTH );

    uint8_t key[24];
    for(i = 0 ; i < 24 ; i++)
    {
        key[i] = (uint8_t)ctx ->sk[i] ;
    }

    if( mode == MBEDTLS_DES_ENCRYPT )
    {
        LTC_DES3_encrypt_cbc(LTC_INSTANCE, input, output, length, iv, key, key + 8, key + 16);
        memcpy( iv, output + length - 8, 8 );
    }
    else /* MBEDTLS_DES_DECRYPT */
    {
        memcpy( temp, input + length - 8, 8 );
        LTC_DES3_decrypt_cbc(LTC_INSTANCE, input, output, length, iv, key, key + 8, key + 16) ;
        memcpy( iv, temp, 8 );
    }

    return( 0 );
}

#endif /* MBEDTLS_FREESCALE_LTC_DES */
#endif /* MBEDTLS_CIPHER_MODE_CBC */

#endif /*MBEDTLS_FREESCALE_LTC_DES || MBEDTLS_FREESCALE_MMCAU_DES*/

#endif /* MBEDTLS_DES_C */


/******************************************************************************/
/*************************** AES **********************************************/
/******************************************************************************/

#if defined(MBEDTLS_AES_C)

#if defined (MBEDTLS_FREESCALE_LTC_AES) || defined (MBEDTLS_FREESCALE_MMCAU_AES)

#include "mbedtls/aes.h"

/*
 * AES key schedule (encryption)
 */
int mbedtls_aes_setkey_enc( mbedtls_aes_context *ctx, const unsigned char *key,
                    unsigned int keybits )
{
    uint32_t *RK;

#if defined(MBEDTLS_FREESCALE_LTC_AES)
    const unsigned char *key_tmp = key;
    ctx->rk = RK = ctx->buf;
    memcpy( RK, key_tmp, keybits/8 );
   
    switch( keybits )
    { /* Set keysize in bytes.*/
        case 128: ctx->nr = 16; break;
        case 192: ctx->nr = 24; break;
        case 256: ctx->nr = 32; break;
        default : return( MBEDTLS_ERR_AES_INVALID_KEY_LENGTH );
    }
#elif defined(MBEDTLS_FREESCALE_MMCAU_AES)
    ctx->rk = RK = ctx->buf;

    switch( keybits )
    {
        case 128: ctx->nr = 10; break;
        case 192: ctx->nr = 12; break;
        case 256: ctx->nr = 14; break;
        default : return( MBEDTLS_ERR_AES_INVALID_KEY_LENGTH );
    }

    cau_aes_set_key(key, keybits, (unsigned char *)RK);
#endif 
    return( 0 );
}

/*
 * AES key schedule (decryption)
 */
int mbedtls_aes_setkey_dec( mbedtls_aes_context *ctx, const unsigned char *key,
                    unsigned int keybits )
{
    uint32_t *RK;

    ctx->rk = RK = ctx->buf;

#if defined(MBEDTLS_FREESCALE_LTC_AES)
    const unsigned char *key_tmp = key;
    
    memcpy( RK, key_tmp, keybits/8 );

    switch( keybits )
    {
        case 128: ctx->nr = 16; break;
        case 192: ctx->nr = 24; break;
        case 256: ctx->nr = 32; break;
        default : return( MBEDTLS_ERR_AES_INVALID_KEY_LENGTH );
    }
#elif defined(MBEDTLS_FREESCALE_MMCAU_AES)
    ctx->rk = RK = ctx->buf;

    switch( keybits )
    {
        case 128: ctx->nr = 10; break;
        case 192: ctx->nr = 12; break;
        case 256: ctx->nr = 14; break;
        default : return( MBEDTLS_ERR_AES_INVALID_KEY_LENGTH );
    }

    cau_aes_set_key((unsigned char *)key, keybits, (unsigned char *)RK);
#endif 
    return 0;
}

/*
 * AES-ECB block encryption
 */
void mbedtls_aes_encrypt( mbedtls_aes_context *ctx,
                          const unsigned char input[16],
                          unsigned char output[16] )
{
    uint8_t *key ;

    key = (uint8_t *)ctx -> rk ;
#if defined (MBEDTLS_FREESCALE_LTC_AES)
    LTC_AES_EncryptEcb( LTC_INSTANCE, input, output, 16, key, ctx->nr);
#elif defined(MBEDTLS_FREESCALE_MMCAU_AES)
    cau_aes_encrypt(input, key, ctx->nr, output);
#endif 
}

/*
 * AES-ECB block decryption
 */
void mbedtls_aes_decrypt( mbedtls_aes_context *ctx,
                          const unsigned char input[16],
                          unsigned char output[16] )
{
    uint8_t *key ;

    key = (uint8_t *)ctx -> rk ;
#if defined (MBEDTLS_FREESCALE_LTC_AES)
    LTC_AES_DecryptEcb(LTC_INSTANCE, input, output, 16, key, ctx->nr, kLTC_EncryptKey);
#elif defined(MBEDTLS_FREESCALE_MMCAU_AES)
    cau_aes_decrypt(input, key, ctx->nr, output);
#endif 
}

#if defined(MBEDTLS_CIPHER_MODE_CBC)
/*
 * AES-CBC buffer encryption/decryption
 */
#if defined(MBEDTLS_FREESCALE_LTC_AES)
int mbedtls_aes_crypt_cbc( mbedtls_aes_context *ctx,
                    int mode,
                    size_t length,
                    unsigned char iv[16],
                    const unsigned char *input,
                    unsigned char *output )
{
    int i;
    unsigned char temp[16];

    uint8_t *key = (uint8_t*)ctx ->rk ;
    uint32_t keySize = ctx->nr ;
    memcpy( temp, input, 16 );

    if( length % 16 )
        return( MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH );

    if( mode == MBEDTLS_AES_DECRYPT )
    {
        LTC_AES_DecryptCbc(LTC_INSTANCE, temp, output, length, iv, key, keySize, kLTC_EncryptKey);
        memcpy( iv, temp, 16 );
    }
    else
    {
        LTC_AES_EncryptCbc(LTC_INSTANCE, temp, output, length, iv, key, keySize);
        memcpy( iv, output, 16 );
    }

    return( 0 );
}
#endif /* MBEDTLS_FREESCALE_LTC_AES */
#endif /* MBEDTLS_CIPHER_MODE_CBC */

#if defined(MBEDTLS_CIPHER_MODE_CTR)
/*
 * AES-CTR buffer encryption/decryption
 */
#if defined(MBEDTLS_FREESCALE_LTC_AES)
int mbedtls_aes_crypt_ctr( mbedtls_aes_context *ctx,
                       size_t length,
                       size_t *nc_off,
                       unsigned char nonce_counter[16],
                       unsigned char stream_block[16],
                       const unsigned char *input,
                       unsigned char *output )
{
    uint8_t *key ;
    uint32_t keySize ;

    key = (uint8_t *)ctx->rk;
    keySize = ctx->nr ;
    LTC_AES_CryptCtr(LTC_INSTANCE, input, output, length, nonce_counter, key, keySize, stream_block, nc_off);

    return( 0 );
}
#endif /* MBEDTLS_FREESCALE_LTC_AES */
#endif /* MBEDTLS_CIPHER_MODE_CTR */

#if defined(MBEDTLS_CCM_C)

#include "mbedtls/ccm.h"

#define CCM_ENCRYPT 0
#define CCM_DECRYPT 1

/*
 * Authenticated encryption or decryption
 */
#if defined(MBEDTLS_FREESCALE_LTC_AES)
static int ccm_auth_crypt( mbedtls_ccm_context *ctx, int mode, size_t length,
                           const unsigned char *iv, size_t iv_len,
                           const unsigned char *add, size_t add_len,
                           const unsigned char *input, unsigned char *output,
                           unsigned char *tag, size_t tag_len )
{

    const uint8_t *key ;
    uint8_t keySize ;
    mbedtls_aes_context *aes_ctx ;

    aes_ctx = (mbedtls_aes_context*)ctx -> cipher_ctx.cipher_ctx ;
    key = (uint8_t*)aes_ctx->rk ;
    keySize = aes_ctx->nr ;
    if( mode == CCM_ENCRYPT )
    {
        LTC_AES_EncryptTagCcm(LTC_INSTANCE, input, output, length, iv, iv_len, add, add_len, key, keySize, tag, tag_len);
    }
    else
    {
        LTC_AES_DecryptTagCcm(LTC_INSTANCE, input, output, length, iv, iv_len, add, add_len, key, keySize, tag, tag_len);
    }
    return( 0 );
}

/*
 * Authenticated encryption
 */
int mbedtls_ccm_encrypt_and_tag( mbedtls_ccm_context *ctx, size_t length,
                         const unsigned char *iv, size_t iv_len,
                         const unsigned char *add, size_t add_len,
                         const unsigned char *input, unsigned char *output,
                         unsigned char *tag, size_t tag_len )
{
    return( ccm_auth_crypt( ctx, CCM_ENCRYPT, length, iv, iv_len,
                            add, add_len, input, output, tag, tag_len ) );
}

/*
 * Authenticated decryption
 */
int mbedtls_ccm_auth_decrypt( mbedtls_ccm_context *ctx, size_t length,
                      const unsigned char *iv, size_t iv_len,
                      const unsigned char *add, size_t add_len,
                      const unsigned char *input, unsigned char *output,
                      const unsigned char *tag, size_t tag_len )
{
    int ret;
    unsigned char check_tag[16];
    unsigned char i;
    int diff;

    if( ( ret = ccm_auth_crypt( ctx, CCM_DECRYPT, length,
                                iv, iv_len, add, add_len,
                                input, output, check_tag, tag_len ) ) != 0 )
    {
        return( ret );
    }

    return( 0 );
}
#endif /* MBEDTLS_FREESCALE_LTC_AES */
#endif /* MBEDTLS_CCM_C */



#if defined(MBEDTLS_GCM_C)
#if defined(MBEDTLS_FREESCALE_LTC_AES)

#include "mbedtls/gcm.h"

int mbedtls_gcm_crypt_and_tag( mbedtls_gcm_context *ctx,
                       int mode,
                       size_t length,
                       const unsigned char *iv,
                       size_t iv_len,
                       const unsigned char *add,
                       size_t add_len,
                       const unsigned char *input,
                       unsigned char *output,
                       size_t tag_len,
                       unsigned char *tag )
{

    uint8_t *key ;
    uint32_t keySize ;
    mbedtls_aes_context *aes_ctx ;

    ctx ->len =  length ;
    ctx -> add_len = add_len ;
    aes_ctx = (mbedtls_aes_context*)ctx ->cipher_ctx.cipher_ctx ;
    key = (uint8_t *)aes_ctx -> rk ;
    keySize = aes_ctx->nr;
    if( mode == MBEDTLS_GCM_ENCRYPT)
    {
        LTC_AES_EncryptTagGcm(LTC_INSTANCE, input, output, length, iv, iv_len, add, add_len, key, keySize, tag, tag_len);
    }
    else
    {
        LTC_AES_DecryptTagGcm(LTC_INSTANCE, input, output, length, iv, iv_len, add, add_len, key, keySize, tag, tag_len);
    }

    return( 0 );
}

#endif /* MBEDTLS_FREESCALE_LTC_AES */
#endif /* MBEDTLS_GCM_C */

#endif /* MBEDTLS_FREESCALE_LTC_AES || MBEDTLS_FREESCALE_MMCAU_AES */

#endif /* MBEDTLS_AES_C */

/******************************************************************************/
/*************************** PKHA *********************************************/
/******************************************************************************/

#if defined(MBEDTLS_FREESCALE_LTC_PKHA)

static void ltc_reverse_array(uint8_t *src, size_t src_len)
{
    int i;

    for (i = 0; i < src_len/2; i++)
    {
        uint8_t tmp;

        tmp = src[i];
        src[i] = src[src_len - 1 - i];
        src[src_len - 1 - i] = tmp;
    }
}


#if defined(MBEDTLS_BIGNUM_C)

#include "mbedtls/bignum.h"

#define LTC_MAX_INT     256


/*
 * Unsigned addition: X = |A| + |B|  (HAC 14.7)
 */
int mbedtls_mpi_add_abs( mbedtls_mpi *X, const mbedtls_mpi *A, const mbedtls_mpi *B )
{
    int ret;
    size_t i, j;
    uint16_t sizeN = LTC_MAX_INT;
    uint8_t  N[LTC_MAX_INT];

    memset(N,  0xFF, sizeN);

    uint8_t ptrA[LTC_MAX_INT], ptrB[LTC_MAX_INT], ptrC[LTC_MAX_INT];
    uint16_t sizeA, sizeB, sizeC;

    sizeA = mbedtls_mpi_size(A);
    sizeB = mbedtls_mpi_size(B);
    if ((sizeA > sizeN) || (sizeB > sizeN))
    {
        return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }
    mbedtls_mpi_write_binary(A, ptrA, sizeA);
    ltc_reverse_array(ptrA, sizeA);

    mbedtls_mpi_write_binary(B, ptrB, sizeB);
    ltc_reverse_array(ptrB, sizeB);

    ret = (int)LTC_PKHA_ModAdd(LTC_INSTANCE, ptrA, sizeA, ptrB, sizeB, N, sizeN, ptrC, &sizeC, kLTC_PKHA_IntegerArith);

    if (ret != kStatus_Success)
        return ret;

    ltc_reverse_array(ptrC, sizeC);
    mbedtls_mpi_read_binary(X, ptrC, sizeC);
    X->s = 1;

    return( ret );
}

/*
 * Unsigned subtraction: X = |A| - |B|  (HAC 14.9)
 */
int mbedtls_mpi_sub_abs( mbedtls_mpi *X, const mbedtls_mpi *A, const mbedtls_mpi *B )
{
    int ret;
    uint16_t sizeN = LTC_MAX_INT;
    uint8_t  N[LTC_MAX_INT];

    memset(N,  0xFF, sizeN);

    uint8_t ptrA[LTC_MAX_INT], ptrB[LTC_MAX_INT], ptrC[LTC_MAX_INT];
    uint16_t sizeA, sizeB, sizeC;

    sizeA = mbedtls_mpi_size(A);
    sizeB = mbedtls_mpi_size(B);
    if ((sizeA > sizeN) || (sizeB > sizeN))
    {
        return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }
    mbedtls_mpi_write_binary(A, ptrA, sizeA);
    ltc_reverse_array(ptrA, sizeA);

    mbedtls_mpi_write_binary(B, ptrB, sizeB);
    ltc_reverse_array(ptrB, sizeB);

    ret = (int)LTC_PKHA_ModSub1(LTC_INSTANCE, ptrA, sizeA, ptrB, sizeB, N, sizeN, ptrC, &sizeC);

    if (ret != kStatus_Success)
        return ret;

    ltc_reverse_array(ptrC, sizeC);
    mbedtls_mpi_read_binary(X, ptrC, sizeC);
    X->s = 1;

    return( ret );
}

/*
 * Baseline multiplication: X = A * B  (HAC 14.12)
 */
int mbedtls_mpi_mul_mpi( mbedtls_mpi *X, const mbedtls_mpi *A, const mbedtls_mpi *B )
{
    int ret;
    uint16_t    sizeN = LTC_MAX_INT;
    uint8_t  N[LTC_MAX_INT];
    uint8_t     ptrA[LTC_MAX_INT], ptrB[LTC_MAX_INT], ptrC[LTC_MAX_INT];
    uint16_t    sizeA, sizeB, sizeC;

    memset(N,  0xFF, sizeN);

    sizeA = mbedtls_mpi_size(A);
    sizeB = mbedtls_mpi_size(B);
    if ((sizeA > sizeN) || (sizeB > sizeN))
    {
        return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }
    mbedtls_mpi_write_binary(A, ptrA, sizeA);
    ltc_reverse_array(ptrA, sizeA);

    mbedtls_mpi_write_binary(B, ptrB, sizeB);
    ltc_reverse_array(ptrB, sizeB);

    ret = (int)LTC_PKHA_ModMul(LTC_INSTANCE, ptrA, sizeA, ptrB, sizeB, N, sizeN, ptrC, &sizeC,
                                    kLTC_PKHA_IntegerArith,
                                    kLTC_PKHA_NormalValue,
                                    kLTC_PKHA_NormalValue,
                                    kLTC_PKHA_TimingEqualized);

    if (ret != kStatus_Success)
        return ret;

    ltc_reverse_array(ptrC, sizeC);
    mbedtls_mpi_read_binary(X, ptrC, sizeC);
    X->s = A->s * B->s;

    return( ret );
}

/*
 * Modulo: R = A mod B
 */
int mbedtls_mpi_mod_mpi( mbedtls_mpi *R, const mbedtls_mpi *A, const mbedtls_mpi *B )
{
    int ret;
    uint8_t ptrA[LTC_MAX_INT], ptrB[LTC_MAX_INT], ptrC[LTC_MAX_INT];
    uint16_t sizeA, sizeB, sizeC;

    sizeA = mbedtls_mpi_size(A);
    sizeB = mbedtls_mpi_size(B);
    if ((sizeA > sizeof(ptrA)) || (sizeB > sizeof(ptrB)))
    {
        return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }
    mbedtls_mpi_write_binary(A, ptrA, sizeA);
    ltc_reverse_array(ptrA, sizeA);

    mbedtls_mpi_write_binary(B, ptrB, sizeB);
    ltc_reverse_array(ptrB, sizeB);

    ret = (int)LTC_PKHA_ModRed(LTC_INSTANCE, ptrA, sizeA, ptrB, sizeB, ptrC, &sizeC, kLTC_PKHA_IntegerArith);

    if (ret != kStatus_Success)
        return ret;

    ltc_reverse_array(ptrC, sizeC);
    mbedtls_mpi_read_binary(R, ptrC, sizeC);
    R->s = A->s;

    while( mbedtls_mpi_cmp_int( R, 0 ) < 0 )
        mbedtls_mpi_add_mpi( R, R, B ); /* MBEDTLS_MPI_CHK( mbedtls_mpi_add_mpi( R, R, B ) ); */

    while( mbedtls_mpi_cmp_mpi( R, B ) >= 0 )
        mbedtls_mpi_sub_mpi( R, R, B ); /* MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mpi( R, R, B ) ); cleanup:*/

    return( ret );
}

/*
 * Sliding-window exponentiation: X = A^E mod N  (HAC 14.85)
 */
int mbedtls_mpi_exp_mod( mbedtls_mpi *X, const mbedtls_mpi *A, const mbedtls_mpi *E, const mbedtls_mpi *N, mbedtls_mpi *_RR )
{
    int ret;
    uint8_t ptrA[LTC_MAX_INT], ptrE[LTC_MAX_INT], ptrN[LTC_MAX_INT];
    uint16_t sizeA, sizeE, sizeN;

    sizeA = mbedtls_mpi_size(A);
    sizeE = mbedtls_mpi_size(E);
    sizeN = mbedtls_mpi_size(N);
    if ((sizeA > LTC_MAX_INT) || (sizeE > LTC_MAX_INT) || (sizeN > LTC_MAX_INT))
    {
        return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }
    mbedtls_mpi_write_binary(A, ptrA, sizeA);
    ltc_reverse_array(ptrA, sizeA);

    mbedtls_mpi_write_binary(E, ptrE, sizeE);
    ltc_reverse_array(ptrE, sizeE);

    mbedtls_mpi_write_binary(N, ptrN, sizeN);
    ltc_reverse_array(ptrN, sizeN);

    /* if number if greater that modulo, we must first reduce due to LTC requirement on modular exponentiaton */
    /* it needs number less than modulus.  */
    /* we can take advantage of modular arithmetic rule that: A^B mod C = ( (A mod C)^B ) mod C
       and so we do first (A mod N) : LTC does not give size requirement on A versus N,
       and then the modular exponentiation.
     */
    //if (sizeE < sizeA)
    /* if A >= N then */
    if (mbedtls_mpi_cmp_mpi (A, N) >= 0)
    {
        ret = (int)LTC_PKHA_ModRed(LTC_INSTANCE, ptrA, sizeA, ptrN, sizeN, ptrA, &sizeA, kLTC_PKHA_IntegerArith);

        if (ret != kStatus_Success)
            return ret;
    }

    ret = (int)LTC_PKHA_ModExp(LTC_INSTANCE, ptrA, sizeA, ptrN, sizeN, ptrE, sizeE, ptrN, &sizeN,
                                   kLTC_PKHA_IntegerArith, kLTC_PKHA_NormalValue, kLTC_PKHA_TimingEqualized);

    if (ret != kStatus_Success)
        return ret;

    ltc_reverse_array(ptrN, sizeN);
    mbedtls_mpi_read_binary(X, ptrN, sizeN);

    return( ret );
}

/*
 * Greatest common divisor: G = gcd(A, B)  (HAC 14.54)
 */
int mbedtls_mpi_gcd( mbedtls_mpi *G, const mbedtls_mpi *A, const mbedtls_mpi *B )
{
    int ret;
    uint8_t ptrA[LTC_MAX_INT], ptrB[LTC_MAX_INT], ptrC[LTC_MAX_INT];
    uint16_t sizeA, sizeB, sizeC;

    sizeA = mbedtls_mpi_size(A);
    sizeB = mbedtls_mpi_size(B);
    if ((sizeA > LTC_MAX_INT) || (sizeB > LTC_MAX_INT))
    {
        return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }
    mbedtls_mpi_write_binary(A, ptrA, sizeA);
    ltc_reverse_array(ptrA, sizeA);

    mbedtls_mpi_write_binary(B, ptrB, sizeB);
    ltc_reverse_array(ptrB, sizeB);

    if (mbedtls_mpi_cmp_mpi(A, B) >= 0)
    {
        ret = (int)LTC_PKHA_ModRed(LTC_INSTANCE, ptrA, sizeA, ptrB, sizeB, ptrA, &sizeA, kLTC_PKHA_IntegerArith);

        if (ret != kStatus_Success)
            return ret;
    }

    ret = (int)LTC_PKHA_GCD(LTC_INSTANCE, ptrA, sizeA, ptrB, sizeB, ptrC, &sizeC, kLTC_PKHA_IntegerArith);

    if (ret != kStatus_Success)
        return ret;

    ltc_reverse_array(ptrC, sizeC);
    mbedtls_mpi_read_binary(G, ptrC, sizeC);

    return( ret );
}

/*
 * Modular inverse: X = A^-1 mod N  (HAC 14.61 / 14.64)
 */
int mbedtls_mpi_inv_mod( mbedtls_mpi *X, const mbedtls_mpi *A, const mbedtls_mpi *N )
{
    int ret;
    uint8_t ptrA[LTC_MAX_INT], ptrN[LTC_MAX_INT], ptrC[LTC_MAX_INT];
    uint16_t sizeA, sizeN, sizeC;

    /* N cannot be negative */
    if (N->s < 0 || mbedtls_mpi_cmp_int(N, 0) == 0)
    {
        return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }

    sizeA = mbedtls_mpi_size(A);
    sizeN = mbedtls_mpi_size(N);
    if ((sizeA > LTC_MAX_INT) || (sizeN > LTC_MAX_INT))
    {
        return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }
    mbedtls_mpi_write_binary(A, ptrA, sizeA);
    ltc_reverse_array(ptrA, sizeA);

    mbedtls_mpi_write_binary(N, ptrN, sizeN);
    ltc_reverse_array(ptrN, sizeN);

    if (mbedtls_mpi_cmp_mpi(A, N) >= 0)
    {
        ret = (int)LTC_PKHA_ModRed(LTC_INSTANCE, ptrA, sizeA, ptrN, sizeN, ptrA, &sizeA, kLTC_PKHA_IntegerArith);

        if (ret != kStatus_Success)
            return ret;
    }

    ret = (int)LTC_PKHA_ModInv(LTC_INSTANCE, ptrA, sizeA, ptrN, sizeN, ptrC, &sizeC, kLTC_PKHA_IntegerArith);

    if (ret != kStatus_Success)
        return ret;

    ltc_reverse_array(ptrC, sizeC);
    mbedtls_mpi_read_binary(X, ptrC, sizeC);

    return( ret );
}

/*
 * Pseudo-primality test: small factors, then Miller-Rabin
 */
int mbedtls_mpi_is_prime( const mbedtls_mpi *X,
                  int (*f_rng)(void *, unsigned char *, size_t),
                  void *p_rng )
{
    int ret;
    uint8_t ptrX[LTC_MAX_INT];
    uint16_t sizeX;
    int random;
    bool result = false;

    sizeX = mbedtls_mpi_size(X);
    if (sizeX > LTC_MAX_INT)
    {
        return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }
    mbedtls_mpi_write_binary(X, ptrX, LTC_MAX_INT);
    ltc_reverse_array(ptrX, LTC_MAX_INT);

    // Get the random seed number
    f_rng( p_rng, (unsigned char*)(&random), sizeof(random) );

    ret = (int)LTC_PKHA_PrimalityTest(LTC_INSTANCE, (unsigned char*)&random, sizeof(random), "1", 1, ptrX, sizeX, &result);

    if (ret != kStatus_Success)
        return ret;

    if (result == false)
        return MBEDTLS_ERR_MPI_NOT_ACCEPTABLE;

    return ret;
}

#endif /* MBEDTLS_BIGNUM_C */



#if defined(MBEDTLS_ECP_C)

#include "mbedtls/ecp.h"

#define LTC_MAX_ECC (512)


/*
 * Multiplication using the comb method,
 * for curves in short Weierstrass form
 */
int ecp_mul_comb( mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                         const mbedtls_mpi *m, const mbedtls_ecp_point *P,
                         int (*f_rng)(void *, unsigned char *, size_t),
                         void *p_rng )
{
    int ret;
    bool is_inf;
    size_t size;
    ltc_pkha_ecc_point_t A;
    ltc_pkha_ecc_point_t result;

    uint8_t AX[LTC_MAX_ECC/8] = {0};
    uint8_t AY[LTC_MAX_ECC/8] = {0};
    uint8_t RX[LTC_MAX_ECC/8] = {0};
    uint8_t RY[LTC_MAX_ECC/8] = {0};
    uint8_t E[LTC_MAX_ECC/8] = {0};
    uint8_t N[LTC_MAX_ECC/8] = {0};
    uint8_t paramA[LTC_MAX_ECC/8] = {0};
    uint8_t paramB[LTC_MAX_ECC/8] = {0};
        
    A.X = AX;
    A.Y = AY;
    result.X = RX;
    result.Y = RY;
    size = mbedtls_mpi_size( &grp->P );
    if ( mbedtls_mpi_size( &P->X ) > ( LTC_MAX_ECC/8 ) || ( mbedtls_mpi_get_bit( &grp->N, 0 ) != 1 ) )
    {
        return ( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );
    }

    /* Convert multi precision integers to arrays */
    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &P->X, A.X, size ) );
    ltc_reverse_array( A.X, size );
    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &P->Y, A.Y, size ) );
    ltc_reverse_array( A.Y, size );
    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( m, E, size ) );
    ltc_reverse_array( E, size );
    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &grp->A, paramA, size ) );
    ltc_reverse_array( paramA, size );
    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &grp->B, paramB, size ) );
    ltc_reverse_array( paramB, size );
    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &grp->P, N, size ) );
    ltc_reverse_array( N, size );
    /* Multiply */
    LTC_PKHA_ECC_PointMul(LTC_INSTANCE, &A, E, sizeof( E ), N, NULL, paramA, paramB, size, kLTC_PKHA_TimingEqualized, kLTC_PKHA_IntegerArith, &result, &is_inf );
    /* Convert result */
    ltc_reverse_array( RX, size );
    MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &R->X, RX, size ) );
    ltc_reverse_array( RY, size );
    MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &R->Y, RY, size ) );
    R->X.s = P->X.s;
    R->Y.s = P->Y.s;
    mbedtls_mpi_read_string( &R->Z, 10, "1" );

cleanup:
    return( ret );
}

/*
 * Curve types: internal for now, might be exposed later
 */
typedef enum
{
    ECP_TYPE_NONE = 0,
    ECP_TYPE_SHORT_WEIERSTRASS,    /* y^2 = x^3 + a x + b      */
    ECP_TYPE_MONTGOMERY,           /* y^2 = x^3 + a x^2 + x    */
} ecp_curve_type;
/*
 * Get the type of a curve
 */
static inline ecp_curve_type ecp_get_type( const mbedtls_ecp_group *grp )
{
    if( grp->G.X.p == NULL )
        return( ECP_TYPE_NONE );

    if( grp->G.Y.p == NULL )
        return( ECP_TYPE_MONTGOMERY );
    else
        return( ECP_TYPE_SHORT_WEIERSTRASS );
}

/*
 * Addition: R = P + Q, result's coordinates normalized
 */
int ecp_add( const mbedtls_ecp_group *grp, mbedtls_ecp_point *R,  const mbedtls_ecp_point *P, const mbedtls_ecp_point *Q )
{    
    int ret;
    bool is_inf;
    size_t size;
    ltc_pkha_ecc_point_t A;
    ltc_pkha_ecc_point_t B;
    ltc_pkha_ecc_point_t result;

    uint8_t AX[LTC_MAX_ECC/8] = {0};
    uint8_t AY[LTC_MAX_ECC/8] = {0};
    uint8_t BX[LTC_MAX_ECC/8] = {0};
    uint8_t BY[LTC_MAX_ECC/8] = {0};
    uint8_t RX[LTC_MAX_ECC/8] = {0};
    uint8_t RY[LTC_MAX_ECC/8] = {0};
    uint8_t N[LTC_MAX_ECC/8] = {0};
    uint8_t paramA[LTC_MAX_ECC/8] = {0};
    uint8_t paramB[LTC_MAX_ECC/8] = {0};


    if( ecp_get_type( grp ) != ECP_TYPE_SHORT_WEIERSTRASS )
        return( MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE );
    
    A.X = AX;
    A.Y = AY;
    B.X = BX;
    B.Y = BY;
    result.X = RX;
    result.Y = RY;
    size = mbedtls_mpi_size( &grp->P );
    if ( mbedtls_mpi_size( &P->X ) > ( LTC_MAX_ECC/8 ) || ( mbedtls_mpi_get_bit( &grp->P, 0 ) != 1 ) )
    {
        return ( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );
    }

    /* Convert multi precision integers to arrays */
    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &P->X, A.X, size ) );
    ltc_reverse_array( A.X, size );
    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &P->Y, A.Y, size ) );
    ltc_reverse_array( A.Y, size );
    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &Q->X, B.X, size ) );
    ltc_reverse_array( B.X, size );
    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &Q->Y, B.Y, size ) );
    ltc_reverse_array( B.Y, size );
    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &grp->A, paramA, size ) );
    ltc_reverse_array( paramA, size );
    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &grp->B, paramB, size ) );
    ltc_reverse_array( paramB, size );
    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &grp->P, N, size ) );
    ltc_reverse_array( N, size );
    /* Multiply */
    LTC_PKHA_ECC_PointAdd(LTC_INSTANCE, &A, &B, N, NULL, paramA, paramB, size, kLTC_PKHA_IntegerArith, &result);
    /* Convert result */
    ltc_reverse_array( RX, size );
    MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &R->X, RX, size ) );
    ltc_reverse_array( RY, size );
    MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &R->Y, RY, size ) );
    R->X.s = P->X.s;
    R->Y.s = P->Y.s;
    mbedtls_mpi_read_string( &R->Z, 10, "1" );

cleanup:
    return( ret );
}

#endif /* MBEDTLS_ECP_C */

#endif /* MBEDTLS_FREESCALE_LTC_PKHA */

/******************************************************************************/
/*************************** MD5 **********************************************/
/******************************************************************************/

#if defined(MBEDTLS_MD5_C)

#if defined(MBEDTLS_FREESCALE_MMCAU_MD5)

#include "mbedtls/md5.h"

void mbedtls_md5_process( mbedtls_md5_context *ctx, const unsigned char data[64] )
{
    cau_md5_hash_n((data), 1, (unsigned char*)(ctx)->state);
}


#endif /* MBEDTLS_FREESCALE_MMCAU_MD5 */

#endif /* MBEDTLS_MD5_C */

/******************************************************************************/
/*************************** SHA1 *********************************************/
/******************************************************************************/

#if defined(MBEDTLS_SHA1_C)
#if defined(MBEDTLS_FREESCALE_MMCAU_SHA1)

#include "mbedtls/sha1.h"

void mbedtls_sha1_process( mbedtls_sha1_context *ctx, const unsigned char data[64] )
{
    cau_sha1_hash_n((data), 1, (unsigned int *)(ctx)->state);
}


#endif /* MBEDTLS_FREESCALE_MMCAU_SHA1 */
#endif /* MBEDTLS_SHA1_C */

/******************************************************************************/
/*************************** SHA256********************************************/
/******************************************************************************/

#if defined(MBEDTLS_SHA256_C)
#if defined(MBEDTLS_FREESCALE_MMCAU_SHA256)

#include "mbedtls/sha256.h"

void mbedtls_sha256_process( mbedtls_sha256_context *ctx, const unsigned char data[64] )
{
    cau_sha256_hash_n((data), 1, (unsigned int *)(ctx)->state);
}

#endif /* MBEDTLS_FREESCALE_MMCAU_SHA1 */
#endif /* MBEDTLS_SHA1_C */
