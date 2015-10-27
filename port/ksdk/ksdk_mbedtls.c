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

#if defined(MBEDTLS_DES_C)

#include "mbedtls/des.h"

#if defined (MBEDTLS_FREESCALE_LTC_DES) || defined (MBEDTLS_FREESCALE_MMCAU_DES)


/*************************** DES **********************************************/


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


/*************************** AES **********************************************/

#if defined(MBEDTLS_AES_C)

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



#endif /* MBEDTLS_AES_C */
