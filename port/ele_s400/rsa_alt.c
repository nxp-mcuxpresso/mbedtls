/*
 * Copyright 2022 NXP
 * All rights reserved.
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "common.h"

#if defined(MBEDTLS_RSA_C)

#include <string.h>

#include "mbedtls/rsa.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/platform.h"
#include "mbedtls/error.h"

#if defined(MBEDTLS_RSA_KEYGEN_ALT) || defined(MBEDTLS_PKCS1_V15_ALT) || defined(MBEDTLS_PKCS1_V21_ALT)
#include "rsa_alt.h"
#include "ele_crypto.h"
#include "ele_mbedtls.h"

#define RSA_VALIDATE_RET( cond ) \
    MBEDTLS_INTERNAL_VALIDATE_RET( cond, MBEDTLS_ERR_RSA_BAD_INPUT )
#define RSA_VALIDATE( cond ) \
    MBEDTLS_INTERNAL_VALIDATE( cond )


#if defined(MBEDTLS_RSA_KEYGEN_ALT)
/*
 * Generate an RSA keypair
 *
 * This generation method follows the RSA key pair generation procedure of
 * FIPS 186-4 if 2^16 < exponent < 2^256 and nbits = 2048, 3072 or 4096.
 */
int mbedtls_rsa_gen_key( mbedtls_rsa_context *ctx,
                 int (*f_rng)(void *, unsigned char *, size_t),
                 void *p_rng,
                 unsigned int nbits, int exponent )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    RSA_VALIDATE_RET( ctx != NULL );
    uint32_t *modulo_tmp, *priv_exp_tmp;
    uint32_t pub_exponent;

    /* Minimum nbit size is 2048 */
    if( nbits < 2048 || exponent < 3 || nbits % 2 != 0 )
    {
        ret = MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
        goto cleanup;
    }

    mbedtls_mpi_init(&ctx->N);
    mbedtls_mpi_init(&ctx->D);

    /* Alocate MPI structure for Public modulus */
    modulo_tmp = mbedtls_calloc(1, nbits / 8u);
    if(modulo_tmp == NULL)
      return MBEDTLS_ERR_MPI_ALLOC_FAILED;
    

    /* Alocate MPI structure for Private exponent */
    priv_exp_tmp = mbedtls_calloc(1, nbits / 8u);
    if(priv_exp_tmp == NULL)
      return MBEDTLS_ERR_MPI_ALLOC_FAILED;
    
    /* Convert to Big Endian */
    pub_exponent = __REV(exponent);

    ele_generic_rsa_t GenericRsaKeygen;
    GenericRsaKeygen.modulus            = (uint32_t)modulo_tmp;
    GenericRsaKeygen.priv_exponent      = (uint32_t)priv_exp_tmp;
    GenericRsaKeygen.priv_exponent_size = nbits / 8u;
    GenericRsaKeygen.modulus_size       = nbits / 8u;
    GenericRsaKeygen.pub_exponent       = (uint32_t)&pub_exponent;
    GenericRsaKeygen.pub_exponent_size  = sizeof(pub_exponent);
    GenericRsaKeygen.key_size           = nbits;

    MBEDTLS_MPI_CHK(ELE_GenericRsaKeygen(S3MU, &GenericRsaKeygen));
 
    /* Set Public Exponent in Ctx */
    MBEDTLS_MPI_CHK( mbedtls_mpi_lset( &ctx->E, exponent ));
    
    /* Read modulo in MPI */
    mbedtls_mpi_read_binary(&ctx->N, (const unsigned char *) modulo_tmp, nbits / 8u);

    /* Read private exonent in MPI */
    mbedtls_mpi_read_binary(&ctx->D, (const unsigned char *) priv_exp_tmp, nbits / 8u);
    
    /* Set Ctx length */
    ctx->len = mbedtls_mpi_size( &ctx->N );

    /* Compute P and Q in CTX. */
    /* Not needed for RSA operation, only to pass MbedTLS ctx check (not mandatory). */
    //mbedtls_rsa_complete(ctx);
    
    /* Double-check. No need in alt implementation, takes too long time */
    //MBEDTLS_MPI_CHK( mbedtls_rsa_check_privkey( ctx ) );

cleanup:
    mbedtls_free(modulo_tmp);
    mbedtls_free(priv_exp_tmp);   
  
    if( ret != 0 )
    {
        mbedtls_rsa_free( ctx );

        if( ( -ret & ~0x7f ) == 0 )
            ret = MBEDTLS_ERROR_ADD( MBEDTLS_ERR_RSA_KEY_GEN_FAILED, ret );
        return( ret );
    }

    return( 0 );
}
#endif /* MBEDTLS_RSA_KEYGEN_ALT */

#if defined(MBEDTLS_PKCS1_V15_ALT)
/*
 * Implementation of the PKCS#1 v2.1 RSAES-PKCS1-V1_5-ENCRYPT function
 */
int mbedtls_rsa_rsaes_pkcs1_v15_encrypt( mbedtls_rsa_context *ctx,
                                 int (*f_rng)(void *, unsigned char *, size_t),
                                 void *p_rng,
                                 int mode, size_t ilen,
                                 const unsigned char *input,
                                 unsigned char *output )
{
    size_t olen, nbits;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    ele_generic_rsa_t GenericRsaEnc;
    uint32_t *modulo_tmp;
    uint32_t pub_exp;

    
    RSA_VALIDATE_RET( ctx != NULL );
    RSA_VALIDATE_RET( mode == MBEDTLS_RSA_PRIVATE ||
                      mode == MBEDTLS_RSA_PUBLIC );
    RSA_VALIDATE_RET( output != NULL );
    RSA_VALIDATE_RET( ilen == 0 || input != NULL );

    if( mode == MBEDTLS_RSA_PRIVATE && ctx->padding != MBEDTLS_RSA_PKCS_V15 )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    olen = ctx->len;
    nbits = ctx->len * 8u;
    
    /* first comparison checks for overflow */
    if( ilen + 11 < ilen || olen < ilen + 11 )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
 
    /* Alocate MPI structure for Public modulus */
    modulo_tmp = mbedtls_calloc(nbits / 8u, 8u);
    if(modulo_tmp == NULL)
      return MBEDTLS_ERR_MPI_ALLOC_FAILED;
    
    /* Read motulus data from MPI ctx structure */
    mbedtls_mpi_write_binary(&ctx->N, (unsigned char *) modulo_tmp, olen);

    /* Read public exponent data from MPI ctx structure */
    mbedtls_mpi_write_binary(&ctx->E, (unsigned char *) &pub_exp, sizeof(uint32_t));
    
    /* Set ELE RSA structure */
    GenericRsaEnc.algo     = RSA_PKCS1_V1_5_CRYPT;   
    GenericRsaEnc.mode     = kEncryption;
    GenericRsaEnc.key_size = nbits;
    /* Public exponent */
    GenericRsaEnc.pub_exponent      = (uint32_t)&pub_exp;
    GenericRsaEnc.pub_exponent_size = sizeof(pub_exp);
    /* Modulus */
    GenericRsaEnc.modulus      = (uint32_t)modulo_tmp;
    GenericRsaEnc.modulus_size = olen;
    /* Plaintext */
    GenericRsaEnc.plaintext      = (uint32_t)input;
    GenericRsaEnc.plaintext_size = ilen;
    /* Ciphertext */
    GenericRsaEnc.ciphertext      = (uint32_t)output;
    GenericRsaEnc.ciphertext_size = olen;

    if (ELE_GenericRsa(S3MU, &GenericRsaEnc) != kStatus_Success)
    {
        ret = MBEDTLS_ERR_RSA_PUBLIC_FAILED;
        goto cleanup;
    }
    else
    {
        ret = 0;
    }

cleanup:
    mbedtls_free(modulo_tmp);   
    
    return ret;
}

/*
 * Implementation of the PKCS#1 v2.1 RSAES-PKCS1-V1_5-DECRYPT function
 */
int mbedtls_rsa_rsaes_pkcs1_v15_decrypt( mbedtls_rsa_context *ctx,
                                 int (*f_rng)(void *, unsigned char *, size_t),
                                 void *p_rng,
                                 int mode,
                                 size_t *olen,
                                 const unsigned char *input,
                                 unsigned char *output,
                                 size_t output_max_len )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t ilen, nbits;
    ele_generic_rsa_t GenericRsaEnc;
    uint32_t *modulo_tmp, *priv_exp_tmp;

    RSA_VALIDATE_RET( ctx != NULL );
    RSA_VALIDATE_RET( mode == MBEDTLS_RSA_PRIVATE ||
                      mode == MBEDTLS_RSA_PUBLIC );
    RSA_VALIDATE_RET( output_max_len == 0 || output != NULL );
    RSA_VALIDATE_RET( input != NULL );
    RSA_VALIDATE_RET( olen != NULL );

    ilen = ctx->len;
    nbits = ctx->len * 8u;

    if( mode == MBEDTLS_RSA_PRIVATE && ctx->padding != MBEDTLS_RSA_PKCS_V15 )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
    
    
    /* Alocate MPI structure for Public modulus */
    modulo_tmp = mbedtls_calloc(nbits / 8u, 8u);
    if(modulo_tmp == NULL)
      return MBEDTLS_ERR_MPI_ALLOC_FAILED;
    
    /* Alocate MPI structure for Private exponent */
    priv_exp_tmp = mbedtls_calloc(nbits / 8u, 8u);
    if(priv_exp_tmp == NULL)
      return MBEDTLS_ERR_MPI_ALLOC_FAILED;

    /* Read motulus data from MPI ctx structure */
    mbedtls_mpi_write_binary(&ctx->N, (unsigned char *) modulo_tmp, ilen);

    /* Read private exponent data from MPI ctx structure */
    mbedtls_mpi_write_binary(&ctx->D, (unsigned char *) priv_exp_tmp, ilen);
   
    /* Set ELE RSA structure */
    GenericRsaEnc.algo     = RSA_PKCS1_V1_5_CRYPT;
    GenericRsaEnc.mode     = kDecryption;
    GenericRsaEnc.key_size = nbits;
    /* Public exponent */
    GenericRsaEnc.priv_exponent      = (uint32_t)priv_exp_tmp;
    GenericRsaEnc.priv_exponent_size = ilen;
    /* Modulus */
    GenericRsaEnc.modulus      = (uint32_t)modulo_tmp;
    GenericRsaEnc.modulus_size = ilen;
    /* Plaintext */
    GenericRsaEnc.plaintext      = (uint32_t)output;
    GenericRsaEnc.plaintext_size = (uint32_t)output_max_len;
    /* Ciphertext */
    GenericRsaEnc.ciphertext      = (uint32_t)input;
    GenericRsaEnc.ciphertext_size = ilen;

    if (ELE_GenericRsa(S3MU, &GenericRsaEnc) != kStatus_Success)
    {
        ret = MBEDTLS_ERR_RSA_PUBLIC_FAILED;
        goto cleanup;
    }
    else
    {
        *olen = GenericRsaEnc.out_plaintext_len;
        ret = 0;
    }


cleanup:
    mbedtls_free(modulo_tmp);
    mbedtls_free(priv_exp_tmp);
    
    return( ret );
}                                        
#endif /* MBEDTLS_PKCS1_V15_ALT */


#if defined(MBEDTLS_PKCS1_V21_ALT)
/*
 * Implementation of the PKCS#1 v2.1 RSAES-OAEP-ENCRYPT function
 */
int mbedtls_rsa_rsaes_oaep_encrypt( mbedtls_rsa_context *ctx,
                            int (*f_rng)(void *, unsigned char *, size_t),
                            void *p_rng,
                            int mode,
                            const unsigned char *label, size_t label_len,
                            size_t ilen,
                            const unsigned char *input,
                            unsigned char *output )
{
    size_t olen, nbits;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *p = output;
    unsigned int hlen;
    const mbedtls_md_info_t *md_info;
    mbedtls_md_context_t md_ctx;
    ele_generic_rsa_t GenericRsaEnc;
    uint32_t *modulo_tmp;
    uint32_t pub_exp;
      
    RSA_VALIDATE_RET( ctx != NULL );
    RSA_VALIDATE_RET( mode == MBEDTLS_RSA_PRIVATE ||
                      mode == MBEDTLS_RSA_PUBLIC );
    RSA_VALIDATE_RET( output != NULL );
    RSA_VALIDATE_RET( ilen == 0 || input != NULL );
    RSA_VALIDATE_RET( label_len == 0 || label != NULL );

    if( mode == MBEDTLS_RSA_PRIVATE && ctx->padding != MBEDTLS_RSA_PKCS_V21 )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    md_info = mbedtls_md_info_from_type( (mbedtls_md_type_t) ctx->hash_id );
    if( md_info == NULL )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    olen = ctx->len;
    nbits = ctx->len * 8u;
    hlen = mbedtls_md_get_size( md_info );

    /* first comparison checks for overflow */
    if( ilen + 2 * hlen + 2 < ilen || olen < ilen + 2 * hlen + 2 )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    memset( output, 0, olen );

    /* Set MGF (HASH) algo */
    switch(ctx->hash_id)
    {
        case (MBEDTLS_MD_SHA1):
            GenericRsaEnc.algo     = RSA_PKCS1_OAEP_SHA1;
            break;
        case (MBEDTLS_MD_SHA224):
            GenericRsaEnc.algo     = RSA_PKCS1_OAEP_SHA224;
            break;
        case (MBEDTLS_MD_SHA256):
            GenericRsaEnc.algo     = RSA_PKCS1_OAEP_SHA256;
            break;
        case (MBEDTLS_MD_SHA384):
            GenericRsaEnc.algo     = RSA_PKCS1_OAEP_SHA384;
            break;
        case (MBEDTLS_MD_SHA512):
            GenericRsaEnc.algo     = RSA_PKCS1_OAEP_SHA512;
            break;
        case (MBEDTLS_MD_NONE):
        default:
            return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
    }
    
    /* Alocate MPI structure for Public modulus */
    modulo_tmp = mbedtls_calloc(nbits / 8u, 8u);
    if(modulo_tmp == NULL)
      return MBEDTLS_ERR_MPI_ALLOC_FAILED;
    
    /* Read motulus data from MPI ctx structure */
    mbedtls_mpi_write_binary(&ctx->N, (unsigned char *) modulo_tmp, olen);

    /* Read public exponent data from MPI ctx structure */
    mbedtls_mpi_write_binary(&ctx->E, (unsigned char *) &pub_exp, sizeof(uint32_t));
    
    /* Set ELE RSA structure */
    GenericRsaEnc.mode     = kEncryption;
    GenericRsaEnc.key_size = nbits;
    /* Public exponent */
    GenericRsaEnc.pub_exponent      = (uint32_t)&pub_exp;
    GenericRsaEnc.pub_exponent_size = sizeof(pub_exp);
    /* Modulus */
    GenericRsaEnc.modulus      = (uint32_t)modulo_tmp;
    GenericRsaEnc.modulus_size = olen;
    /* Plaintext */
    GenericRsaEnc.plaintext      = (uint32_t)input;
    GenericRsaEnc.plaintext_size = ilen;
    /* Ciphertext */
    GenericRsaEnc.ciphertext      = (uint32_t)output;
    GenericRsaEnc.ciphertext_size = olen;
    /* Label */
    GenericRsaEnc.label      = (uint32_t)label;
    GenericRsaEnc.label_size = label_len;
    
    if (ELE_GenericRsa(S3MU, &GenericRsaEnc) != kStatus_Success)
    {
        ret = MBEDTLS_ERR_RSA_PUBLIC_FAILED;
        goto exit;
    }
    else
    {
        ret = 0u;
    }

exit:
    mbedtls_md_free( &md_ctx );
    mbedtls_free(modulo_tmp);

    if( ret != 0 )
        return( ret );

    return( 0 ); 
}

/*
 * Implementation of the PKCS#1 v2.1 RSAES-OAEP-DECRYPT function
 */
int mbedtls_rsa_rsaes_oaep_decrypt( mbedtls_rsa_context *ctx,
                            int (*f_rng)(void *, unsigned char *, size_t),
                            void *p_rng,
                            int mode,
                            const unsigned char *label, size_t label_len,
                            size_t *olen,
                            const unsigned char *input,
                            unsigned char *output,
                            size_t output_max_len )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t ilen, nbits;
    unsigned char buf[MBEDTLS_MPI_MAX_SIZE];
    unsigned int hlen;
    const mbedtls_md_info_t *md_info;
    mbedtls_md_context_t md_ctx;
    ele_generic_rsa_t GenericRsaEnc;
    uint32_t *modulo_tmp, *priv_exp_tmp;
    uint32_t pub_exp;
    
    RSA_VALIDATE_RET( ctx != NULL );
    RSA_VALIDATE_RET( mode == MBEDTLS_RSA_PRIVATE ||
                      mode == MBEDTLS_RSA_PUBLIC );
    RSA_VALIDATE_RET( output_max_len == 0 || output != NULL );
    RSA_VALIDATE_RET( label_len == 0 || label != NULL );
    RSA_VALIDATE_RET( input != NULL );
    RSA_VALIDATE_RET( olen != NULL );

    /*
     * Parameters sanity checks
     */
    if( mode == MBEDTLS_RSA_PRIVATE && ctx->padding != MBEDTLS_RSA_PKCS_V21 )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    ilen = ctx->len;
    nbits = ctx->len * 8u;
    
    if( ilen < 16 || ilen > sizeof( buf ) )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    md_info = mbedtls_md_info_from_type( (mbedtls_md_type_t) ctx->hash_id );
    if( md_info == NULL )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    hlen = mbedtls_md_get_size( md_info );

    // checking for integer underflow
    if( 2 * hlen + 2 > ilen )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
/*********************************************************************/

    /* Set MGF (HASH) algo */
    switch(ctx->hash_id)
    {
        case (MBEDTLS_MD_SHA1):
            GenericRsaEnc.algo     = RSA_PKCS1_OAEP_SHA1;
            break;
        case (MBEDTLS_MD_SHA224):
            GenericRsaEnc.algo     = RSA_PKCS1_OAEP_SHA224;
            break;
        case (MBEDTLS_MD_SHA256):
            GenericRsaEnc.algo     = RSA_PKCS1_OAEP_SHA256;
            break;
        case (MBEDTLS_MD_SHA384):
            GenericRsaEnc.algo     = RSA_PKCS1_OAEP_SHA384;
            break;
        case (MBEDTLS_MD_SHA512):
            GenericRsaEnc.algo     = RSA_PKCS1_OAEP_SHA512;
            break;
        case (MBEDTLS_MD_NONE):
        default:
            return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
    }
    
    /* Alocate MPI structure for Public modulus */
    modulo_tmp = mbedtls_calloc(nbits / 8u, 8u);
    if(modulo_tmp == NULL)
      return MBEDTLS_ERR_MPI_ALLOC_FAILED;

    /* Alocate MPI structure for Private exponent */
    priv_exp_tmp = mbedtls_calloc(nbits / 8u, 8u);
    if(priv_exp_tmp == NULL)
      return MBEDTLS_ERR_MPI_ALLOC_FAILED;
    
    /* Read motulus data from MPI ctx structure */
    mbedtls_mpi_write_binary(&ctx->N, (unsigned char *) modulo_tmp, ilen);
    
    /* Read private exponent data from MPI ctx structure */
    mbedtls_mpi_write_binary(&ctx->D, (unsigned char *) priv_exp_tmp, ilen);
    
    /* Set ELE RSA structure */
    GenericRsaEnc.mode     = kDecryption;
    GenericRsaEnc.key_size = nbits;
    /* Public exponent */
    GenericRsaEnc.priv_exponent      = (uint32_t)priv_exp_tmp;
    GenericRsaEnc.priv_exponent_size = ilen;
    /* Modulus */
    GenericRsaEnc.modulus      = (uint32_t)modulo_tmp;
    GenericRsaEnc.modulus_size = ilen;
    /* Plaintext */
    GenericRsaEnc.plaintext      = (uint32_t)output;
    GenericRsaEnc.plaintext_size = (uint32_t)output_max_len;
    /* Ciphertext */
    GenericRsaEnc.ciphertext      = (uint32_t)input;
    GenericRsaEnc.ciphertext_size = ilen;
    /* Label */
    GenericRsaEnc.label      = (uint32_t)label;
    GenericRsaEnc.label_size = label_len;
    
    if (ELE_GenericRsa(S3MU, &GenericRsaEnc) != kStatus_Success)
    {
        ret = MBEDTLS_ERR_RSA_PUBLIC_FAILED;
        goto cleanup;
    }
    else
    {
        *olen = GenericRsaEnc.out_plaintext_len;
        ret = 0;
    }

/*********************************************************************/

cleanup:
    mbedtls_free(modulo_tmp);
    mbedtls_free(priv_exp_tmp);

    return( ret );
}

#endif /* MBEDTLS_PKCS1_V21_ALT */                                     

#endif /* MBEDTLS_RSA_ALT || MBEDTLS_PKCS1_V15_ALT || MBEDTLS_PKCS1_V21_ALT */

#endif /* MBEDTLS_RSA_C */


