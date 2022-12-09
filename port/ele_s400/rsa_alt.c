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

#if defined(MBEDTLS_RSA_KEYGEN_ALT)
#include "rsa_alt.h"
#include "ele_crypto.h"
#include "ele_mbedtls.h"

#define RSA_VALIDATE_RET( cond ) \
    MBEDTLS_INTERNAL_VALIDATE_RET( cond, MBEDTLS_ERR_RSA_BAD_INPUT )
#define RSA_VALIDATE( cond ) \
    MBEDTLS_INTERNAL_VALIDATE( cond )

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

    /* Minimum nbit size is 2048 */
    if( nbits < 2048 || exponent < 3 || nbits % 2 != 0 )
    {
        ret = MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
        goto cleanup;
    }

    mbedtls_mpi_init(&ctx->N);
    mbedtls_mpi_init(&ctx->D);
    
    /* Set Public Exponent in Ctx */
    MBEDTLS_MPI_CHK( mbedtls_mpi_lset( &ctx->E, exponent ) );

    /* Alocate MPI structure for Public modulus */
    MBEDTLS_MPI_CHK( mbedtls_mpi_grow( &ctx->N, nbits / 8u ) );

    /* Alocate MPI structure for Private exponent */
    MBEDTLS_MPI_CHK( mbedtls_mpi_grow( &ctx->D, nbits / 8u ) );

    ele_generic_rsa_t GenericRsaKeygen;
    GenericRsaKeygen.modulus       = (uint32_t)ctx->N.p;
    GenericRsaKeygen.priv_exponent = (uint32_t)ctx->D.p;
    GenericRsaKeygen.exponent_size = nbits / 8u;
    GenericRsaKeygen.modulus_size  = nbits / 8u;
    GenericRsaKeygen.pub_exponent  = (uint32_t)exponent;
    GenericRsaKeygen.key_size      = nbits;
    
    MBEDTLS_MPI_CHK(ELE_GenericRsaKeygen(S3MU, &GenericRsaKeygen));

    /* Set Ctx length */
    ctx->len = mbedtls_mpi_size( &ctx->N );

cleanup:

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
#endif /* MBEDTLS_RSA_C */


