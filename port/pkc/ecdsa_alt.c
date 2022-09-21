/*--------------------------------------------------------------------------*/
/* Copyright 2021 NXP                                                       */
/*                                                                          */
/* NXP Confidential. This software is owned or controlled by NXP and may    */
/* only be used strictly in accordance with the applicable license terms.   */
/* By expressly accepting such terms or by downloading, installing,         */
/* activating and/or otherwise using the software, you are agreeing that    */
/* you have read, and that you agree to comply with and are bound by, such  */
/* license terms. If you do not agree to be bound by the applicable license */
/* terms, then you may not retain, install, activate or otherwise use the   */
/* software.                                                                */
/*--------------------------------------------------------------------------*/

/** @file  ecdsa_alt.c
 *  @brief Alternative ECDSA implementation
 */
#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include <stdint.h>
#include <mcuxClCss.h>
#include <mcuxClPkc.h>
#include <mcuxClEcc.h>
#include <mcuxClMemory.h>
#include <mbedtls/ccm.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/error.h>
#include <mbedtls/platform.h>
#include <platform_hw_ip.h>
#include <mbedtls/ctr_drbg.h>
#include <ecc_alt.h>
#include <ecdh.h>


#if (!defined(MBEDTLS_ECDSA_VERIFY_ALT) || !defined(MBEDTLS_ECDSA_SIGN_ALT) || !defined(MBEDTLS_ECDSA_GENKEY_ALT))
#error This implmenetation requires that all 3 alternative implementation options are enabled together.
#else

/* Parameter validation macros based on platform_util.h */
#define ECDSA_VALIDATE_RET( cond )    \
    MBEDTLS_INTERNAL_VALIDATE_RET( cond, MBEDTLS_ERR_ECP_BAD_INPUT_DATA )
#define ECDSA_VALIDATE( cond )        \
    MBEDTLS_INTERNAL_VALIDATE( cond )

static void mbedtls_ecp_free_ecdsa(mcuxClEcc_DomainParam_t* pDomainParams, mcuxClEcc_PointMult_Param_t* pPointMultParams, 
                            mcuxClEcc_Verify_Param_t* pVerifyParams, mcuxClEcc_Sign_Param_t* pSignParams)
{
    /* Avoid accessing a NULL pointer. Freeing a NULL pointer is fine. */
    if(pDomainParams != NULL)
    {
        mbedtls_free((void*)pDomainParams->pA);
        mbedtls_free((void*)pDomainParams->pB);
        mbedtls_free((void*)pDomainParams->pP);
        mbedtls_free((void*)pDomainParams->pG);
        mbedtls_free((void*)pDomainParams->pN);
    }

    /* Avoid accessing a NULL pointer. Freeing a NULL pointer is fine. */
    if(pPointMultParams != NULL)
    {
        mbedtls_free((void*)pPointMultParams->pScalar);
        mbedtls_free((void*)pPointMultParams->pResult);
    }

    /* Avoid accessing a NULL pointer. Freeing a NULL pointer is fine. */
    if(pVerifyParams != NULL)
    {
        mbedtls_free((void*)pVerifyParams->pSignature);
        mbedtls_free((void*)pVerifyParams->pPublicKey);
        mbedtls_free((void*)pVerifyParams->pOutputR);
    }

    /* Avoid accessing a NULL pointer. Freeing a NULL pointer is fine. */
    if(pSignParams != NULL)
    {
        mbedtls_free((void*)pSignParams->pPrivateKey);
        mbedtls_free((void*)pSignParams->pSignature);
    }

}

/*
 * Compute ECDSA signature of a hashed message
 */
int mbedtls_ecdsa_sign( mbedtls_ecp_group *grp, mbedtls_mpi *r, mbedtls_mpi *s,
                const mbedtls_mpi *d, const unsigned char *buf, size_t blen,
                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    /* Check input parameters. */
    ECDSA_VALIDATE_RET( grp   != NULL );
    ECDSA_VALIDATE_RET( r     != NULL );
    ECDSA_VALIDATE_RET( s     != NULL );
    ECDSA_VALIDATE_RET( d     != NULL );
    ECDSA_VALIDATE_RET( f_rng != NULL );
    ECDSA_VALIDATE_RET( buf   != NULL || blen == 0 );

    /* Initialize Hardware */
    int ret_hw_init = mbedtls_hw_init();
    if( 0 != ret_hw_init )
    {
        return MBEDTLS_ERR_CCM_HW_ACCEL_FAILED;
    }

    /* Byte-length of prime p. */
    const uint32_t pByteLength = (grp->pbits + 7u) / 8u;
    /* Byte-length of group-order n. */
    const uint32_t nByteLength = (grp->nbits + 7u) / 8u;
    
    /* Setup session */
    mcuxClSession_Descriptor_t session;
    const uint32_t wordSizePkcWa = MCUXCLECC_POINTMULT_WAPKC_SIZE(pByteLength, nByteLength);
    (void) mcuxClSession_init(&session,
                             NULL, /* CPU workarea size for point multiplication is zero */
                             MCUXCLECC_POINTMULT_WACPU_SIZE,
                             (uint32_t *) MCUXCLPKC_RAM_START_ADDRESS + 2,
                             wordSizePkcWa);

    /* Set up domain parameters. */
    mcuxClEcc_DomainParam_t pDomainParams =
    {
        .pA = mbedtls_calloc(pByteLength, sizeof(uint8_t)),
        .pB = mbedtls_calloc(pByteLength, sizeof(uint8_t)),
        .pP = mbedtls_calloc(pByteLength, sizeof(uint8_t)),
        .pG = mbedtls_calloc(pByteLength*2u, sizeof(uint8_t)),
        .pN = mbedtls_calloc(nByteLength, sizeof(uint8_t)),
        .misc = 0
    };
    if(0u != mbedtls_ecp_setupDomainParams(grp, &pDomainParams))
    {
        mbedtls_ecp_free_ecdsa(&pDomainParams, NULL, NULL, NULL);
        return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    }

    /* Set up ECC sign parameters. */
    uint8_t* pPrivateKey = mbedtls_calloc(nByteLength, sizeof(uint8_t));

    if(0 != mbedtls_mpi_write_binary(d, (unsigned char *)pPrivateKey, nByteLength))
    {
        mbedtls_ecp_free_ecdsa(&pDomainParams, NULL, NULL, NULL);
        mbedtls_free(pPrivateKey);
        return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    }
    
    uint8_t* pSignature = mbedtls_calloc(nByteLength*2u, sizeof(uint8_t));

    mcuxClEcc_Sign_Param_t paramSign =
    {
        .curveParam = pDomainParams,
        .pHash = buf,
        .pPrivateKey = pPrivateKey,
        .pSignature = pSignature,
        .optLen = mcuxClEcc_Sign_Param_optLen_Pack(blen)
    };
    
    /* Call ECC sign. */
    MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(retEccSign, tokenEccSign,mcuxClEcc_Sign(&session, &paramSign));
    if (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_Sign) != tokenEccSign)
    {
        mbedtls_ecp_free_ecdsa(&pDomainParams, NULL, NULL, &paramSign);
        return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    }
    if(MCUXCLECC_STATUS_SIGN_INVALID_PARAMS == retEccSign)
    {
        mbedtls_ecp_free_ecdsa(&pDomainParams, NULL, NULL, &paramSign);
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
    else if(MCUXCLECC_STATUS_SIGN_RNG_ERROR == retEccSign)
    {
        mbedtls_ecp_free_ecdsa(&pDomainParams, NULL, NULL, &paramSign);
        return MBEDTLS_ERR_ECP_RANDOM_FAILED;
    }
    else if(MCUXCLECC_STATUS_SIGN_OK != retEccSign)
    {
        mbedtls_ecp_free_ecdsa(&pDomainParams, NULL, NULL, &paramSign);
        return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    }
    else /* MCUXCLECC_STATUS_SIGN_OK */
    {
        /* Convert signature from big-endian representation to mbedtls_mpi. */
        (void) mbedtls_mpi_read_binary(r, paramSign.pSignature, nByteLength);
        (void) mbedtls_mpi_read_binary(s, paramSign.pSignature + nByteLength, nByteLength);

        /* Free allocated memory */
        mbedtls_ecp_free_ecdsa(&pDomainParams, NULL, NULL, &paramSign);

        /* Clean session. */
        (void) mcuxClSession_cleanup(&session);
        (void) mcuxClSession_destroy(&session);

        return 0;
    }
}

/*
 * Verify ECDSA signature of hashed message
 */
int mbedtls_ecdsa_verify( mbedtls_ecp_group *grp,
                          const unsigned char *buf, size_t blen,
                          const mbedtls_ecp_point *Q,
                          const mbedtls_mpi *r,
                          const mbedtls_mpi *s)
{
    /* Check input parameters. */
    ECDSA_VALIDATE_RET( grp != NULL );
    ECDSA_VALIDATE_RET( Q   != NULL );
    ECDSA_VALIDATE_RET( r   != NULL );
    ECDSA_VALIDATE_RET( s   != NULL );
    ECDSA_VALIDATE_RET( buf != NULL || blen == 0 );

    /* Initialize Hardware */
    int ret_hw_init = mbedtls_hw_init();
    if( 0 != ret_hw_init )
    {
        return MBEDTLS_ERR_CCM_HW_ACCEL_FAILED;
    }

    /* Byte-length of prime p. */
    const uint32_t pByteLength = (grp->pbits + 7u) / 8u;
    /* Byte-length of group-order n. */
    const uint32_t nByteLength = (grp->nbits + 7u) / 8u;
    
    /* Setup session */
    mcuxClSession_Descriptor_t session;
    const uint32_t wordSizePkcWa = MCUXCLECC_POINTMULT_WAPKC_SIZE(pByteLength, nByteLength);
    (void) mcuxClSession_init(&session,
                             NULL, /* CPU workarea size for point multiplication is zero */
                             MCUXCLECC_POINTMULT_WACPU_SIZE,
                             (uint32_t *) MCUXCLPKC_RAM_START_ADDRESS + 2,
                             wordSizePkcWa);


    /* Set up domain parameters. */
    mcuxClEcc_DomainParam_t pDomainParams =
    {
        .pA = mbedtls_calloc(pByteLength, sizeof(uint8_t)),
        .pB = mbedtls_calloc(pByteLength, sizeof(uint8_t)),
        .pP = mbedtls_calloc(pByteLength, sizeof(uint8_t)),
        .pG = mbedtls_calloc(pByteLength*2u, sizeof(uint8_t)),
        .pN = mbedtls_calloc(nByteLength, sizeof(uint8_t)),
        .misc = 0
    };
    if(0u != mbedtls_ecp_setupDomainParams(grp, &pDomainParams))
    {
        mbedtls_ecp_free_ecdsa(&pDomainParams, NULL, NULL, NULL);
        return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    }

    /* Prepare the scalar to compute PrecG. The formula for the scalar is: 2 ^ (4 * nByteLength). */
    uint8_t* pScalarPrecG = mbedtls_calloc(nByteLength, sizeof(uint8_t));

    uint32_t scalarBitIndex = 4u * nByteLength;
    pScalarPrecG[nByteLength - 1u - (scalarBitIndex / 8u)] = (uint8_t) 1u << (scalarBitIndex & 7u);

    /* Set up ECC point multiplication parameters for the precomputed point PrecG required by mcuxClEcc_Verify. */
    uint8_t* pResult = mbedtls_calloc(pByteLength*2u, sizeof(uint8_t));
    mcuxClEcc_PointMult_Param_t pointMultParams =
    {
     .curveParam = pDomainParams,
     .pScalar = pScalarPrecG,
     .pPoint = pDomainParams.pG,
     .pResult = pResult,
     .optLen = 0u
    };

    /* Call ECC point multiplication. */
    MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(retEccPointMult, tokenEccPointMult,mcuxClEcc_PointMult(&session, &pointMultParams));
    if (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_PointMult) != tokenEccPointMult)
    {
        mbedtls_ecp_free_ecdsa(&pDomainParams, &pointMultParams, NULL, NULL);
        return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    }
    if(MCUXCLECC_STATUS_POINTMULT_INVALID_PARAMS == retEccPointMult)
    {
        mbedtls_ecp_free_ecdsa(&pDomainParams, &pointMultParams, NULL, NULL);
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
    else if(MCUXCLECC_STATUS_POINTMULT_OK != retEccPointMult)
    {
        mbedtls_ecp_free_ecdsa(&pDomainParams, &pointMultParams, NULL, NULL);
        return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    }
    else /* MCUXCLECC_STATUS_POINTMULT_OK */
    {
        /* Set up ECC verify parameters. */
        uint8_t* pSignature = mbedtls_calloc(nByteLength*2u, sizeof(uint8_t));
        if(0 != mbedtls_mpi_write_binary(r, (unsigned char *)pSignature, nByteLength))
        {
            mbedtls_ecp_free_ecdsa(&pDomainParams, &pointMultParams, NULL, NULL);
            mbedtls_free(pSignature);
            return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        }
        if(0 != mbedtls_mpi_write_binary(s, (unsigned char *)pSignature + nByteLength, nByteLength))
        {
            mbedtls_ecp_free_ecdsa(&pDomainParams, &pointMultParams, NULL, NULL);
            mbedtls_free(pSignature);
            return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        }

        uint8_t* pPublicKey = mbedtls_calloc(pByteLength*2u, sizeof(uint8_t));
        if(0 != mbedtls_mpi_write_binary(&Q->X, (unsigned char *)pPublicKey, pByteLength))
        {
            mbedtls_ecp_free_ecdsa(&pDomainParams, &pointMultParams, NULL, NULL);
            mbedtls_free(pSignature);
            mbedtls_free(pPublicKey);
            return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        }
        if(0 != mbedtls_mpi_write_binary(&Q->Y, (unsigned char *)pPublicKey + pByteLength, pByteLength))
        {
            mbedtls_ecp_free_ecdsa(&pDomainParams, &pointMultParams, NULL, NULL);
            mbedtls_free(pSignature);
            mbedtls_free(pPublicKey);
            return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        }

        uint8_t* pOutputR = mbedtls_calloc(nByteLength, sizeof(uint8_t));
        mcuxClEcc_Verify_Param_t paramVerify =
        {
           .curveParam = pDomainParams,
           .pPrecG = pResult,
           .pHash = (const uint8_t *) buf,
           .pSignature = pSignature,
           .pPublicKey = pPublicKey,
           .pOutputR = pOutputR,
           .optLen = mcuxClEcc_Verify_Param_optLen_Pack(blen)
        };
        
        /* Call ECC verify. */
        MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(retEccVerify, tokenEccVerify,mcuxClEcc_Verify(&session, &paramVerify));
        /* Note: according to mbedtls headers, the return code at failure is indeed MBEDTLS_ERR_ECP_BAD_INPUT_DATA and not MBEDTLS_ERR_ECP_VERIFY_FAILED. */
        if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_Verify) != tokenEccVerify) || (MCUXCLECC_STATUS_VERIFY_OK != retEccVerify))
        {
            mbedtls_ecp_free_ecdsa(&pDomainParams, &pointMultParams, &paramVerify, NULL);
            return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        }

        /* Free allocated memory */
        mbedtls_ecp_free_ecdsa(&pDomainParams, &pointMultParams, &paramVerify, NULL);

        /* Note: mcuxClEcc_Verify outputs the calculated signature R if verification is successful, but mbedtls has no such output, so it is dropped. */

        /* Clean session. */
        (void) mcuxClSession_cleanup(&session);
        (void) mcuxClSession_destroy(&session);

        return 0;
    }
}

/*
 * Generate key pair
 */
int mbedtls_ecdsa_genkey( mbedtls_ecdsa_context *ctx, mbedtls_ecp_group_id gid,
                  int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    /* Check input parameters. */
    ECDSA_VALIDATE_RET( ctx   != NULL );
    ECDSA_VALIDATE_RET( f_rng != NULL );

    /* Set up the group context from the given gid. */
    int ret = mbedtls_ecp_group_load( &ctx->grp, gid );
    if( ret != 0 )
    {
        return( ret );
    }

    /* Initialize Hardware */
    int ret_hw_init = mbedtls_hw_init();
    if( 0 != ret_hw_init )
    {
        return MBEDTLS_ERR_CCM_HW_ACCEL_FAILED;
    }

    /* Byte-length of prime p. */
    const uint32_t pByteLength = (ctx->grp.pbits + 7u) / 8u;
    /* Byte-length of group-order n. */
    const uint32_t nByteLength = (ctx->grp.nbits + 7u) / 8u;

    /* Setup session */
    mcuxClSession_Descriptor_t session;
    const uint32_t wordSizePkcWa = MCUXCLECC_POINTMULT_WAPKC_SIZE(pByteLength, nByteLength);
    (void) mcuxClSession_init(&session,
                             NULL, /* CPU workarea size for point multiplication is zero */
                             MCUXCLECC_POINTMULT_WACPU_SIZE,
                             (uint32_t *) MCUXCLPKC_RAM_START_ADDRESS + 2,
                             wordSizePkcWa);

    /* Set up domain parameters. */
    mcuxClEcc_DomainParam_t pDomainParams =
    {
        .pA = mbedtls_calloc(pByteLength, sizeof(uint8_t)),
        .pB = mbedtls_calloc(pByteLength, sizeof(uint8_t)),
        .pP = mbedtls_calloc(pByteLength, sizeof(uint8_t)),
        .pG = mbedtls_calloc(pByteLength*2u, sizeof(uint8_t)),
        .pN = mbedtls_calloc(nByteLength, sizeof(uint8_t)),
        .misc = 0
    };
    if(0u != mbedtls_ecp_setupDomainParams(&ctx->grp, &pDomainParams))
    {
        mbedtls_ecp_free_ecdsa(&pDomainParams, NULL, NULL, NULL);
        return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    }

    /* Set up ECC point multiplication parameters. */
    mbedtls_ctr_drbg_context rng_ctx;
    rng_ctx.prediction_resistance = 0u;
    uint8_t* pScalar = mbedtls_calloc(nByteLength, sizeof(uint8_t));

    if(0u != f_rng(&rng_ctx, pScalar, nByteLength))
    {
        return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    }

    uint8_t* pResult = mbedtls_calloc(pByteLength*2u, sizeof(uint8_t));
    mcuxClEcc_PointMult_Param_t PointMultParams =
    {
        .curveParam = pDomainParams,
        .pScalar = pScalar,
        .pPoint =  pDomainParams.pG,
        .pResult = pResult,
        .optLen = 0u
    };

    /* Call ECC point multiplication. */
    MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(retEccPointMult, tokenEccPointMult,mcuxClEcc_PointMult(&session, &PointMultParams));
    if (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_PointMult) != tokenEccPointMult)
    {
        mbedtls_ecp_free_ecdsa(&pDomainParams, &PointMultParams, NULL, NULL);
        return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    }
    if(MCUXCLECC_STATUS_POINTMULT_INVALID_PARAMS == retEccPointMult)
    {
        mbedtls_ecp_free_ecdsa(&pDomainParams, &PointMultParams, NULL, NULL);
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
    else if(MCUXCLECC_STATUS_POINTMULT_RNG_ERROR == retEccPointMult)
    {
        mbedtls_ecp_free_ecdsa(&pDomainParams, &PointMultParams, NULL, NULL);
        return MBEDTLS_ERR_ECP_RANDOM_FAILED;
    }
    else if(MCUXCLECC_STATUS_POINTMULT_OK != retEccPointMult)
    {
        mbedtls_ecp_free_ecdsa(&pDomainParams, &PointMultParams, NULL, NULL);
        return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    }
    else
    {
        /* Convert generated point from big-endian representation to mbedtls_mpi. */
        mbedtls_mpi_read_binary(&ctx->d, pScalar, nByteLength);
        mbedtls_mpi_read_binary(&ctx->Q.X, PointMultParams.pResult, pByteLength);
        mbedtls_mpi_read_binary(&ctx->Q.Y, PointMultParams.pResult + pByteLength, pByteLength);

        /* Free allocated memory */
        mbedtls_ecp_free_ecdsa(&pDomainParams, &PointMultParams, NULL, NULL);
        
        /* Clean session. */
        (void) mcuxClSession_cleanup(&session);
        (void) mcuxClSession_destroy(&session);
    }

    return 0;
}

int mbedtls_ecdsa_can_do( mbedtls_ecp_group_id gid )
{
    switch( gid )
    {
#ifdef MBEDTLS_ECP_DP_CURVE25519_ENABLED
        case MBEDTLS_ECP_DP_CURVE25519: return 0;
#endif
#ifdef MBEDTLS_ECP_DP_CURVE448_ENABLED
        case MBEDTLS_ECP_DP_CURVE448: return 0;
#endif
    default: return 1;
    }
}

#endif /* (!defined(MBEDTLS_ECDSA_VERIFY_ALT) || !defined(MBEDTLS_ECDSA_SIGN_ALT) || !defined(MBEDTLS_ECDSA_GENKEY_ALT)) */

