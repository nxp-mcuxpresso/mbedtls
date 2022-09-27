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

/**
 * @file  cmac_alt.c
 * @brief alternative CMAC implementation with mcuxClMac component
 */

#include <stdint.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClMac.h>
#include <internal/mcuxClMac_internal.h>

#include <mbedtls/error.h>
#include <mbedtls/aes.h>
#include <mbedtls/cmac.h>
#include <cmac_alt.h>

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc     calloc
#define mbedtls_free       free
#endif /* MBEDTLS_PLATFORM_C */



#if defined(MBEDTLS_AES_CMAC_ALT)
#if !defined(MBEDTLS_AES_CTX_ALT)
#error only supports the alternative AES context-type
#endif  /* !MBEDTLS_AES_CTX_ALT */

//#define MAX(value0, value1)  (((value0) > (value1)) ? (value0) : (value1))

// to be used in mbedtls_cipher_aes_cmac_starts only
#define ZEROIZE_AND_FREE_ALLOCATED_MEMORY \
    mbedtls_platform_zeroize(aesCmacCtx->macKeyDestination, keyType->size); \
    mbedtls_free(aesCmacCtx->macKeyDestination); \
    mbedtls_platform_zeroize(aesCmacCtx, MAX(sizeof(mbedtls_aes_cmac_context_t), sizeof(mbedtls_cmac_context_t))); \
    mbedtls_free(aesCmacCtx);

/*
 * AES CMAC alternative implementation, to be called via original mbedtls_cipher_cmac_starts
 */
int mbedtls_cipher_aes_cmac_starts( mbedtls_cipher_context_t *ctx )
{
    /* Get KeyType */
    const mcuxClKey_Type_t *keyType;
    mbedtls_cipher_type_t cipherType = ctx->cipher_info->type;
    switch(cipherType)
    {
        case MBEDTLS_CIPHER_AES_128_ECB:
            keyType = &mcuxKey_keyType_Aes128;
            break;
        case MBEDTLS_CIPHER_AES_256_ECB:
            keyType = &mcuxKey_keyType_Aes256;
            break;
        default:
            keyType = NULL;
            /* These cases should not occur, if they do then the code flow has been modified and later an error occurs when allocating aesCmacCtx->macKeyDestination. */
            break;
    }

    /******************************************************/
    /* Allocate AES CMac context                          */
    /******************************************************/
    mbedtls_aes_cmac_context_t *aesCmacCtx = (mbedtls_aes_cmac_context_t *)
            mbedtls_calloc(1u, MAX(sizeof(mbedtls_aes_cmac_context_t), sizeof(mbedtls_cmac_context_t)));

    if(NULL == aesCmacCtx)
    {
        return MBEDTLS_ERR_CIPHER_ALLOC_FAILED;
    }
    mbedtls_platform_zeroize(aesCmacCtx, sizeof(mbedtls_aes_cmac_context_t));

    /******************************************************/
    /* Allocate key destination memory buffer             */
    /******************************************************/
    aesCmacCtx->macKeyDestination = (uint32_t *) mbedtls_calloc(1u, keyType->size);

    if(NULL == aesCmacCtx->macKeyDestination)
    {
        mbedtls_free(aesCmacCtx);
        return MBEDTLS_ERR_CIPHER_ALLOC_FAILED;
    }
    mbedtls_platform_zeroize(aesCmacCtx->macKeyDestination, keyType->size);

    /******************************************************/
    /* Initialize key in AES CMac context                 */
    /******************************************************/

    /* Initialize session description for mcuxClKey_init. */
    /* Share the space of macSession, which is not used yet. */
    mcuxClSession_Handle_t pSessionKeyInit = &(aesCmacCtx->macSession);
    MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED( retSessionInitKey, tokenSessionInitKey,
        mcuxClSession_init(pSessionKeyInit,
                          NULL, /* no cpuWaBuffer */
                          0u,
                          NULL, /* no pkcWaBuffer */
                          0u) );
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_init) != tokenSessionInitKey)
        || (MCUXCLSESSION_STATUS_OK != retSessionInitKey) )
    {
        ZEROIZE_AND_FREE_ALLOCATED_MEMORY;
        return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    }

    /* Initialize and load key */
    MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED( retKeyInit, tokenKeyInit,
        mcuxClKey_init(pSessionKeyInit,
                      &(aesCmacCtx->macKey),
                      keyType,
                      &mcuxClKey_protection_none,
                      (uint8_t *) ((mbedtls_aes_context *) ctx->cipher_ctx)->pKey,
                      NULL, /* no srcAuxData */
                      0u) );
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != tokenKeyInit)
        || (MCUXCLKEY_STATUS_OK != retKeyInit) )
    {
        ZEROIZE_AND_FREE_ALLOCATED_MEMORY;
        return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    }


    MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED( retKeyLoadMemory, tokenKeyLoadMemory,
        mcuxClKey_loadMemory(pSessionKeyInit,
                            &(aesCmacCtx->macKey),
                            aesCmacCtx->macKeyDestination) );
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_loadMemory) != tokenKeyLoadMemory)
        || (MCUXCLKEY_STATUS_OK != retKeyLoadMemory) )
    {
        ZEROIZE_AND_FREE_ALLOCATED_MEMORY;
        return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    }

    /* Clean-up and destroy session for mcuxClKey_init and mcuxClKey_loadMemory. */
    MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED( retSessionCleanKey, tokenSessionCleanKey,
        mcuxClSession_cleanup(pSessionKeyInit) );
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_cleanup) != tokenSessionCleanKey)
        || (MCUXCLSESSION_STATUS_OK != retSessionCleanKey) )
    {
        ZEROIZE_AND_FREE_ALLOCATED_MEMORY;
        return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED( retSessionDestroyKey, tokenSessionDestroyKey,
        mcuxClSession_destroy(pSessionKeyInit) );
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_destroy) != tokenSessionDestroyKey)
        || (MCUXCLSESSION_STATUS_OK != retSessionDestroyKey) )
    {
        ZEROIZE_AND_FREE_ALLOCATED_MEMORY;
        return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    }


    /******************************************************/
    /* Initialize CMAC computation.                       */
    /******************************************************/

    /* Initialize session descriptor for mcuxClMac. */
    MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED( retSessionInitMac, tokenSessionInitMac,
        mcuxClSession_init(&(aesCmacCtx->macSession),
                          aesCmacCtx->macCpuWa,
                          MCUXCLMAC_WA_SIZE_MAX,
                          NULL, /* no pkcWaBuffer */
                          0u) );
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_init) != tokenSessionInitMac)
        || (MCUXCLSESSION_STATUS_OK != retSessionInitMac) )
    {
        ZEROIZE_AND_FREE_ALLOCATED_MEMORY;
        return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    }

    /* Initialize Cmac */
    MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED( retMacInit, tokenMacInit,
        mcuxClMac_init(&(aesCmacCtx->macSession),
                      &(aesCmacCtx->macContext),
                      &(aesCmacCtx->macKey),
                      mcuxClMac_Mode_CMAC) );
    if (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMac_init) != tokenMacInit)
    {
        ZEROIZE_AND_FREE_ALLOCATED_MEMORY;
        return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    }
    if (MCUXCLMAC_ERRORCODE_ERROR == retMacInit)
    {
        ZEROIZE_AND_FREE_ALLOCATED_MEMORY;
        return MBEDTLS_ERR_CMAC_HW_ACCEL_FAILED;
    }
    else if (MCUXCLMAC_ERRORCODE_OK != retMacInit)
    {
        ZEROIZE_AND_FREE_ALLOCATED_MEMORY;
        return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    }
    else
    {
        /* nothing */
    }

    /* Clean-up session for mcuxClMac_init. */
    MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(retSessionClean, tokenSessionClean,
        mcuxClSession_cleanup(&(aesCmacCtx->macSession)) );
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_cleanup) != tokenSessionClean)
        || (MCUXCLSESSION_STATUS_OK != retSessionClean) )
    {
        ZEROIZE_AND_FREE_ALLOCATED_MEMORY;
        return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    }

    ctx->cmac_ctx = (mbedtls_cmac_context_t *) aesCmacCtx;

    return 0;
}


/*
 * AES CMAC alternative implementation, to be called via original mbedtls_cipher_cmac_update.
 */
int mbedtls_cipher_aes_cmac_update( mbedtls_cipher_context_t *ctx,
                                    const unsigned char *input,
                                    size_t ilen )
{
    mbedtls_aes_cmac_context_t *aesCmacCtx = (mbedtls_aes_cmac_context_t *) ctx->cmac_ctx;

    MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(retCode, token,
        mcuxClMac_process(&(aesCmacCtx->macSession),
                         &(aesCmacCtx->macContext),
                         input, (uint32_t) ilen) );
    if (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMac_process) != token)
    {
        return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    }
    if (MCUXCLMAC_ERRORCODE_ERROR == retCode)
    {
        return MBEDTLS_ERR_CMAC_HW_ACCEL_FAILED;
    }
    else if (MCUXCLMAC_ERRORCODE_OK != retCode)
    {
        return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    }
    else
    {
        /* nothing */
    }

    /* Clean-up session for mcuxClMac_process. */
    MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(retSessionClean, tokenSessionClean,
        mcuxClSession_cleanup(&(aesCmacCtx->macSession)) );
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_cleanup) != tokenSessionClean)
        || (MCUXCLSESSION_STATUS_OK != retSessionClean) )
    {
        return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    }

    return 0;
}


/*
 * AES CMAC alternative implementation, to be called via original mbedtls_cipher_cmac_finish.
 */
int mbedtls_cipher_aes_cmac_finish( mbedtls_cipher_context_t *ctx,
                                    unsigned char *output )
{
    mbedtls_aes_cmac_context_t *aesCmacCtx = (mbedtls_aes_cmac_context_t *) ctx->cmac_ctx;

    if (NULL != output)
    {
        MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(retCode, token,
            mcuxClMac_finish(&(aesCmacCtx->macSession),
                            &(aesCmacCtx->macContext),
                            output) );
        if (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMac_finish) != token)
        {
            return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        }
        if (MCUXCLMAC_ERRORCODE_ERROR == retCode)
        {
            return MBEDTLS_ERR_CMAC_HW_ACCEL_FAILED;
        }
        else if (MCUXCLMAC_ERRORCODE_OK != retCode)
        {
            return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        }
        else
        {
            /* nothing */
        }
    }

    /* Flush and free key memory location */
    MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED( retKeyFlush, tokenKeyFlush,
        mcuxClKey_flush(&(aesCmacCtx->macSession),
                       &(aesCmacCtx->macKey)) );
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_flush) != tokenKeyFlush)
        || (MCUXCLKEY_STATUS_OK != retKeyFlush) )
    {
        return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    }
    mbedtls_free(aesCmacCtx->macKeyDestination);

    /* Clean-up session for mcuxClMac_finish. */
    MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(retSessionClean, tokenSessionClean,
        mcuxClSession_cleanup(&(aesCmacCtx->macSession)) );
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_cleanup) != tokenSessionClean)
        || (MCUXCLSESSION_STATUS_OK != retSessionClean) )
    {
        return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    }

    if (NULL == output)
    {
        return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }

    return 0;
}
#endif  /* MBEDTLS_AES_CMAC_ALT */

