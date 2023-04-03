/*--------------------------------------------------------------------------*/
/* Copyright 2021, 2022 NXP                                                 */
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

/** @file  cbc_mac.c
 *  @brief alternative implementation of AES CBC-MAC with CSS IP
 */

#include <cbc_mac_alt.h>
#include <mbedtls/ccm.h>
#include <mbedtls/platform.h>
#include <platform_hw_ip.h>
#include <mcuxClCss.h>
#include <string.h>

#if defined(MBEDTLS_THREADING_C)
#include "mbedtls/threading.h"
#include "els_pkc_mbedtls.h"
#endif

#if !defined(MBEDTLS_CCM_USE_AES_CBC_MAC) || !defined(MBEDTLS_AES_CTX_ALT)
#error the alternative implementations shall be enabled together
#endif

int mbedtls_aes_cbc_mac(mbedtls_aes_context *ctx,
                        size_t length,
                        unsigned char *iv,
                        const unsigned char *pInput)
{
    int return_code = 0;
#ifdef MBEDTLS_CBC_MAC_USE_CMAC
    mcuxClCss_CmacOption_t cmac_options = { 0 };

    cmac_options.bits.extkey = MCUXCLCSS_CMAC_EXTERNAL_KEY_ENABLE;
    /* Set options to UPDATE (i.e., neither initialize nor finalize) for cbc-mac operation */
    cmac_options.bits.initialize = MCUXCLCSS_CMAC_INITIALIZE_DISABLE;
    cmac_options.bits.finalize = MCUXCLCSS_CMAC_FINALIZE_DISABLE;
#endif

    mcuxClCss_CipherOption_t cipher_options = { 0 };
    cipher_options.bits.dcrpt = MCUXCLCSS_CIPHER_ENCRYPT;
    cipher_options.bits.extkey = MCUXCLCSS_CIPHER_EXTERNAL_KEY;
    cipher_options.bits.cphmde = MCUXCLCSS_CIPHERPARAM_ALGORITHM_AES_CBC;

    uint8_t *pKey = (uint8_t *) ctx->pKey;
    size_t key_length = ctx->keyLength;
    size_t nr_full_blocks = length / 16u;
    size_t len_last_block = length - (nr_full_blocks * 16u);
    uint8_t last_block_output[16] = { 0U };
#if defined(MBEDTLS_THREADING_C)
    int ret;
    if ((ret = mbedtls_mutex_lock(&mbedtls_threading_hwcrypto_css_mutex)) != 0) {
        return ret;
    }
#endif
    /* Initialize CSS */
    int ret_hw_init = mbedtls_hw_init();
    if (0 != ret_hw_init) {
        return_code = MBEDTLS_ERR_CCM_HW_ACCEL_FAILED;
        goto cleanup;
    }

    /* process all complete blocks */
    if (nr_full_blocks > 0u) {
        if ((MCUXCLCSS_CMAC_KEY_SIZE_128 == key_length) || // use CMAC for HW Acceleration of 128-bit and 256-bit keys
            (MCUXCLCSS_CMAC_KEY_SIZE_256 == key_length)) {
#ifdef MBEDTLS_CBC_MAC_USE_CMAC
            /* call mcuxClCss_Cmac_Async on full blocks */
            MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(resultFullBlocks, tokenFullBlocks,
                                                 mcuxClCss_Cmac_Async(cmac_options,
                                                                      0, /* keyIdx is ignored */
                                                                      pKey,
                                                                      key_length,
                                                                      (uint8_t const *) pInput,
                                                                      (nr_full_blocks * 16u),
                                                                      (uint8_t *) iv));

            if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Cmac_Async) != tokenFullBlocks) ||
                (MCUXCLCSS_STATUS_OK_WAIT != resultFullBlocks)) {
                return_code = MBEDTLS_ERR_CCM_HW_ACCEL_FAILED;
                goto cleanup;
            }

            /* wait for mcuxClCss_Cmac_Async. */
            MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(retCssWaitFullBlocks, tokenCssWaitFullBlocks,
                                                 mcuxClCss_WaitForOperation(
                                                     MCUXCLCSS_ERROR_FLAGS_CLEAR));
            if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation) !=
                 tokenCssWaitFullBlocks) ||
                (MCUXCLCSS_STATUS_OK != retCssWaitFullBlocks)) {
                return_code MBEDTLS_ERR_CCM_HW_ACCEL_FAILED;
                goto cleanup;
            }
#else
            uint8_t *pOutput = (uint8_t *) mbedtls_calloc(1U, (nr_full_blocks * 16u));
            mbedtls_platform_zeroize(pOutput, (nr_full_blocks * 16u));

            MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(retCssCipherAsync, tokenCssCipherAsync,
                                                 mcuxClCss_Cipher_Async(cipher_options,
                                                                        0u, /* keyIdx is ignored. */
                                                                        pKey,
                                                                        key_length,
                                                                        (uint8_t const *) pInput,
                                                                        (nr_full_blocks * 16u),
                                                                        (uint8_t *) iv,
                                                                        (uint8_t *) pOutput));
            if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Cipher_Async) != tokenCssCipherAsync)
                || (MCUXCLCSS_STATUS_OK_WAIT != retCssCipherAsync)) {
                mbedtls_free(pOutput);
                /* _Cipher_Async shall not return _SW_CANNOT_INTERRUPT after successfully returning from _WaitForOperation. */
                /* _Cipher_Async shall not return _SW_INVALID_PARAM if parameters are set properly. */
                return_code = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
                goto cleanup;
            }

            /* Wait for mcuxClCss_Cipher_Async. */
            MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(retCssWaitCipher, tokenCssWaitCipher,
                                                 mcuxClCss_WaitForOperation(
                                                     MCUXCLCSS_ERROR_FLAGS_CLEAR));
            if (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation) != tokenCssWaitCipher) {
                mbedtls_free(pOutput);
                return_code = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
                goto cleanup;
            }
            if (MCUXCLCSS_STATUS_OK != retCssWaitCipher) {
                mbedtls_free(pOutput);
                return_code = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
                goto cleanup;
            }
            memcpy(iv, &pOutput[(nr_full_blocks * 16u) - 16], 16);
            mbedtls_free(pOutput);
#endif //MBEDTLS_CBC_MAC_USE_CMAC
        } else if (MCUXCLCSS_CIPHER_KEY_SIZE_AES_192 == key_length) { // use CIPHER for HW acceleration of 192-bit keys
            uint8_t *pOutput = (uint8_t *) mbedtls_calloc(1U, (nr_full_blocks * 16u));
            mbedtls_platform_zeroize(pOutput, (nr_full_blocks * 16u));
            MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(retCssCipherAsync, tokenCssCipherAsync,
                                                 mcuxClCss_Cipher_Async(cipher_options,
                                                                        0u, /* keyIdx is ignored. */
                                                                        pKey,
                                                                        key_length,
                                                                        (uint8_t const *) pInput,
                                                                        (nr_full_blocks * 16u),
                                                                        (uint8_t *) iv,
                                                                        (uint8_t *) pOutput));
            if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Cipher_Async) != tokenCssCipherAsync)
                || (MCUXCLCSS_STATUS_OK_WAIT != retCssCipherAsync)) {
                mbedtls_free(pOutput);
                /* _Cipher_Async shall not return _SW_CANNOT_INTERRUPT after successfully returning from _WaitForOperation. */
                /* _Cipher_Async shall not return _SW_INVALID_PARAM if parameters are set properly. */
                return_code = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
                goto cleanup;
            }

            /* Wait for mcuxClCss_Cipher_Async. */
            MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(retCssWaitCipher, tokenCssWaitCipher,
                                                 mcuxClCss_WaitForOperation(
                                                     MCUXCLCSS_ERROR_FLAGS_CLEAR));
            if (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation) != tokenCssWaitCipher) {
                mbedtls_free(pOutput);
                return_code = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
                goto cleanup;

            }
            if (MCUXCLCSS_STATUS_OK != retCssWaitCipher) {
                return_code = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
                goto cleanup;
            }
            memcpy(iv, &pOutput[(nr_full_blocks * 16u) - 16], 16);
            mbedtls_free(pOutput);
        }
        pInput += (nr_full_blocks * 16u);
    }
    /* process last block */
    if (len_last_block > 0u) {
        // pad with zeros
        uint8_t last_block[16];
        (void) memset(last_block, 0, 16);
        (void) memcpy(last_block, pInput, len_last_block);

        if ((MCUXCLCSS_CMAC_KEY_SIZE_128 == key_length) || // use CMAC for HW Acceleration of 128-bit and 256-bit keys
            (MCUXCLCSS_CMAC_KEY_SIZE_256 == key_length)) {
#ifdef MBEDTLS_CBC_MAC_USE_CMAC
            /* call mcuxClCss_Cmac_Async on padded last block */
            MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(resultLastBlock, tokenLastBlock,
                                                 mcuxClCss_Cmac_Async(cmac_options,
                                                                      0, /* keyIdx is ignored */
                                                                      pKey,
                                                                      key_length,
                                                                      last_block,
                                                                      16u,
                                                                      (uint8_t *) iv));

            if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Cmac_Async) != tokenLastBlock) ||
                (MCUXCLCSS_STATUS_OK_WAIT != resultLastBlock)) {
                return_code = MBEDTLS_ERR_CCM_HW_ACCEL_FAILED;
                goto cleanup;
            }

            /* wait for mcuxClCss_Cmac_Async. */
            MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(retCssWaitLastBlock, tokenCssWaitLastBlock,
                                                 mcuxClCss_WaitForOperation(
                                                     MCUXCLCSS_ERROR_FLAGS_CLEAR));
            if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation) !=
                 tokenCssWaitLastBlock) ||
                (MCUXCLCSS_STATUS_OK != retCssWaitLastBlock)) {
                return_code = MBEDTLS_ERR_CCM_HW_ACCEL_FAILED;
                goto cleanup;
            }
#else
            MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(retCssCipherAsync, tokenCssCipherAsync,
                                                 mcuxClCss_Cipher_Async(cipher_options,
                                                                        0u, /* keyIdx is ignored. */
                                                                        pKey,
                                                                        key_length,
                                                                        last_block,
                                                                        16u,
                                                                        (uint8_t *) iv,
                                                                        (uint8_t *)
                                                                        last_block_output));
            if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Cipher_Async) != tokenCssCipherAsync)
                || (MCUXCLCSS_STATUS_OK_WAIT != retCssCipherAsync)) {
                /* _Cipher_Async shall not return _SW_CANNOT_INTERRUPT after successfully returning from _WaitForOperation. */
                /* _Cipher_Async shall not return _SW_INVALID_PARAM if parameters are set properly. */
                return_code = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
                goto cleanup;
            }

            /* Wait for mcuxClCss_Cipher_Async. */
            MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(retCssWaitCipher, tokenCssWaitCipher,
                                                 mcuxClCss_WaitForOperation(
                                                     MCUXCLCSS_ERROR_FLAGS_CLEAR));
            if (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation) != tokenCssWaitCipher) {
                return_code = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
                goto cleanup;
            }
            if (MCUXCLCSS_STATUS_OK != retCssWaitCipher) {
                return_code = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
                goto cleanup;
            }
            memcpy(iv, last_block_output, 16);
#endif //MBEDTLS_CBC_MAC_USE_CMAC
        } else if (MCUXCLCSS_CIPHER_KEY_SIZE_AES_192 == key_length) { // use CIPHER for HW acceleration of 192-bit keys
            MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(retCssCipherAsync, tokenCssCipherAsync,
                                                 mcuxClCss_Cipher_Async(cipher_options,
                                                                        0u, /* keyIdx is ignored. */
                                                                        pKey,
                                                                        key_length,
                                                                        last_block,
                                                                        16u,
                                                                        (uint8_t *) iv,
                                                                        (uint8_t *)
                                                                        last_block_output));
            if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Cipher_Async) != tokenCssCipherAsync)
                || (MCUXCLCSS_STATUS_OK_WAIT != retCssCipherAsync)) {
                /* _Cipher_Async shall not return _SW_CANNOT_INTERRUPT after successfully returning from _WaitForOperation. */
                /* _Cipher_Async shall not return _SW_INVALID_PARAM if parameters are set properly. */
                return_code = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
                goto cleanup;
            }

            /* Wait for mcuxClCss_Cipher_Async. */
            MCUX_CSSL_FP_FUNCTION_CALL_PROTECTED(retCssWaitCipher, tokenCssWaitCipher,
                                                 mcuxClCss_WaitForOperation(
                                                     MCUXCLCSS_ERROR_FLAGS_CLEAR));
            if (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_WaitForOperation) != tokenCssWaitCipher) {
                return_code = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
                goto cleanup;
            }
            if (MCUXCLCSS_STATUS_OK != retCssWaitCipher) {
                return_code = MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
                goto cleanup;
            }
            memcpy(iv, last_block_output, 16);
        }
    }

    return_code = 0;
cleanup:
  #if defined(MBEDTLS_THREADING_C)
    if ((ret = mbedtls_mutex_unlock(&mbedtls_threading_hwcrypto_css_mutex)) != 0) {
        return ret;
    }
#endif
    return return_code;
}
