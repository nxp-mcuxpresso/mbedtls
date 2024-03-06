/*
 * Copyright 2023 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_THREADING_C)
#include "mbedtls/threading.h"
#endif

#include "platform_hw_ip.h"
#if defined(MBEDTLS_MCUX_ELS_PKC_API)
#include "els_pkc_mbedtls.h"
#elif defined(MBEDTLS_MCUX_ELS_API)
#include "els_mbedtls.h"
#endif

/* For RW61x, SOC_TRNG count is greater than one, this can be utilized 
   to use RNG4 as default entropy source */
#if defined(MBEDTLS_MCUX_USE_TRNG_AS_ENTROPY_SEED)
#include "fsl_trng.h"
/* Change required as different naming is used for TRNG for RW61x (TRNG) and MCXN (TRNG0)*/
#ifndef TRNG
#define TRNG TRNG0
#endif

#else /* Handle the default case, currently to include crypto-lib files
         to use PRNG for default entropy source */

#include <mcuxClEls.h>               // Interface to the entire mcuxClEls component
#include <mcuxCsslFlowProtection.h>  // Code flow protection

#endif /* FSL_FEATURE_SOC_TRNG_COUNT */

#include <mbedtls/error.h>
#include <mbedtls/platform.h>

/* Static function to carry out the initilization only once,
   based upon device configs*/
static void mbedtls_mcux_rng_init(void)
{
    /* Initialize TRNG, CSS/ELS and it's PRNG if not already initialized */
    mbedtls_hw_init();
}

/* Entropy poll callback for a hardware source */
#if defined(MBEDTLS_ENTROPY_HARDWARE_ALT)
int mbedtls_hardware_poll(void *data, unsigned char *output, size_t len, size_t *olen)
{
#if defined(MBEDTLS_THREADING_C)
    int ret;
    if ((ret = mbedtls_mutex_lock(&mbedtls_threading_hwcrypto_els_mutex)) != 0)
        return ret;
#endif

    static bool rng_init_is_done = false;
    status_t return_code = kStatus_Fail;
    
    if(rng_init_is_done == false)
    {
        mbedtls_mcux_rng_init();
        rng_init_is_done = true;
    }

#if defined(MBEDTLS_MCUX_USE_TRNG_AS_ENTROPY_SEED)
    /* call to generate random number and have it in "output" */
    return_code = TRNG_GetRandomData(TRNG, output, len);  

#else

    /* Call ELS to get random data */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClEls_Prng_GetRandom(output, len));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Prng_GetRandom) != token) || (MCUXCLELS_STATUS_OK != result))
    {
        goto cleanup;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    return_code = kStatus_Success;
#endif

    /* If result is success, only then update the *olen*/
    if (kStatus_Success == return_code)
    {
        *olen = len;
    }

#if !(defined(MBEDTLS_MCUX_USE_TRNG_AS_ENTROPY_SEED))
cleanup:
#endif
#if defined(MBEDTLS_THREADING_C)
    if ((ret = mbedtls_mutex_unlock(&mbedtls_threading_hwcrypto_els_mutex)) != 0)
        return ret;
#endif
    return return_code;
}
#endif /* MBEDTLS_ENTROPY_HARDWARE_ALT */
