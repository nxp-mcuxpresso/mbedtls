/*
 * Copyright 2022 NXP
 * All rights reserved.
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif


#if defined(MBEDTLS_ENTROPY_HARDWARE_ALT)

#include "ele_crypto.h"
#include "ele_mbedtls.h"

extern ele_ctx_t g_ele_ctx; /* Global context */

/* Initialize RNG and store its handle ID in global ctx */
status_t mbedtls_mcux_rng_init(void)
{
    return ELE_OpenRngService(S3MU, g_ele_ctx.session_handle, &g_ele_ctx.rng_handle);
}

/* Entropy poll callback for a hardware source */
int mbedtls_hardware_poll(void *data, unsigned char *output, size_t len, size_t *olen)
{
    status_t result = kStatus_Success;
    
    /* Check global ctx if RNG is initialized */
    if(g_ele_ctx.rng_handle == 0)
    {
        result = mbedtls_mcux_rng_init();
        if(result != kStatus_Success)
        {
            return kStatus_Fail;
        }
        
    }

    result = ELE_RngGetRandom(S3MU, g_ele_ctx.rng_handle, (uint32_t*) output, len);

    if (result == kStatus_Success)
    {
        *olen = len;
        return 0;
    }
    else
    {
        return result;
    }
}

#endif /* MBEDTLS_ENTROPY_HARDWARE_ALT */

