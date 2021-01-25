/*
 * Copyright 2019-2020 NXP
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

#include "sssapi_mbedtls.h"
#include "fsl_common.h"
#include "fsl_snt.h"

sss_sscp_key_store_t g_keyStore;
sss_sscp_session_t g_sssSession;
sscp_context_t g_sscpContext;
static uint32_t g_isCryptoHWInitialized = 0;

/******************************************************************************/
/******************** CRYPTO_InitHardware **************************************/
/******************************************************************************/
/*!
 * @brief Application init for various Crypto blocks.
 *
 * This function is provided to be called by MCUXpresso SDK applications.
 * It calls basic init for Crypto Hw acceleration and Hw entropy modules.
 */
void CRYPTO_InitHardware(void)
{
    if (!g_isCryptoHWInitialized)
    {
        sss_sscp_rng_t rctx;
        SNT_loadFwLocal(S3MUA);
        if (SNT_mu_wait_for_ready(S3MUA, SSS_MAX_SUBSYTEM_WAIT) != kStatus_SNT_Success)
        {
        }
        else if (sscp_mu_init(&g_sscpContext, (MU_Type*)S3MUA) != kStatus_SSCP_Success)
        {
        }
        else if (sss_sscp_open_session(&g_sssSession, SSS_SUBSYSTEM, &g_sscpContext, 0u, NULL) !=
                 kStatus_SSS_Success)
        {
        }
        else if (sss_sscp_key_store_context_init(&g_keyStore, &g_sssSession) != kStatus_SSS_Success)
        {
        }
        else if (sss_sscp_key_store_allocate(&g_keyStore, 0u) != kStatus_SSS_Success)
        {
        }
        /* RNG call used to init Sentinel TRNG required e.g. by sss_sscp_key_store_generate_key service
        if TRNG inicialization is no needed for used operations, the following code can be removed
        to increase the perfomance.*/
        else if (sss_sscp_rng_context_init(&g_sssSession, &rctx, 0x1u) != kStatus_SSS_Success)
        {
        }
        else if (sss_sscp_rng_get_random(&rctx, NULL, 0x0u) != kStatus_SSS_Success)
        {
        }
        else if (sss_sscp_rng_free(&rctx) != kStatus_SSS_Success)
        {
        }
        g_isCryptoHWInitialized = 1;
    }
}