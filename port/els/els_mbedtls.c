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

/* Initilize the TRNG driver if available*/
#if defined(FSL_FEATURE_SOC_TRNG_COUNT) && (FSL_FEATURE_SOC_TRNG_COUNT > 0)
#include "fsl_trng.h"
#endif

#include "mcux_els.h"           // Power Down Wake-up Init
#include "platform_hw_ip.h"
#include "els_mbedtls.h"
#include "fsl_common.h"

#if !defined(MBEDTLS_MCUX_ELS_PKC_API)

static uint32_t g_isCryptoHWInitialized = ELS_PKC_CRYPTOHW_NONINITIALIZED;

__WEAK uint32_t __stack_chk_guard;

__WEAK void __stack_chk_fail(void)
{
    while (1)
    {
    };
}

int mbedtls_hw_init(void)
{
    status_t status;

    if (g_isCryptoHWInitialized == ELS_PKC_CRYPTOHW_NONINITIALIZED)
    {
        /* Enable ELS and related clocks */
        status = ELS_PowerDownWakeupInit(ELS);
        if (status != kStatus_Success)
        {
            return status;
        }
#if defined(FSL_FEATURE_SOC_TRNG_COUNT) && (FSL_FEATURE_SOC_TRNG_COUNT > 0)
        /* Initilize the TRNG driver */
        {
            trng_config_t trngConfig;
            /* Get default TRNG configs*/
            TRNG_GetDefaultConfig(&trngConfig);
            /* Set sample mode of the TRNG ring oscillator to Von Neumann, for better random data.*/
            /* Initialize TRNG */
            TRNG_Init(TRNG, &trngConfig);
        }
#endif
    }
    else
    {
        return kStatus_Success;
    }

    return status;
}

/******************************************************************************/
/******************** CRYPTO_InitHardware **************************************/
/******************************************************************************/
/*!
 * @brief Application init for various Crypto blocks.
 *
 * This function is provided to be called by MCUXpresso SDK applications.
 * It calls basic init for Crypto Hw acceleration and Hw entropy modules.
 */
status_t CRYPTO_InitHardware(void)
{
    status_t status;
    
    if (g_isCryptoHWInitialized == ELS_PKC_CRYPTOHW_NONINITIALIZED)
    {
        /* Enable ELS and related clocks */
        status = ELS_PowerDownWakeupInit(ELS);
        if (status != kStatus_Success)
        {
            return kStatus_Fail;
        }
#if defined(FSL_FEATURE_SOC_TRNG_COUNT) && (FSL_FEATURE_SOC_TRNG_COUNT > 0)
            /* Initilize the TRNG driver */
            {
                trng_config_t trngConfig;
                /* Get default TRNG configs*/
                TRNG_GetDefaultConfig(&trngConfig);
                /* Set sample mode of the TRNG ring oscillator to Von Neumann, for better random data.*/
                /* Initialize TRNG */
                TRNG_Init(TRNG, &trngConfig);
            }
#endif    
        g_isCryptoHWInitialized = ELS_PKC_CRYPTOHW_INITIALIZED;
    }
    else
    {
        return kStatus_Success;
    }
    return status;
}

/******************************************************************************/
/******************** CRYPTO_ReInitHardware **************************************/
/******************************************************************************/
/*!
 * @brief Application Re-init for various Crypto blocks.
 *
 * This function is provided to be called by MCUXpresso SDK applications after 
 * wake up from different power modes. 
 * It calls basic init for Crypto Hw acceleration and Hw entropy modules.
 * NOTE: The function must be called in single thread context
 */
status_t CRYPTO_ReInitHardware(void)
{
    status_t status;
    /* Only initialize if global static variable is set to initialized, to 
       make sure that CRYPTO_InitHardware is already called once */
    if (g_isCryptoHWInitialized == ELS_PKC_CRYPTOHW_INITIALIZED)
    {
        /* Enable ELS and related clocks */
        status = ELS_PowerDownWakeupInit(ELS);
        if (status != kStatus_Success)
        {
            return kStatus_Fail;
        }
#if defined(FSL_FEATURE_SOC_TRNG_COUNT) && (FSL_FEATURE_SOC_TRNG_COUNT > 0)
            /* Initilize the TRNG driver */
            {
                trng_config_t trngConfig;
                /* Get default TRNG configs*/
                TRNG_GetDefaultConfig(&trngConfig);
                /* Set sample mode of the TRNG ring oscillator to Von Neumann, for better random data.*/
                /* Initialize TRNG */
                TRNG_Init(TRNG, &trngConfig);
            }
#endif
    }
    else
    {
        return kStatus_Success;
    }
    return status;
}
#endif /* !defined(MBEDTLS_MCUX_ELS_PKC_API) */
