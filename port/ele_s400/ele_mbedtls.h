/*
 * Copyright 2021 NXP
 * All rights reserved.
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef ELE_MBEDTLS_H
#define ELE_MBEDTLS_H

#include "fsl_common.h"

#if defined(MIMXRT1189_cm33_SERIES)
#define S3MU MU_RT_S3MUA
#elif defined(MIMXRT1189_cm7_SERIES)
#define S3MU MU_APPS_S3MUA
#else
#error "No valid SoC defined"
#endif /* MIMXRT1189_cm33_SERIES | MIMXRT1189_cm7_SERIES */

typedef struct 
{
    uint32_t session_handle;
    uint32_t key_store_handle;
    uint32_t storage_handle;
    uint32_t data_storage_handle;
    uint32_t key_management_handle;
    uint32_t signature_gen_handle;
    uint32_t signature_verif_handle;
    uint32_t hash_handle;
    bool is_fw_loaded;
    bool is_storage_init;
    uint32_t cipher_handle;
    uint32_t mac_handle;
    uint32_t rng_handle;
} ele_ctx_t;

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * @brief Application init for Crypto blocks.
 *
 * This function is provided to be called by MCUXpresso SDK applications.
 * It calls basic init for Crypto Hw acceleration and Hw entropy modules.
 */
status_t CRYPTO_InitHardware(void);

/*!
 * @brief Application deinit for Crypto blocks.
 *
 * This function is provided to be called by MCUXpresso SDK applications.
 * It calls basic deinit for Crypto Hw acceleration and Hw entropy modules.
 */
status_t CRYPTO_DeinitHardware(void);


status_t mbedtls_mcux_rng_init(void);

#ifdef __cplusplus
}
#endif

#endif /* ELE_MBEDTLS_H */
