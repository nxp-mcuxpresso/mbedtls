/*
 * Copyright 2017 NXP
 * All rights reserved.
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef KSDK_MBEDTLS_H
#define KSDK_MBEDTLS_H

#ifdef __cplusplus
extern "C" {
#endif

int fsl_mbedtls_printf(const char *fmt_s, ...);
status_t CRYPTO_InitHardware(void);

#if defined(MBEDTLS_MCUX_FREERTOS_THREADING_ALT)
/**
 * @brief Initializes the mbedTLS mutex functions.
 *
 * Provides mbedTLS access to mutex create, destroy, take and free.
 *
 * @see MBEDTLS_THREADING_ALT
 */
void CRYPTO_ConfigureThreading(void);
#endif /* defined(MBEDTLS_MCUX_FREERTOS_THREADING_ALT) */

#ifdef __cplusplus
}
#endif

#endif /* KSDK_MBEDTLS_H */
