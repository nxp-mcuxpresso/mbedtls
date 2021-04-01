/*
 * Copyright 2019-2020 NXP
 * All rights reserved.
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef SSSAPI_MBEDTLS_H
#define SSSAPI_MBEDTLS_H

#if defined(MBEDTLS_NXP_SENTINEL200)
#define SSS_SUBSYSTEM (kType_SSS_Sentinel200)
#elif defined(MBEDTLS_NXP_SENTINEL300)
#define SSS_SUBSYSTEM (kType_SSS_Sentinel300)
#else
#define SSS_SUBSYSTEM (kType_SSS_Software)
#endif

#define SSS_MAX_SUBSYTEM_WAIT          (0xFFFFFFFFu)
#define SSS_PUBLIC_KEY_PART_EXPORTABLE (0xF0u)
#define SSS_FULL_KEY_EXPORTABLE        (0xFFu)
#define SSS_CRYPTOHW_INITIALIZED       (0xF0F0F0F0)
#define SSS_CRYPTOHW_NONINITIALIZED    (0x0F0F0F0F)

#ifdef __cplusplus
extern "C" {
#endif

#include "fsl_sss_mgmt.h"
#include "fsl_sss_sscp.h"
#include "fsl_sscp_mu.h"

extern sss_sscp_key_store_t g_keyStore;
extern sss_sscp_session_t g_sssSession;
extern sscp_context_t g_sscpContext;
extern uint32_t g_isCryptoHWInitialized;

int fsl_mbedtls_printf(const char *fmt_s, ...);
status_t CRYPTO_InitHardware(void);

#ifdef __cplusplus
}
#endif

#endif /* SSSAPI_MBEDTLS_H */
