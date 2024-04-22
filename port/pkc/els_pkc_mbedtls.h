/*
 * Copyright 2022 NXP
 * All rights reserved.
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef ELS_PKC_MBEDTLS_H
#define ELS_PKC_MBEDTLS_H

#ifdef __cplusplus
extern "C" {
#endif

#include "fsl_common.h"

#if defined(MBEDTLS_THREADING_C)
/* Threading mutex implementations for mbedTLS. */
#include "mbedtls/threading.h"
#include "threading_alt.h"
#endif

#define PKC_INIT_ZEROIZE        (0xA0A0A0A0u)
#define PKC_INIT_NO_ZEROIZE     (0x0A0A0A0Au)
#define ELS_PKC_CRYPTOHW_INITIALIZED    (0xF0F0F0F0U)
#define ELS_PKC_CRYPTOHW_NONINITIALIZED (0x0F0F0F0FU)

int fsl_mbedtls_printf(const char *fmt_s, ...);
status_t CRYPTO_InitHardware(void);
status_t CRYPTO_ReInitHardware(void);

#if defined(MBEDTLS_THREADING_C) && defined(MBEDTLS_THREADING_ALT)
/* MUTEX FOR HW Modules*/
extern mbedtls_threading_mutex_t mbedtls_threading_hwcrypto_els_mutex;
extern mbedtls_threading_mutex_t mbedtls_threading_hwcrypto_pkc_mutex;
#endif /* (MBEDTLS_THREADING_C) && defined(MBEDTLS_THREADING_ALT) */ 

#if defined(MBEDTLS_THREADING_C) && defined(MBEDTLS_THREADING_ALT)
static inline int mcux_els_mutex_lock(void)
{
    int ret;
    if ((ret = mbedtls_mutex_lock(&mbedtls_threading_hwcrypto_els_mutex)) != 0)
    {
        return ret;
    }
    return ret;
}

static inline int mcux_els_mutex_unlock(void)
{
    int ret;
    if ((ret = mbedtls_mutex_unlock(&mbedtls_threading_hwcrypto_els_mutex)) != 0)
    {
        return ret;
    }
    return ret;
}

static inline int mcux_pkc_mutex_lock(void)
{
    int ret;
    if ((ret = mbedtls_mutex_lock(&mbedtls_threading_hwcrypto_pkc_mutex)) != 0)
    {
        return ret;
    }
    return ret;
}

static inline int mcux_pkc_mutex_unlock(void)
{
    int ret;
    if ((ret = mbedtls_mutex_unlock(&mbedtls_threading_hwcrypto_pkc_mutex)) != 0)
    {
        return ret;
    }
    return ret;
}
#endif /* (MBEDTLS_THREADING_C) && defined(MBEDTLS_THREADING_ALT) */ 
#ifdef __cplusplus
}
#endif

#endif /* ELS_PKC_MBEDTLS_H */
