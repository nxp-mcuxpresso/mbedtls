/*
 * Copyright 2023-2024 NXP
 * All rights reserved.
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "platform_alt.h"
#include "els_pkc_mbedtls.h"

#if defined(MBEDTLS_PLATFORM_C)

#if defined(MBEDTLS_PLATFORM_SETUP_TEARDOWN_ALT)

#include "app.h"

/*
 * Placeholder platform setup that does nothing by default
 */
int mbedtls_platform_setup(mbedtls_platform_context *ctx)
{
    BOARD_InitHardware();
    CRYPTO_InitHardware();

    return 0;
}

/*
 * Placeholder platform teardown that does nothing by default
 */
void mbedtls_platform_teardown(mbedtls_platform_context *ctx)
{
    (void) ctx;
}
#endif /* MBEDTLS_PLATFORM_SETUP_TEARDOWN_ALT */

#endif /* MBEDTLS_PLATFORM_C */

