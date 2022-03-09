/** @file wmsdk_platform_config.h
 *
 *  @brief This file contains header for configuring wmsdk platform
 *
 *  Copyright 2008-2020 NXP
 *
 *  NXP CONFIDENTIAL
 *  The source code contained or described herein and all documents related to
 *  the source code ("Materials") are owned by NXP, its suppliers and/or its
 *  licensors. Title to the Materials remains with NXP, its suppliers and/or its
 *  licensors. The Materials contain trade secrets and proprietary and
 *  confidential information of NXP, its suppliers and/or its licensors. The
 *  Materials are protected by worldwide copyright and trade secret laws and
 *  treaty provisions. No part of the Materials may be used, copied, reproduced,
 *  modified, published, uploaded, posted, transmitted, distributed, or
 *  disclosed in any way without NXP's prior express written permission.
 *
 *  No license under any patent, copyright, trade secret or other intellectual
 *  property right is granted to or conferred upon you by disclosure or delivery
 *  of the Materials, either expressly, by implication, inducement, estoppel or
 *  otherwise. Any license under such intellectual property rights must be
 *  express and approved by NXP in writing.
 *
 */

#ifndef WMSDK_PLATFORM_CONFIG_H
#define WMSDK_PLATFORM_CONFIG_H

#include <wmcrypto_mem.h>
#include <wmlog.h>

/*----------------------------------------------------------------------
 * Enable the platform abstraction layer
 */
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_PLATFORM_PRINTF_ALT
#define MBEDTLS_PLATFORM_STD_PRINTF        PRINTF
/*----------------------------------------------------------------------*/

/*----------------------------------------------------------------------
 * Enable the platform-specific entropy code
 */
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_NO_DEFAULT_ENTROPY_SOURCES
#define MBEDTLS_NO_PLATFORM_ENTROPY
/*----------------------------------------------------------------------*/

/*----------------------------------------------------------------------
 * Enable the memory allocation layer.
 */
#define MBEDTLS_PLATFORM_MEMORY
#define MBEDTLS_PLATFORM_STD_CALLOC		NULL
#define MBEDTLS_PLATFORM_STD_FREE		NULL

/*----------------------------------------------------------------------
 * Enable the semi-portable timing interface.
 */
#define MBEDTLS_TIMING_C
#define MBEDTLS_TIMING_ALT
/*----------------------------------------------------------------------*/

/*----------------------------------------------------------------------
 * Enable the threading abstraction layer.
 */
#define MBEDTLS_THREADING_C
#define MBEDTLS_THREADING_ALT
/*----------------------------------------------------------------------*/

/* The compiler has support for asm(). */
#define MBEDTLS_HAVE_ASM

/* System has time.h and time(). */
#define MBEDTLS_HAVE_TIME
/* System has time.h and time(), gmtime() and the clock is correct. */
#define MBEDTLS_HAVE_TIME_DATE

/*----------------------------------------------------------------------*/
#endif /* WMSDK_PLATFORM_CONFIG_H */
