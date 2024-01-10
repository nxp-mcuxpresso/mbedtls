#ifndef MBEDTLS_PLATFORM_ALT_H
#define MBEDTLS_PLATFORM_ALT_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "limits.h"


#ifdef __cplusplus
extern "C" {
#endif

// Avoid duplicate definition (from mbedtls/tests/include/test/macros.h and fsl_common.h (via debug console))
#undef MIN
#undef MAX

// #define stderr          0
typedef struct mbedtls_platform_context {
    char dummy; /**< A placeholder member, as empty structs are not portable. */
}
mbedtls_platform_context;

#ifdef __cplusplus
}
#endif
#endif /* platform.h */
