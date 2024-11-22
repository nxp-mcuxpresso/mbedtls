/*
 * Copyright 2022,2024 NXP
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

#if !defined(MBEDTLS_MCUX_FREERTOS_THREADING_ALT) && defined(MBEDTLS_THREADING_C) && defined(MBEDTLS_THREADING_ALT)
extern void CRYPTO_ConfigureThreading(void);
#endif

/* Initilize the TRNG driver if available*/
#if defined(MBEDTLS_MCUX_USE_TRNG_AS_ENTROPY_SEED)
#include "fsl_trng.h"
/* Change required as different naming is used for TRNG for RW61x (TRNG) and MCXN (TRNG0)*/
#ifndef TRNG
#define TRNG TRNG0
#endif
#endif

#include "mcux_els.h"           // Power Down Wake-up Init
#include "mcux_pkc.h"           // Power Down Wake-up Init
#include "platform_hw_ip.h"
#include "els_pkc_mbedtls.h"
#include "fsl_common.h"

#ifndef PKC
#define PKC PKC0
#endif

#if defined(MBEDTLS_MPI_EXP_MOD_ALT)

#include "mbedtls/platform.h"
#include "mbedtls/platform_util.h"

#include "mbedtls/bignum.h"
#include "mbedtls/error.h"

#include "ip_platform.h"
#include <mcuxClEls.h>
#include <mcuxClPkc.h>
#include <mcuxClMath.h>

#include <mcuxCsslFlowProtection.h>
#include <mcuxClPkc_Functions.h>
#include <internal/mcuxClPkc_Macros.h>
#include <internal/mcuxClPkc_Operations.h>
#include <internal/mcuxClSession_Internal.h>
#include <internal/mcuxClPkc_ImportExport.h>

#define MPI_VALIDATE_RET(cond)                                       \
    MBEDTLS_INTERNAL_VALIDATE_RET(cond, MBEDTLS_ERR_MPI_BAD_INPUT_DATA)
#define MPI_VALIDATE(cond)                                           \
    MBEDTLS_INTERNAL_VALIDATE(cond)

#define ASSERT_CALLED_OR_EXIT(call, func, retval)                            \
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, call);                   \
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(func) != token) || (retval != result)) \
    {                                                                        \
        ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;                         \
        goto exit;                                                           \
    }                                                                        \
    MCUX_CSSL_FP_FUNCTION_CALL_END()

#define ASSERT_CALLED_VOID_OR_EXIT(call, func)          \
    MCUX_CSSL_FP_FUNCTION_CALL_VOID_BEGIN(token, call); \
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(func) != token))  \
    {                                                   \
        ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;    \
        goto exit;                                      \
    }                                                   \
    MCUX_CSSL_FP_FUNCTION_CALL_END()

#define ASSERT_RET_0_OR_EXIT(call) \
    ret = call;                    \
    if (ret != 0)                  \
    {                              \
        goto exit;                 \
    }

#endif // if defined(MBEDTLS_MPI_EXP_MOD_ALT)

/******************************************************************************/
/*************************** Mutex ********************************************/
/******************************************************************************/
#if defined(MBEDTLS_THREADING_C)

/**
 * \def MBEDTLS_MCUX_FREERTOS_THREADING_ALT
 * You can comment this macro if you provide your own alternate implementation.
 *
 */
#if defined(SDK_OS_FREE_RTOS)
#define MBEDTLS_MCUX_FREERTOS_THREADING_ALT
#endif

/*
 * Define global mutexes for HW accelerator
 */
mbedtls_threading_mutex_t mbedtls_threading_hwcrypto_els_mutex;
mbedtls_threading_mutex_t mbedtls_threading_hwcrypto_pkc_mutex;

#if defined(MBEDTLS_MCUX_FREERTOS_THREADING_ALT)
/**
 * @brief Initializes the mbedTLS mutex functions.
 *
 * Provides mbedTLS access to mutex create, destroy, take and free.
 *
 * @see MBEDTLS_THREADING_ALT
 */
static void CRYPTO_ConfigureThreadingMcux(void);
#endif /* defined(MBEDTLS_MCUX_FREERTOS_THREADING_ALT) */

#endif /* defined(MBEDTLS_THREADING_C) */

static uint32_t g_isCryptoHWInitialized = ELS_PKC_CRYPTOHW_NONINITIALIZED;

__WEAK uint32_t __stack_chk_guard;

__WEAK void __stack_chk_fail(void)
{
    while (1)
    {
    };
}

static status_t common_init_els_pkc_and_trng(uint32_t pkc_init_mode)
{
    status_t status;
    /* Enable ELS and related clocks */
    status = ELS_PowerDownWakeupInit(ELS);
    if (status == kStatus_Success)
    {
        if (pkc_init_mode == PKC_INIT_ZEROIZE)
        {
          /* Enable PKC related clocks and RAM zeroize */
          status = PKC_PowerDownWakeupInit(PKC);
        }
        else if (pkc_init_mode == PKC_INIT_NO_ZEROIZE)
        {
          /* Enable PKC related clocks without RAM zeroize */
          status = PKC_InitNoZeroize(PKC);
        }
        else
        {
          status = kStatus_Fail;
        }
    
#if defined(MBEDTLS_MCUX_USE_TRNG_AS_ENTROPY_SEED)
        /* Initilize the TRNG driver */
        if (status == kStatus_Success)
        {
            trng_config_t trngConfig;
            
            /* Get default TRNG configs*/
            status = TRNG_GetDefaultConfig(&trngConfig);
            
            if(status == kStatus_Success)
            {
                /* Set sample mode of the TRNG ring oscillator to Von Neumann, for better random data.*/
                /* Initialize TRNG */
                status = TRNG_Init(TRNG, &trngConfig);
            }
        }
#endif
    }
    return status;
}

int mbedtls_hw_init(void)
{
    status_t status;

    if (g_isCryptoHWInitialized == ELS_PKC_CRYPTOHW_NONINITIALIZED)
    {
        status = common_init_els_pkc_and_trng(PKC_INIT_NO_ZEROIZE);
    }
    else
    {
        status = kStatus_Success;
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
#if defined(MBEDTLS_THREADING_C) && defined(MBEDTLS_THREADING_ALT)
        CRYPTO_ConfigureThreadingMcux();
        mbedtls_mutex_init(&mbedtls_threading_hwcrypto_els_mutex);
        mbedtls_mutex_init(&mbedtls_threading_hwcrypto_pkc_mutex);
#endif /* (MBEDTLS_THREADING_C) && defined(MBEDTLS_THREADING_ALT) */

        /* Initialize the els_pkc and trng*/
        status = common_init_els_pkc_and_trng(PKC_INIT_ZEROIZE);

        /* Set the global static flag for els_pkc HW init to initialized*/
        g_isCryptoHWInitialized = ELS_PKC_CRYPTOHW_INITIALIZED;
    }
    else
    {
        status = kStatus_Success;
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
 * wake up from different power modes. Mutex re-init is not required as RAM is 
 * retained and mutexes are already available.
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
        /* Initialize the els_pkc and trng*/
        status = common_init_els_pkc_and_trng(PKC_INIT_ZEROIZE); 
    }
    else
    {
        status = kStatus_Success;
    }
    return status;
}
/*-----------------------------------------------------------*/
/*--------- mbedTLS threading functions for FreeRTOS --------*/
/*--------------- See MBEDTLS_THREADING_ALT -----------------*/
/*-----------------------------------------------------------*/
#if defined(MBEDTLS_MCUX_FREERTOS_THREADING_ALT)
/* Threading mutex implementations for mbedTLS. */
#include "mbedtls/threading.h"
#include "threading_alt.h"

/**
 * @brief Implementation of mbedtls_mutex_init for thread-safety.
 *
 */
void mcux_mbedtls_mutex_init(mbedtls_threading_mutex_t *mutex)
{
    mutex->mutex = xSemaphoreCreateMutex();

    if (mutex->mutex != NULL)
    {
        mutex->is_valid = 1;
    }
    else
    {
        mutex->is_valid = 0;
    }
}

/**
 * @brief Implementation of mbedtls_mutex_free for thread-safety.
 *
 */
void mcux_mbedtls_mutex_free(mbedtls_threading_mutex_t *mutex)
{
    if (mutex->is_valid == 1)
    {
        vSemaphoreDelete(mutex->mutex);
        mutex->is_valid = 0;
    }
}

/**
 * @brief Implementation of mbedtls_mutex_lock for thread-safety.
 *
 * @return 0 if successful, MBEDTLS_ERR_THREADING_MUTEX_ERROR if timeout,
 * MBEDTLS_ERR_THREADING_BAD_INPUT_DATA if the mutex is not valid.
 */
int mcux_mbedtls_mutex_lock(mbedtls_threading_mutex_t *mutex)
{
    int ret = MBEDTLS_ERR_THREADING_BAD_INPUT_DATA;

    if (mutex->is_valid == 1)
    {
        if (xSemaphoreTake(mutex->mutex, portMAX_DELAY))
        {
            ret = 0;
        }
        else
        {
            ret = MBEDTLS_ERR_THREADING_MUTEX_ERROR;
        }
    }

    return ret;
}

/**
 * @brief Implementation of mbedtls_mutex_unlock for thread-safety.
 *
 * @return 0 if successful, MBEDTLS_ERR_THREADING_MUTEX_ERROR if timeout,
 * MBEDTLS_ERR_THREADING_BAD_INPUT_DATA if the mutex is not valid.
 */
int mcux_mbedtls_mutex_unlock(mbedtls_threading_mutex_t *mutex)
{
    int ret = MBEDTLS_ERR_THREADING_BAD_INPUT_DATA;

    if (mutex->is_valid == 1)
    {
        if (xSemaphoreGive(mutex->mutex))
        {
            ret = 0;
        }
        else
        {
            ret = MBEDTLS_ERR_THREADING_MUTEX_ERROR;
        }
    }

    return ret;
}

static void CRYPTO_ConfigureThreadingMcux(void)
{
    /* Configure mbedtls to use FreeRTOS mutexes. */
    mbedtls_threading_set_alt(mcux_mbedtls_mutex_init, mcux_mbedtls_mutex_free, mcux_mbedtls_mutex_lock,
                              mcux_mbedtls_mutex_unlock);
}
#endif /* defined(MBEDTLS_MCUX_FREERTOS_THREADING_ALT) */

#if defined(MBEDTLS_MPI_EXP_MOD_ALT)


// The following operands are used for calculation of the 
// modular exponentiation    
#define OP_X   0u
#define OP_R   1u
#define OP_N   2u
#define OP_T0  3u
#define OP_T1  4u
#define OP_T2  5u
#define OP_T3  6u
#define OP_TE  7u
    
// The following ones are used only during calcualtion of montgomery 
// representation of N and for transforming the result back. Those can 
// be overlayed with (temp) buffers from the exponentiation exponentiation 
// to save memory in PKC RAM.
#define NUMBER_BUFFER  8u
#define OP_S     OP_T0
#define OP_Q2    OP_T1
#define OP_T     OP_T2

#define OFFSET_FIRST_OPERAND  0x0u


static size_t sz_max(size_t a, size_t b) {
    if (a > b) {
        return a;
    }
    return b;
}

/* Access to original version of mbedtls_mpi_exp_mod function. */
int mbedtls_mpi_exp_mod_orig(
    mbedtls_mpi *X,
    const mbedtls_mpi *A,
    const mbedtls_mpi *E,
    const mbedtls_mpi *N,
    mbedtls_mpi *_RR); 


int mbedtls_mpi_exp_mod(
    mbedtls_mpi *X, const mbedtls_mpi *A, const mbedtls_mpi *E, const mbedtls_mpi *N, mbedtls_mpi *_RR)
{
    int ret                  = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
#if defined(MBEDTLS_THREADING_C)
    bool pkc_mutex_locked    = false;
#endif
    bool pkc_initialized     = false;
    bool session_initialized = false;
    mcuxClPkc_State_t pkc_state;

    // In case of negative or too large base, we need a temporary 
    // positive/reduced copy of A.
    mbedtls_mpi A_pos;
    mbedtls_mpi_init(&A_pos);
    mbedtls_mpi A_reduced;
    mbedtls_mpi_init(&A_reduced);

    uint8_t* exp_buffer = NULL;
    uint32_t* tmp_buffer = NULL;

    MPI_VALIDATE_RET(X != NULL);
    MPI_VALIDATE_RET(A != NULL);
    MPI_VALIDATE_RET(E != NULL);
    MPI_VALIDATE_RET(N != NULL);

    // Points may not be normalized. For the PKC operations, we want to reserve as 
    // little space as possible, so we need to know the real bitsizes of the operands.
    size_t bitlen_n = mbedtls_mpi_bitlen(N);
    size_t bitlen_e = mbedtls_mpi_bitlen(E);

    // A negative or even modulus is invalid.
    if (mbedtls_mpi_cmp_int(N, 0) <= 0 || (N->p[0] & 1) == 0)
    {
        ret = MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
        goto exit;
    }

    if (bitlen_e > MBEDTLS_MPI_MAX_BITS || bitlen_n > MBEDTLS_MPI_MAX_BITS)
    {
        ret = MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
        goto exit;
    }

    // A negative exponent is invalid.
    if (mbedtls_mpi_cmp_int(E, 0) < 0)
    {
        ret = MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
        goto exit;
    }

    // If the exponent is 0, fall back to SW implementation.
    if (mbedtls_mpi_cmp_int(E, 0) == 0)
    {
        ret = mbedtls_mpi_exp_mod_orig(X, A, E, N, _RR);
        goto exit;
    }

    // If the modulus or the exponent is too small, fall back to SW implementation.
    if ((bitlen_n < (MCUXCLPKC_WORDSIZE * 8)) || (bitlen_e < (MCUXCLPKC_WORDSIZE * 8)))
    {
        ret = mbedtls_mpi_exp_mod_orig(X, A, E, N, _RR);
        goto exit;
    }

    // Compensate for negative A (and correct at the end).
    bool neg = (A->s == -1);
    if (neg) {
        ASSERT_RET_0_OR_EXIT(mbedtls_mpi_copy(&A_pos, A));
        A_pos.s = 1;
        A = &A_pos;
    }

    // If base is greater than modulus, we must first reduce it due to PKC requirement
    // on modular exponentiaton that it needs number less than modulus.
    // We can take advantage of modular arithmetic rule that: A^B mod C = ( (A mod C)^B ) mod C.
    // So we do (A mod N) first, then we can do modular exponentiation in PKC.
    if (mbedtls_mpi_cmp_mpi(A, N) >= 0)
    {
        ASSERT_RET_0_OR_EXIT(mbedtls_mpi_mod_mpi(&A_reduced, A, N));
        A = &A_reduced;
    }

#if defined(MBEDTLS_THREADING_C)
    ASSERT_RET_0_OR_EXIT(mbedtls_mutex_lock(&mbedtls_threading_hwcrypto_pkc_mutex));
    pkc_mutex_locked = true;
#endif

    ASSERT_CALLED_VOID_OR_EXIT(mcuxClPkc_Initialize(&pkc_state), mcuxClPkc_Initialize);
    pkc_initialized = true;

    const size_t bytelen_n = (bitlen_n + 7) / 8;
    const size_t bytelen_e = (bitlen_e + 7) / 8;

    // The most significant 32 bits / 4 bytes of the modulus need to be 0 because 
    // of PKC requirements. We achieve that by artificially increasing the operand size 
    // by 4 bytes.
    size_t pkc_operand_size = MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(bytelen_n + 4);

    // mbedtls_printf("operand_size: 0x (%d)\n", operandSize, operandSize);

    // iX (bits 16~23): index of base number (PKC operand),
    // size = operandSize + MCUXCLPKC_WORDSIZE (= lenN + MCUXCLPKC_WORDSIZE).
    const size_t bufferSizeX = pkc_operand_size + MCUXCLPKC_WORDSIZE; // size of the base

    // size of the result of the exponentiation
    // iR (bits 0~7): index of result (PKC operand).
    // The size shall be at least max(MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(expByteLength + 1), lenN + MCUXCLPKC_WORDSIZE).
    const size_t bufferSizeR = sz_max(MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(bytelen_e + 1), pkc_operand_size + MCUXCLPKC_WORDSIZE);

    // iN (bits 24~31): index of modulus (PKC operand), size = operandSize (= lenN).
    const size_t bufferSizeN =
        pkc_operand_size + MCUXCLPKC_WORDSIZE; // size of N + PKC word in front of the modulus buffer for NDash

    // iT0 (bits 8~15): index of temp0 (PKC operand).
    // The size shall be at least max(MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(expByteLength + 1), lenN + MCUXCLPKC_WORDSIZE).
    const size_t bufferSizeT0 = sz_max(MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(bytelen_e + 1), pkc_operand_size + MCUXCLPKC_WORDSIZE);

    // iT1 (bits 0~7): index of temp1 (PKC operand).
    // Its size shall be at least max(MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(expByteLength + 1), lenN + MCUXCLPKC_WORDSIZE, 2 *
    // MCUXCLPKC_WORDSIZE).
    const size_t bufferSizeT1 = sz_max(
        sz_max(MCUXCLPKC_ALIGN_TO_PKC_WORDSIZE(bytelen_e + 1), pkc_operand_size + MCUXCLPKC_WORDSIZE), 2 * MCUXCLPKC_WORDSIZE);

    // iT2 (bits 8~15): index of temp2 (PKC operand).
    // Its size shall be at least max(lenN + MCUXCLPKC_WORDSIZE, 2 * MCUXCLPKC_WORDSIZE).
    const size_t bufferSizeT2 = sz_max(pkc_operand_size + MCUXCLPKC_WORDSIZE, 2 * MCUXCLPKC_WORDSIZE);

    // iT3 (bits 24~31): index of temp3 (PKC operand).
    // Its size shall be at least max(lenN + MCUXCLPKC_WORDSIZE, 2 * MCUXCLPKC_WORDSIZE).
    const size_t bufferSizeT3 = sz_max(pkc_operand_size + MCUXCLPKC_WORDSIZE, 2 * MCUXCLPKC_WORDSIZE);

    // iTE (bits 16~23): index of temp4 (PKC operand).
    // The size shall be at least (6 * MCUXCLPKC_WORDSIZE).
    const size_t bufferSizeTE = 6u * MCUXCLPKC_WORDSIZE;

    // ### NDash calculation:
    // iT (bits 0~7): index of temp (PKC operand).
    // The size of temp shall be at least (2 * MCUXCLPKC_WORDSIZE).
    // T is overlayed with mod_exp_T2, size is OK.
    const uint32_t bufferSizeT = bufferSizeT2;

    // ### QSqared calculation:
    // iT (bits 0~7): index of temp (PKC operand).
    // The size of temp shall be at least (operandSize + MCUXCLPKC_WORDSIZE).
    // T is overlayed with mod_exp_T2, size is OK.

    // iN (bits 8~15): index of modulus (PKC operand), size = operandSize.
    // NDash of modulus shall be stored in the PKC word before modulus.
    // This the modulus buffer used throughout the function, size is OK.

    // iNShifted (bits 16~23): index of shifted modulus (PKC operand), size = operandSize.
    // If there is no leading zero in the PKC operand modulus, it can be iN.
    // This is overlayed with mod_exp_T0, size is OK.

    // iQSqr (bits 24~31): index of result QSquared (PKC operand), size = operandSize.
    // QSquared might be greater than modulus.
    // Q2 is overlayed with mod_exp_T1, size is OK

    // ### Calculate montgomery representation of base
    // iR: result of the multiplication size shall be operandSize.
    // iR is overlayed with mod_exp_X - the base of the exponentiation, size is OK.

    // iX, iY: the two numbers that are multiplied, size shall be operandSize.
    // iX is overlayed with mod_exp_T1, size is OK.
    // iY is overlayed with mod_exp_T0, size is OK.

    // iZ: the modulus
    // This the modulus buffer used throughout the function, size is OK.

    // ### reduction of result
    // iR: the result, size shall be operandSize.
    // This is overlayed with mod_exp_T2, size is OK.

    // iX: the number to reduce
    // This is the output of the exponentiaion, mod_exp_R, size is OK.

    // iZ: the modulus
    // This the modulus buffer used throughout the function, size is OK.

    const size_t bufferSizeS = bufferSizeT0;
    const size_t pkcWaLength =
        bufferSizeR + bufferSizeN + bufferSizeT0 + bufferSizeT1 + bufferSizeT2 + bufferSizeT3 + bufferSizeTE;

    if ((pkcWaLength + OFFSET_FIRST_OPERAND) > PKC_RAM_SIZE) 
    {
        ret = mbedtls_mpi_exp_mod_orig(X, A, E, N, _RR);
        goto exit;
    }

    uint32_t *pPkcWaBuffer = (uint32_t *)(PKC_RAM_ADDR + OFFSET_FIRST_OPERAND);
    uint8_t *pPkcWaBuffer8 = (uint8_t *)pPkcWaBuffer;

    mcuxClSession_Descriptor_t session;
    ASSERT_CALLED_OR_EXIT(mcuxClSession_init(&session, NULL, 0, pPkcWaBuffer, pkcWaLength), mcuxClSession_init,
                          MCUXCLSESSION_STATUS_OK);
    session_initialized = true;

    uint16_t pOperands[NUMBER_BUFFER];
    pOperands[OP_X]  = MCUXCLPKC_PTR2OFFSET(pPkcWaBuffer8);
    pOperands[OP_R]  = MCUXCLPKC_PTR2OFFSET(pPkcWaBuffer8 + bufferSizeX);
    pOperands[OP_N]  = MCUXCLPKC_PTR2OFFSET(pPkcWaBuffer8 + bufferSizeX + bufferSizeR);
    pOperands[OP_T0] = MCUXCLPKC_PTR2OFFSET(pPkcWaBuffer8 + bufferSizeX + bufferSizeR + bufferSizeN);
    pOperands[OP_T1] = MCUXCLPKC_PTR2OFFSET(pPkcWaBuffer8 + bufferSizeX + bufferSizeR + bufferSizeN + bufferSizeT0);
    pOperands[OP_T2] =
        MCUXCLPKC_PTR2OFFSET(pPkcWaBuffer8 + bufferSizeX + bufferSizeR + bufferSizeN + bufferSizeT0 + bufferSizeT1);
    pOperands[OP_T3] = MCUXCLPKC_PTR2OFFSET(pPkcWaBuffer8 + bufferSizeX + bufferSizeR + bufferSizeN + bufferSizeT0 +
                                            bufferSizeT1 + bufferSizeT2);
    pOperands[OP_TE] = MCUXCLPKC_PTR2OFFSET(pPkcWaBuffer8 + bufferSizeX + bufferSizeR + bufferSizeN + bufferSizeT0 +
                                            bufferSizeT1 + bufferSizeT2 + bufferSizeT3);

    /* Set UPTRT table */
    MCUXCLPKC_WAITFORREADY();
    MCUXCLPKC_SETUPTRT(pOperands);

    /* Clear work area */
    MCUXCLPKC_WAITFORREADY();
    MCUXCLPKC_PS1_SETLENGTH(0u, pkcWaLength);
    MCUXCLPKC_WAITFORREADY();
    ASSERT_CALLED_VOID_OR_EXIT(MCUXCLPKC_CALC_OP1_CONST(OP_X, 0u), mcuxClPkc_CalcConst);

    /* Set operand size for the rest of the operations */
    MCUXCLPKC_WAITFORREADY();
    MCUXCLPKC_PS1_SETLENGTH(pkc_operand_size, pkc_operand_size);

    /* Import N. */
    uint16_t offsetN = pOperands[OP_N] + MCUXCLPKC_WORDSIZE;
    pOperands[OP_N]  = offsetN;

    uint8_t *pN = (uint8_t *)MCUXCLPKC_OFFSET2PTR(pOperands[OP_N]);
    uint8_t *pT = (uint8_t *)MCUXCLPKC_OFFSET2PTR(pOperands[OP_T]);
    uint8_t *pS = (uint8_t *)MCUXCLPKC_OFFSET2PTR(pOperands[OP_S]);

    MCUXCLPKC_WAITFORFINISH();
    ASSERT_RET_0_OR_EXIT(mbedtls_mpi_write_binary_le(N, pN, bufferSizeN));
    __DSB();

    // Calculate Q^2 and N-Dash
    MCUXCLPKC_WAITFORREADY();
    ASSERT_CALLED_VOID_OR_EXIT(MCUXCLMATH_NDASH(OP_N, OP_T), mcuxClMath_NDash);
    MCUXCLPKC_WAITFORREADY();
    ASSERT_CALLED_VOID_OR_EXIT(MCUXCLMATH_SHIFTMODULUS(OP_S, OP_N), mcuxClMath_ShiftModulus);
    MCUXCLPKC_WAITFORREADY();
    ASSERT_CALLED_VOID_OR_EXIT(MCUXCLMATH_QSQUARED(OP_Q2, OP_S, OP_N, OP_T), mcuxClMath_QSquared);

    // Import base
    MCUXCLPKC_WAITFORFINISH();
    ASSERT_RET_0_OR_EXIT(mbedtls_mpi_write_binary_le(A, pS, bufferSizeS));
    __DSB();

    // Calculate montgomery representation of base
    MCUXCLPKC_WAITFORREADY();
    ASSERT_CALLED_VOID_OR_EXIT(MCUXCLPKC_CALC_MC1_MM(OP_X, OP_Q2, OP_S, OP_N), mcuxClPkc_Calc);

    const uint32_t tmp_buffer_alignment = sizeof(uint32_t);
    exp_buffer = mbedtls_calloc(bytelen_e, sizeof(uint8_t));
    tmp_buffer = mbedtls_calloc(bytelen_e + tmp_buffer_alignment, sizeof(uint8_t));
    if (exp_buffer == NULL || tmp_buffer == NULL)
    {
        ret = MBEDTLS_ERR_MPI_ALLOC_FAILED;
        goto exit;
    }
    uint32_t tmp_buffer_addr = (uint32_t) tmp_buffer;
    uint32_t tmp_buffer_addr_aligned = ((tmp_buffer_addr + tmp_buffer_alignment - 1) / tmp_buffer_alignment) * tmp_buffer_alignment;
    uint32_t* tmp_buffer_aligned = (uint32_t*) tmp_buffer_addr_aligned;
    ASSERT_RET_0_OR_EXIT(mbedtls_mpi_write_binary(E, exp_buffer, bytelen_e));

    MCUXCLPKC_WAITFORREADY();
    ASSERT_CALLED_OR_EXIT(MCUXCLMATH_SECMODEXP(&session, exp_buffer, tmp_buffer_aligned, bytelen_e, OP_R, OP_X, OP_N,
                                               OP_TE, OP_T0, OP_T1, OP_T2, OP_T3),
                          mcuxClMath_SecModExp, MCUXCLMATH_STATUS_OK);

    /* Convert R back to NR. */
    MCUXCLPKC_WAITFORREADY();
    ASSERT_CALLED_VOID_OR_EXIT(MCUXCLPKC_CALC_MC1_MR(OP_T, OP_R, OP_N), mcuxClPkc_Calc);
    MCUXCLPKC_WAITFORREADY();
    ASSERT_CALLED_VOID_OR_EXIT(MCUXCLPKC_CALC_MC1_MS(OP_T, OP_T, OP_N, OP_N), mcuxClPkc_Calc);

    /* Put the result back into a mpi structure */
    MCUXCLPKC_WAITFORFINISH();
    mbedtls_mpi_free(X);
    ASSERT_RET_0_OR_EXIT(mbedtls_mpi_read_binary_le(X, pT, bufferSizeT));

    // Compoensate for negative numbers
    if (neg && E->n != 0 && (E->p[0] & 1) != 0) {
        X->s = -1;
        ASSERT_RET_0_OR_EXIT(mbedtls_mpi_add_mpi(X, N, X));
    }

exit:
    mbedtls_mpi_free(&A_pos);
    mbedtls_mpi_free(&A_reduced);
    mbedtls_free(exp_buffer);
    mbedtls_free(tmp_buffer);

    if (session_initialized)
    {
        MCUXCLPKC_WAITFORREADY();
        MCUX_CSSL_FP_FUNCTION_CALL_VOID_BEGIN(token, mcuxClSession_cleanup(&session));
        if (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_cleanup) != token)
        {
            return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        }
        MCUX_CSSL_FP_FUNCTION_CALL_END();
    }

    if (pkc_initialized)
    {
        MCUXCLPKC_WAITFORREADY();
        MCUX_CSSL_FP_FUNCTION_CALL_VOID_BEGIN(token, mcuxClPkc_Deinitialize(&pkc_state));
        if (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClPkc_Deinitialize) != token)
        {
            return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        }
        MCUX_CSSL_FP_FUNCTION_CALL_END();
    }

#if defined(MBEDTLS_THREADING_C)
    if (pkc_mutex_locked)
    {
        ASSERT_RET_0_OR_EXIT(mbedtls_mutex_unlock(&mbedtls_threading_hwcrypto_pkc_mutex));
    }
#endif
    return ret;
}

#endif // defined(MBEDTLS_MPI_EXP_MOD_ALT)
