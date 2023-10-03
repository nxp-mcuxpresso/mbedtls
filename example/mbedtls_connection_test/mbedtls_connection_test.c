/*
 * Copyright (c) 2016, Freescale Semiconductor, Inc.
 * Copyright 2016-2023 NXP
 * All rights reserved.
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*******************************************************************************
 * Includes
 ******************************************************************************/

#include "lwip/opt.h"

#if LWIP_SOCKET
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>

#include "ethernetif.h"
#include "board.h"
#include "app.h"
#ifndef configMAC_ADDR
#include "fsl_silicon_id.h"
#endif
#include "fsl_phy.h"

#include "lwip/netif.h"
#include "lwip/sys.h"
#include "lwip/arch.h"
#include "lwip/api.h"
#include "lwip/netifapi.h"
#include "lwip/tcpip.h"
#include "lwip/ip.h"
#include "lwip/sockets.h"
#include "netif/etharp.h"

#ifdef MBEDTLS_MCUX_ELE_S400_API
#include "ele_mbedtls.h"
#else
#include "ksdk_mbedtls.h"
#endif /* MBEDTLS_MCUX_ELE_S400_API */

#include "httpsrv.h"

#include "mbedtls/certs.h"

#include "mbedtls_httpscli.h"

#include "semphr.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/

#ifndef EXAMPLE_NETIF_INIT_FN
/*! @brief Network interface initialization function. */
#define EXAMPLE_NETIF_INIT_FN ethernetif0_init
#endif /* EXAMPLE_NETIF_INIT_FN */

#ifndef HTTPD_DEBUG
#define HTTPD_DEBUG LWIP_DBG_ON
#endif
#ifndef HTTPD_STACKSIZE
#define HTTPD_STACKSIZE (DEFAULT_THREAD_STACKSIZE + 4 * 1024)
#endif
#ifndef HTTPD_PRIORITY
#define HTTPD_PRIORITY DEFAULT_THREAD_PRIO
#endif
#ifndef DEBUG_WS
#define DEBUG_WS 0
#endif

/*******************************************************************************
 * Prototypes
 ******************************************************************************/

/*******************************************************************************
 * Variables
 ******************************************************************************/
/* FS data. */
extern const HTTPSRV_FS_DIR_ENTRY httpsrv_fs_data[];
SemaphoreHandle_t xSem;
/*******************************************************************************
 * Code
 ******************************************************************************/

#if HTTPSRV_CFG_MBEDTLS_ENABLE
static HTTPSRV_TLS_PARAM_STRUCT tls_params;
#endif

/*!
 * @brief Initializes lwIP stack.
 */
static void stack_init(void)
{
    PRINTF("Initializing crypto...\r\n");
    CRYPTO_InitHardware();
    tcpip_init(NULL, NULL);
}

/*!
 * @brief Initializes server.
 */
static void http_server_socket_init(void)
{
    HTTPSRV_PARAM_STRUCT params;
    uint32_t httpsrv_handle;

    /* Init Fs */
    PRINTF("Initializing https fs...\r\n");
    HTTPSRV_FS_init(httpsrv_fs_data);

    /* Init HTTPSRV parameters. */
    memset(&params, 0, sizeof(params));
    params.root_dir   = "";
    params.index_page = "/index.html";
#if HTTPSRV_CFG_MBEDTLS_ENABLE
    tls_params.certificate_buffer      = (const unsigned char *)mbedtls_test_srv_crt;
    tls_params.certificate_buffer_size = mbedtls_test_srv_crt_len;
    tls_params.private_key_buffer      = (const unsigned char *)mbedtls_test_srv_key;
    tls_params.private_key_buffer_size = mbedtls_test_srv_key_len;

    params.tls_param = &tls_params;
#endif
    /* Init HTTP Server. */
    PRINTF("Initializing https server...\r\n");
    httpsrv_handle = HTTPSRV_init(&params);
    if (httpsrv_handle == 0)
    {
        LWIP_PLATFORM_DIAG(("http_server_socket_init has Failed"));
    }
}

/*!
 * @brief The main function containing server thread.
 */
static void mainThread(void *arg)
{
    LWIP_UNUSED_ARG(arg);

    stack_init();
    http_server_socket_init();
    PRINTF("Initializations done!\r\n");
    xSemaphoreGive(xSem);

    vTaskDelete(NULL);
}

/*!
 * @brief Main function.
 */
int main(void)
{
    BOARD_InitHardware();
    xSem = xSemaphoreCreateBinary();
    if (xSem == NULL)
    {
        PRINTF("Semaphore creation failed!");
        __BKPT(0);
    }
    /* create server thread in RTOS */
    if (sys_thread_new("main", mainThread, NULL, HTTPD_STACKSIZE, HTTPD_PRIORITY) == NULL)
        LWIP_ASSERT("main(): Task creation failed.", 0);

    if (sys_thread_new("httpsClientTask", httpsClientTask, &xSem, HTTPD_STACKSIZE, HTTPD_PRIORITY) == NULL)
        LWIP_ASSERT("main(): Task creation failed.", 0);

    /* run RTOS */
    vTaskStartScheduler();

    /* should not reach this statement */
    for (;;)
        ;
}

#endif /* LWIP_SOCKET */
