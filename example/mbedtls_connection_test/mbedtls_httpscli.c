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
#include "httpsclient.h"

#include "fsl_debug_console.h"
#include "mbedtls_httpscli.h"
#include "semphr.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/

/*******************************************************************************
 * Prototypes
 ******************************************************************************/

/*******************************************************************************
 * Variables
 ******************************************************************************/

/*******************************************************************************
 * Code
 ******************************************************************************/

void httpsClientTask(void *arg)
{
    if (arg == NULL)
    {
        PRINTF("Semaphore handle is null!\r\n");
        __BKPT(0);
    }
    SemaphoreHandle_t *xSem = (SemaphoreHandle_t *)arg;
    xSemaphoreTake(*xSem, (TickType_t)10000000);
    PRINTF("Starting server!\r\n");
    https_client_tls_init("127.0.0.1");
    vTaskDelete(NULL);
}
