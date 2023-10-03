/*
 * Copyright (c) 2016, Freescale Semiconductor, Inc.
 * Copyright 2016 - 2023 NXP.
 * All rights reserved.
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*******************************************************************************
 * Includes
 ******************************************************************************/
#include "lwip/opt.h"
#include "lwip/debug.h"
#include "lwip/stats.h"
#include "lwip/tcp.h"
#include "lwip/sockets.h"
#include "httpsclient.h"
#include "lwip/netdb.h"
#include "fsl_debug_console.h"
#include <stdlib.h>
#include <stdio.h>

/*******************************************************************************
 * Definitions
 ******************************************************************************/
/* This is the value used for ssl read timeout */
#define IOT_SSL_READ_TIMEOUT 10
#define GET_REQUEST              \
    "GET /index.html HTTP/1.0\n" \
    "Host: 127.0.0.1\n\n"

#define DEBUG_LEVEL 0

/*******************************************************************************
 * Prototypes
 ******************************************************************************/

/*******************************************************************************
 * Variables
 ******************************************************************************/
TLSDataParams tlsDataParams;
const char *HTTPS_SERVER_PORT = "443";
unsigned char httpsBuf[1024];
/*******************************************************************************
 * Code
 ******************************************************************************/

/* Send function used by mbedtls ssl */
static int lwipSend(void *fd, unsigned char const *buf, size_t len)
{
    return lwip_send((*(int *)fd), buf, len, 0);
}

/* Send function used by mbedtls ssl */
static int lwipRecv(void *fd, unsigned char const *buf, size_t len)
{
    return lwip_recv((*(int *)fd), (void *)buf, len, 0);
}

static int writeRequest()
{
    /*
     * Write the GET request
     */
    int ret = 0;

    int len = sprintf((char *)httpsBuf, GET_REQUEST);

    while ((ret = mbedtls_ssl_write(&(tlsDataParams.ssl), httpsBuf, len)) <= 0)
    {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            PRINTF(" failed\r\n  ! mbedtls_ssl_write returned %d\r\n", ret);
            goto exit;
        }
    }

    len = ret;
    PRINTF("[Client writes %dB]: %s\r\n", len, (char *)httpsBuf);

    return ret;

exit:
    httpsClientTlsRelease();
    return -1;
}

static int readRequest()
{
    /*
     * Read the HTTPS response
     */
    int ret       = 0;
    int len       = 0;
    char succRead = 0;
    PRINTF("[Client reads]: ");

    do
    {
        len = sizeof(httpsBuf) - 1;
        memset(httpsBuf, 0, sizeof(httpsBuf));
        ret = mbedtls_ssl_read(&(tlsDataParams.ssl), httpsBuf, len);

        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
            continue;

        if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
        {
            PRINTF("[Client]: Peer connection closed!\r\n");
            ret = succRead;
            break;
        }
        if (ret < 0)
        {
            PRINTF("failed\r\n  ! mbedtls_ssl_read returned %d\r\n", ret);
            goto exit;
        }

        if (ret == 0)
        {
            PRINTF("\r\nEOF\r\n");
            break;
        }

        len = ret;
        PRINTF("%s", (char *)httpsBuf);
        succRead = 1;
    } while (1);

    return ret;

exit:
    httpsClientTlsRelease();
    return -1;
}

static int _iot_tls_verify_cert(void *data, mbedtls_x509_crt *crt, int depth, uint32_t *flags)
{
    char buf[1024];
    ((void)data);

    PRINTF("\r\nVerify requested for (Depth %d):\r\n", depth);
    mbedtls_x509_crt_info(buf, sizeof(buf) - 1, "", crt);
    PRINTF("%s", buf);

    if ((*flags) == 0)
    {
        PRINTF("This certificate has no flags\r\n");
    }
    else
    {
        PRINTF(buf, sizeof(buf), "  ! 0x%X", *flags);
        PRINTF("%s\r\n", buf);
    }

    return 0;
}

#ifdef MBEDTLS_DEBUG_C
static void my_debug(void *ctx, int level, const char *file, int line, const char *str)
{
    ((void)level);

    PRINTF("\r\n%s, at line %d in file %s\n", str, line, file);
}
#endif

int https_client_tls_init(const char *host)
{
    int ret          = 0;
    const char *pers = "tls_wrapper";
    char vrfyBuf[512];
    bool ServerVerificationFlag = false;
    const mbedtls_md_info_t *md_info;

#ifdef MBEDTLS_DEBUG_C
    unsigned char buf[MBEDTLS_SSL_MAX_CONTENT_LEN + 1];
#endif

    mbedtls_ssl_init(&(tlsDataParams.ssl));
    mbedtls_ssl_config_init(&(tlsDataParams.conf));
    mbedtls_hmac_drbg_init(&(tlsDataParams.hmac_drbg));
    mbedtls_x509_crt_init(&(tlsDataParams.cacert));
    mbedtls_x509_crt_init(&(tlsDataParams.clicert));
    mbedtls_pk_init(&(tlsDataParams.pkey));

#if defined(MBEDTLS_DEBUG_C)
    /* Enable debug output of mbedtls */
    mbedtls_ssl_conf_dbg(&(tlsDataParams.conf), my_debug, NULL);
    mbedtls_debug_set_threshold(DEBUG_LEVEL);
#endif

    PRINTF("Seeding the random number generator... ");
    mbedtls_entropy_init(&(tlsDataParams.entropy));
    md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if ((ret = mbedtls_hmac_drbg_seed(&(tlsDataParams.hmac_drbg), md_info, mbedtls_entropy_func,
                                      &(tlsDataParams.entropy), (const unsigned char *)pers, strlen(pers))) != 0)
    {
        PRINTF("failed! mbedtls_hmac_drbg_seed returned 0x%X\r\n", ret);
        return NETWORK_MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED;
    }

    PRINTF("\r\nLoading the CA root certificate... ");
    ret = mbedtls_x509_crt_parse(&(tlsDataParams.cacert), (const unsigned char *)mbedtls_test_ca_crt,
                                 mbedtls_test_ca_crt_len);
    if (ret < 0)
    {
        PRINTF(" failed\r\n! mbedtls_x509_crt_parse returned 0x%X while parsing root cert\r\n", ret);
        return NETWORK_X509_ROOT_CRT_PARSE_ERROR;
    }
    PRINTF("ok (%d skipped)\r\n", ret);

    PRINTF("Loading the client cert. and key... ");
    ret = mbedtls_x509_crt_parse(&(tlsDataParams.clicert), (const unsigned char *)mbedtls_test_cli_crt,
                                 mbedtls_test_cli_crt_len);
    if (ret != 0)
    {
        PRINTF("failed\r\n!  mbedtls_x509_crt_parse returned 0x%X while parsing device cert\r\n", ret);
        return NETWORK_X509_DEVICE_CRT_PARSE_ERROR;
    }

    ret = mbedtls_pk_parse_key(&(tlsDataParams.pkey), (const unsigned char *)mbedtls_test_cli_key,
                               mbedtls_test_cli_key_len, NULL, 0);
    if (ret != 0)
    {
        PRINTF("failed\r\n!  mbedtls_pk_parse_key returned 0x%X while parsing private key\r\n", ret);
        return NETWORK_PK_PRIVATE_KEY_PARSE_ERROR;
    }
    PRINTF("ok\r\n");
    PRINTF("Connecting to %s/%s\r\n", host, HTTPS_SERVER_PORT);

    struct addrinfo hints;
    struct addrinfo *res;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags    = AI_PASSIVE;

    ret = getaddrinfo(host, HTTPS_SERVER_PORT, &hints, &res);
    if ((ret != 0) || (res == NULL))
    {
        return NETWORK_ERR_NET_UNKNOWN_HOST;
    }

    tlsDataParams.fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (tlsDataParams.fd < 0)
    {
        return NETWORK_ERR_NET_SOCKET_FAILED;
    }

    ret = connect(tlsDataParams.fd, res->ai_addr, res->ai_addrlen);

    freeaddrinfo(res);

    if (ret != 0)
    {
        close(tlsDataParams.fd);
        PRINTF("Connection failed!\r\n");
        return NETWORK_ERR_NET_CONNECT_FAILED;
    }

    PRINTF("Setting up the SSL/TLS structure... ");
    if ((ret = mbedtls_ssl_config_defaults(&(tlsDataParams.conf), MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
        PRINTF("failed\r\n  ! mbedtls_ssl_config_defaults returned 0x%X\r\n", ret);
        close(tlsDataParams.fd);
        return SSL_CONNECTION_ERROR;
    }

    mbedtls_ssl_conf_verify(&(tlsDataParams.conf), _iot_tls_verify_cert, NULL);
    if (ServerVerificationFlag == true)
    {
        mbedtls_ssl_conf_authmode(&(tlsDataParams.conf), MBEDTLS_SSL_VERIFY_REQUIRED);
    }
    else
    {
        mbedtls_ssl_conf_authmode(&(tlsDataParams.conf), MBEDTLS_SSL_VERIFY_OPTIONAL);
    }
    mbedtls_ssl_conf_rng(&(tlsDataParams.conf), mbedtls_hmac_drbg_random, &(tlsDataParams.hmac_drbg));

    mbedtls_ssl_conf_ca_chain(&(tlsDataParams.conf), &(tlsDataParams.cacert), NULL);
    if ((ret = mbedtls_ssl_conf_own_cert(&(tlsDataParams.conf), &(tlsDataParams.clicert), &(tlsDataParams.pkey))) != 0)
    {
        PRINTF("failed\r\n  ! mbedtls_ssl_conf_own_cert returned 0x%X\r\n", ret);
        close(tlsDataParams.fd);
        return SSL_CONNECTION_ERROR;
    }

    if ((ret = mbedtls_ssl_setup(&(tlsDataParams.ssl), &(tlsDataParams.conf))) != 0)
    {
        PRINTF("failed\r\n  ! mbedtls_ssl_setup returned 0x%X\r\n", ret);
        close(tlsDataParams.fd);
        return SSL_CONNECTION_ERROR;
    }
    if ((ret = mbedtls_ssl_set_hostname(&(tlsDataParams.ssl), host)) != 0)
    {
        PRINTF("failed\n\r  ! mbedtls_ssl_set_hostname returned 0x%X\r\n", ret);
        close(tlsDataParams.fd);
        return SSL_CONNECTION_ERROR;
    }
    PRINTF("\r\nSSL state connect : %d ", tlsDataParams.ssl.state);

    mbedtls_ssl_set_bio(&(tlsDataParams.ssl), &(tlsDataParams.fd), lwipSend, (mbedtls_ssl_recv_t *)lwipRecv, NULL);

    PRINTF("ok\r\n");
    PRINTF("\r\nSSL state connect : %d ", tlsDataParams.ssl.state);
    PRINTF("Performing the SSL/TLS handshake...");
    while ((ret = mbedtls_ssl_handshake(&(tlsDataParams.ssl))) != 0)
    {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            PRINTF(" failed\r\nmbedtls_ssl_handshake returned 0x%X\r\n", ret);
            if (ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED)
            {
                PRINTF(
                    "    Unable to verify the server's certificate. "
                    "    Alternatively, you may want to use "
                    "auth_mode=optional for testing purposes.\n");
            }
            httpsClientTlsRelease();
            return SSL_CONNECTION_ERROR;
        }
    }

    PRINTF("ok\r\n[ Protocol is %s ]\r\n[ Ciphersuite is %s ]\r\n", mbedtls_ssl_get_version(&(tlsDataParams.ssl)),
           mbedtls_ssl_get_ciphersuite(&(tlsDataParams.ssl)));
    if ((ret = mbedtls_ssl_get_record_expansion(&(tlsDataParams.ssl))) >= 0)
    {
        PRINTF("[ Record expansion is %d ]\r\n", ret);
    }
    else
    {
        PRINTF("[ Record expansion is unknown (compression) ]\r\n");
    }

    PRINTF("Verifying peer X.509 certificate...");

    if (ServerVerificationFlag == true)
    {
        if ((tlsDataParams.flags = mbedtls_ssl_get_verify_result(&(tlsDataParams.ssl))) != 0)
        {
            PRINTF(" failed\r\n");
            mbedtls_x509_crt_verify_info(vrfyBuf, sizeof(vrfyBuf), "  ! ", tlsDataParams.flags);
            PRINTF("%s\r\n", vrfyBuf);
            ret = SSL_CONNECTION_ERROR;
        }
        else
        {
            PRINTF(" ok\r\n");
            ret = SUCCESS;
        }
    }
    else
    {
        PRINTF(" Server Verification skipped\r\n");
        ret = SUCCESS;
    }

#ifdef MBEDTLS_DEBUG_C
    if (mbedtls_ssl_get_peer_cert(&(tlsDataParams.ssl)) != NULL)
    {
        PRINTF("  . Peer certificate information    ...\n");
        mbedtls_x509_crt_info((char *)buf, sizeof(buf) - 1, "      ", mbedtls_ssl_get_peer_cert(&(tlsDataParams.ssl)));
        PRINTF("%s\n", buf);
    }
#endif

    mbedtls_ssl_conf_read_timeout(&(tlsDataParams.conf), IOT_SSL_READ_TIMEOUT);
    PRINTF("\r\n");
    int writeRet, readRet;
    writeRet = writeRequest();
    readRet  = readRequest();

    PRINTF("========================\r\n");
    PRINTF("Client send: %s\r\n", (writeRet >= 0) ? "OK!" : "ERROR!");
    PRINTF("Client read: %s\r\n", (readRet == 1) ? "OK!" : "ERROR!");

    httpsClientTlsRelease();
    return (Error_t)ret;
}

/* Release TLS */
static void httpsClientTlsRelease()
{
    close(tlsDataParams.fd);
    mbedtls_x509_crt_free(&(tlsDataParams.clicert));
    mbedtls_x509_crt_free(&(tlsDataParams.cacert));
    mbedtls_pk_free(&(tlsDataParams.pkey));
    mbedtls_ssl_free(&(tlsDataParams.ssl));
    mbedtls_ssl_config_free(&(tlsDataParams.conf));
    mbedtls_hmac_drbg_free(&(tlsDataParams.hmac_drbg));
    mbedtls_entropy_free(&(tlsDataParams.entropy));
}
