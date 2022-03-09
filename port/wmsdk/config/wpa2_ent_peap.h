#ifndef HIGH_SECURITY_CONFIG_H
#define HIGH_SECURITY_CONFIG_H

#include "wmsdk_platform_config.h"

/* Enable the debug functions. */
#ifdef CONFIG_WM_MBEDTLS_DEBUG
  #define MBEDTLS_DEBUG_C
#endif /* CONFIG_WM_MBEDTLS_DEBUG */

/*----------------------------------------------------------------------
 * Enable the generic cipher layer
 */
#define MBEDTLS_CIPHER_C
/* Enable the generic SSL/TLS code */
#define MBEDTLS_SSL_TLS_C
/* Enable the generic message digest layer */
#define MBEDTLS_MD_C
/*----------------------------------------------------------------------*/

/*----------------------------------------------------------------------
 * Enable the SSL/TLS client and server code
 */
#define MBEDTLS_SSL_CLI_C
#define MBEDTLS_SSL_SRV_C
/*----------------------------------------------------------------------*/

/*----------------------------------------------------------------------
 */
/* Enable sending of all alert messages */
#define MBEDTLS_SSL_ALL_ALERT_MESSAGES

/*
 * Maximum content length in bytes,
 * determines the default size of each of the two internal I/O buffers.
 * All values between 1 and 16384 (inclusive) are allowed.
 *
 * @note The RFC defines the default size of SSL / TLS messages.
 * If you change the value here, other clients / servers may not be able to
 * communicate with you anymore. Only change this value if you control
 * both sides of the connection and have it reduced at both sides, or
 * if you're using the Max Fragment Length (MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
 * extension and you know all your peers are using it too! (Ref: mbedtls/ssl.h)
 *
 * @note Setting MBEDTLS_SSL_MAX_CONTENT_LEN provides a compile-time mechanism
 * to set the same maximum content length for all SSL / TLS sessions in all
 * (in+out) directions. Additionally, Marvell has added a run-time mechanism
 * (\ref wm_mbedtls_ssl_conf_buffsizes()) to set maximum content length for a
 * particular ssl session in a particular direction (in and/or out).
 * Applications can use a combination of both mechanism to communicate
 * with other ends of connection successfully and still be able to reduce
 * memory footprint. Marvell has set the default value of
 * MBEDTLS_SSL_MAX_CONTENT_LEN to (1024 * 4) to cater to most common use-cases
 * where maximum content length is <= (1024 *4), while using \ref
 * wm_mbedtls_ssl_conf_buffsizes() in cases where transfer sizes can be larger,
 * e.g. over-the-air upgrade of large firmware upgrade files over SSL / TLS.
 *
 * @note If Max Fragment Length (MBEDTLS_SSL_MAX_FRAGMENT_LENGTH) extension is
 * enabled, effective buffer length is rounded down to one of 512, 1024, 2048,
 * 4096 or 16384 internally to avoid failures. It also supports values < 512
 * bytes, in which case effective buffer length is set to actual value,
 * disabling exchange of Max Fragment Length extension during handshake. This
 * allows for maximum flexiblity by allowing all values between 1 to 16384.
 * Applications can override the default behavior by calling
 * mbedtls_ssl_conf_max_frag_len(conf, MBEDTLS_SSL_MAX_FRAG_LEN_NONE)
 * after wm_mbedtls_ssl_config_new() or after calling
 * wm_mbedtls_ssl_conf_buffsizes(conf, in_buf_len, out_buf_len)
 * in which case effective buffer length will be set exactly to
 * MBEDTLS_SSL_MAX_FRAGMENT_LENGTH or (in_buf_len, out_buf_len) respectively,
 * disabling the exchange of Max Fragment Length extension during handshake.
 * In this case, transfers will be subject to same conditions as described in
 * first note above.
 */
#define MBEDTLS_SSL_MAX_CONTENT_LEN			(1024 * 4)

/* Enable support for configurable sizes for internal I/O buffers on per
 * session basis. Support is added by Marvell. */
#define MBEDTLS_SSL_BUFFER_SIZES

/* Remove RC4 ciphersuites by default in SSL / TLS. */
#define MBEDTLS_REMOVE_ARC4_CIPHERSUITES

/*----------------------------------------------------------------------*/

/*----------------------------------------------------------------------
 * Enable specific cipher modes
 */
#define MBEDTLS_CIPHER_MODE_CBC
#define MBEDTLS_CIPHER_MODE_CFB
#define MBEDTLS_CIPHER_MODE_CTR
/*----------------------------------------------------------------------*/

/*
 * Enable the DES block cipher.
 */
#define MBEDTLS_DES_C

/*----------------------------------------------------------------------
 * Enable AES block cipher
 */
#define MBEDTLS_AES_C

/* Store the AES tables in ROM instead of RAM */
#define MBEDTLS_AES_ROM_TABLES

/* Enable the CTR_DRBG AES-256-based random generator. */
#define MBEDTLS_CTR_DRBG_C

/* Enable the Counter with CBC-MAC (CCM) mode for
 * 128-bit block cipher. */
#define MBEDTLS_CCM_C
/* Enable the Galois/Counter Mode (GCM) for AES. */
#define MBEDTLS_GCM_C
/*----------------------------------------------------------------------*/

/*----------------------------------------------------------------------
 * Enable padding modes in the cipher layer.
 */
#define MBEDTLS_CIPHER_PADDING_PKCS7
#define MBEDTLS_CIPHER_PADDING_ONE_AND_ZEROS
#define MBEDTLS_CIPHER_PADDING_ZEROS_AND_LEN
#define MBEDTLS_CIPHER_PADDING_ZEROS
/*----------------------------------------------------------------------*/

/*----------------------------------------------------------------------
 * Enable the particular set of ciphersuite modes in SSL / TLS.
 */
#define MBEDTLS_KEY_EXCHANGE_PSK_ENABLED

/* Enable the RSA public-key cryptosystem. */
#define MBEDTLS_RSA_C
/* Enable the elliptic curve Diffie-Hellman library. */
#define MBEDTLS_ECDH_C
/* Enable the Diffie-Hellman-Merkle module. */
#define MBEDTLS_DHM_C
/* Enable the elliptic curve DSA library. */
#define MBEDTLS_ECDSA_C

#define MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
#define MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED
#define MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED

#define MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED
#define MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED

#define MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED
#define MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED

#define MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED
#define MBEDTLS_KEY_EXCHANGE_RSA_ENABLED
/*----------------------------------------------------------------------*/

/*----------------------------------------------------------------------
 * Enable error code to error string conversion
 */
#define MBEDTLS_ERROR_C
#define MBEDTLS_ERROR_STRERROR_DUMMY
/*----------------------------------------------------------------------*/

/*----------------------------------------------------------------------
 * Enable the test certificates.
 */
#define MBEDTLS_CERTS_C
/*----------------------------------------------------------------------*/

/*----------------------------------------------------------------------
 * Enable support for particular protocol
 */
#define MBEDTLS_SSL_PROTO_TLS1
#define MBEDTLS_SSL_PROTO_TLS1_1
#define MBEDTLS_SSL_PROTO_TLS1_2
/*----------------------------------------------------------------------*/

/*----------------------------------------------------------------------
 * Enable the multi-precision integer library
 */
#define MBEDTLS_BIGNUM_C

/* Enable the prime-number generation code. */
#define MBEDTLS_GENPRIME
/*----------------------------------------------------------------------*/

/*----------------------------------------------------------------------
 * Enable the elliptic curve over GF(p) library
 */
#define MBEDTLS_ECP_C

/* Enables specific curves within the Elliptic Curve module. */
#define MBEDTLS_ECP_DP_SECP192R1_ENABLED
#define MBEDTLS_ECP_DP_SECP224R1_ENABLED
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
/*----------------------------------------------------------------------*/

/*----------------------------------------------------------------------
 * Enable X.509 core for using certificates.
 */
#define MBEDTLS_X509_USE_C

/* Enable X.509 certificate parsing */
#define MBEDTLS_X509_CRT_PARSE_C
/*----------------------------------------------------------------------*/

/*----------------------------------------------------------------------
 * Enable the Base64 module.
 */
#define MBEDTLS_BASE64_C

/* Enable PEM decoding / parsing. */
#define MBEDTLS_PEM_PARSE_C
/*----------------------------------------------------------------------*/

/*----------------------------------------------------------------------
 * Enable the generic public (asymetric) key layer.
 */
#define MBEDTLS_PK_C

/* Enable the generic public (asymetric) key parser. */
#define MBEDTLS_PK_PARSE_C
/*----------------------------------------------------------------------*/

/*----------------------------------------------------------------------
 * Enable the particular hash algorithm
 */
#define MBEDTLS_MD4_C
#define MBEDTLS_MD5_C
#define MBEDTLS_SHA1_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_SHA512_C
/*----------------------------------------------------------------------*/

/*----------------------------------------------------------------------
 */
/* Enable support for PKCS#1 v1.5 encoding. */
#define MBEDTLS_PKCS1_V15
/* Enable support for PKCS#1 v2.1 encoding. */
#define MBEDTLS_PKCS1_V21

/* Enable support for Encrypt-then-MAC, RFC 7366. */
#define MBEDTLS_SSL_ENCRYPT_THEN_MAC

/* Enable support for FALLBACK_SCSV */
#define MBEDTLS_SSL_FALLBACK_SCSV

/* Enable 1/n-1 record splitting for CBC mode in SSLv3
 * and TLS 1.0. */
#define MBEDTLS_SSL_CBC_RECORD_SPLITTING

/* Disable support for TLS renegotiation. */
#define MBEDTLS_SSL_RENEGOTIATION

/* Enable support for RFC 6066 max_fragment_length extension
 * in SSL. */
#define MBEDTLS_SSL_MAX_FRAGMENT_LENGTH

/* Enable the generic ASN1 parser and writer */
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C

/* Enable the OID database. */
#define MBEDTLS_OID_C

/* Enable PKCS#5 functions. */
#define MBEDTLS_PKCS5_C
/* Enable PKCS#12 PBE functions. */
#define MBEDTLS_PKCS12_C

/* Enable the HMAC_DRBG random generator. */
#define MBEDTLS_HMAC_DRBG_C

/* Enable verification of the keyUsage extension (CA and
 * leaf certificates). */
#define MBEDTLS_X509_CHECK_KEY_USAGE

/* Enable support for RFC 7301 Application Layer Protocol
 * Negotiation. */
#define MBEDTLS_SSL_ALPN

/* Enable support for RFC 6066 server name
 * indication (SNI) in SSL. */
#define MBEDTLS_SSL_SERVER_NAME_INDICATION

/*----------------------------------------------------------------------*/

/*----------------------------------------------------------------------
 * Enable the generic public (asymetric) key writer.
 */
#define MBEDTLS_PK_WRITE_C

/*----------------------------------------------------------------------
 * Enable support for RCF 5216 to generate key_material
 */
#define MBEDTLS_EAP_TLS_KEY_MATERIAL
/*----------------------------------------------------------------------*/

#include <mbedtls/check_config.h>
/*----------------------------------------------------------------------*/
#endif /* HIGH_SECURITY_CONFIG_H */
