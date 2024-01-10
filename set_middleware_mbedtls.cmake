include_guard(GLOBAL)


if (CONFIG_USE_middleware_mbedtls_template)
# Add set(CONFIG_USE_middleware_mbedtls_template true) in config.cmake to use this component

message("middleware_mbedtls_template component is included from ${CMAKE_CURRENT_LIST_FILE}.")

add_config_file(${CMAKE_CURRENT_LIST_DIR}/./port/ksdk/ksdk_mbedtls_config.h ${CMAKE_CURRENT_LIST_DIR}/./port/ksdk middleware_mbedtls_template)

if(CONFIG_USE_COMPONENT_CONFIGURATION)
  message("===>Import configuration from ${CMAKE_CURRENT_LIST_FILE}")

  target_compile_definitions(${MCUX_SDK_PROJECT_NAME} PUBLIC
    -DMBEDTLS_CONFIG_FILE="ksdk_mbedtls_config.h"
  )

endif()


endif()


if (CONFIG_USE_middleware_mbedtls_els_pkc_config)
# Add set(CONFIG_USE_middleware_mbedtls_els_pkc_config true) in config.cmake to use this component

message("middleware_mbedtls_els_pkc_config component is included from ${CMAKE_CURRENT_LIST_FILE}.")

add_config_file(${CMAKE_CURRENT_LIST_DIR}/./port/pkc/els_pkc_mbedtls_config.h ${CMAKE_CURRENT_LIST_DIR}/./port/pkc middleware_mbedtls_els_pkc_config)

if(CONFIG_USE_COMPONENT_CONFIGURATION)
  message("===>Import configuration from ${CMAKE_CURRENT_LIST_FILE}")

  target_compile_definitions(${MCUX_SDK_PROJECT_NAME} PUBLIC
    -DMBEDTLS_CONFIG_FILE="els_pkc_mbedtls_config.h"
  )

endif()


endif()


if (CONFIG_USE_middleware_mbedtls_port_ksdk)
# Add set(CONFIG_USE_middleware_mbedtls_port_ksdk true) in config.cmake to use this component

message("middleware_mbedtls_port_ksdk component is included from ${CMAKE_CURRENT_LIST_FILE}.")

if(CONFIG_USE_middleware_mbedtls AND CONFIG_USE_middleware_mbedtls_template AND ((CONFIG_USE_driver_sha AND CONFIG_USE_driver_rng AND CONFIG_USE_driver_aes AND (CONFIG_DEVICE_ID STREQUAL LPC54S005 OR CONFIG_DEVICE_ID STREQUAL LPC54S016 OR CONFIG_DEVICE_ID STREQUAL LPC54S018 OR CONFIG_DEVICE_ID STREQUAL LPC54S018J2M OR CONFIG_DEVICE_ID STREQUAL LPC54S018J4M)) OR (CONFIG_USE_driver_sha AND CONFIG_USE_driver_rng AND (CONFIG_DEVICE_ID STREQUAL LPC54005 OR CONFIG_DEVICE_ID STREQUAL LPC54016 OR CONFIG_DEVICE_ID STREQUAL LPC54018 OR CONFIG_DEVICE_ID STREQUAL LPC54018J2M OR CONFIG_DEVICE_ID STREQUAL LPC54018J4M OR CONFIG_DEVICE_ID STREQUAL LPC54628J512)) OR (CONFIG_USE_driver_rng AND (CONFIG_DEVICE_ID STREQUAL LPC54605J512 OR CONFIG_DEVICE_ID STREQUAL LPC54605J256 OR CONFIG_DEVICE_ID STREQUAL LPC54606J512 OR CONFIG_DEVICE_ID STREQUAL LPC54606J256 OR CONFIG_DEVICE_ID STREQUAL LPC54607J256 OR CONFIG_DEVICE_ID STREQUAL LPC54607J512 OR CONFIG_DEVICE_ID STREQUAL LPC54608J512 OR CONFIG_DEVICE_ID STREQUAL LPC54616J512 OR CONFIG_DEVICE_ID STREQUAL LPC54616J256 OR CONFIG_DEVICE_ID STREQUAL LPC54618J512)) OR (CONFIG_USE_driver_rng_1 AND CONFIG_USE_driver_casper AND CONFIG_USE_driver_hashcrypt AND (CONFIG_DEVICE_ID STREQUAL LPC55S04 OR CONFIG_DEVICE_ID STREQUAL LPC55S06 OR CONFIG_DEVICE_ID STREQUAL LPC55S14 OR CONFIG_DEVICE_ID STREQUAL LPC55S16 OR CONFIG_DEVICE_ID STREQUAL LPC55S26 OR CONFIG_DEVICE_ID STREQUAL LPC55S28 OR CONFIG_DEVICE_ID STREQUAL LPC55S66 OR CONFIG_DEVICE_ID STREQUAL LPC55S69)) OR (CONFIG_USE_driver_trng AND CONFIG_USE_driver_casper AND CONFIG_USE_driver_hashcrypt AND (CONFIG_DEVICE_ID STREQUAL MIMXRT533S OR CONFIG_DEVICE_ID STREQUAL MIMXRT555S OR CONFIG_DEVICE_ID STREQUAL MIMXRT595S OR CONFIG_DEVICE_ID STREQUAL MIMXRT633S OR CONFIG_DEVICE_ID STREQUAL MIMXRT685S)) OR (CONFIG_USE_driver_dcp AND CONFIG_USE_driver_trng AND CONFIG_USE_driver_cache_armv7_m7 AND (CONFIG_DEVICE_ID STREQUAL MIMXRT1011xxxxx OR CONFIG_DEVICE_ID STREQUAL MIMXRT1021xxxxx OR CONFIG_DEVICE_ID STREQUAL MIMXRT1024xxxxx OR CONFIG_DEVICE_ID STREQUAL MIMXRT1041xxxxB OR CONFIG_DEVICE_ID STREQUAL MIMXRT1042xxxxB OR CONFIG_DEVICE_ID STREQUAL MIMXRT1051xxxxB OR CONFIG_DEVICE_ID STREQUAL MIMXRT1052xxxxB OR CONFIG_DEVICE_ID STREQUAL MIMXRT1061xxxxA OR CONFIG_DEVICE_ID STREQUAL MIMXRT1061xxxxB OR CONFIG_DEVICE_ID STREQUAL MIMXRT1062xxxxA OR CONFIG_DEVICE_ID STREQUAL MIMXRT1062xxxxB OR CONFIG_DEVICE_ID STREQUAL MIMXRT1064xxxxA OR CONFIG_DEVICE_ID STREQUAL MIMXRT1064xxxxB)) OR (CONFIG_USE_driver_trng AND CONFIG_USE_middleware_mmcau_cm0p AND (CONFIG_DEVICE_ID STREQUAL K32L2A31xxxxA OR CONFIG_DEVICE_ID STREQUAL K32L2A41xxxxA)) OR (CONFIG_USE_driver_trng AND CONFIG_USE_middleware_mmcau_cm4_cm7 AND (CONFIG_DEVICE_ID STREQUAL K32L2A41xxxxA)) OR (CONFIG_USE_driver_rnga AND CONFIG_USE_middleware_mmcau_cm4_cm7 AND (CONFIG_DEVICE_ID STREQUAL MKM35Z512xxx7 OR CONFIG_DEVICE_ID STREQUAL MKM35Z256xxx7)) OR (CONFIG_USE_driver_rnga AND CONFIG_USE_middleware_mmcau_cm0p AND (CONFIG_DEVICE_ID STREQUAL MKM35Z512xxx7 OR CONFIG_DEVICE_ID STREQUAL MKM35Z256xxx7)) OR (CONFIG_USE_driver_cau3 AND CONFIG_USE_driver_trng AND (CONFIG_DEVICE_ID STREQUAL K32L3A60xxx)) OR (CONFIG_USE_driver_trng AND CONFIG_USE_driver_ltc AND CONFIG_USE_middleware_mmcau_cm4_cm7 AND (CONFIG_DEVICE_ID STREQUAL MCIMX7U5xxxxx)) OR (CONFIG_USE_driver_caam AND (CONFIG_DEVICE_ID STREQUAL MIMXRT1165xxxxx OR CONFIG_DEVICE_ID STREQUAL MIMXRT1166xxxxx OR CONFIG_DEVICE_ID STREQUAL MIMXRT1171xxxxx OR CONFIG_DEVICE_ID STREQUAL MIMXRT1172xxxxx OR CONFIG_DEVICE_ID STREQUAL MIMXRT1173xxxxx OR CONFIG_DEVICE_ID STREQUAL MIMXRT1175xxxxx OR CONFIG_DEVICE_ID STREQUAL MIMXRT1176xxxxx))))

target_sources(${MCUX_SDK_PROJECT_NAME} PRIVATE
  ${CMAKE_CURRENT_LIST_DIR}/./port/ksdk/ksdk_mbedtls.c
  ${CMAKE_CURRENT_LIST_DIR}/./port/ksdk/des_alt.c
  ${CMAKE_CURRENT_LIST_DIR}/./port/ksdk/aes_alt.c
  ${CMAKE_CURRENT_LIST_DIR}/./port/ksdk/ecp_alt.c
  ${CMAKE_CURRENT_LIST_DIR}/./port/ksdk/ecp_curves_alt.c
  ${CMAKE_CURRENT_LIST_DIR}/./port/ksdk/ecp_alt_ksdk.c
)

target_include_directories(${MCUX_SDK_PROJECT_NAME} PUBLIC
  ${CMAKE_CURRENT_LIST_DIR}/./port/ksdk
)

else()

message(SEND_ERROR "middleware_mbedtls_port_ksdk dependency does not meet, please check ${CMAKE_CURRENT_LIST_FILE}.")

endif()

endif()


if (CONFIG_USE_middleware_mbedtls)
# Add set(CONFIG_USE_middleware_mbedtls true) in config.cmake to use this component

message("middleware_mbedtls component is included from ${CMAKE_CURRENT_LIST_FILE}.")

if(CONFIG_USE_utility_debug_console AND (CONFIG_USE_middleware_mbedtls_port_ksdk))

target_sources(${MCUX_SDK_PROJECT_NAME} PRIVATE
  ${CMAKE_CURRENT_LIST_DIR}/./library/aes.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/aesni.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/arc4.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/aria.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/asn1parse.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/asn1write.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/base64.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/bignum.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/blowfish.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/camellia.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/ccm.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/certs.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/chacha20.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/chachapoly.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/cipher.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/cipher_wrap.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/cmac.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/constant_time.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/ctr_drbg.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/debug.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/des.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/dhm.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/ecdh.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/ecdsa.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/ecjpake.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/ecp.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/ecp_curves.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/entropy.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/entropy_poll.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/error.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/gcm.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/havege.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/hkdf.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/hmac_drbg.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/md.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/md2.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/md4.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/md5.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/memory_buffer_alloc.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/mps_reader.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/mps_trace.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/net_sockets.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/nist_kw.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/oid.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/padlock.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/pem.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/pk.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/pk_wrap.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/pkcs5.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/pkcs11.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/pkcs12.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/pkparse.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/pkwrite.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/platform.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/platform_util.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/poly1305.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/psa_crypto.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/psa_crypto_aead.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/psa_crypto_cipher.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/psa_crypto_client.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/psa_crypto_driver_wrappers.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/psa_crypto_ecp.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/psa_crypto_hash.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/psa_crypto_mac.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/psa_crypto_rsa.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/psa_crypto_se.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/psa_crypto_slot_management.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/psa_crypto_storage.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/psa_its_file.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/ripemd160.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/rsa.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/rsa_internal.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/sha1.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/sha256.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/sha512.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/ssl_cache.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/ssl_ciphersuites.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/ssl_cli.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/ssl_cookie.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/ssl_msg.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/ssl_srv.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/ssl_ticket.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/ssl_tls.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/ssl_tls13_keys.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/threading.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/timing.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/version.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/version_features.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/x509.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/x509_create.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/x509_crl.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/x509_crt.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/x509_csr.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/x509write_crt.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/x509write_csr.c
  ${CMAKE_CURRENT_LIST_DIR}/./library/xtea.c
)

target_include_directories(${MCUX_SDK_PROJECT_NAME} PUBLIC
  ${CMAKE_CURRENT_LIST_DIR}/./include
  ${CMAKE_CURRENT_LIST_DIR}/./library
)

if(CONFIG_USE_COMPONENT_CONFIGURATION)
  message("===>Import configuration from ${CMAKE_CURRENT_LIST_FILE}")

  if(CONFIG_TOOLCHAIN STREQUAL iar)
    target_compile_options(${MCUX_SDK_PROJECT_NAME} PUBLIC
      --diag_suppress Pa167,Pe177,Pe191,Pe546
    )
  endif()
  if(CONFIG_TOOLCHAIN STREQUAL armgcc)
    target_compile_options(${MCUX_SDK_PROJECT_NAME} PUBLIC
      -fomit-frame-pointer
      -Wno-unused-function
    )
  endif()

endif()

else()

message(SEND_ERROR "middleware_mbedtls dependency does not meet, please check ${CMAKE_CURRENT_LIST_FILE}.")

endif()

endif()

