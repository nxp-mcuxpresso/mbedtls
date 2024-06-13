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


if (CONFIG_USE_middleware_mbedtls_tests)
# Add set(CONFIG_USE_middleware_mbedtls_tests true) in config.cmake to use this component

message("middleware_mbedtls_tests component is included from ${CMAKE_CURRENT_LIST_FILE}.")

target_sources(${MCUX_SDK_PROJECT_NAME} PRIVATE
  ${CMAKE_CURRENT_LIST_DIR}/./tests/src/asn1_helpers.c
  ${CMAKE_CURRENT_LIST_DIR}/./tests/src/helpers.c
  ${CMAKE_CURRENT_LIST_DIR}/./tests/src/psa_crypto_helpers.c
  ${CMAKE_CURRENT_LIST_DIR}/./tests/src/psa_exercise_key.c
  ${CMAKE_CURRENT_LIST_DIR}/./tests/src/random.c
  ${CMAKE_CURRENT_LIST_DIR}/./tests/src/threading_helpers.c
  ${CMAKE_CURRENT_LIST_DIR}/./tests/src/fake_external_rng_for_test.c
  ${CMAKE_CURRENT_LIST_DIR}/./tests/src/test_helpers/ssl_helpers.c
)

target_include_directories(${MCUX_SDK_PROJECT_NAME} PUBLIC
  ${CMAKE_CURRENT_LIST_DIR}/./tests/include/test
  ${CMAKE_CURRENT_LIST_DIR}/./tests/include
)


endif()


if (CONFIG_USE_middleware_mbedtls_3rdparty)
# Add set(CONFIG_USE_middleware_mbedtls_3rdparty true) in config.cmake to use this component

message("middleware_mbedtls_3rdparty component is included from ${CMAKE_CURRENT_LIST_FILE}.")

target_sources(${MCUX_SDK_PROJECT_NAME} PRIVATE
  ${CMAKE_CURRENT_LIST_DIR}/./3rdparty/everest/library/Hacl_Curve25519.c
  ${CMAKE_CURRENT_LIST_DIR}/./3rdparty/everest/library/Hacl_Curve25519_joined.c
  ${CMAKE_CURRENT_LIST_DIR}/./3rdparty/everest/library/everest.c
  ${CMAKE_CURRENT_LIST_DIR}/./3rdparty/everest/library/kremlib/FStar_UInt128_extracted.c
  ${CMAKE_CURRENT_LIST_DIR}/./3rdparty/everest/library/kremlib/FStar_UInt64_FStar_UInt32_FStar_UInt16_FStar_UInt8.c
  ${CMAKE_CURRENT_LIST_DIR}/./3rdparty/everest/library/legacy/Hacl_Curve25519.c
  ${CMAKE_CURRENT_LIST_DIR}/./3rdparty/everest/library/x25519.c
)

target_include_directories(${MCUX_SDK_PROJECT_NAME} PUBLIC
  ${CMAKE_CURRENT_LIST_DIR}/./3rdparty/everest/include
  ${CMAKE_CURRENT_LIST_DIR}/./3rdparty/everest/include/everest
  ${CMAKE_CURRENT_LIST_DIR}/./3rdparty/everest/include/everest/kremlib
  ${CMAKE_CURRENT_LIST_DIR}/./3rdparty/everest/include/everest/kremlin
  ${CMAKE_CURRENT_LIST_DIR}/./3rdparty/everest/include/everest/kremlin/internal
)


endif()


if (CONFIG_USE_middleware_mbedtls_port_ele_s400)
# Add set(CONFIG_USE_middleware_mbedtls_port_ele_s400 true) in config.cmake to use this component

message("middleware_mbedtls_port_ele_s400 component is included from ${CMAKE_CURRENT_LIST_FILE}.")

if(CONFIG_USE_driver_s3mu AND CONFIG_USE_component_ele_crypto AND CONFIG_USE_middleware_mbedtls)

target_sources(${MCUX_SDK_PROJECT_NAME} PRIVATE
  ${CMAKE_CURRENT_LIST_DIR}/./port/ele_s400/ele_mbedtls.c
  ${CMAKE_CURRENT_LIST_DIR}/./port/ele_s400/ele_entropy.c
  ${CMAKE_CURRENT_LIST_DIR}/./port/ele_s400/aes_alt.c
  ${CMAKE_CURRENT_LIST_DIR}/./port/ele_s400/ccm_alt.c
  ${CMAKE_CURRENT_LIST_DIR}/./port/ele_s400/gcm_alt.c
  ${CMAKE_CURRENT_LIST_DIR}/./port/ele_s400/rsa_alt.c
  ${CMAKE_CURRENT_LIST_DIR}/./port/ele_s400/sha256_alt.c
  ${CMAKE_CURRENT_LIST_DIR}/./port/ele_s400/sha512_alt.c
  ${CMAKE_CURRENT_LIST_DIR}/./port/ele_s400/hmac_alt.c
)

target_include_directories(${MCUX_SDK_PROJECT_NAME} PUBLIC
  ${CMAKE_CURRENT_LIST_DIR}/./port/ele_s400
)

if(CONFIG_USE_COMPONENT_CONFIGURATION)
  message("===>Import configuration from ${CMAKE_CURRENT_LIST_FILE}")

  target_compile_definitions(${MCUX_SDK_PROJECT_NAME} PUBLIC
    -DMBEDTLS_MCUX_ELE_S400_API
    -DMBEDTLS_CONFIG_FILE="ele_s400_mbedtls_config.h"
  )

endif()

else()

message(SEND_ERROR "middleware_mbedtls_port_ele_s400 dependency does not meet, please check ${CMAKE_CURRENT_LIST_FILE}.")

endif()

endif()


if (CONFIG_USE_middleware_mbedtls_port_ele_s400_ecc_opaque)
# Add set(CONFIG_USE_middleware_mbedtls_port_ele_s400_ecc_opaque true) in config.cmake to use this component

message("middleware_mbedtls_port_ele_s400_ecc_opaque component is included from ${CMAKE_CURRENT_LIST_FILE}.")

if(CONFIG_USE_driver_s3mu AND CONFIG_USE_component_ele_crypto AND CONFIG_USE_middleware_mbedtls)

target_sources(${MCUX_SDK_PROJECT_NAME} PRIVATE
  ${CMAKE_CURRENT_LIST_DIR}/./port/ele_s400/ele_entropy.c
  ${CMAKE_CURRENT_LIST_DIR}/./port/ele_s400/aes_alt.c
  ${CMAKE_CURRENT_LIST_DIR}/./port/ele_s400/ccm_alt.c
  ${CMAKE_CURRENT_LIST_DIR}/./port/ele_s400/gcm_alt.c
  ${CMAKE_CURRENT_LIST_DIR}/./port/ele_s400/rsa_alt.c
  ${CMAKE_CURRENT_LIST_DIR}/./port/ele_s400/sha256_alt.c
  ${CMAKE_CURRENT_LIST_DIR}/./port/ele_s400/sha512_alt.c
  ${CMAKE_CURRENT_LIST_DIR}/./port/ele_s400/hmac_alt.c
  ${CMAKE_CURRENT_LIST_DIR}/./port/ele_s400/ecc_opaque/ele_mbedtls.c
  ${CMAKE_CURRENT_LIST_DIR}/./port/ele_s400/ecc_opaque/ecdsa_alt.c
  ${CMAKE_CURRENT_LIST_DIR}/./port/ele_s400/ecc_opaque/pk_alt.c
)

target_include_directories(${MCUX_SDK_PROJECT_NAME} PUBLIC
  ${CMAKE_CURRENT_LIST_DIR}/./port/ele_s400
  ${CMAKE_CURRENT_LIST_DIR}/./port/ele_s400/ecc_opaque
)

if(CONFIG_USE_COMPONENT_CONFIGURATION)
  message("===>Import configuration from ${CMAKE_CURRENT_LIST_FILE}")

  target_compile_definitions(${MCUX_SDK_PROJECT_NAME} PUBLIC
    -DMBEDTLS_MCUX_ELE_S400_API
    -DMBEDTLS_CONFIG_FILE="ele_ecc_opaque_mbedtls_config.h"
  )

endif()

else()

message(SEND_ERROR "middleware_mbedtls_port_ele_s400_ecc_opaque dependency does not meet, please check ${CMAKE_CURRENT_LIST_FILE}.")

endif()

endif()


if (CONFIG_USE_middleware_mbedtls_port_els_pkc)
# Add set(CONFIG_USE_middleware_mbedtls_port_els_pkc true) in config.cmake to use this component

message("middleware_mbedtls_port_els_pkc component is included from ${CMAKE_CURRENT_LIST_FILE}.")

if(CONFIG_USE_middleware_mbedtls_port_els AND CONFIG_USE_component_els_pkc AND CONFIG_USE_middleware_mbedtls_els_pkc_config AND ((CONFIG_USE_driver_trng AND (CONFIG_DEVICE_ID STREQUAL RW610 OR CONFIG_DEVICE_ID STREQUAL RW612)) OR ((CONFIG_DEVICE_ID STREQUAL LPC55S36 OR CONFIG_DEVICE_ID STREQUAL MCXN235 OR CONFIG_DEVICE_ID STREQUAL MCXN236 OR CONFIG_DEVICE_ID STREQUAL MCXN546 OR CONFIG_DEVICE_ID STREQUAL MCXN547 OR CONFIG_DEVICE_ID STREQUAL MCXN946 OR CONFIG_DEVICE_ID STREQUAL MCXN947))))

target_sources(${MCUX_SDK_PROJECT_NAME} PRIVATE
  ${CMAKE_CURRENT_LIST_DIR}/./port/pkc/ecc_alt.c
  ${CMAKE_CURRENT_LIST_DIR}/./port/pkc/ecdh_alt.c
  ${CMAKE_CURRENT_LIST_DIR}/./port/pkc/ecdsa_alt.c
  ${CMAKE_CURRENT_LIST_DIR}/./port/pkc/rsa_alt.c
  ${CMAKE_CURRENT_LIST_DIR}/./port/pkc/els_pkc_mbedtls.c
)

target_include_directories(${MCUX_SDK_PROJECT_NAME} PUBLIC
  ${CMAKE_CURRENT_LIST_DIR}/./port/pkc
)

if(CONFIG_USE_COMPONENT_CONFIGURATION)
  message("===>Import configuration from ${CMAKE_CURRENT_LIST_FILE}")

  target_compile_definitions(${MCUX_SDK_PROJECT_NAME} PUBLIC
    -DMBEDTLS_MCUX_ELS_PKC_API
    -DMBEDTLS_MCUX_USE_PKC
    -DMBEDTLS_CONFIG_FILE="els_pkc_mbedtls_config.h"
  )

endif()

else()

message(SEND_ERROR "middleware_mbedtls_port_els_pkc dependency does not meet, please check ${CMAKE_CURRENT_LIST_FILE}.")

endif()

endif()


if (CONFIG_USE_middleware_mbedtls_port_els)
# Add set(CONFIG_USE_middleware_mbedtls_port_els true) in config.cmake to use this component

message("middleware_mbedtls_port_els component is included from ${CMAKE_CURRENT_LIST_FILE}.")

if(CONFIG_USE_component_els_pkc_els AND CONFIG_USE_middleware_mbedtls)

target_sources(${MCUX_SDK_PROJECT_NAME} PRIVATE
  ${CMAKE_CURRENT_LIST_DIR}/./port/els/aes_alt.c
  ${CMAKE_CURRENT_LIST_DIR}/./port/els/cbc_mac_alt.c
  ${CMAKE_CURRENT_LIST_DIR}/./port/els/cmac_alt.c
  ${CMAKE_CURRENT_LIST_DIR}/./port/els/ctr_drbg_alt.c
  ${CMAKE_CURRENT_LIST_DIR}/./port/els/gcm_alt.c
  ${CMAKE_CURRENT_LIST_DIR}/./port/els/sha256_alt.c
  ${CMAKE_CURRENT_LIST_DIR}/./port/els/sha512_alt.c
  ${CMAKE_CURRENT_LIST_DIR}/./port/els/entropy_poll_alt.c
  ${CMAKE_CURRENT_LIST_DIR}/./port/els/els_mbedtls.c
)

target_include_directories(${MCUX_SDK_PROJECT_NAME} PUBLIC
  ${CMAKE_CURRENT_LIST_DIR}/./port/els
)

if(CONFIG_USE_COMPONENT_CONFIGURATION)
  message("===>Import configuration from ${CMAKE_CURRENT_LIST_FILE}")

  target_compile_definitions(${MCUX_SDK_PROJECT_NAME} PUBLIC
    -DMBEDTLS_MCUX_ELS_API
    -DMBEDTLS_MCUX_USE_ELS
    -DMCUXCL_FEATURE_CSSL_MEMORY_C_FALLBACK
    -DMBEDTLS_CONFIG_FILE="els_mbedtls_config.h"
  )

endif()

else()

message(SEND_ERROR "middleware_mbedtls_port_els dependency does not meet, please check ${CMAKE_CURRENT_LIST_FILE}.")

endif()

endif()


if (CONFIG_USE_middleware_mbedtls_port_sssapi)
# Add set(CONFIG_USE_middleware_mbedtls_port_sssapi true) in config.cmake to use this component

message("middleware_mbedtls_port_sssapi component is included from ${CMAKE_CURRENT_LIST_FILE}.")

if(CONFIG_USE_middleware_mbedtls AND CONFIG_USE_middleware_secure-subsystem_elemu_port_kw45_k4w1 AND (CONFIG_DEVICE_ID STREQUAL K32W1480xxxA OR CONFIG_DEVICE_ID STREQUAL KW45B41Z52xxxA OR CONFIG_DEVICE_ID STREQUAL KW45B41Z53xxxA OR CONFIG_DEVICE_ID STREQUAL KW45B41Z82xxxA OR CONFIG_DEVICE_ID STREQUAL KW45B41Z83xxxA OR CONFIG_DEVICE_ID STREQUAL KW45Z41052xxxA OR CONFIG_DEVICE_ID STREQUAL KW45Z41053xxxA OR CONFIG_DEVICE_ID STREQUAL KW45Z41082xxxA OR CONFIG_DEVICE_ID STREQUAL KW45Z41083xxxA OR CONFIG_DEVICE_ID STREQUAL MCXW716AxxxA OR CONFIG_DEVICE_ID STREQUAL MCXW716CxxxA))

target_sources(${MCUX_SDK_PROJECT_NAME} PRIVATE
  ${CMAKE_CURRENT_LIST_DIR}/./port/sssapi/sssapi_mbedtls.c
  ${CMAKE_CURRENT_LIST_DIR}/./port/sssapi/aes_alt.c
  ${CMAKE_CURRENT_LIST_DIR}/./port/sssapi/ccm_alt.c
  ${CMAKE_CURRENT_LIST_DIR}/./port/sssapi/cmac_alt.c
  ${CMAKE_CURRENT_LIST_DIR}/./port/sssapi/sha256_alt.c
  ${CMAKE_CURRENT_LIST_DIR}/./port/sssapi/sha512_alt.c
  ${CMAKE_CURRENT_LIST_DIR}/./port/sssapi/ecdh_alt.c
  ${CMAKE_CURRENT_LIST_DIR}/./port/sssapi/ecdsa_alt.c
  ${CMAKE_CURRENT_LIST_DIR}/./port/sssapi/entropy_poll_alt.c
)

target_include_directories(${MCUX_SDK_PROJECT_NAME} PUBLIC
  ${CMAKE_CURRENT_LIST_DIR}/./port/sssapi
)

if(CONFIG_USE_COMPONENT_CONFIGURATION)
  message("===>Import configuration from ${CMAKE_CURRENT_LIST_FILE}")

  target_compile_definitions(${MCUX_SDK_PROJECT_NAME} PUBLIC
    -DMBEDTLS_NXP_SSSAPI
    -DMBEDTLS_NXP_ELE200
    -DMBEDTLS_CONFIG_FILE="sssapi_mbedtls_config.h"
  )

endif()

else()

message(SEND_ERROR "middleware_mbedtls_port_sssapi dependency does not meet, please check ${CMAKE_CURRENT_LIST_FILE}.")

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

if((CONFIG_USE_utility_debug_console OR CONFIG_USE_utility_debug_console_lite) AND (CONFIG_USE_middleware_mbedtls_port_ksdk OR CONFIG_USE_middleware_mbedtls_port_sssapi OR CONFIG_USE_middleware_mbedtls_port_ele_s400 OR CONFIG_USE_middleware_mbedtls_port_ele_s400_ecc_opaque OR CONFIG_USE_middleware_mbedtls_port_els_pkc))

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

