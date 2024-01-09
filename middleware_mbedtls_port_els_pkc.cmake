#Description: MbedTLS MCUX SDK port layer via PKC; user_visible: True
include_guard(GLOBAL)
message("middleware_mbedtls_port_els_pkc component is included.")

target_sources(${MCUX_SDK_PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/port/pkc/ecc_alt.c
    ${CMAKE_CURRENT_LIST_DIR}/port/pkc/ecdh_alt.c
    ${CMAKE_CURRENT_LIST_DIR}/port/pkc/ecdsa_alt.c
    ${CMAKE_CURRENT_LIST_DIR}/port/pkc/rsa_alt.c
    ${CMAKE_CURRENT_LIST_DIR}/port/pkc/els_pkc_mbedtls.c
)

target_include_directories(${MCUX_SDK_PROJECT_NAME} PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/port/pkc
)


include(middleware_mbedtls_port_els)
include(middleware_mbedtls_els_pkc_config)
