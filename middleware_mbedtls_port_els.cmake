#Description: MbedTLS MCUX SDK port layer via ELS; user_visible: False
include_guard(GLOBAL)
message("middleware_mbedtls_port_els component is included.")

target_sources(${MCUX_SDK_PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/port/els/aes_alt.c
    ${CMAKE_CURRENT_LIST_DIR}/port/els/cbc_mac_alt.c
    ${CMAKE_CURRENT_LIST_DIR}/port/els/cmac_alt.c
    ${CMAKE_CURRENT_LIST_DIR}/port/els/ctr_drbg_alt.c
    ${CMAKE_CURRENT_LIST_DIR}/port/els/gcm_alt.c
    ${CMAKE_CURRENT_LIST_DIR}/port/els/sha256_alt.c
    ${CMAKE_CURRENT_LIST_DIR}/port/els/sha512_alt.c
    ${CMAKE_CURRENT_LIST_DIR}/port/els/entropy_poll_alt.c
    ${CMAKE_CURRENT_LIST_DIR}/port/els/els_mbedtls.c
)

target_include_directories(${MCUX_SDK_PROJECT_NAME} PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/port/els
)


include(driver_trng)
include(component_els_pkc_platform_rw61x)
include(middleware_mbedtls_RW612)
