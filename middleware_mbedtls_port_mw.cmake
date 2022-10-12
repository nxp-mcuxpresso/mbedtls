#Description: MbedTLS MCUX SDK port layer; user_visible: True
include_guard(GLOBAL)
message("middleware_mbedtls_port_mw component is included.")

target_sources(${MCUX_SDK_PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/port/mw/ksdk_mbedtls.c
    ${CMAKE_CURRENT_LIST_DIR}/port/mw/ccm_alt.c
    ${CMAKE_CURRENT_LIST_DIR}/port/mw/aes_alt.c
)

target_include_directories(${MCUX_SDK_PROJECT_NAME} PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/port/mw
)


