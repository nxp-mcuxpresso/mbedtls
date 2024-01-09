#Description: els_pkc config; user_visible: False
include_guard(GLOBAL)
message("middleware_mbedtls_els_pkc_config component is included.")

target_sources(${MCUX_SDK_PROJECT_NAME} PRIVATE
)

target_include_directories(${MCUX_SDK_PROJECT_NAME} PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/port/pkc
)


