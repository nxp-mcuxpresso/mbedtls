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

