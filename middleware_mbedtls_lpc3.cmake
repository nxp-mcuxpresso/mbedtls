#Description: MbedTLS Adaptation for On-chip LPC Crypto accelerator; user_visible: True
include_guard(GLOBAL)
message("middleware_mbedtls_lpc3 component is included.")

target_sources(${MCUX_SDK_PROJECT_NAME} PRIVATE
)

target_include_directories(${MCUX_SDK_PROJECT_NAME} PUBLIC
)


include(driver_rng)
include(driver_sha)
include(middleware_mbedtls_port_ksdk)
