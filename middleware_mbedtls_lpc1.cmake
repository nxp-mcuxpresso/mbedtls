#Description: MbedTLS Adaptation for On-chip LPC Crypto accelerator; user_visible: True
include_guard(GLOBAL)
message("middleware_mbedtls_lpc1 component is included.")

target_sources(${MCUX_SDK_PROJECT_NAME} PRIVATE
)

target_include_directories(${MCUX_SDK_PROJECT_NAME} PUBLIC
)


include(driver_casper)
include(middleware_mbedtls_port_ksdk)
include(driver_hashcrypt)
include(driver_rng_1)
