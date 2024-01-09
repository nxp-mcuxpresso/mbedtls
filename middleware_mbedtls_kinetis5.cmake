#Description: MbedTLS Adaptation for On-chip Kinetis Crypto accelerator; user_visible: True
include_guard(GLOBAL)
message("middleware_mbedtls_kinetis5 component is included.")

target_sources(${MCUX_SDK_PROJECT_NAME} PRIVATE
)

target_include_directories(${MCUX_SDK_PROJECT_NAME} PUBLIC
)


include(driver_trng)
include(driver_ltc)
include(middleware_mbedtls_port_ksdk)
include(middleware_mmcau_cm4_cm7)
