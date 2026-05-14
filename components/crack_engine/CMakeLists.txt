idf_component_register(
    SRCS "crack_engine.c"
    INCLUDE_DIRS "include"
    REQUIRES
        mbedtls
        storage_manager
        esp_timer
)
