idf_component_register(
    SRCS "nfc_engine.c"
    INCLUDE_DIRS "include"
    REQUIRES
        driver
        esp_timer
        storage_manager
)
