idf_component_register(
    SRCS "ai_engine.c"
    INCLUDE_DIRS "include"
    REQUIRES
        storage_manager
        ble_engine
        wifi_engine
        esp_timer
)
