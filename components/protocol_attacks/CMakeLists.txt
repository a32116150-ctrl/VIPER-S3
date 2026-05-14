idf_component_register(
    SRCS
        "downgrade.c"
        "canary.c"
        "behavioral.c"
    INCLUDE_DIRS "include"
    REQUIRES
        wifi_engine
        storage_manager
        esp_timer
        lwip
)
