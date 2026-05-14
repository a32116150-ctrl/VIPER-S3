idf_component_register(
    SRCS "attack_orchestrator.c"
    INCLUDE_DIRS "include"
    REQUIRES
        wifi_engine
        ble_engine
        usb_engine
        camera_engine
        web_dashboard
        storage_manager
        esp_timer
)
