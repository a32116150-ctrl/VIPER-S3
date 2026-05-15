idf_component_register(
    SRCS "web_dashboard.c"
    INCLUDE_DIRS "include"
    REQUIRES
        esp_http_server
        esp_wifi
        storage_manager
        wifi_engine
        camera_engine
        ble_engine
        responder
        crack_engine
        protocol_attacks
        ir_engine
        nfc_engine
        usb_engine
        ai_engine
        attack_orchestrator
)
