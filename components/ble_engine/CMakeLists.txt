idf_component_register(
    SRCS
        "ble_engine.c"
        "ble_scanner.c"
        "ble_spam.c"
        "ble_uart.c"
        "ble_adv_ext.c"
        "ble_scan_proprietary.c"
        "ble_mitm.c"
    INCLUDE_DIRS "include"
    REQUIRES
        bt
        esp_timer
        storage_manager
        nvs_flash
)
