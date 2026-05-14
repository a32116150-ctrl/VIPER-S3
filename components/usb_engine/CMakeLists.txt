idf_component_register(
    SRCS
        "usb_engine.c"
        "usb_hid.c"
        "usb_ducky.c"
        "usb_payloads.c"
    INCLUDE_DIRS "include"
    REQUIRES
        espressif__esp_tinyusb
        storage_manager
        driver
        esp_timer
)
