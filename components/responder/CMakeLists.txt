idf_component_register(
    SRCS
        "responder.c"
        "smb_honey.c"
    INCLUDE_DIRS "include"
    REQUIRES
        lwip
        esp_timer
        storage_manager
)
