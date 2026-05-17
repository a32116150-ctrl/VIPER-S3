# Auto-generate self-signed certs if missing
set(CERT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/certs")
if(NOT EXISTS "${CERT_DIR}/servercert.pem" OR NOT EXISTS "${CERT_DIR}/prvtkey.pem")
    message(STATUS "Generating self-signed HTTPS certs in ${CERT_DIR}")
    execute_process(
        COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/gen_certs.sh"
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    )
endif()

idf_component_register(
    SRCS "web_dashboard.c"
    INCLUDE_DIRS "include"
    REQUIRES
        esp_http_server
        esp_https_server
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
    EMBED_TXTFILES
        "certs/servercert.pem"
        "certs/prvtkey.pem"
)
