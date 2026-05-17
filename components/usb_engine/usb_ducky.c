#include "usb_engine.h"
#include "storage_manager.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static const char *TAG = "DUCKY";

esp_err_t usb_ducky_execute(const char *script_path)
{
    FILE *f = fopen(script_path, "r");
    if (!f) {
        ESP_LOGE(TAG, "Script not found: %s", script_path);
        return ESP_ERR_NOT_FOUND;
    }

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (fsize <= 0) {
        fclose(f);
        return ESP_ERR_NOT_FOUND;
    }

    char *content = malloc(fsize + 1);
    if (!content) {
        fclose(f);
        return ESP_ERR_NO_MEM;
    }

    size_t read_size = fread(content, 1, fsize, f);
    fclose(f);
    content[read_size] = '\0';

    ESP_LOGI(TAG, "Executing Ducky Script: %s (%ld bytes)", script_path, (long)read_size);
    esp_err_t ret = usb_payload_execute_script(content);
    free(content);
    return ret;
}

esp_err_t usb_ducky_execute_string(const char *script)
{
    return usb_payload_execute_script(script);
}

esp_err_t usb_ducky_set_default_delay(uint32_t ms)
{
    extern uint32_t usb_payload_set_default_delay(uint32_t ms);
    usb_payload_set_default_delay(ms);
    return ESP_OK;
}
