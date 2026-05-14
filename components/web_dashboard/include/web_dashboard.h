#pragma once
#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

esp_err_t web_dashboard_init(void);
esp_err_t web_dashboard_deinit(void);

esp_err_t web_dashboard_broadcast(const char *event_type, const char *json_data);
