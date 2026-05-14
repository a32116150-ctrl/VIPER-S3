#pragma once
#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

typedef enum {
    HASH_TYPE_NTLM   = 0,
    HASH_TYPE_MD5    = 1,
    HASH_TYPE_SHA1   = 2,
    HASH_TYPE_PMKID  = 3,
} hash_type_t;

typedef struct {
    char     password[64];
    hash_type_t type;
    bool     found;
    uint32_t attempts;
    uint32_t duration_ms;
} crack_result_t;

esp_err_t crack_engine_init(void);
esp_err_t crack_engine_deinit(void);

esp_err_t crack_engine_crack(const char *hash_str, hash_type_t type,
                              const char *wordlist_path, crack_result_t *result);

esp_err_t crack_engine_crack_ntlm(const uint8_t *target_hash, const char *wordlist_path,
                                   char *out_pass, size_t out_len);

esp_err_t crack_engine_crack_md5(const char *target_hex, const char *wordlist_path,
                                  char *out_pass, size_t out_len);

esp_err_t crack_engine_crack_sha1(const char *target_hex, const char *wordlist_path,
                                   char *out_pass, size_t out_len);

uint32_t crack_engine_get_speed(hash_type_t type);
void     crack_engine_get_stats(uint32_t *total_cracked, uint32_t *total_attempts);
