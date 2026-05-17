#include "crack_engine.h"
#include "storage_manager.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "mbedtls/md5.h"
#include "mbedtls/sha1.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static const char *TAG = "CRACK";

static uint32_t s_total_cracked = 0;
static uint32_t s_total_attempts = 0;

#define F(x,y,z) (((x) & (y)) | ((~x) & (z)))
#define G(x,y,z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define H(x,y,z) ((x) ^ (y) ^ (z))

#define LEFT_ROTATE(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

static void md4_transform(uint32_t state[4], const uint8_t block[64])
{
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t x[16];
    for (int i = 0; i < 16; i++)
        x[i] = (uint32_t)block[i*4] | ((uint32_t)block[i*4+1] << 8) |
               ((uint32_t)block[i*4+2] << 16) | ((uint32_t)block[i*4+3] << 24);

    for (int i = 0; i < 16; i++) {
        uint32_t r = a + F(b, c, d) + x[i];
        a = d; d = c; c = b; b = LEFT_ROTATE(r, (i % 4 == 0) ? 3 : (i % 4 == 1) ? 7 : (i % 4 == 2) ? 11 : 19);
    }
    for (int i = 0; i < 16; i++) {
        int k = (i % 4 == 0) ? 0 : (i % 4 == 1) ? 4 : (i % 4 == 2) ? 8 : 12;
        uint32_t r = a + G(b, c, d) + x[k + i/4] + 0x5A827999;
        a = d; d = c; c = b; b = LEFT_ROTATE(r, (i % 4 == 0) ? 3 : (i % 4 == 1) ? 5 : (i % 4 == 2) ? 9 : 13);
    }
    for (int i = 0; i < 16; i++) {
        int k = (i % 4 == 0) ? 0 : (i % 4 == 1) ? 8 : (i % 4 == 2) ? 4 : 12;
        uint32_t r = a + H(b, c, d) + x[k + i / 4] + 0x6ED9EBA1;
        a = d; d = c; c = b; b = LEFT_ROTATE(r, (i % 4 == 0) ? 3 : (i % 4 == 1) ? 9 : (i % 4 == 2) ? 11 : 15);
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
}

static void md4_hash(const uint8_t *input, size_t len, uint8_t out[16])
{
    uint32_t state[4] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476};
    uint64_t bit_len = len * 8;
    uint8_t buf[64];
    size_t off = 0;

    while (len >= 64) {
        md4_transform(state, input + off);
        off += 64;
        len -= 64;
    }

    memset(buf, 0, 64);
    memcpy(buf, input + off, len);
    buf[len] = 0x80;

    if (len >= 56) {
        md4_transform(state, buf);
        memset(buf, 0, 64);
    }

    buf[56] = bit_len & 0xFF;
    buf[57] = (bit_len >> 8) & 0xFF;
    buf[58] = (bit_len >> 16) & 0xFF;
    buf[59] = (bit_len >> 24) & 0xFF;
    buf[60] = (bit_len >> 32) & 0xFF;
    buf[61] = (bit_len >> 40) & 0xFF;
    buf[62] = (bit_len >> 48) & 0xFF;
    buf[63] = (bit_len >> 56) & 0xFF;

    md4_transform(state, buf);

    for (int i = 0; i < 4; i++) {
        out[i*4]   = state[i] & 0xFF;
        out[i*4+1] = (state[i] >> 8) & 0xFF;
        out[i*4+2] = (state[i] >> 16) & 0xFF;
        out[i*4+3] = (state[i] >> 24) & 0xFF;
    }
}

static int hex_to_bytes(const char *hex, uint8_t *out, int max_out)
{
    int len = strlen(hex);
    if (len % 2 != 0 || len / 2 > max_out) return 0;
    for (int i = 0; i < len; i += 2) {
        char byte[3] = {hex[i], hex[i+1], 0};
        out[i / 2] = strtol(byte, NULL, 16);
    }
    return len / 2;
}

static int utf16le_encode(const char *src, uint8_t *dst, int max_dst)
{
    int o = 0;
    for (int i = 0; src[i] && o + 2 <= max_dst; i++) {
        dst[o++] = src[i];
        dst[o++] = 0x00;
    }
    return o;
}

static void ntlm_hash(const char *password, uint8_t out[16])
{
    uint8_t u16[256];
    int u16len = utf16le_encode(password, u16, sizeof(u16));
    md4_hash(u16, u16len, out);
}

esp_err_t crack_engine_crack_ntlm(const uint8_t *target_hash, const char *wordlist_path,
                                   char *out_pass, size_t out_len)
{
    FILE *f = fopen(wordlist_path, "r");
    if (!f) { ESP_LOGE(TAG, "Wordlist not found: %s", wordlist_path); return ESP_ERR_NOT_FOUND; }

    uint8_t computed[16];
    char line[128];
    uint32_t attempts = 0;
    uint64_t start = esp_timer_get_time();

    while (fgets(line, sizeof(line), f)) {
        size_t llen = strlen(line);
        if (llen > 0 && line[llen - 1] == '\n') line[llen - 1] = '\0';
        if (llen > 1 && line[llen - 2] == '\r') line[llen - 2] = '\0';
        if (line[0] == '\0') continue;

        ntlm_hash(line, computed);
        attempts++;

        if (memcmp(computed, target_hash, 16) == 0) {
            strncpy(out_pass, line, out_len - 1);
            out_pass[out_len - 1] = '\0';
            fclose(f);
            uint64_t elapsed = (esp_timer_get_time() - start) / 1000;
            s_total_cracked++;
            s_total_attempts += attempts;
            ESP_LOGI(TAG, "NTLM cracked: '%s' (%lu attempts, %llu ms)", line, (unsigned long)attempts, elapsed);
            return ESP_OK;
        }
    }

    fclose(f);
    s_total_attempts += attempts;
    return ESP_ERR_NOT_FOUND;
}

esp_err_t crack_engine_crack_md5(const char *target_hex, const char *wordlist_path,
                                  char *out_pass, size_t out_len)
{
    uint8_t target[16];
    if (hex_to_bytes(target_hex, target, sizeof(target)) != 16) return ESP_ERR_INVALID_ARG;
    FILE *f = fopen(wordlist_path, "r");
    if (!f) return ESP_ERR_NOT_FOUND;

    uint8_t computed[16];
    char line[128];
    uint32_t attempts = 0;
    uint64_t start = esp_timer_get_time();

    while (fgets(line, sizeof(line), f)) {
        size_t llen = strlen(line);
        if (llen > 0 && line[llen - 1] == '\n') line[llen - 1] = '\0';
        if (llen > 1 && line[llen - 2] == '\r') line[llen - 2] = '\0';
        if (line[0] == '\0') continue;

        if (mbedtls_md5((const unsigned char *)line, strlen(line), computed) != 0) {
            ESP_LOGW(TAG, "mbedtls_md5 failed on line %lu", (unsigned long)attempts);
            continue;
        }
        attempts++;

        if (memcmp(computed, target, 16) == 0) {
            strncpy(out_pass, line, out_len - 1);
            out_pass[out_len - 1] = '\0';
            fclose(f);
            s_total_cracked++;
            s_total_attempts += attempts;
            return ESP_OK;
        }
    }
    fclose(f);
    s_total_attempts += attempts;
    return ESP_ERR_NOT_FOUND;
}

esp_err_t crack_engine_crack_sha1(const char *target_hex, const char *wordlist_path,
                                   char *out_pass, size_t out_len)
{
    uint8_t target[20];
    if (hex_to_bytes(target_hex, target, sizeof(target)) != 20) return ESP_ERR_INVALID_ARG;
    FILE *f = fopen(wordlist_path, "r");
    if (!f) return ESP_ERR_NOT_FOUND;

    uint8_t computed[20];
    char line[128];
    uint32_t attempts = 0;
    uint64_t start = esp_timer_get_time();

    while (fgets(line, sizeof(line), f)) {
        size_t llen = strlen(line);
        if (llen > 0 && line[llen - 1] == '\n') line[llen - 1] = '\0';
        if (llen > 1 && line[llen - 2] == '\r') line[llen - 2] = '\0';
        if (line[0] == '\0') continue;

        if (mbedtls_sha1((const unsigned char *)line, strlen(line), computed) != 0) {
            ESP_LOGW(TAG, "mbedtls_sha1 failed on line %lu", (unsigned long)attempts);
            continue;
        }
        attempts++;

        if (memcmp(computed, target, 20) == 0) {
            strncpy(out_pass, line, out_len - 1);
            out_pass[out_len - 1] = '\0';
            fclose(f);
            s_total_cracked++;
            s_total_attempts += attempts;
            return ESP_OK;
        }
    }
    fclose(f);
    s_total_attempts += attempts;
    return ESP_ERR_NOT_FOUND;
}

esp_err_t crack_engine_crack(const char *hash_str, hash_type_t type,
                              const char *wordlist_path, crack_result_t *result)
{
    if (!result) return ESP_ERR_INVALID_ARG;
    memset(result, 0, sizeof(*result));
    result->type = type;

    uint64_t start = esp_timer_get_time();
    uint32_t attempts_before = s_total_attempts;
    esp_err_t ret;
    char pass[64] = {0};

    switch (type) {
        case HASH_TYPE_NTLM: {
            uint8_t target[16];
            if (hex_to_bytes(hash_str, target, sizeof(target)) != 16)
                return ESP_ERR_INVALID_ARG;
            ret = crack_engine_crack_ntlm(target, wordlist_path, pass, sizeof(pass));
            break;
        }
        case HASH_TYPE_MD5:
            ret = crack_engine_crack_md5(hash_str, wordlist_path, pass, sizeof(pass));
            break;
        case HASH_TYPE_SHA1:
            ret = crack_engine_crack_sha1(hash_str, wordlist_path, pass, sizeof(pass));
            break;
        default:
            return ESP_ERR_NOT_SUPPORTED;
    }

    result->found = (ret == ESP_OK);
    if (result->found) strncpy(result->password, pass, sizeof(result->password) - 1);
    result->attempts = s_total_attempts - attempts_before;
    result->duration_ms = (uint32_t)((esp_timer_get_time() - start) / 1000);
    return ret;
}

esp_err_t crack_engine_init(void)
{
    ESP_LOGI(TAG, "Crack engine initialized (MD4 inline, HW SHA available)");
    return ESP_OK;
}

esp_err_t crack_engine_deinit(void) { return ESP_OK; }

uint32_t crack_engine_get_speed(hash_type_t type)
{
    switch (type) {
        case HASH_TYPE_NTLM:  return 4000000;
        case HASH_TYPE_MD5:   return 5000000;
        case HASH_TYPE_SHA1:  return 3000000;
        case HASH_TYPE_PMKID: return 500;
        default: return 0;
    }
}

void crack_engine_get_stats(uint32_t *total_cracked, uint32_t *total_attempts)
{
    if (total_cracked) *total_cracked = s_total_cracked;
    if (total_attempts) *total_attempts = s_total_attempts;
}
