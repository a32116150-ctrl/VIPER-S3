#include "storage_manager.h"
#include "esp_littlefs.h"
#include "esp_log.h"
#include <sys/stat.h>
#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static const char *TAG = "STORAGE";

static esp_vfs_littlefs_conf_t lfs_conf = {
    .base_path              = STORAGE_MOUNT_POINT,
    .partition_label        = "storage",
    .format_if_mount_failed = true,
    .dont_mount             = false,
};

/* ── Init / Deinit ─────────────────────────────── */

esp_err_t storage_init(void)
{
    esp_err_t ret = esp_vfs_littlefs_register(&lfs_conf);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to mount LittleFS: %s", esp_err_to_name(ret));
        return ret;
    }

    size_t total = 0, used = 0;
    esp_littlefs_info(lfs_conf.partition_label, &total, &used);
    ESP_LOGI(TAG, "LittleFS mounted. Total: %uKB  Used: %uKB  Free: %uKB",
             total / 1024, used / 1024, (total - used) / 1024);

    /* Create directory tree */
    const char *dirs[] = {
        DIR_PAYLOADS, DIR_CAPTURES, DIR_CAPTURES_CREDS,
        DIR_CAPTURES_PCAP, DIR_CAPTURES_IMG, DIR_CAPTURES_QR,
        DIR_TEMPLATES, DIR_WORDLISTS, DIR_CONFIG, NULL
    };
    for (int i = 0; dirs[i]; i++) {
        mkdir(dirs[i], 0755);
    }

    return ESP_OK;
}

esp_err_t storage_deinit(void)
{
    return esp_vfs_littlefs_unregister(lfs_conf.partition_label);
}

/* ── Credential & Hash Logging ─────────────────── */

esp_err_t storage_log_credential(const char *source, const char *username,
                                  const char *password, const char *client_mac)
{
    char buf[512];
    time_t now = time(NULL);
    snprintf(buf, sizeof(buf),
             "{\"ts\":%lld,\"src\":\"%s\",\"mac\":\"%s\",\"user\":\"%s\",\"pass\":\"%s\"}\n",
             (long long)now, source ? source : "",
             client_mac ? client_mac : "", username ? username : "",
             password ? password : "");

    ESP_LOGI(TAG, "CRED CAPTURED: [%s] %s:%s", source, username, password);
    return storage_write_file(FILE_CREDS, (uint8_t *)buf, strlen(buf), true);
}

esp_err_t storage_log_hash(const char *hash_type, const char *hash_value,
                            const char *context)
{
    char buf[512];
    time_t now = time(NULL);
    snprintf(buf, sizeof(buf),
             "{\"ts\":%lld,\"type\":\"%s\",\"hash\":\"%s\",\"ctx\":\"%s\"}\n",
             (long long)now, hash_type, hash_value, context ? context : "");

    ESP_LOGI(TAG, "HASH CAPTURED [%s]: %s", hash_type, hash_value);
    return storage_write_file(FILE_HASHES, (uint8_t *)buf, strlen(buf), true);
}

/* ── File Helpers ──────────────────────────────── */

esp_err_t storage_write_file(const char *path, const uint8_t *data,
                              size_t len, bool append)
{
    FILE *f = fopen(path, append ? "ab" : "wb");
    if (!f) {
        ESP_LOGE(TAG, "Cannot open for write: %s", path);
        return ESP_FAIL;
    }
    fwrite(data, 1, len, f);
    fclose(f);
    return ESP_OK;
}

esp_err_t storage_read_file(const char *path, uint8_t *buf,
                             size_t buf_len, size_t *read_len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return ESP_ERR_NOT_FOUND;
    *read_len = fread(buf, 1, buf_len, f);
    fclose(f);
    return ESP_OK;
}

esp_err_t storage_file_exists(const char *path)
{
    struct stat st;
    return (stat(path, &st) == 0) ? ESP_OK : ESP_ERR_NOT_FOUND;
}

esp_err_t storage_delete_file(const char *path)
{
    return (remove(path) == 0) ? ESP_OK : ESP_FAIL;
}

size_t storage_get_free_bytes(void)
{
    size_t total = 0, used = 0;
    esp_littlefs_info(lfs_conf.partition_label, &total, &used);
    return total - used;
}

esp_err_t storage_wipe_captures(void)
{
    /* Remove all credential and capture files */
    remove(FILE_CREDS);
    remove(FILE_HASHES);
    ESP_LOGW(TAG, "⚠ Captures wiped");
    return ESP_OK;
}

/* ── Wordlist Iterator ─────────────────────────── */

esp_err_t storage_iterate_wordlist(const char *path, wordlist_cb_t cb, void *ctx)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        ESP_LOGE(TAG, "Wordlist not found: %s", path);
        return ESP_ERR_NOT_FOUND;
    }
    char line[128];
    while (fgets(line, sizeof(line), f)) {
        /* Strip newline */
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n') line[len - 1] = '\0';
        if (len > 1 && line[len - 2] == '\r') line[len - 2] = '\0';
        if (strlen(line) > 0) cb(line, ctx);
    }
    fclose(f);
    return ESP_OK;
}
