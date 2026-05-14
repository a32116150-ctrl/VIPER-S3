#pragma once
#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

/* LittleFS mount point */
#define STORAGE_MOUNT_POINT     "/viper"

/* Directory structure on flash */
#define DIR_PAYLOADS            "/viper/payloads"   /* Ducky scripts & shellcode */
#define DIR_CAPTURES            "/viper/captures"   /* Captured creds, hashes, pcap */
#define DIR_CAPTURES_CREDS      "/viper/captures/creds"
#define DIR_CAPTURES_PCAP       "/viper/captures/pcap"
#define DIR_CAPTURES_IMG        "/viper/captures/img"
#define DIR_CAPTURES_QR         "/viper/captures/qr"
#define DIR_TEMPLATES           "/viper/templates"  /* Captive portal HTML templates */
#define DIR_WORDLISTS           "/viper/wordlists"  /* Password wordlists */
#define DIR_CONFIG              "/viper/config"     /* Device config */

/* Key files */
#define FILE_CONFIG             "/viper/config/config.json"
#define FILE_CREDS              "/viper/captures/creds/creds.jsonl"  /* JSONL — one credential per line */
#define FILE_HASHES             "/viper/captures/creds/hashes.jsonl"
#define FILE_WORDLIST_10K       "/viper/wordlists/rockyou_10k.txt"
#define FILE_WORDLIST_100K      "/viper/wordlists/rockyou_100k.txt"
#define FILE_OUI_DB             "/viper/config/oui.txt"

esp_err_t storage_init(void);
esp_err_t storage_deinit(void);

/* Credential logging */
esp_err_t storage_log_credential(const char *source, const char *username,
                                  const char *password, const char *client_mac);
esp_err_t storage_log_hash(const char *hash_type, const char *hash_value,
                            const char *context);

/* File helpers */
esp_err_t storage_write_file(const char *path, const uint8_t *data, size_t len, bool append);
esp_err_t storage_read_file(const char *path, uint8_t *buf, size_t buf_len, size_t *read_len);
esp_err_t storage_file_exists(const char *path);
esp_err_t storage_delete_file(const char *path);
size_t    storage_get_free_bytes(void);
esp_err_t storage_wipe_captures(void);  /* Panic wipe */

/* Wordlist iteration (for crack engine) */
typedef void (*wordlist_cb_t)(const char *word, void *ctx);
esp_err_t storage_iterate_wordlist(const char *path, wordlist_cb_t cb, void *ctx);
