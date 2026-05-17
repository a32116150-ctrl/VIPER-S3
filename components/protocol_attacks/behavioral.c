#include "protocol_attacks.h"
#include "esp_log.h"
#include "esp_timer.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static const char *TAG = "BEHAVIOR";

#define MAX_SAMPLES 512
#define MAX_RESULTS 16

typedef struct {
    uint32_t size;
    uint32_t timestamp_us;
    bool     used;
} packet_sample_t;

static packet_sample_t s_samples[MAX_SAMPLES];
static int s_sample_count = 0;

static fingerprint_result_t s_results[MAX_RESULTS];
static int s_result_count = 0;

static uint32_t s_total_bytes = 0;
static uint32_t s_total_packets = 0;
static uint64_t s_first_packet = 0;
static uint64_t s_last_packet = 0;

static uint32_t s_small_packets = 0;
static uint32_t s_large_packets = 0;
static uint32_t s_burst_events = 0;

const char *app_type_to_string(app_type_t app)
{
    switch (app) {
        case APP_ZOOM:         return "Zoom";
        case APP_SSH:          return "SSH";
        case APP_NETFLIX:      return "Netflix";
        case APP_HTTP_BROWSE:  return "HTTP Browse";
        case APP_STREAMING:    return "Streaming";
        case APP_VOIP:         return "VoIP";
        case APP_FILE_TRANSFER: return "File Transfer";
        case APP_GAMING:       return "Gaming";
        default:               return "Unknown";
    }
}

static app_type_t classify_traffic(void)
{
    if (s_total_packets < 10) return APP_UNKNOWN;

    float avg_size = (float)s_total_bytes / s_total_packets;
    uint32_t duration_us = (uint32_t)(s_last_packet - s_first_packet);
    float duration_sec = duration_us > 0 ? duration_us / 1000000.0f : 1.0f;
    float pkt_rate = s_total_packets / duration_sec;
    float small_ratio = (float)s_small_packets / s_total_packets;
    float large_ratio = (float)s_large_packets / s_total_packets;

    if (pkt_rate > 50 && avg_size > 1000 && large_ratio > 0.6f) {
        return APP_NETFLIX;
    }

    if (pkt_rate > 20 && avg_size < 200 && small_ratio > 0.7f) {
        uint32_t bursts = 0;
        for (int i = 1; i < s_sample_count; i++) {
            if (s_samples[i].used && s_samples[i-1].used) {
                uint32_t gap = s_samples[i].timestamp_us - s_samples[i-1].timestamp_us;
                if (gap > 200000 && gap < 2000000) bursts++;
            }
        }
        float burst_ratio = (float)bursts / s_total_packets;
        if (burst_ratio > 0.1f) return APP_SSH;
        return APP_VOIP;
    }

    if (pkt_rate > 10 && avg_size > 200 && avg_size < 800) {
        if (small_ratio > 0.3f && large_ratio < 0.2f) {
            return APP_ZOOM;
        }
    }

    if (pkt_rate < 10 && avg_size > 500 && s_burst_events > 3) {
        return APP_HTTP_BROWSE;
    }

    if (avg_size > 800 && large_ratio > 0.4f) {
        return APP_STREAMING;
    }

    if (avg_size > 500 && pkt_rate > 5 && duration_sec > 30) {
        return APP_FILE_TRANSFER;
    }

    if (pkt_rate < 5 && small_ratio > 0.3f) {
        return APP_GAMING;
    }

    return APP_HTTP_BROWSE;
}

esp_err_t behavioral_init(void)
{
    memset(s_samples, 0, sizeof(s_samples));
    s_sample_count = 0;
    s_total_bytes = 0;
    s_total_packets = 0;
    s_first_packet = 0;
    s_last_packet = 0;
    s_small_packets = 0;
    s_large_packets = 0;
    s_burst_events = 0;
    s_result_count = 0;

    ESP_LOGI(TAG, "Behavioral fingerprinting initialized");
    return ESP_OK;
}

esp_err_t behavioral_deinit(void)
{
    behavioral_clear();
    return ESP_OK;
}

void behavioral_feed_packet(uint32_t size, uint32_t timestamp_us)
{
    if (s_sample_count < MAX_SAMPLES) {
        s_samples[s_sample_count].size = size;
        s_samples[s_sample_count].timestamp_us = timestamp_us;
        s_samples[s_sample_count].used = true;
        s_sample_count++;
    }

    s_total_bytes += size;
    s_total_packets++;
    s_last_packet = timestamp_us;
    if (s_first_packet == 0) s_first_packet = timestamp_us;

    if (size < 100) s_small_packets++;
    if (size > 1000) s_large_packets++;

    if (s_sample_count >= 2) {
        uint32_t gap = timestamp_us - s_samples[s_sample_count - 2].timestamp_us;
        if (gap > 50000 && gap < 500000) {
            s_burst_events++;
        }
    }
}

app_type_t behavioral_classify(void)
{
    if (s_total_packets < 10) return APP_UNKNOWN;

    app_type_t app = classify_traffic();

    uint32_t duration_us = (uint32_t)(s_last_packet - s_first_packet);

    if (s_result_count < MAX_RESULTS) {
        fingerprint_result_t *r = &s_results[s_result_count++];
        snprintf(r->client_ip, sizeof(r->client_ip), "192.168.4.x");
        r->app = app;
        r->packet_count = s_total_packets;
        r->avg_packet_size = s_total_packets > 0 ? s_total_bytes / s_total_packets : 0;
        r->duration_sec = duration_us / 1000000;
        r->confidence = s_total_packets < 10 ? 0.0f :
            s_total_packets < 50 ? 0.4f :
            s_total_packets < 200 ? 0.6f :
            s_total_packets < 1000 ? 0.75f : 0.85f;
        r->last_seen = esp_timer_get_time() / 1000;

        ESP_LOGI(TAG, "Classified: %s (%lu pkts, %lu avg, %lu sec, %.0f%% conf)",
                 app_type_to_string(app), (unsigned long)r->packet_count,
                 (unsigned long)r->avg_packet_size, (unsigned long)r->duration_sec,
                 r->confidence * 100);
    }

    return app;
}

int behavioral_get_results(fingerprint_result_t *results, int max)
{
    int copy = max < s_result_count ? max : s_result_count;
    if (copy > 0) memcpy(results, s_results, copy * sizeof(fingerprint_result_t));
    return copy;
}

void behavioral_clear(void)
{
    memset(s_samples, 0, sizeof(s_samples));
    s_sample_count = 0;
    s_total_bytes = 0;
    s_total_packets = 0;
    s_first_packet = 0;
    s_last_packet = 0;
    s_small_packets = 0;
    s_large_packets = 0;
    s_burst_events = 0;
    s_result_count = 0;
}
