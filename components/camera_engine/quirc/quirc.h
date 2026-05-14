#pragma once
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct quirc;

struct quirc *quirc_new(void);
void quirc_destroy(struct quirc *q);

int  quirc_resize(struct quirc *q, int w, int h);
int  quirc_count(const struct quirc *q);
int  quirc_decode(const struct quirc *q, int index);

uint8_t *quirc_begin(struct quirc *q, int *w, int *h);
void     quirc_end(struct quirc *q);

typedef struct {
    int      version;
    uint8_t  ecc_level;
    uint8_t  mask;
    int      dlen;
    uint8_t  payload[4096];
    int      payload_len;
} quirc_data_t;

int quirc_decode_data(const struct quirc *q, int index, quirc_data_t *data);

const char *quirc_version(void);

#ifdef __cplusplus
}
#endif
