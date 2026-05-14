#include "quirc.h"
#include <stdlib.h>
#include <string.h>

#define QUIRC_GF_SIZE 256
#define QUIRC_MAX_CODES 8
#define QUIRC_MAX_VERSION 10
#define QUIRC_MODULE_SIZE(__v__) ((__v__) * 4 + 17)

static const uint8_t gf_exp[QUIRC_GF_SIZE * 2];
static const uint8_t gf_log[QUIRC_GF_SIZE];

static void init_gf(void)
{
    static int done;
    if (done) return; done = 1;
    int i, x = 1;
    for (i = 0; i < QUIRC_GF_SIZE; i++) {
        gf_exp[i] = gf_exp[i + QUIRC_GF_SIZE] = (uint8_t)x;
        gf_log[x] = (uint8_t)i;
        x <<= 1;
        if (x >= QUIRC_GF_SIZE) x ^= 0x11D;
    }
}

static int gf_mul(int x, int y) {
    if (!x || !y) return 0;
    return gf_exp[gf_log[x] + gf_log[y]];
}

static int gf_poly_eval(const uint8_t *p, int degree, int x) {
    int r = p[0];
    for (int i = 1; i <= degree; i++) r = gf_mul(r, x) ^ p[i];
    return r;
}

static void gf_poly_scale(const uint8_t *p, int deg, int scale, uint8_t *out) {
    for (int i = 0; i <= deg; i++) out[i] = gf_mul(p[i], scale);
}

static void gf_poly_add(const uint8_t *a, int da, const uint8_t *b, int db, uint8_t *out) {
    int n = (da > db) ? da : db;
    for (int i = 0; i <= n; i++) {
        int va = (da - n + i >= 0) ? a[da - n + i] : 0;
        int vb = (db - n + i >= 0) ? b[db - n + i] : 0;
        out[i] = va ^ vb;
    }
}

static void gf_poly_mul(const uint8_t *a, int da, const uint8_t *b, int db, uint8_t *out) {
    memset(out, 0, (da + db + 1));
    for (int i = 0; i <= da; i++)
        for (int j = 0; j <= db; j++)
            out[i + j] ^= gf_mul(a[i], b[j]);
}

static int rs_decode(const uint8_t *received, int n, int k, uint8_t *out) {
    init_gf();
    int nsym = n - k;
    uint8_t synd[nsym + 1];
    memset(synd, 0, nsym + 1);
    int syn_error = 0;
    for (int i = 0; i < nsym; i++) {
        synd[i] = gf_poly_eval(received, n - 1, gf_exp[i]);
        if (synd[i]) syn_error = 1;
    }
    if (!syn_error) { memcpy(out, received, n); return 0; }

    uint8_t b[nsym + 1], t[nsym + 1], omega[nsym + 1];
    uint8_t lambda[nsym + 1], old[nsym + 1];
    memset(lambda, 0, nsym + 1); lambda[0] = 1;
    memset(old, 0, nsym + 1); old[0] = 1;
    int L = 0, m = 1;
    for (int r = 0; r < nsym; r++) {
        int delta = synd[r];
        for (int i = 1; i <= L; i++) delta ^= gf_mul(lambda[i], synd[r - i]);
        memcpy(b, old, nsym + 1);
        if (delta) {
            gf_poly_scale(b, nsym, delta, b);
            gf_poly_add(lambda, L, b, nsym, t);
            int dL = L;
            int shift = r - m;
            if (shift > nsym - L) shift = nsym - L;
            memcpy(lambda, t, nsym + 1);
            L = (r - m > L) ? r - m : L;
            if (dL <= r / 2) { memcpy(old, b, nsym + 1); m = r + 1; }
        }
    }

    for (int i = 0; i < nsym; i++) {
        omega[i] = 0;
        for (int j = 0; j <= i; j++)
            omega[i] ^= gf_mul(lambda[j], synd[i - j]);
    }

    int err_count = 0;
    for (int i = 0; i < n; i++) {
        int x = gf_exp[255 - i];
        int val = gf_poly_eval(lambda, L, x);
        if (val == 0) {
            int deriv = 0;
            for (int j = 1; j <= L; j += 2)
                deriv ^= gf_mul(j, lambda[j]);
            if (deriv == 0) continue;
            int err_val = gf_mul(gf_poly_eval(omega, nsym - 1, x),
                                  gf_exp[gf_log[deriv] + 255 - gf_log[x]]);
            out[n - 1 - i] = received[n - 1 - i] ^ err_val;
            err_count++;
        } else {
            out[n - 1 - i] = received[n - 1 - i];
        }
    }
    return (err_count == 0) ? 0 : 1;
}

struct quirc {
    int w, h;
    uint8_t *image;
    struct {
        int cx, cy;
        int size;
    } codes[QUIRC_MAX_CODES];
    int code_count;
    int version;
};

struct quirc *quirc_new(void) {
    struct quirc *q = calloc(1, sizeof(*q));
    return q;
}

void quirc_destroy(struct quirc *q) {
    if (q) { free(q->image); free(q); }
}

int quirc_resize(struct quirc *q, int w, int h) {
    uint8_t *img = realloc(q->image, w * h);
    if (!img) return -1;
    q->image = img;
    q->w = w;
    q->h = h;
    return 0;
}

int quirc_count(const struct quirc *q) { return q->code_count; }

uint8_t *quirc_begin(struct quirc *q, int *w, int *h) {
    if (!q->image || q->w <= 0 || q->h <= 0) return NULL;
    *w = q->w; *h = q->h;
    return q->image;
}

static int finder_score(const uint8_t *row, int pos, int len) {
    int total = 0, counts[5] = {0};
    int idx = 0, in_white = 1;
    for (int i = 0; i < len; i++) {
        int p = pos + (in_white ? -1 : 1) * (idx);
        if (p < 0 || p >= len) break;
        int pixel = row[p];
        if ((in_white && pixel > 128) || (!in_white && pixel <= 128)) {
            counts[idx]++;
        } else {
            idx++;
            if (idx >= 5) break;
            in_white = !in_white;
            counts[idx] = 1;
        }
    }
    if (idx < 4) return 0;
    int ref = (counts[0] + counts[2] + counts[4]) / 3;
    if (ref == 0) return 0;
    int err = abs(counts[0] - ref) + abs(counts[1] - ref)
            + abs(counts[2] - 3*ref) + abs(counts[3] - ref)
            + abs(counts[4] - ref);
    return (err * 100) / (ref * 7);
}

void quirc_end(struct quirc *q) {
    q->code_count = 0;
    int w = q->w, h = q->h;
    uint8_t *img = q->image;
    int step = 4;
    int search_size = 100;

    for (int y = search_size; y < h - search_size && q->code_count < QUIRC_MAX_CODES; y += step) {
        for (int x = search_size; x < w - search_size && q->code_count < QUIRC_MAX_CODES; x += step) {
            int score_v = 0, score_h = 0;
            for (int s = -2; s <= 2; s++) {
                if (y + s > 0 && y + s < h) {
                    score_h += finder_score(img + (y + s) * w, x, w - x);
                }
                if (x + s > 0 && x + s < w) {
                    uint8_t col[h];
                    for (int r = 0; r < h; r++) col[r] = img[r * w + x + s];
                    score_v += finder_score(col, y, h - y);
                }
            }
            if (score_h < 200 && score_v < 200) continue;
            int cx = x + 14, cy = y + 14;
            int sz = 7;
            q->codes[q->code_count].cx = cx;
            q->codes[q->code_count].cy = cy;
            q->codes[q->code_count].size = sz;
            q->code_count++;
        }
    }

    if (q->code_count > 0) {
        q->version = 1;
        for (int i = 0; i < q->code_count; i++) {
            int s = q->codes[i].size;
            int v = (s - 17) / 4;
            if (v > q->version) q->version = v;
            if (q->version > QUIRC_MAX_VERSION) q->version = QUIRC_MAX_VERSION;
        }
    }
}

static int extract_bits(const uint8_t *img, int w, int h,
                         int cx, int cy, int version,
                         uint8_t *bits)
{
    int size = QUIRC_MODULE_SIZE(version);
    int module_px = (cx * 2) / size;
    if (module_px < 2) return -1;
    int x_off = cx - (size / 2) * module_px;
    int y_off = cy - (size / 2) * module_px;

    for (int r = 0; r < size; r++) {
        for (int c = 0; c < size; c++) {
            int px = x_off + c * module_px;
            int py = y_off + r * module_px;
            int val = 0;
            int samples = 0;
            for (int dy = -1; dy <= 1; dy++) {
                for (int dx = -1; dx <= 1; dx++) {
                    int sx = px + dx, sy = py + dy;
                    if (sx >= 0 && sx < w && sy >= 0 && sy < h) {
                        val += img[sy * w + sx];
                        samples++;
                    }
                }
            }
            int idx = r * size + c;
            bits[idx] = (samples > 0 && val / samples < 128) ? 1 : 0;
        }
    }
    return 0;
}

static const int fmt_mask[15] = {
    0,1,1,1,0,0,1,1,1,0,1,1,0,0,1
};

static int decode_format(const uint8_t *bits, int size, int *ec_level, int *mask) {
    int fmt_bits[15];
    int fpos[][2] = {
        {8,0},{8,1},{8,2},{8,3},{8,4},{8,5},{8,7},{8,8},
        {7,8},{5,8},{4,8},{3,8},{2,8},{1,8},{0,8}
    };
    for (int i = 0; i < 15; i++) {
        int r = fpos[i][0], c = fpos[i][1];
        if (r >= 0 && r < size && c >= 0 && c < size) {
            fmt_bits[i] = bits[r * size + c] ^ fmt_mask[i];
        } else fmt_bits[i] = 0;
    }
    int best = 9999, best_ec = 1, best_mask = 0;
    for (int ec = 0; ec < 4; ec++) {
        for (int mk = 0; mk < 8; mk++) {
            int data = (ec << 3) | mk;
            int gen = 0b10100110111;
            int poly = data << 10;
            for (int i = 14; i >= 10; i--) {
                if ((poly >> i) & 1) poly ^= gen << (i - 10);
            }
            int codeword = (data << 10) | poly;
            int errs = 0;
            for (int i = 14; i >= 0; i--) {
                int expected = (codeword >> i) & 1;
                if (expected != fmt_bits[14 - i]) errs++;
            }
            if (errs < best) {
                best = errs; best_ec = ec; best_mask = mk;
            }
        }
    }
    *ec_level = best_ec;
    *mask = best_mask;
    return (best < 7) ? 0 : -1;
}

static int apply_mask(uint8_t *bits, int size, int mask) {
    for (int r = 0; r < size; r++) {
        for (int c = 0; c < size; c++) {
            if (r < 9 && (c < 9 || c >= size - 8)) continue;
            if (c < 9 && r >= size - 8) continue;
            int invert = 0;
            switch (mask) {
                case 0: invert = ((r + c) % 2 == 0); break;
                case 1: invert = (r % 2 == 0); break;
                case 2: invert = (c % 3 == 0); break;
                case 3: invert = ((r + c) % 3 == 0); break;
                case 4: invert = ((r / 2 + c / 3) % 2 == 0); break;
                case 5: invert = ((r * c) % 2 + (r * c) % 3 == 0); break;
                case 6: invert = (((r * c) % 2 + (r * c) % 3) % 2 == 0); break;
                case 7: invert = (((r + c) % 2 + (r * c) % 3) % 2 == 0); break;
            }
            int idx = r * size + c;
            if (invert) bits[idx] = bits[idx] ? 0 : 1;
        }
    }
    return 0;
}

static int read_data(const uint8_t *bits, int size, int version,
                      uint8_t *data_words, int *data_count)
{
    int total = 0;
    uint8_t buf[512];
    int buf_bits = 0;
    int dir = 1;
    int col = size - 1;

    while (col > 0) {
        if (col == 6) col--;
        for (int r = (dir > 0) ? size - 1 : 0;
             (dir > 0) ? r >= 0 : r < size;
             r += dir) {
            for (int c = 0; c < 2; c++) {
                int cx = col - c;
                int idx = r * size + cx;
                if (r < 9 && (cx < 9 || cx >= size - 8)) continue;
                if (cx < 9 && r >= size - 8) continue;
                if (total < 512 * 8) {
                    buf[total / 8] = (buf[total / 8] << 1) | bits[idx];
                    total++;
                }
            }
        }
        col -= 2;
        dir = -dir;
    }

    int ec_level = 1;
    int rs_blocks[] = { 0, 7, 10, 13, 16 };
    int data_codewords[] = { 0, 16, 28, 44, 64, 86, 108, 124, 154, 172, 200 };
    int block_sizes[] = { 0, 26, 44, 70, 100, 134, 168, 196, 242, 292, 346 };

    int dc = data_codewords[version];
    int bc = block_sizes[version];
    int rs_c = rs_blocks[ec_level];

    if (total < dc * 8) return -1;

    uint8_t received[512];
    for (int i = 0; i < bc; i++) {
        received[i] = 0;
        for (int j = 0; j < 8; j++) {
            int bit_idx = i * 8 + j;
            if (bit_idx < total)
                received[i] = (received[i] << 1) | ((buf[bit_idx / 8] >> (7 - (bit_idx % 8))) & 1);
        }
    }

    uint8_t decoded[512];
    rs_decode(received, bc, dc, decoded);

    memcpy(data_words, decoded, dc);
    *data_count = dc;
    return 0;
}

static int decode_payload(const uint8_t *data, int count, quirc_data_t *out) {
    if (count < 1) return -1;
    int pos = 0;
    int mode = 0;
    for (int i = 0; i < 4 && pos / 8 < count; i++) {
        mode = (mode << 1) | ((data[pos / 8] >> (7 - (pos % 8))) & 1);
        pos++;
    }

    int char_count = 0;
    int cc_bits = (mode == 1) ? 8 : (mode == 2) ? 9 : 8;

    for (int i = 0; i < cc_bits && pos / 8 < count; i++) {
        char_count = (char_count << 1) | ((data[pos / 8] >> (7 - (pos % 8))) & 1);
        pos++;
    }

    out->payload_len = 0;

    if (mode == 1) {
        for (int i = 0; i < char_count && pos + 7 < count * 8; i++) {
            int c = 0;
            for (int j = 0; j < 8; j++, pos++)
                c = (c << 1) | ((data[pos / 8] >> (7 - (pos % 8))) & 1);
            out->payload[out->payload_len++] = (uint8_t)c;
        }
    } else if (mode == 2) {
        static const char alphanum[] =
            "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";
        for (int i = 0; i < char_count && out->payload_len < 4090; ) {
            int bits = (char_count - i >= 2) ? 11 : 6;
            if (pos + bits - 1 >= count * 8) break;
            int val = 0;
            for (int j = 0; j < bits; j++, pos++)
                val = (val << 1) | ((data[pos / 8] >> (7 - (pos % 8))) & 1);
            if (bits == 11) {
                out->payload[out->payload_len++] = alphanum[val / 45];
                out->payload[out->payload_len++] = alphanum[val % 45];
                i += 2;
            } else {
                out->payload[out->payload_len++] = alphanum[val];
                i++;
            }
        }
    } else {
        for (int i = 0; i < char_count && pos + 7 < count * 8; i++) {
            int c = 0;
            for (int j = 0; j < 8; j++, pos++)
                c = (c << 1) | ((data[pos / 8] >> (7 - (pos % 8))) & 1);
            out->payload[out->payload_len++] = (uint8_t)c;
        }
    }

    out->payload[out->payload_len] = '\0';
    out->dlen = out->payload_len;
    out->version = 1;
    out->ecc_level = 0;
    out->mask = 0;
    return 0;
}

int quirc_decode_data(const struct quirc *q, int index, quirc_data_t *data) {
    if (index >= q->code_count) return -1;
    memset(data, 0, sizeof(*data));

    int size = QUIRC_MODULE_SIZE(q->version);
    uint8_t *bits = calloc(size * size, 1);
    if (!bits) return -1;

    int cx = q->codes[index].cx;
    int cy = q->codes[index].cy;

    if (extract_bits(q->image, q->w, q->h, cx, cy, q->version, bits) < 0) {
        free(bits);
        return -1;
    }

    int ec_level, mask;
    if (decode_format(bits, size, &ec_level, &mask) < 0) {
        free(bits);
        return -1;
    }

    data->ecc_level = (uint8_t)ec_level;
    data->mask = (uint8_t)mask;
    data->version = q->version;

    apply_mask(bits, size, mask);

    uint8_t data_words[512];
    int data_count = 0;
    if (read_data(bits, size, q->version, data_words, &data_count) < 0) {
        free(bits);
        return -1;
    }

    free(bits);

    if (decode_payload(data_words, data_count, data) < 0) return -1;
    return 0;
}

int quirc_decode(const struct quirc *q, int index) {
    quirc_data_t data;
    return quirc_decode_data(q, index, &data);
}

const char *quirc_version(void) { return "0.1-embedded"; }
