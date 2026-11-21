#ifndef BYTES_H
#define BYTES_H

#include <stdint.h>

typedef struct rd {
    const uint8_t *data;
    uint32_t len;
    uint32_t off;
} rd_mt;

void rd_init(rd_mt *rd, const uint8_t *data, uint32_t len);
uint32_t rd_remaining(const rd_mt *rd);
int rd_left(const rd_mt *rd, uint32_t n);

int rd_u8(rd_mt *rd, uint8_t *out);
int rd_be16(rd_mt *rd, uint16_t *out);
int rd_be24(rd_mt *rd, uint32_t *out);
int rd_be32(rd_mt *rd, uint32_t *out);
int rd_bytes(rd_mt *rd, void *dst, uint32_t n);
int rd_skip(rd_mt *rd, uint32_t n);
int rd_peek_u8(const rd_mt *rd, uint32_t i, uint8_t *out);

int rd_sub(rd_mt *rd, uint32_t n, rd_mt *child);
void rd_limit(rd_mt *rd, uint32_t n);
int rd_seek(rd_mt *rd, uint32_t pos);

#endif
