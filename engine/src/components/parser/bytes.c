#include <string.h>

#include "bytes.h"

void rd_init(rd_mt *rd, const uint8_t *data, uint32_t len)
{
    rd->data = data;
    rd->len = len;
    rd->off = 0;
}

uint32_t rd_remaining(const rd_mt *rd)
{
    return rd->len - rd->off;
}

int rd_left(const rd_mt *rd, uint32_t n)
{
    return rd->len - rd->off >= n;
}

int rd_u8(rd_mt *rd, uint8_t *out)
{
    if (!rd_left(rd, 1))
        return -1;
    *out = rd->data[rd->off];
    rd->off += 1;
    return 0;
}

int rd_be16(rd_mt *rd, uint16_t *out)
{
    if (!rd_left(rd, 2))
        return -1;
    const uint8_t *p = rd->data + rd->off;
    *out = (uint16_t)((uint16_t)p[0] << 8 | p[1]);
    rd->off += 2;
    return 0;
}

int rd_be24(rd_mt *rd, uint32_t *out)
{
    if (!rd_left(rd, 3))
        return -1;
    const uint8_t *p = rd->data + rd->off;
    *out = (uint32_t)p[0] << 16 | (uint32_t)p[1] << 8 | p[2];
    rd->off += 3;
    return 0;
}

int rd_be32(rd_mt *rd, uint32_t *out)
{
    if (!rd_left(rd, 4))
        return -1;
    const uint8_t *p = rd->data + rd->off;
    *out = (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
           (uint32_t)p[2] << 8 | p[3];
    rd->off += 4;
    return 0;
}

int rd_bytes(rd_mt *rd, void *dst, uint32_t n)
{
    if (!rd_left(rd, n))
        return -1;
    if (n > 0)
        memcpy(dst, rd->data + rd->off, n);
    rd->off += n;
    return 0;
}

int rd_skip(rd_mt *rd, uint32_t n)
{
    if (!rd_left(rd, n))
        return -1;
    rd->off += n;
    return 0;
}

int rd_peek_u8(const rd_mt *rd, uint32_t i, uint8_t *out)
{
    if (i >= rd->len - rd->off)
        return -1;
    *out = rd->data[rd->off + i];
    return 0;
}

int rd_sub(rd_mt *rd, uint32_t n, rd_mt *child)
{
    if (!rd_left(rd, n))
        return -1;
    child->data = rd->data + rd->off;
    child->len = n;
    child->off = 0;
    rd->off += n;
    return 0;
}

void rd_limit(rd_mt *rd, uint32_t n)
{
    if (rd_left(rd, n))
        rd->len = rd->off + n;
}

int rd_seek(rd_mt *rd, uint32_t pos)
{
    if (pos > rd->len)
        return -1;
    rd->off = pos;
    return 0;
}
