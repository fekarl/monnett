#include "decode.h"

parse_rc_mt proto_ipv4(rd_mt *rd, pkt_info_mt *info) {
    uint8_t b0, ttl, proto;
    uint16_t total_len, frag;
    uint32_t hlen, wire_left;

    if (!rd_left(rd, IP4_HDR_MIN))
        return PRS_SHORT;
    wire_left = info->wirelen > rd->off ? info->wirelen - rd->off : 0;

    if (rd_u8(rd, &b0) || rd_skip(rd, 1) || rd_be16(rd, &total_len))
        return PRS_SHORT;
    if (b0 >> 4 != 4)
        return PRS_BAD;
    hlen = (uint32_t)(b0 & 0x0Fu) * 4u;
    if (hlen < IP4_HDR_MIN || total_len < hlen || total_len > wire_left)
        return PRS_BAD;
    rd_limit(rd, (uint32_t)total_len - 4u);

    if (rd_skip(rd, 2) || rd_be16(rd, &frag) || rd_u8(rd, &ttl) ||
        rd_u8(rd, &proto) || rd_skip(rd, 2) || rd_bytes(rd, info->src_ip, 4) ||
        rd_bytes(rd, info->dst_ip, 4))
        return PRS_SHORT;

    info->layers |= L_IP4;
    info->family = 4;
    info->ip_len = total_len;
    info->ttl = ttl;
    info->ip_proto = proto;
    if (frag & IP4_OFF_MASK)
        info->is_frag = FRAG_LATER;
    else if (frag & IP4_MF)
        info->is_frag = FRAG_FIRST;

    if (rd_skip(rd, hlen - IP4_HDR_MIN))
        return PRS_SHORT;
    return PRS_OK;
}
