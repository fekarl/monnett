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

static int ip6_is_ext(uint8_t nh) {
    return nh == NH_HOPOPT || nh == NH_ROUTING || nh == NH_DSTOPTS ||
           nh == NH_AH || nh == NH_FRAGMENT;
}

static parse_rc_mt ip6_skip_ext(rd_mt *rd, uint8_t nh, uint8_t *next) {
    uint8_t len;
    uint32_t size;

    if (rd_u8(rd, next) || rd_u8(rd, &len))
        return PRS_SHORT;
    if (nh == NH_AH)
        size = ((uint32_t)len + 2u) * 4u;
    else
        size = ((uint32_t)len + 1u) * 8u;
    if (rd_skip(rd, size - 2u))
        return PRS_SHORT;
    return PRS_OK;
}

static parse_rc_mt ip6_fragment(rd_mt *rd, pkt_info_mt *info, uint8_t *next) {
    uint16_t offm;

    if (rd_u8(rd, next) || rd_skip(rd, 1) || rd_be16(rd, &offm) ||
        rd_skip(rd, 4))
        return PRS_SHORT;
    if (offm >> 3)
        info->is_frag = FRAG_LATER;
    else if (offm & IP6_FRAG_M)
        info->is_frag = FRAG_FIRST;
    return PRS_OK;
}

parse_rc_mt proto_ipv6(rd_mt *rd, pkt_info_mt *info) {
    uint32_t vtcfl, wire_left;
    uint16_t payload_len;
    uint8_t nh, hop, next;
    parse_rc_mt rc;

    if (!rd_left(rd, IP6_HDR_LEN))
        return PRS_SHORT;
    wire_left = info->wirelen > rd->off ? info->wirelen - rd->off : 0;

    if (rd_be32(rd, &vtcfl) || rd_be16(rd, &payload_len) || rd_u8(rd, &nh) ||
        rd_u8(rd, &hop) || rd_bytes(rd, info->src_ip, 16) ||
        rd_bytes(rd, info->dst_ip, 16))
        return PRS_SHORT;
    if (vtcfl >> 28 != 6)
        return PRS_BAD;
    if (payload_len == 0 || IP6_HDR_LEN + (uint32_t)payload_len > wire_left)
        return PRS_BAD;
    rd_limit(rd, payload_len);

    info->layers |= L_IP6;
    info->family = 6;
    info->ttl = hop;
    info->ip_len = IP6_HDR_LEN + (uint32_t)payload_len;

    for (int n = 0; ip6_is_ext(nh); n++) {
        if (n == IP6_MAX_EXT)
            return PRS_BAD;
        if (nh == NH_FRAGMENT)
            rc = ip6_fragment(rd, info, &next);
        else
            rc = ip6_skip_ext(rd, nh, &next);
        if (rc != PRS_OK)
            return rc;
        nh = next;
        if (info->is_frag == FRAG_LATER)
            break;
    }

    info->ip_proto = nh;
    return PRS_OK;
}
