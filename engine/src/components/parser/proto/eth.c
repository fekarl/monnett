#include <string.h>

#include "decode.h"

parse_rc_mt proto_eth(rd_mt *rd, pkt_info_mt *info) {
    uint16_t type, tci;
    int tags = 0;

    if (rd_bytes(rd, info->dst_mac, 6) || rd_bytes(rd, info->src_mac, 6) ||
        rd_be16(rd, &type))
        return PRS_SHORT;
    info->layers |= L_ETH;

    while (type == ETYPE_VLAN || type == ETYPE_QINQ) {
        if (++tags > VLAN_MAX_TAGS)
            return PRS_BAD;
        if (rd_be16(rd, &tci) || rd_be16(rd, &type))
            return PRS_SHORT;
        if (tags == 1)
            info->vlan = (uint16_t)(tci & VLAN_ID_MASK);
        info->layers |= L_VLAN;
    }

    if (type < ETYPE_MIN)
        return PRS_OTHER;
    info->ethertype = type;
    return PRS_OK;
}

parse_rc_mt proto_sll2(rd_mt *rd, pkt_info_mt *info) {
    uint16_t type, hatype;
    uint8_t alen, addr[SLL2_ADDR_LEN];

    if (rd_be16(rd, &type) || rd_skip(rd, 6) || rd_be16(rd, &hatype) ||
        rd_skip(rd, 1) || rd_u8(rd, &alen) || rd_bytes(rd, addr, SLL2_ADDR_LEN))
        return PRS_SHORT;
    if (alen > SLL2_ADDR_LEN)
        return PRS_BAD;
    info->layers |= L_SLL2;

    if (hatype == ARPHRD_ETH && alen == 6)
        memcpy(info->src_mac, addr, 6);

    if (type < ETYPE_MIN)
        return PRS_OTHER;
    info->ethertype = type;
    return PRS_OK;
}
