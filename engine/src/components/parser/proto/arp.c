#include <string.h>

#include "decode.h"

static const uint8_t zero_ip[4];

parse_rc_mt proto_arp(rd_mt *rd, pkt_info_mt *info, event_mt *ev) {
    ev_arp_mt *arp = &ev->u.arp;
    uint16_t htype, ptype, opcode;
    uint8_t hlen, plen;

    if (!rd_left(rd, ARP_LEN))
        return PRS_SHORT;
    if (rd_be16(rd, &htype) || rd_be16(rd, &ptype) || rd_u8(rd, &hlen) ||
        rd_u8(rd, &plen) || rd_be16(rd, &opcode))
        return PRS_SHORT;
    info->layers |= L_ARP;

    if (htype != ARPHRD_ETH || ptype != ETYPE_IP4 || hlen != 6 || plen != 4)
        return PRS_OTHER;
    if (opcode != ARP_REQUEST && opcode != ARP_REPLY)
        return PRS_OTHER;

    memset(arp, 0, sizeof *arp);
    if (rd_bytes(rd, arp->sender_mac, 6) || rd_bytes(rd, arp->sender_ip, 4) ||
        rd_bytes(rd, arp->target_mac, 6) || rd_bytes(rd, arp->target_ip, 4))
        return PRS_SHORT;

    arp->opcode = opcode;
    arp->gratuitous = memcmp(arp->sender_ip, arp->target_ip, 4) == 0;
    arp->probe = memcmp(arp->sender_ip, zero_ip, 4) == 0;
    ev->type = EV_ARP;
    return PRS_OK;
}
