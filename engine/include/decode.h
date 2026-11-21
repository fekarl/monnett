#ifndef DECODE_H
#define DECODE_H

#include "bytes.h"
#include "proto.h"

#define ETYPE_IP4 0x0800
#define ETYPE_ARP 0x0806
#define ETYPE_VLAN 0x8100
#define ETYPE_IP6 0x86DD
#define ETYPE_QINQ 0x88A8
#define ETYPE_MIN 0x0600

#define IP4_HDR_MIN 20
#define IP4_MF 0x2000u
#define IP4_OFF_MASK 0x1FFFu

#define VLAN_MAX_TAGS 2
#define VLAN_ID_MASK 0x0FFFu

#define ARPHRD_ETH 1
#define ARP_LEN 28
#define ARP_REQUEST 1
#define ARP_REPLY 2
#define SLL2_ADDR_LEN 8

parse_rc_mt proto_eth(rd_mt *rd, pkt_info_mt *info);
parse_rc_mt proto_sll2(rd_mt *rd, pkt_info_mt *info);
parse_rc_mt proto_arp(rd_mt *rd, pkt_info_mt *info, event_mt *ev);
parse_rc_mt proto_ipv4(rd_mt *rd, pkt_info_mt *info);

#endif
