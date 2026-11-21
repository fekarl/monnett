#ifndef PROTO_H
#define PROTO_H

#include <stdint.h>

typedef enum parse_rc {
    PRS_OK = 0,
    PRS_SHORT = 1,
    PRS_BAD = 2,
    PRS_OTHER = 3,
} parse_rc_mt;

#define L_ETH (1u << 0)
#define L_SLL2 (1u << 1)
#define L_VLAN (1u << 2)
#define L_ARP (1u << 3)
#define L_IP4 (1u << 4)
#define L_IP6 (1u << 5)
#define L_ICMP (1u << 6)
#define L_ICMP6 (1u << 7)
#define L_TCP (1u << 8)
#define L_UDP (1u << 9)
#define L_APP (1u << 10)

#define FRAG_NONE 0
#define FRAG_FIRST 1
#define FRAG_LATER 2

#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20
#define TCP_ECE 0x40
#define TCP_CWR 0x80

typedef enum app {
    APP_NONE = 0,
    APP_DNS = 1,
    APP_DHCP = 2,
    APP_DHCP6 = 3,
    APP_TLS = 4,
    APP_ND = 5,
} app_mt;

typedef enum proto {
    PROTO_ARP = 0,
    PROTO_IP4 = 1,
    PROTO_IP6 = 2,
    PROTO_ICMP = 3,
    PROTO_ICMP6 = 4,
    PROTO_TCP = 5,
    PROTO_UDP = 6,
    PROTO_DNS = 7,
    PROTO_DHCP = 8,
    PROTO_DHCP6 = 9,
    PROTO_TLS = 10,
    PROTO_ND = 11,
    PROTO_COUNT = 12,
} proto_mt;

typedef struct pkt_info {
    uint64_t ts_ns, seq;
    uint32_t wirelen, caplen;
    uint32_t layers;

    uint8_t src_mac[6], dst_mac[6];
    uint16_t vlan;
    uint16_t ethertype;

    uint8_t family;
    uint8_t src_ip[16], dst_ip[16];
    uint8_t ip_proto;
    uint8_t ttl;
    uint8_t is_frag;
    uint32_t ip_len;

    uint16_t src_port, dst_port;
    uint8_t tcp_flags;
    uint8_t icmp_type, icmp_code;
    uint16_t payload_off, payload_len;

    uint8_t app;
    uint8_t truncated;
} pkt_info_mt;

typedef struct ev_arp {
    uint16_t opcode;
    uint8_t sender_mac[6], sender_ip[4];
    uint8_t target_mac[6], target_ip[4];
    uint8_t gratuitous;
    uint8_t probe;
} ev_arp_mt;

#define ND_RS 133
#define ND_RA 134
#define ND_NS 135
#define ND_NA 136

#define ND_FLAG_R 0x80
#define ND_FLAG_S 0x40
#define ND_FLAG_O 0x20

typedef struct ev_nd {
    uint8_t type;
    uint8_t flags;
    uint8_t target[16];
    uint8_t lladdr[6];
    uint8_t has_lladdr;
} ev_nd_mt;

#define DNS_NAME_MAX 256
#define DNS_ADDRS_MAX 8

typedef struct dns_addr {
    uint8_t family;
    uint8_t addr[16];
    uint32_t ttl;
} dns_addr_mt;

typedef struct ev_dns {
    uint16_t id;
    uint8_t qr, opcode, rcode;
    char qname[DNS_NAME_MAX];
    uint16_t qtype, qclass;
    uint16_t ancount;
    uint8_t naddrs;
    dns_addr_mt addrs[DNS_ADDRS_MAX];
    uint8_t trunc;
} ev_dns_mt;

#define DHCP_HOST_MAX 65
#define DHCP_DUID_MAX 32

typedef struct ev_dhcp {
    uint8_t version;
    uint8_t msg_type;
    uint32_t xid;
    uint8_t client_mac[6];
    uint8_t client_duid[DHCP_DUID_MAX];
    uint8_t client_duid_len;
    uint8_t server_id[DHCP_DUID_MAX];
    uint8_t server_id_len;
    uint8_t yiaddr[16];
    uint8_t requested_ip[16];
    char hostname[DHCP_HOST_MAX];
    uint8_t trunc;
} ev_dhcp_mt;

#define TLS_SNI_MAX 256
#define TLS_CIPHERS_MAX 64
#define TLS_EXTS_MAX 32
#define TLS_GROUPS_MAX 16
#define TLS_POINTS_MAX 8
#define TLS_SIGALGS_MAX 32
#define TLS_VERSIONS_MAX 8
#define TLS_ALPN_MAX 2
#define TLS_ALPN_LEN 33

typedef struct ev_tls {
    uint16_t record_version;
    uint16_t hello_version;
    char sni[TLS_SNI_MAX];
    uint16_t ciphers[TLS_CIPHERS_MAX];
    uint16_t exts[TLS_EXTS_MAX];
    uint16_t groups[TLS_GROUPS_MAX];
    uint16_t sig_algs[TLS_SIGALGS_MAX];
    uint16_t versions[TLS_VERSIONS_MAX];
    uint8_t points[TLS_POINTS_MAX];
    char alpn[TLS_ALPN_MAX][TLS_ALPN_LEN];
    uint8_t n_ciphers, n_exts, n_groups, n_sig_algs, n_versions, n_points,
        n_alpn;
    uint8_t trunc;
} ev_tls_mt;

typedef enum ev_type {
    EV_NONE = 0,
    EV_ARP = 1,
    EV_ND = 2,
    EV_DNS = 3,
    EV_DHCP = 4,
    EV_TLS = 5,
} ev_type_mt;

typedef struct event {
    ev_type_mt type;
    uint64_t ts_ns, seq;
    union {
        ev_arp_mt arp;
        ev_nd_mt nd;
        ev_dns_mt dns;
        ev_dhcp_mt dhcp;
        ev_tls_mt tls;
    } u;
} event_mt;

#endif
