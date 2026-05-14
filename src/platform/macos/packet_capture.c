/*
 * macOS Packet Capture Implementation using PF (Packet Filter) divert sockets
 *
 * macOS uses divert sockets with pf (packet filter) rules to intercept packets.
 *
 * Required pf rules (add to /etc/pf.conf or load with pfctl):
 *   pass out on en0 proto tcp from any to any port {80, 443} divert-to 127.0.0.1 port 1234
 *   pass in on en0 proto tcp from any port {80, 443} to any divert-to 127.0.0.1 port 1234
 *
 * Note: macOS Network Extension framework is the modern alternative but requires
 * code signing with Apple Developer account and entitlements.
 * This implementation uses the simpler (but less modern) divert socket approach.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <errno.h>
#include "../platform.h"
#include "../../goodbyedpi.h"

/*
 * macOS doesn't have IPPROTO_DIVERT in public headers since 10.10+
 * but the kernel still supports it. We define it manually.
 */
#ifndef IPPROTO_DIVERT
#define IPPROTO_DIVERT 254
#endif

typedef struct {
    int divert_fd;
    uint32_t flags;
    uint16_t divert_port;
    struct sockaddr_in sin;
} macos_handle_t;

typedef struct {
    uint8_t packet_buf[MAX_PACKET_SIZE];
    uint32_t packet_len;
    struct sockaddr_in from_addr;
    socklen_t from_len;
    /* Parsed headers */
    struct ip *ip_hdr;
    struct ip6_hdr *ipv6_hdr;
    struct tcphdr *tcp_hdr;
    struct udphdr *udp_hdr;
    uint8_t *data;
    uint32_t data_len;
    macos_handle_t *mh;
} macos_pkt_ctx_t;

/* Compute TCP checksum (same as Linux) */
static uint16_t tcp_checksum_v4(const struct ip *iph, const struct tcphdr *tcp, int payload_len) {
    uint32_t sum = 0;
    int tcp_len = sizeof(struct tcphdr) + payload_len;

    const uint16_t *src = (const uint16_t *)&iph->ip_src;
    const uint16_t *dst = (const uint16_t *)&iph->ip_dst;
    sum += src[0] + src[1] + dst[0] + dst[1];
    sum += htons(IPPROTO_TCP);
    sum += htons((uint16_t)tcp_len);

    const uint16_t *ptr = (const uint16_t *)tcp;
    int remaining = tcp_len;
    while (remaining > 1) { sum += *ptr++; remaining -= 2; }
    if (remaining == 1) sum += *(const uint8_t *)ptr;

    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

static uint16_t ip_checksum(const struct ip *iph) {
    uint32_t sum = 0;
    int len = iph->ip_hl * 4;
    const uint16_t *ptr = (const uint16_t *)iph;

    while (len > 1) { sum += *ptr++; len -= 2; }
    if (len == 1) sum += *(const uint8_t *)ptr;

    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

pkt_handle_t pkt_open(const char *filter_expr, uint32_t flags) {
    macos_handle_t *mh = calloc(1, sizeof(macos_handle_t));
    if (!mh) return NULL;

    mh->flags = flags;
    mh->divert_port = 1234; /* Default divert port */

    /* Parse port from filter expression if provided */
    if (filter_expr && strstr(filter_expr, "port=")) {
        sscanf(strstr(filter_expr, "port="), "port=%hu", &mh->divert_port);
    }

    /* Create divert socket */
    mh->divert_fd = socket(AF_INET, SOCK_RAW, IPPROTO_DIVERT);
    if (mh->divert_fd < 0) {
        printf("Error: Cannot create divert socket: %s\n", strerror(errno));
        printf("Note: This requires root privileges and may need SIP disabled on newer macOS.\n");
        printf("Consider using the Network Extension framework for modern macOS support.\n");
        free(mh);
        return NULL;
    }

    /* Bind to divert port */
    memset(&mh->sin, 0, sizeof(mh->sin));
    mh->sin.sin_family = AF_INET;
    mh->sin.sin_port = htons(mh->divert_port);
    mh->sin.sin_addr.s_addr = INADDR_ANY;

    if (bind(mh->divert_fd, (struct sockaddr *)&mh->sin, sizeof(mh->sin)) < 0) {
        printf("Error: Cannot bind divert socket to port %d: %s\n",
               mh->divert_port, strerror(errno));
        close(mh->divert_fd);
        free(mh);
        return NULL;
    }

    printf("Divert socket bound to port %d\n", mh->divert_port);
    return (pkt_handle_t)mh;
}

int pkt_receive(pkt_handle_t handle, packet_info_t *pkt_info) {
    macos_handle_t *mh = (macos_handle_t *)handle;
    macos_pkt_ctx_t *ctx;
    ssize_t n;

    if (!mh || !pkt_info) return 0;

    memset(pkt_info, 0, sizeof(packet_info_t));
    ctx = (macos_pkt_ctx_t *)pkt_info->platform_ctx_data;
    pkt_info->platform_ctx = ctx;
    ctx->mh = mh;

    ctx->from_len = sizeof(ctx->from_addr);
    n = recvfrom(mh->divert_fd, ctx->packet_buf, sizeof(ctx->packet_buf), 0,
                 (struct sockaddr *)&ctx->from_addr, &ctx->from_len);
    if (n <= 0) return 0;

    ctx->packet_len = (uint32_t)n;
    pkt_info->raw_packet = ctx->packet_buf;
    pkt_info->raw_packet_len = ctx->packet_len;

    /* Direction: if from_addr.sin_addr is 0, it's outbound; otherwise inbound */
    pkt_info->direction = (ctx->from_addr.sin_addr.s_addr == 0) ?
                          PACKET_DIR_OUTBOUND : PACKET_DIR_INBOUND;

    /* Parse IP header */
    uint8_t version = (ctx->packet_buf[0] >> 4) & 0x0F;

    if (version == 4) {
        ctx->ip_hdr = (struct ip *)ctx->packet_buf;
        ctx->ipv6_hdr = NULL;
        pkt_info->is_ipv6 = 0;
        pkt_info->ip_ttl = ctx->ip_hdr->ip_ttl;
        pkt_info->src_ip[0] = ctx->ip_hdr->ip_src.s_addr;
        pkt_info->dst_ip[0] = ctx->ip_hdr->ip_dst.s_addr;
        pkt_info->ip_id = ntohs(ctx->ip_hdr->ip_id);

        int ip_hdr_len = ctx->ip_hdr->ip_hl * 4;
        uint8_t *transport = ctx->packet_buf + ip_hdr_len;
        int transport_len = (int)ctx->packet_len - ip_hdr_len;

        if (ctx->ip_hdr->ip_p == IPPROTO_TCP && transport_len >= (int)sizeof(struct tcphdr)) {
            ctx->tcp_hdr = (struct tcphdr *)transport;
            ctx->udp_hdr = NULL;
            pkt_info->has_tcp = 1;
            pkt_info->src_port = ntohs(ctx->tcp_hdr->th_sport);
            pkt_info->dst_port = ntohs(ctx->tcp_hdr->th_dport);
            pkt_info->tcp_seq = ntohl(ctx->tcp_hdr->th_seq);
            pkt_info->tcp_ack = ntohl(ctx->tcp_hdr->th_ack);
            pkt_info->tcp_syn = (ctx->tcp_hdr->th_flags & TH_SYN) ? 1 : 0;
            pkt_info->tcp_ack_flag = (ctx->tcp_hdr->th_flags & TH_ACK) ? 1 : 0;
            pkt_info->tcp_rst = (ctx->tcp_hdr->th_flags & TH_RST) ? 1 : 0;
            pkt_info->tcp_window = ntohs(ctx->tcp_hdr->th_win);

            int tcp_hdr_len = ctx->tcp_hdr->th_off * 4;
            ctx->data = transport + tcp_hdr_len;
            ctx->data_len = (uint32_t)(transport_len - tcp_hdr_len);
            if (ctx->data_len > 0) {
                pkt_info->payload = ctx->data;
                pkt_info->payload_len = ctx->data_len;
            }
        } else if (ctx->ip_hdr->ip_p == IPPROTO_UDP && transport_len >= (int)sizeof(struct udphdr)) {
            ctx->udp_hdr = (struct udphdr *)transport;
            ctx->tcp_hdr = NULL;
            pkt_info->has_udp = 1;
            pkt_info->src_port = ntohs(ctx->udp_hdr->uh_sport);
            pkt_info->dst_port = ntohs(ctx->udp_hdr->uh_dport);

            ctx->data = transport + sizeof(struct udphdr);
            ctx->data_len = (uint32_t)(transport_len - (int)sizeof(struct udphdr));
            if (ctx->data_len > 0) {
                pkt_info->payload = ctx->data;
                pkt_info->payload_len = ctx->data_len;
            }
        }
    } else if (version == 6) {
        ctx->ipv6_hdr = (struct ip6_hdr *)ctx->packet_buf;
        ctx->ip_hdr = NULL;
        pkt_info->is_ipv6 = 1;
        pkt_info->ip_ttl = ctx->ipv6_hdr->ip6_hlim;
        memcpy(pkt_info->src_ip, &ctx->ipv6_hdr->ip6_src, 16);
        memcpy(pkt_info->dst_ip, &ctx->ipv6_hdr->ip6_dst, 16);
        pkt_info->ipv6_flow_label = ntohl(ctx->ipv6_hdr->ip6_flow) & 0xFFFFF;

        uint8_t *transport = ctx->packet_buf + 40;
        int transport_len = (int)ctx->packet_len - 40;
        uint8_t next_hdr = ctx->ipv6_hdr->ip6_nxt;

        if (next_hdr == IPPROTO_TCP && transport_len >= (int)sizeof(struct tcphdr)) {
            ctx->tcp_hdr = (struct tcphdr *)transport;
            pkt_info->has_tcp = 1;
            pkt_info->src_port = ntohs(ctx->tcp_hdr->th_sport);
            pkt_info->dst_port = ntohs(ctx->tcp_hdr->th_dport);
            pkt_info->tcp_seq = ntohl(ctx->tcp_hdr->th_seq);
            pkt_info->tcp_ack = ntohl(ctx->tcp_hdr->th_ack);
            pkt_info->tcp_syn = (ctx->tcp_hdr->th_flags & TH_SYN) ? 1 : 0;
            pkt_info->tcp_ack_flag = (ctx->tcp_hdr->th_flags & TH_ACK) ? 1 : 0;
            pkt_info->tcp_rst = (ctx->tcp_hdr->th_flags & TH_RST) ? 1 : 0;
            pkt_info->tcp_window = ntohs(ctx->tcp_hdr->th_win);

            int tcp_hdr_len = ctx->tcp_hdr->th_off * 4;
            ctx->data = transport + tcp_hdr_len;
            ctx->data_len = (uint32_t)(transport_len - tcp_hdr_len);
            if (ctx->data_len > 0) {
                pkt_info->payload = ctx->data;
                pkt_info->payload_len = ctx->data_len;
            }
        } else if (next_hdr == IPPROTO_UDP && transport_len >= (int)sizeof(struct udphdr)) {
            ctx->udp_hdr = (struct udphdr *)transport;
            pkt_info->has_udp = 1;
            pkt_info->src_port = ntohs(ctx->udp_hdr->uh_sport);
            pkt_info->dst_port = ntohs(ctx->udp_hdr->uh_dport);

            ctx->data = transport + sizeof(struct udphdr);
            ctx->data_len = (uint32_t)(transport_len - (int)sizeof(struct udphdr));
            if (ctx->data_len > 0) {
                pkt_info->payload = ctx->data;
                pkt_info->payload_len = ctx->data_len;
            }
        }
    }

    return 1;
}

int pkt_send(pkt_handle_t handle, packet_info_t *pkt_info) {
    macos_handle_t *mh = (macos_handle_t *)handle;
    macos_pkt_ctx_t *ctx;

    if (!mh || !pkt_info) return 0;
    ctx = (macos_pkt_ctx_t *)pkt_info->platform_ctx_data;

    /* Reinject by writing back to the divert socket */
    ssize_t n = sendto(mh->divert_fd, ctx->packet_buf, ctx->packet_len, 0,
                       (struct sockaddr *)&ctx->from_addr, ctx->from_len);
    return (n > 0) ? 1 : 0;
}

int pkt_send_raw(pkt_handle_t handle, packet_info_t *pkt_info,
                 const uint8_t *raw_data, uint32_t data_len) {
    macos_handle_t *mh = (macos_handle_t *)handle;
    macos_pkt_ctx_t *ctx;

    if (!mh || !pkt_info) return 0;
    ctx = (macos_pkt_ctx_t *)pkt_info->platform_ctx_data;

    /* Send via divert socket */
    ssize_t n = sendto(mh->divert_fd, raw_data, data_len, 0,
                       (struct sockaddr *)&ctx->from_addr, ctx->from_len);
    return (n > 0) ? 1 : 0;
}

void pkt_recalc_checksums(packet_info_t *pkt_info) {
    macos_pkt_ctx_t *ctx;
    if (!pkt_info) return;
    ctx = (macos_pkt_ctx_t *)pkt_info->platform_ctx_data;

    if (ctx->ip_hdr) {
        ctx->ip_hdr->ip_sum = 0;
        ctx->ip_hdr->ip_sum = ip_checksum(ctx->ip_hdr);

        if (ctx->tcp_hdr) {
            ctx->tcp_hdr->th_sum = 0;
            ctx->tcp_hdr->th_sum = tcp_checksum_v4(ctx->ip_hdr, ctx->tcp_hdr,
                                                    (int)ctx->data_len);
        }
    }
    /* TODO: IPv6 TCP checksum */
}

void pkt_set_tcp_window(packet_info_t *pkt_info, uint16_t new_window) {
    macos_pkt_ctx_t *ctx;
    if (!pkt_info) return;
    ctx = (macos_pkt_ctx_t *)pkt_info->platform_ctx_data;
    if (ctx->tcp_hdr) {
        ctx->tcp_hdr->th_win = htons(new_window);
    }
}

void pkt_set_ttl(packet_info_t *pkt_info, uint8_t ttl) {
    macos_pkt_ctx_t *ctx;
    if (!pkt_info) return;
    ctx = (macos_pkt_ctx_t *)pkt_info->platform_ctx_data;
    if (ctx->ip_hdr) {
        ctx->ip_hdr->ip_ttl = ttl;
    } else if (ctx->ipv6_hdr) {
        ctx->ipv6_hdr->ip6_hlim = ttl;
    }
    pkt_info->ip_ttl = ttl;
}

void pkt_set_tcp_seq(packet_info_t *pkt_info, uint32_t seq) {
    macos_pkt_ctx_t *ctx;
    if (!pkt_info) return;
    ctx = (macos_pkt_ctx_t *)pkt_info->platform_ctx_data;
    if (ctx->tcp_hdr) {
        ctx->tcp_hdr->th_seq = htonl(seq);
        pkt_info->tcp_seq = seq;
    }
}

void pkt_set_tcp_ack(packet_info_t *pkt_info, uint32_t ack) {
    macos_pkt_ctx_t *ctx;
    if (!pkt_info) return;
    ctx = (macos_pkt_ctx_t *)pkt_info->platform_ctx_data;
    if (ctx->tcp_hdr) {
        ctx->tcp_hdr->th_ack = htonl(ack);
        pkt_info->tcp_ack = ack;
    }
}

void pkt_set_payload(packet_info_t *pkt_info, const uint8_t *new_payload, uint32_t new_len) {
    macos_pkt_ctx_t *ctx;
    int32_t len_diff;

    if (!pkt_info) return;
    ctx = (macos_pkt_ctx_t *)pkt_info->platform_ctx_data;
    if (!ctx->data) return;

    len_diff = (int32_t)new_len - (int32_t)ctx->data_len;
    if (ctx->packet_len + len_diff > MAX_PACKET_SIZE) return;

    memcpy(ctx->data, new_payload, new_len);
    ctx->packet_len = (uint32_t)((int32_t)ctx->packet_len + len_diff);
    ctx->data_len = new_len;

    if (ctx->ip_hdr) {
        ctx->ip_hdr->ip_len = htons((uint16_t)ctx->packet_len);
    } else if (ctx->ipv6_hdr) {
        ctx->ipv6_hdr->ip6_plen = htons((uint16_t)(ctx->packet_len - 40));
    }

    pkt_info->payload = ctx->data;
    pkt_info->payload_len = new_len;
    pkt_info->raw_packet_len = ctx->packet_len;
}

void pkt_damage_tcp_checksum(packet_info_t *pkt_info) {
    macos_pkt_ctx_t *ctx;
    if (!pkt_info) return;
    ctx = (macos_pkt_ctx_t *)pkt_info->platform_ctx_data;
    if (ctx->tcp_hdr) {
        ctx->tcp_hdr->th_sum = htons(ntohs(ctx->tcp_hdr->th_sum) - 1);
    }
}

void pkt_close(pkt_handle_t handle) {
    macos_handle_t *mh = (macos_handle_t *)handle;
    if (!mh) return;
    if (mh->divert_fd >= 0) close(mh->divert_fd);
    free(mh);
}
