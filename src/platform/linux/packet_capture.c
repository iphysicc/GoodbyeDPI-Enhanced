/*
 * Linux Packet Capture Implementation using NFQUEUE (netfilter_queue)
 *
 * Requires: libnetfilter_queue-dev, iptables rules to redirect traffic to NFQUEUE
 *
 * Example iptables rules:
 *   iptables -A OUTPUT -p tcp --dport 80 -j NFQUEUE --queue-num 0
 *   iptables -A OUTPUT -p tcp --dport 443 -j NFQUEUE --queue-num 0
 *   iptables -A INPUT -p tcp --sport 80 -j NFQUEUE --queue-num 0
 *   iptables -A INPUT -p tcp --sport 443 -j NFQUEUE --queue-num 0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include "../platform.h"
#include "../../goodbyedpi.h"

typedef struct {
    struct nfq_handle *nfq_h;
    struct nfq_q_handle *nfq_qh;
    int fd;
    uint32_t flags;
    uint16_t queue_num;
    /* Callback state for current packet */
    packet_info_t *current_pkt;
    int packet_ready;
} linux_handle_t;

typedef struct {
    /* Mutable copy of the packet */
    uint8_t packet_buf[MAX_PACKET_SIZE];
    uint32_t packet_len;
    uint32_t packet_id;
    /* Parsed header offsets */
    struct iphdr *ip_hdr;
    struct ip6_hdr *ipv6_hdr;
    struct tcphdr *tcp_hdr;
    struct udphdr *udp_hdr;
    uint8_t *data;
    uint32_t data_len;
    /* Reference to the handle for verdict */
    linux_handle_t *lh;
    int verdict_set;
} linux_pkt_ctx_t;

/* Compute TCP checksum */
static uint16_t tcp_checksum(const void *ip_hdr, const struct tcphdr *tcp,
                             int payload_len, int is_ipv6) {
    uint32_t sum = 0;
    int tcp_len = sizeof(struct tcphdr) + payload_len;

    if (!is_ipv6) {
        const struct iphdr *iph = (const struct iphdr *)ip_hdr;
        const uint16_t *src = (const uint16_t *)&iph->saddr;
        const uint16_t *dst = (const uint16_t *)&iph->daddr;
        sum += src[0] + src[1] + dst[0] + dst[1];
        sum += htons(IPPROTO_TCP);
        sum += htons((uint16_t)tcp_len);
    } else {
        const struct ip6_hdr *ip6h = (const struct ip6_hdr *)ip_hdr;
        const uint16_t *src = (const uint16_t *)&ip6h->ip6_src;
        const uint16_t *dst = (const uint16_t *)&ip6h->ip6_dst;
        for (int i = 0; i < 8; i++) { sum += src[i]; sum += dst[i]; }
        sum += htons(IPPROTO_TCP);
        sum += htons((uint16_t)tcp_len);
    }

    const uint16_t *ptr = (const uint16_t *)tcp;
    int remaining = tcp_len;
    while (remaining > 1) { sum += *ptr++; remaining -= 2; }
    if (remaining == 1) sum += *(const uint8_t *)ptr;

    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

/* Compute IP header checksum */
static uint16_t ip_checksum(const struct iphdr *iph) {
    uint32_t sum = 0;
    int len = iph->ihl * 4;
    const uint16_t *ptr = (const uint16_t *)iph;

    while (len > 1) { sum += *ptr++; len -= 2; }
    if (len == 1) sum += *(const uint8_t *)ptr;

    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

static int nfq_callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                         struct nfq_data *nfa, void *data) {
    (void)qh;
    (void)nfmsg;

    linux_handle_t *lh = (linux_handle_t *)data;
    struct nfqnl_msg_packet_hdr *ph;
    unsigned char *payload_data;
    int payload_len;

    ph = nfq_get_msg_packet_hdr(nfa);
    if (!ph) return -1;

    payload_len = nfq_get_payload(nfa, &payload_data);
    if (payload_len < 0) return -1;

    if (!lh->current_pkt) return -1;

    packet_info_t *pkt_info = lh->current_pkt;
    linux_pkt_ctx_t *ctx = (linux_pkt_ctx_t *)pkt_info->platform_ctx_data;

    memset(pkt_info, 0, sizeof(packet_info_t));
    ctx = (linux_pkt_ctx_t *)pkt_info->platform_ctx_data;
    pkt_info->platform_ctx = ctx;

    /* Copy packet data */
    ctx->packet_len = (uint32_t)payload_len;
    if (ctx->packet_len > MAX_PACKET_SIZE) ctx->packet_len = MAX_PACKET_SIZE;
    memcpy(ctx->packet_buf, payload_data, ctx->packet_len);
    ctx->packet_id = ntohl(ph->packet_id);
    ctx->lh = lh;
    ctx->verdict_set = 0;

    pkt_info->raw_packet = ctx->packet_buf;
    pkt_info->raw_packet_len = ctx->packet_len;

    /* Determine direction from hook (INPUT=inbound, OUTPUT=outbound) */
    uint32_t hook = nfq_get_nfmark(nfa);
    /* Use the packet hook number for direction detection */
    /* NF_IP_LOCAL_IN = 1, NF_IP_LOCAL_OUT = 3 */
    uint32_t indev = nfq_get_indev(nfa);
    pkt_info->direction = (indev != 0) ? PACKET_DIR_INBOUND : PACKET_DIR_OUTBOUND;

    /* Parse IP header */
    uint8_t version = (ctx->packet_buf[0] >> 4) & 0x0F;

    if (version == 4) {
        ctx->ip_hdr = (struct iphdr *)ctx->packet_buf;
        ctx->ipv6_hdr = NULL;
        pkt_info->is_ipv6 = 0;
        pkt_info->ip_ttl = ctx->ip_hdr->ttl;
        pkt_info->src_ip[0] = ctx->ip_hdr->saddr;
        pkt_info->dst_ip[0] = ctx->ip_hdr->daddr;
        pkt_info->ip_id = ntohs(ctx->ip_hdr->id);

        int ip_hdr_len = ctx->ip_hdr->ihl * 4;
        uint8_t *transport = ctx->packet_buf + ip_hdr_len;
        int transport_len = (int)ctx->packet_len - ip_hdr_len;

        if (ctx->ip_hdr->protocol == IPPROTO_TCP && transport_len >= (int)sizeof(struct tcphdr)) {
            ctx->tcp_hdr = (struct tcphdr *)transport;
            ctx->udp_hdr = NULL;
            pkt_info->has_tcp = 1;
            pkt_info->src_port = ntohs(ctx->tcp_hdr->source);
            pkt_info->dst_port = ntohs(ctx->tcp_hdr->dest);
            pkt_info->tcp_seq = ntohl(ctx->tcp_hdr->seq);
            pkt_info->tcp_ack = ntohl(ctx->tcp_hdr->ack_seq);
            pkt_info->tcp_syn = ctx->tcp_hdr->syn;
            pkt_info->tcp_ack_flag = ctx->tcp_hdr->ack;
            pkt_info->tcp_rst = ctx->tcp_hdr->rst;
            pkt_info->tcp_window = ntohs(ctx->tcp_hdr->window);

            int tcp_hdr_len = ctx->tcp_hdr->doff * 4;
            ctx->data = transport + tcp_hdr_len;
            ctx->data_len = (uint32_t)(transport_len - tcp_hdr_len);
            if (ctx->data_len > 0) {
                pkt_info->payload = ctx->data;
                pkt_info->payload_len = ctx->data_len;
            }
        } else if (ctx->ip_hdr->protocol == IPPROTO_UDP && transport_len >= (int)sizeof(struct udphdr)) {
            ctx->udp_hdr = (struct udphdr *)transport;
            ctx->tcp_hdr = NULL;
            pkt_info->has_udp = 1;
            pkt_info->src_port = ntohs(ctx->udp_hdr->source);
            pkt_info->dst_port = ntohs(ctx->udp_hdr->dest);

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

        /* Simplified: assume no extension headers */
        uint8_t *transport = ctx->packet_buf + 40;
        int transport_len = (int)ctx->packet_len - 40;
        uint8_t next_hdr = ctx->ipv6_hdr->ip6_nxt;

        if (next_hdr == IPPROTO_TCP && transport_len >= (int)sizeof(struct tcphdr)) {
            ctx->tcp_hdr = (struct tcphdr *)transport;
            ctx->udp_hdr = NULL;
            pkt_info->has_tcp = 1;
            pkt_info->src_port = ntohs(ctx->tcp_hdr->source);
            pkt_info->dst_port = ntohs(ctx->tcp_hdr->dest);
            pkt_info->tcp_seq = ntohl(ctx->tcp_hdr->seq);
            pkt_info->tcp_ack = ntohl(ctx->tcp_hdr->ack_seq);
            pkt_info->tcp_syn = ctx->tcp_hdr->syn;
            pkt_info->tcp_ack_flag = ctx->tcp_hdr->ack;
            pkt_info->tcp_rst = ctx->tcp_hdr->rst;
            pkt_info->tcp_window = ntohs(ctx->tcp_hdr->window);

            int tcp_hdr_len = ctx->tcp_hdr->doff * 4;
            ctx->data = transport + tcp_hdr_len;
            ctx->data_len = (uint32_t)(transport_len - tcp_hdr_len);
            if (ctx->data_len > 0) {
                pkt_info->payload = ctx->data;
                pkt_info->payload_len = ctx->data_len;
            }
        } else if (next_hdr == IPPROTO_UDP && transport_len >= (int)sizeof(struct udphdr)) {
            ctx->udp_hdr = (struct udphdr *)transport;
            ctx->tcp_hdr = NULL;
            pkt_info->has_udp = 1;
            pkt_info->src_port = ntohs(ctx->udp_hdr->source);
            pkt_info->dst_port = ntohs(ctx->udp_hdr->dest);

            ctx->data = transport + sizeof(struct udphdr);
            ctx->data_len = (uint32_t)(transport_len - (int)sizeof(struct udphdr));
            if (ctx->data_len > 0) {
                pkt_info->payload = ctx->data;
                pkt_info->payload_len = ctx->data_len;
            }
        }
    }

    lh->packet_ready = 1;
    return 0;
}

pkt_handle_t pkt_open(const char *filter_expr, uint32_t flags) {
    linux_handle_t *lh = calloc(1, sizeof(linux_handle_t));
    if (!lh) return NULL;

    lh->flags = flags;

    /* Parse queue number from filter expression (format: "queue_num=N" or just use 0) */
    lh->queue_num = 0;
    if (filter_expr && strstr(filter_expr, "queue_num=")) {
        sscanf(strstr(filter_expr, "queue_num="), "queue_num=%hu", &lh->queue_num);
    }

    lh->nfq_h = nfq_open();
    if (!lh->nfq_h) {
        printf("Error: nfq_open() failed\n");
        free(lh);
        return NULL;
    }

    /* Unbind existing handler (if any) */
    nfq_unbind_pf(lh->nfq_h, AF_INET);
    nfq_unbind_pf(lh->nfq_h, AF_INET6);

    /* Bind to AF_INET and AF_INET6 */
    if (nfq_bind_pf(lh->nfq_h, AF_INET) < 0) {
        printf("Error: nfq_bind_pf(AF_INET) failed\n");
        nfq_close(lh->nfq_h);
        free(lh);
        return NULL;
    }
    nfq_bind_pf(lh->nfq_h, AF_INET6);

    /* Create queue */
    lh->nfq_qh = nfq_create_queue(lh->nfq_h, lh->queue_num, &nfq_callback, lh);
    if (!lh->nfq_qh) {
        printf("Error: nfq_create_queue() failed for queue %d\n", lh->queue_num);
        nfq_close(lh->nfq_h);
        free(lh);
        return NULL;
    }

    /* Set copy mode to copy entire packet */
    if (nfq_set_mode(lh->nfq_qh, NFQNL_COPY_PACKET, MAX_PACKET_SIZE) < 0) {
        printf("Error: nfq_set_mode() failed\n");
        nfq_destroy_queue(lh->nfq_qh);
        nfq_close(lh->nfq_h);
        free(lh);
        return NULL;
    }

    lh->fd = nfq_fd(lh->nfq_h);
    return (pkt_handle_t)lh;
}

int pkt_receive(pkt_handle_t handle, packet_info_t *pkt_info) {
    linux_handle_t *lh = (linux_handle_t *)handle;
    char buf[MAX_PACKET_SIZE + 256];
    int rv;

    if (!lh || !pkt_info) return 0;

    lh->current_pkt = pkt_info;
    lh->packet_ready = 0;

    rv = recv(lh->fd, buf, sizeof(buf), 0);
    if (rv < 0) return 0;

    nfq_handle_packet(lh->nfq_h, buf, rv);

    return lh->packet_ready;
}

int pkt_send(pkt_handle_t handle, packet_info_t *pkt_info) {
    linux_pkt_ctx_t *ctx;
    if (!handle || !pkt_info) return 0;
    ctx = (linux_pkt_ctx_t *)pkt_info->platform_ctx_data;

    if (!ctx->verdict_set) {
        ctx->verdict_set = 1;
        nfq_set_verdict(ctx->lh->nfq_qh, ctx->packet_id, NF_ACCEPT,
                        ctx->packet_len, ctx->packet_buf);
    }
    return 1;
}

int pkt_send_raw(pkt_handle_t handle, packet_info_t *pkt_info,
                 const uint8_t *raw_data, uint32_t data_len) {
    linux_pkt_ctx_t *ctx;
    int sock;
    struct sockaddr_in dst4;
    struct sockaddr_in6 dst6;

    if (!handle || !pkt_info) return 0;
    ctx = (linux_pkt_ctx_t *)pkt_info->platform_ctx_data;

    /* Use raw socket to inject the packet */
    uint8_t version = (raw_data[0] >> 4) & 0x0F;

    if (version == 4) {
        sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (sock < 0) return 0;

        int one = 1;
        setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

        const struct iphdr *iph = (const struct iphdr *)raw_data;
        memset(&dst4, 0, sizeof(dst4));
        dst4.sin_family = AF_INET;
        dst4.sin_addr.s_addr = iph->daddr;

        sendto(sock, raw_data, data_len, 0,
               (struct sockaddr *)&dst4, sizeof(dst4));
        close(sock);
    } else if (version == 6) {
        sock = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
        if (sock < 0) return 0;

        int one = 1;
        setsockopt(sock, IPPROTO_IPV6, IPV6_HDRINCL, &one, sizeof(one));

        const struct ip6_hdr *ip6h = (const struct ip6_hdr *)raw_data;
        memset(&dst6, 0, sizeof(dst6));
        dst6.sin6_family = AF_INET6;
        memcpy(&dst6.sin6_addr, &ip6h->ip6_dst, 16);

        sendto(sock, raw_data, data_len, 0,
               (struct sockaddr *)&dst6, sizeof(dst6));
        close(sock);
    }

    return 1;
}

void pkt_recalc_checksums(packet_info_t *pkt_info) {
    linux_pkt_ctx_t *ctx;
    if (!pkt_info) return;
    ctx = (linux_pkt_ctx_t *)pkt_info->platform_ctx_data;

    if (ctx->ip_hdr) {
        ctx->ip_hdr->check = 0;
        ctx->ip_hdr->check = ip_checksum(ctx->ip_hdr);

        if (ctx->tcp_hdr) {
            ctx->tcp_hdr->check = 0;
            int payload_len = (int)ctx->data_len;
            ctx->tcp_hdr->check = tcp_checksum(ctx->ip_hdr, ctx->tcp_hdr,
                                               payload_len, 0);
        }
    } else if (ctx->ipv6_hdr && ctx->tcp_hdr) {
        ctx->tcp_hdr->check = 0;
        int payload_len = (int)ctx->data_len;
        ctx->tcp_hdr->check = tcp_checksum(ctx->ipv6_hdr, ctx->tcp_hdr,
                                           payload_len, 1);
    }
}

void pkt_set_tcp_window(packet_info_t *pkt_info, uint16_t new_window) {
    linux_pkt_ctx_t *ctx;
    if (!pkt_info) return;
    ctx = (linux_pkt_ctx_t *)pkt_info->platform_ctx_data;
    if (ctx->tcp_hdr) {
        ctx->tcp_hdr->window = htons(new_window);
    }
}

void pkt_set_ttl(packet_info_t *pkt_info, uint8_t ttl) {
    linux_pkt_ctx_t *ctx;
    if (!pkt_info) return;
    ctx = (linux_pkt_ctx_t *)pkt_info->platform_ctx_data;
    if (ctx->ip_hdr) {
        ctx->ip_hdr->ttl = ttl;
    } else if (ctx->ipv6_hdr) {
        ctx->ipv6_hdr->ip6_hlim = ttl;
    }
    pkt_info->ip_ttl = ttl;
}

void pkt_set_tcp_seq(packet_info_t *pkt_info, uint32_t seq) {
    linux_pkt_ctx_t *ctx;
    if (!pkt_info) return;
    ctx = (linux_pkt_ctx_t *)pkt_info->platform_ctx_data;
    if (ctx->tcp_hdr) {
        ctx->tcp_hdr->seq = htonl(seq);
        pkt_info->tcp_seq = seq;
    }
}

void pkt_set_tcp_ack(packet_info_t *pkt_info, uint32_t ack) {
    linux_pkt_ctx_t *ctx;
    if (!pkt_info) return;
    ctx = (linux_pkt_ctx_t *)pkt_info->platform_ctx_data;
    if (ctx->tcp_hdr) {
        ctx->tcp_hdr->ack_seq = htonl(ack);
        pkt_info->tcp_ack = ack;
    }
}

void pkt_set_payload(packet_info_t *pkt_info, const uint8_t *new_payload, uint32_t new_len) {
    linux_pkt_ctx_t *ctx;
    int32_t len_diff;

    if (!pkt_info) return;
    ctx = (linux_pkt_ctx_t *)pkt_info->platform_ctx_data;
    if (!ctx->data) return;

    len_diff = (int32_t)new_len - (int32_t)ctx->data_len;
    if (ctx->packet_len + len_diff > MAX_PACKET_SIZE) return;

    memcpy(ctx->data, new_payload, new_len);
    ctx->packet_len = (uint32_t)((int32_t)ctx->packet_len + len_diff);
    ctx->data_len = new_len;

    /* Update IP length */
    if (ctx->ip_hdr) {
        ctx->ip_hdr->tot_len = htons((uint16_t)ctx->packet_len);
    } else if (ctx->ipv6_hdr) {
        ctx->ipv6_hdr->ip6_plen = htons((uint16_t)(ctx->packet_len - 40));
    }

    pkt_info->payload = ctx->data;
    pkt_info->payload_len = new_len;
    pkt_info->raw_packet_len = ctx->packet_len;
}

void pkt_damage_tcp_checksum(packet_info_t *pkt_info) {
    linux_pkt_ctx_t *ctx;
    if (!pkt_info) return;
    ctx = (linux_pkt_ctx_t *)pkt_info->platform_ctx_data;
    if (ctx->tcp_hdr) {
        ctx->tcp_hdr->check = htons(ntohs(ctx->tcp_hdr->check) - 1);
    }
}

void pkt_close(pkt_handle_t handle) {
    linux_handle_t *lh = (linux_handle_t *)handle;
    if (!lh) return;

    if (lh->nfq_qh) nfq_destroy_queue(lh->nfq_qh);
    if (lh->nfq_h) nfq_close(lh->nfq_h);
    free(lh);
}
