/*
 * Windows Packet Capture Implementation using WinDivert
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "windivert.h"
#include "../platform.h"
#include "../../goodbyedpi.h"

/* Internal context stored alongside each packet */
typedef struct {
    WINDIVERT_ADDRESS addr;
    /* Mutable copy of the packet for modification */
    char packet_buf[MAX_PACKET_SIZE];
    UINT packet_len;
    /* Parsed pointers into packet_buf */
    PWINDIVERT_IPHDR ip_hdr;
    PWINDIVERT_IPV6HDR ipv6_hdr;
    PWINDIVERT_TCPHDR tcp_hdr;
    PWINDIVERT_UDPHDR udp_hdr;
    PVOID data;
    UINT data_len;
} win32_pkt_ctx_t;

pkt_handle_t pkt_open(const char *filter_expr, uint32_t flags) {
    UINT64 windivert_flags = 0;
    HANDLE handle;
    LPTSTR errormessage = NULL;
    DWORD errorcode = 0;

    if (flags & PKT_FLAG_DROP) {
        windivert_flags = WINDIVERT_FLAG_DROP;
    }

    handle = WinDivertOpen(filter_expr, WINDIVERT_LAYER_NETWORK, 0, windivert_flags);
    if (handle == INVALID_HANDLE_VALUE) {
        errorcode = GetLastError();
        FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                      FORMAT_MESSAGE_IGNORE_INSERTS,
                      NULL, errorcode, MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT),
                      (LPTSTR)&errormessage, 0, NULL);
        printf("Error opening filter: %lu %s\n", (unsigned long)errorcode,
               errormessage ? errormessage : "Unknown error");
        if (errormessage) LocalFree(errormessage);

        if (errorcode == 2)
            printf("The driver files WinDivert32.sys or WinDivert64.sys were not found.\n");
        else if (errorcode == 654)
            printf("An incompatible version of the WinDivert driver is currently loaded.\n");
        else if (errorcode == 1275)
            printf("WinDivert driver is blocked by security software or unsupported virtualization.\n");
        else if (errorcode == 577)
            printf("Could not load driver due to invalid digital signature.\n");

        return NULL;
    }

    return (pkt_handle_t)handle;
}

int pkt_receive(pkt_handle_t handle, packet_info_t *pkt_info) {
    HANDLE h = (HANDLE)handle;
    win32_pkt_ctx_t *ctx;
    UINT packetLen;

    if (!handle || !pkt_info) return 0;

    /* Store context in the platform_ctx_data area */
    ctx = (win32_pkt_ctx_t *)pkt_info->platform_ctx_data;
    memset(pkt_info, 0, sizeof(packet_info_t));
    ctx = (win32_pkt_ctx_t *)pkt_info->platform_ctx_data;
    pkt_info->platform_ctx = ctx;

    if (!WinDivertRecv(h, ctx->packet_buf, sizeof(ctx->packet_buf),
                       &packetLen, &ctx->addr)) {
        return 0;
    }

    ctx->packet_len = packetLen;
    ctx->ip_hdr = NULL;
    ctx->ipv6_hdr = NULL;
    ctx->tcp_hdr = NULL;
    ctx->udp_hdr = NULL;
    ctx->data = NULL;
    ctx->data_len = 0;

    /* Parse the packet */
    WinDivertHelperParsePacket(ctx->packet_buf, packetLen,
        &ctx->ip_hdr, &ctx->ipv6_hdr, NULL, NULL, NULL,
        &ctx->tcp_hdr, &ctx->udp_hdr, &ctx->data, &ctx->data_len,
        NULL, NULL);

    /* Fill platform-independent fields */
    pkt_info->raw_packet = (uint8_t *)ctx->packet_buf;
    pkt_info->raw_packet_len = packetLen;
    pkt_info->direction = ctx->addr.Outbound ? PACKET_DIR_OUTBOUND : PACKET_DIR_INBOUND;

    if (ctx->ip_hdr) {
        pkt_info->is_ipv6 = 0;
        pkt_info->ip_ttl = ctx->ip_hdr->TTL;
        pkt_info->src_ip[0] = ctx->ip_hdr->SrcAddr;
        pkt_info->dst_ip[0] = ctx->ip_hdr->DstAddr;
        pkt_info->ip_id = ntohs(ctx->ip_hdr->Id);
    } else if (ctx->ipv6_hdr) {
        pkt_info->is_ipv6 = 1;
        pkt_info->ip_ttl = ctx->ipv6_hdr->HopLimit;
        memcpy(pkt_info->src_ip, ctx->ipv6_hdr->SrcAddr, 16);
        memcpy(pkt_info->dst_ip, ctx->ipv6_hdr->DstAddr, 16);
        pkt_info->ipv6_flow_label = WINDIVERT_IPV6HDR_GET_FLOWLABEL(ctx->ipv6_hdr);
    }

    if (ctx->tcp_hdr) {
        pkt_info->has_tcp = 1;
        pkt_info->src_port = ntohs(ctx->tcp_hdr->SrcPort);
        pkt_info->dst_port = ntohs(ctx->tcp_hdr->DstPort);
        pkt_info->tcp_seq = ntohl(ctx->tcp_hdr->SeqNum);
        pkt_info->tcp_ack = ntohl(ctx->tcp_hdr->AckNum);
        pkt_info->tcp_syn = ctx->tcp_hdr->Syn;
        pkt_info->tcp_ack_flag = ctx->tcp_hdr->Ack;
        pkt_info->tcp_rst = ctx->tcp_hdr->Rst;
        pkt_info->tcp_window = ntohs(ctx->tcp_hdr->Window);
    }

    if (ctx->udp_hdr) {
        pkt_info->has_udp = 1;
        if (!ctx->tcp_hdr) {
            pkt_info->src_port = ntohs(ctx->udp_hdr->SrcPort);
            pkt_info->dst_port = ntohs(ctx->udp_hdr->DstPort);
        }
    }

    if (ctx->data) {
        pkt_info->payload = (uint8_t *)ctx->data;
        pkt_info->payload_len = ctx->data_len;
    }

    return 1;
}

int pkt_send(pkt_handle_t handle, packet_info_t *pkt_info) {
    HANDLE h = (HANDLE)handle;
    win32_pkt_ctx_t *ctx;

    if (!handle || !pkt_info) return 0;
    ctx = (win32_pkt_ctx_t *)pkt_info->platform_ctx_data;

    return WinDivertSend(h, ctx->packet_buf, ctx->packet_len, NULL, &ctx->addr) ? 1 : 0;
}

int pkt_send_raw(pkt_handle_t handle, packet_info_t *pkt_info,
                 const uint8_t *raw_data, uint32_t data_len) {
    HANDLE h = (HANDLE)handle;
    win32_pkt_ctx_t *ctx;
    WINDIVERT_ADDRESS addr;

    if (!handle || !pkt_info) return 0;
    ctx = (win32_pkt_ctx_t *)pkt_info->platform_ctx_data;
    memcpy(&addr, &ctx->addr, sizeof(WINDIVERT_ADDRESS));

    addr.IPChecksum = 0;
    addr.TCPChecksum = 0;

    WinDivertHelperCalcChecksums((PVOID)raw_data, data_len, &addr, 0);
    return WinDivertSend(h, (PVOID)raw_data, data_len, NULL, &addr) ? 1 : 0;
}

void pkt_recalc_checksums(packet_info_t *pkt_info) {
    win32_pkt_ctx_t *ctx;
    if (!pkt_info) return;
    ctx = (win32_pkt_ctx_t *)pkt_info->platform_ctx_data;

    ctx->addr.IPChecksum = 0;
    ctx->addr.TCPChecksum = 0;
    WinDivertHelperCalcChecksums(ctx->packet_buf, ctx->packet_len, &ctx->addr, 0);
}

void pkt_set_tcp_window(packet_info_t *pkt_info, uint16_t new_window) {
    win32_pkt_ctx_t *ctx;
    if (!pkt_info) return;
    ctx = (win32_pkt_ctx_t *)pkt_info->platform_ctx_data;
    if (ctx->tcp_hdr) {
        ctx->tcp_hdr->Window = htons(new_window);
    }
}

void pkt_set_ttl(packet_info_t *pkt_info, uint8_t ttl) {
    win32_pkt_ctx_t *ctx;
    if (!pkt_info) return;
    ctx = (win32_pkt_ctx_t *)pkt_info->platform_ctx_data;
    if (ctx->ip_hdr) {
        ctx->ip_hdr->TTL = ttl;
    } else if (ctx->ipv6_hdr) {
        ctx->ipv6_hdr->HopLimit = ttl;
    }
    pkt_info->ip_ttl = ttl;
}

void pkt_set_tcp_seq(packet_info_t *pkt_info, uint32_t seq) {
    win32_pkt_ctx_t *ctx;
    if (!pkt_info) return;
    ctx = (win32_pkt_ctx_t *)pkt_info->platform_ctx_data;
    if (ctx->tcp_hdr) {
        ctx->tcp_hdr->SeqNum = htonl(seq);
        pkt_info->tcp_seq = seq;
    }
}

void pkt_set_tcp_ack(packet_info_t *pkt_info, uint32_t ack) {
    win32_pkt_ctx_t *ctx;
    if (!pkt_info) return;
    ctx = (win32_pkt_ctx_t *)pkt_info->platform_ctx_data;
    if (ctx->tcp_hdr) {
        ctx->tcp_hdr->AckNum = htonl(ack);
        pkt_info->tcp_ack = ack;
    }
}

void pkt_set_payload(packet_info_t *pkt_info, const uint8_t *new_payload, uint32_t new_len) {
    win32_pkt_ctx_t *ctx;
    int32_t len_diff;

    if (!pkt_info) return;
    ctx = (win32_pkt_ctx_t *)pkt_info->platform_ctx_data;

    if (!ctx->data) return;

    len_diff = (int32_t)new_len - (int32_t)ctx->data_len;

    if (ctx->packet_len + len_diff > MAX_PACKET_SIZE) return;

    memcpy(ctx->data, new_payload, new_len);
    ctx->packet_len = (UINT)((int32_t)ctx->packet_len + len_diff);
    ctx->data_len = new_len;

    /* Update IP length */
    if (ctx->ip_hdr) {
        ctx->ip_hdr->Length = htons((uint16_t)((int32_t)ntohs(ctx->ip_hdr->Length) + len_diff));
    } else if (ctx->ipv6_hdr) {
        ctx->ipv6_hdr->Length = htons((uint16_t)((int32_t)ntohs(ctx->ipv6_hdr->Length) + len_diff));
    }

    pkt_info->payload = (uint8_t *)ctx->data;
    pkt_info->payload_len = new_len;
    pkt_info->raw_packet_len = ctx->packet_len;
}

void pkt_damage_tcp_checksum(packet_info_t *pkt_info) {
    win32_pkt_ctx_t *ctx;
    if (!pkt_info) return;
    ctx = (win32_pkt_ctx_t *)pkt_info->platform_ctx_data;
    if (ctx->tcp_hdr) {
        ctx->tcp_hdr->Checksum = htons(ntohs(ctx->tcp_hdr->Checksum) - 1);
    }
}

void pkt_close(pkt_handle_t handle) {
    HANDLE h = (HANDLE)handle;
    if (h && h != INVALID_HANDLE_VALUE) {
        WinDivertShutdown(h, WINDIVERT_SHUTDOWN_BOTH);
        WinDivertClose(h);
    }
}
