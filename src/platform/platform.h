/*
 * Platform Abstraction Layer for GoodbyeDPI
 *
 * This header defines the cross-platform interface that each
 * platform (Windows, Linux, macOS) must implement.
 */

#ifndef _PLATFORM_H
#define _PLATFORM_H

#include <stdint.h>
#include <stddef.h>

/*
 * =============================================================
 * Platform-independent type definitions
 * =============================================================
 */

/* Boolean type */
#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

/* Packet direction */
typedef enum {
    PACKET_DIR_INBOUND = 0,
    PACKET_DIR_OUTBOUND = 1
} packet_direction_t;

/* IP protocol numbers */
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

/*
 * =============================================================
 * Packet Capture Abstraction
 * =============================================================
 */

/* Opaque handle for a packet capture filter */
typedef void* pkt_handle_t;

/* Parsed packet information (platform-independent) */
typedef struct {
    /* Raw packet buffer */
    const uint8_t *raw_packet;
    uint32_t raw_packet_len;

    /* IP header info */
    uint8_t is_ipv6;
    uint8_t ip_ttl;          /* TTL or HopLimit */
    uint32_t src_ip[4];      /* IPv4 uses [0] only, IPv6 uses all 4 */
    uint32_t dst_ip[4];

    /* For IPv4 */
    uint16_t ip_id;

    /* For IPv6 */
    uint32_t ipv6_flow_label;

    /* TCP header info (NULL-equivalent if not TCP) */
    int has_tcp;
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t tcp_seq;
    uint32_t tcp_ack;
    uint8_t tcp_syn;
    uint8_t tcp_ack_flag;
    uint8_t tcp_rst;
    uint16_t tcp_window;

    /* UDP header info */
    int has_udp;
    /* src_port/dst_port shared with TCP */

    /* Payload */
    uint8_t *payload;
    uint32_t payload_len;

    /* Direction */
    packet_direction_t direction;

    /* Platform-specific opaque data (for reinject) */
    void *platform_ctx;
    uint8_t platform_ctx_data[16384];
} packet_info_t;

/* Filter flags */
#define PKT_FLAG_DROP     (1 << 0)  /* Drop matching packets */
#define PKT_FLAG_READONLY (1 << 1)  /* Don't allow modification */

/*
 * Open a packet capture filter.
 * @param filter_expr  Platform-specific filter expression string
 * @param flags        PKT_FLAG_* flags
 * @return             Handle, or NULL on failure
 */
pkt_handle_t pkt_open(const char *filter_expr, uint32_t flags);

/*
 * Receive a packet from the filter.
 * @param handle       Filter handle
 * @param pkt_info     Output: parsed packet information
 * @return             1 on success, 0 on failure/timeout
 */
int pkt_receive(pkt_handle_t handle, packet_info_t *pkt_info);

/*
 * Send/reinject a packet (possibly modified).
 * @param handle       Filter handle
 * @param pkt_info     Packet to send (with modifications applied)
 * @return             1 on success, 0 on failure
 */
int pkt_send(pkt_handle_t handle, packet_info_t *pkt_info);

/*
 * Send a raw packet buffer.
 * @param handle       Filter handle
 * @param pkt_info     Original packet info (for context/direction)
 * @param raw_data     Raw packet data to send
 * @param data_len     Length of raw data
 * @return             1 on success, 0 on failure
 */
int pkt_send_raw(pkt_handle_t handle, packet_info_t *pkt_info,
                 const uint8_t *raw_data, uint32_t data_len);

/*
 * Recalculate IP/TCP/UDP checksums for a packet.
 * @param pkt_info     Packet whose checksums need recalculation
 */
void pkt_recalc_checksums(packet_info_t *pkt_info);

/*
 * Modify the TCP window size in a packet.
 * @param pkt_info     Packet to modify
 * @param new_window   New window size value
 */
void pkt_set_tcp_window(packet_info_t *pkt_info, uint16_t new_window);

/*
 * Modify the IP TTL/HopLimit in a packet.
 * @param pkt_info     Packet to modify
 * @param ttl          New TTL value
 */
void pkt_set_ttl(packet_info_t *pkt_info, uint8_t ttl);

/*
 * Modify the TCP sequence number in a packet.
 * @param pkt_info     Packet to modify
 * @param seq          New sequence number
 */
void pkt_set_tcp_seq(packet_info_t *pkt_info, uint32_t seq);

/*
 * Modify the TCP acknowledgment number in a packet.
 * @param pkt_info     Packet to modify
 * @param ack          New ack number
 */
void pkt_set_tcp_ack(packet_info_t *pkt_info, uint32_t ack);

/*
 * Modify the IP total length and adjust packet data.
 * @param pkt_info     Packet to modify
 * @param new_payload  New payload data
 * @param new_len      New payload length
 */
void pkt_set_payload(packet_info_t *pkt_info, const uint8_t *new_payload, uint32_t new_len);

/*
 * Damage the TCP checksum (for fake packets).
 * @param pkt_info     Packet to modify
 */
void pkt_damage_tcp_checksum(packet_info_t *pkt_info);

/*
 * Shutdown and close a filter handle.
 * @param handle       Filter handle to close
 */
void pkt_close(pkt_handle_t handle);

/*
 * =============================================================
 * Service/Daemon Abstraction
 * =============================================================
 */

/*
 * Try to register as a system service/daemon.
 * On Windows: registers as a Windows Service
 * On Linux: daemonizes (or integrates with systemd)
 * On macOS: integrates with launchd
 *
 * @param argc, argv   Command line arguments
 * @return             1 if running as service (caller should exit),
 *                     0 if running as normal process
 */
int service_try_register(int argc, char *argv[]);

/*
 * Signal the service manager that we are stopping.
 */
void service_signal_stop(void);

/*
 * =============================================================
 * OS Utility Abstraction
 * =============================================================
 */

/*
 * Flush the system DNS cache.
 */
void os_flush_dns_cache(void);

/*
 * Generate a cryptographically secure random 32-bit integer.
 * @param out          Output value
 * @return             0 on success, non-zero on failure
 */
int os_random_uint32(uint32_t *out);

/*
 * Apply OS-specific security hardening (e.g., DLL search path on Windows).
 */
void os_security_init(void);

/*
 * Get the last OS error code as a human-readable string.
 * @param buf          Output buffer
 * @param bufsize      Buffer size
 */
void os_get_error_string(char *buf, size_t bufsize);

/*
 * Network byte order helpers (most platforms have these, but we ensure availability)
 */
#if defined(_WIN32)
    #include <winsock2.h>
#else
    #include <arpa/inet.h>
#endif

#endif /* _PLATFORM_H */
