/*
 * GoodbyeDPI — Cross-platform main entry point.
 * Uses the platform abstraction layer for packet capture.
 *
 * This file is used on Linux and macOS.
 * Windows still uses the original goodbyedpi.c with WinDivert directly.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <ctype.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "goodbyedpi.h"
#include "utils/repl_str.h"
#include "service.h"
#include "dnsredir.h"
#include "ttltrack.h"
#include "blackwhitelist.h"
#include "fakepackets.h"
#include "platform/platform.h"

#define GOODBYEDPI_VERSION "v0.2.4-cross"

#define die() do { sleep(20); exit(EXIT_FAILURE); } while (0)

#define MAX_FILTERS 4

#define SET_HTTP_FRAGMENT_SIZE_OPTION(fragment_size) do { \
    if (!http_fragment_size) { \
        http_fragment_size = (unsigned int)fragment_size; \
    } \
    else if (http_fragment_size != (unsigned int)fragment_size) { \
        printf( \
            "WARNING: HTTP fragment size is already set to %u, not changing.\n", \
            http_fragment_size \
        ); \
    } \
} while (0)

enum ERROR_CODE{
    ERROR_DEFAULT = 1,
    ERROR_PORT_BOUNDS,
    ERROR_DNS_V4_ADDR,
    ERROR_DNS_V6_ADDR,
    ERROR_DNS_V4_PORT,
    ERROR_DNS_V6_PORT,
    ERROR_BLACKLIST_LOAD,
    ERROR_AUTOTTL,
    ERROR_ATOUSI,
    ERROR_AUTOB
};

static int exiting = 0;
static pkt_handle_t filters[MAX_FILTERS];
static int filter_num = 0;
static const char http10_redirect_302[] = "HTTP/1.0 302 ";
static const char http11_redirect_302[] = "HTTP/1.1 302 ";
static const char http_host_find[] = "\r\nHost: ";
static const char http_host_replace[] = "\r\nhoSt: ";
static const char http_useragent_find[] = "\r\nUser-Agent: ";
static const char location_http[] = "\r\nLocation: http://";
static const char connection_close[] = "\r\nConnection: close";
static const char *http_methods[] = {
    "GET ",
    "HEAD ",
    "POST ",
    "PUT ",
    "DELETE ",
    "CONNECT ",
    "OPTIONS ",
};

static struct option long_options[] = {
    {"port",        required_argument, 0,  'z' },
    {"dns-addr",    required_argument, 0,  'd' },
    {"dns-port",    required_argument, 0,  'g' },
    {"dnsv6-addr",  required_argument, 0,  '!' },
    {"dnsv6-port",  required_argument, 0,  '@' },
    {"dns-verb",    no_argument,       0,  'v' },
    {"blacklist",   required_argument, 0,  'b' },
    {"allow-no-sni",no_argument,       0,  ']' },
    {"frag-by-sni", no_argument,       0,  '>' },
    {"ip-id",       required_argument, 0,  'i' },
    {"set-ttl",     required_argument, 0,  '$' },
    {"min-ttl",     required_argument, 0,  '[' },
    {"auto-ttl",    optional_argument, 0,  '+' },
    {"wrong-chksum",no_argument,       0,  '%' },
    {"wrong-seq",   no_argument,       0,  ')' },
    {"native-frag", no_argument,       0,  '*' },
    {"reverse-frag",no_argument,       0,  '(' },
    {"max-payload", optional_argument, 0,  '|' },
    {"fake-from-hex", required_argument, 0,  'u' },
    {"fake-with-sni", required_argument, 0,  '}' },
    {"fake-gen",    required_argument, 0,  'j' },
    {"fake-resend", required_argument, 0,  't' },
    {"debug-exit",  optional_argument, 0,  'x' },
    {"daemon",      no_argument,       0,  'D' },
    {0,             0,                 0,   0  }
};

/* ============================================================
 * Helper functions
 * ============================================================ */

static char* dumb_memmem(const char* haystack, unsigned int hlen,
                         const char* needle, unsigned int nlen)
{
    if (nlen > hlen) return NULL;
    size_t i;
    for (i=0; i<hlen-nlen+1; i++) {
        if (memcmp(haystack+i,needle,nlen)==0) {
            return (char*)(haystack+i);
        }
    }
    return NULL;
}

static unsigned short int atousi(const char *str, const char *msg) {
    long unsigned int res = strtoul(str, NULL, 10u);
    if(res > 0xFFFFu) {
        puts(msg);
        exit(ERROR_ATOUSI);
    }
    return (unsigned short int)res;
}

static BYTE atoub(const char *str, const char *msg) {
    long unsigned int res = strtoul(str, NULL, 10u);
    if(res > 0xFFu) {
        puts(msg);
        exit(ERROR_AUTOB);
    }
    return (BYTE)res;
}

void deinit_all(void) {
    for (int i = 0; i < filter_num; i++) {
        pkt_close(filters[i]);
    }
}

static void sigint_handler(int sig __attribute__((unused))) {
    exiting = 1;
    deinit_all();
    exit(EXIT_SUCCESS);
}

static void mix_case(char *pktdata, unsigned int pktlen) {
    unsigned int i;
    if (pktlen <= 0) return;
    for (i = 0; i < pktlen; i++) {
        if (i % 2) {
            pktdata[i] = (char) toupper(pktdata[i]);
        }
    }
}

static int is_passivedpi_redirect(const char *pktdata, unsigned int pktlen) {
    if (memcmp(pktdata, http11_redirect_302, sizeof(http11_redirect_302)-1) == 0 ||
        memcmp(pktdata, http10_redirect_302, sizeof(http10_redirect_302)-1) == 0)
    {
        if (dumb_memmem(pktdata, pktlen, location_http, sizeof(location_http)-1) &&
            dumb_memmem(pktdata, pktlen, connection_close, sizeof(connection_close)-1)) {
            return TRUE;
        }
    }
    return FALSE;
}

static int find_header_and_get_info(const char *pktdata, unsigned int pktlen,
                const char *hdrname,
                char **hdrnameaddr,
                char **hdrvalueaddr, unsigned int *hdrvaluelen) {
    char *data_addr_rn;
    char *hdr_begin;

    *hdrvaluelen = 0u;
    *hdrnameaddr = NULL;
    *hdrvalueaddr = NULL;

    hdr_begin = dumb_memmem(pktdata, pktlen, hdrname, strlen(hdrname));
    if (!hdr_begin) return FALSE;
    if (pktdata > hdr_begin) return FALSE;

    *hdrnameaddr = hdr_begin;
    *hdrvalueaddr = hdr_begin + strlen(hdrname);

    data_addr_rn = dumb_memmem(*hdrvalueaddr,
                        pktlen - (unsigned int)(*hdrvalueaddr - pktdata),
                        "\r\n", 2);
    if (data_addr_rn) {
        *hdrvaluelen = (unsigned int)(data_addr_rn - *hdrvalueaddr);
        if (*hdrvaluelen >= 3 && *hdrvaluelen <= HOST_MAXLEN)
            return TRUE;
    }
    return FALSE;
}

static int extract_sni(const char *pktdata, unsigned int pktlen,
                    char **hostnameaddr, unsigned int *hostnamelen) {
    unsigned int ptr = 0;
    unsigned const char *d = (unsigned const char *)pktdata;
    unsigned const char *hnaddr = 0;
    int hnlen = 0;

    while (ptr + 8 < pktlen) {
        if (d[ptr] == '\0' && d[ptr+1] == '\0' && d[ptr+2] == '\0' &&
            d[ptr+4] == '\0' && d[ptr+6] == '\0' && d[ptr+7] == '\0' &&
            d[ptr+3] - d[ptr+5] == 2 && d[ptr+5] - d[ptr+8] == 3)
            {
                if (ptr + 8 + d[ptr+8] > pktlen) {
                    return FALSE;
                }
                hnaddr = &d[ptr+9];
                hnlen = d[ptr+8];
                if (hnlen < 3 || hnlen > HOST_MAXLEN) {
                    return FALSE;
                }
                for (int i=0; i<hnlen; i++) {
                    if (!( (hnaddr[i] >= '0' && hnaddr[i] <= '9') ||
                         (hnaddr[i] >= 'a' && hnaddr[i] <= 'z') ||
                         hnaddr[i] == '.' || hnaddr[i] == '-'))
                    {
                        return FALSE;
                    }
                }
                *hostnameaddr = (char*)hnaddr;
                *hostnamelen = (unsigned int)hnlen;
                return TRUE;
            }
        ptr++;
    }
    return FALSE;
}

static PVOID find_http_method_end(const char *pkt, unsigned int http_frag, int *is_fragmented) {
    unsigned int i;
    for (i = 0; i<(sizeof(http_methods) / sizeof(*http_methods)); i++) {
        if (memcmp(pkt, http_methods[i], strlen(http_methods[i])) == 0) {
            if (is_fragmented)
                *is_fragmented = 0;
            return (char*)pkt + strlen(http_methods[i]) - 1;
        }
        if ((http_frag == 1 || http_frag == 2) &&
            memcmp(pkt, http_methods[i] + http_frag,
                   strlen(http_methods[i]) - http_frag) == 0)
        {
            if (is_fragmented)
                *is_fragmented = 1;
            return (char*)pkt + strlen(http_methods[i]) - http_frag - 1;
        }
    }
    return NULL;
}

/* ============================================================
 * Native fragmentation using platform API
 * ============================================================ */

static void send_native_fragment(pkt_handle_t w_filter, packet_info_t *pkt,
                        unsigned int fragment_size, int step) {
    packet_info_t frag_pkt;
    uint8_t frag_buf[MAX_PACKET_SIZE];

    if (!pkt->payload || !pkt->payload_len) return;
    if (fragment_size >= pkt->payload_len) {
        if (step == 1)
            fragment_size = 0;
        else
            return;
    }

    /* Make a copy */
    memcpy(&frag_pkt, pkt, sizeof(packet_info_t));
    memcpy(frag_buf, pkt->raw_packet, pkt->raw_packet_len);

    if (step == 0) {
        /* Send first fragment_size bytes of payload */
        pkt_set_payload(&frag_pkt, pkt->payload, fragment_size);
    } else if (step == 1) {
        /* Send remaining bytes after fragment_size */
        pkt_set_payload(&frag_pkt, pkt->payload + fragment_size,
                       pkt->payload_len - fragment_size);
        pkt_set_tcp_seq(&frag_pkt, pkt->tcp_seq + fragment_size);
    }

    pkt_recalc_checksums(&frag_pkt);
    pkt_send(w_filter, &frag_pkt);
}

/* ============================================================
 * Main function
 * ============================================================ */

int main(int argc, char *argv[]) {
    int i, opt;
    bool debug_exit = false;
    int should_reinject, should_recalc_checksum;
    int sni_ok;

    pkt_handle_t w_filter = NULL;
    packet_info_t pkt;

    conntrack_info_t dns_conn_info;
    tcp_conntrack_info_t tcp_conn_info;

    int do_passivedpi = 0, do_block_quic = 0,
        do_fragment_http = 0,
        do_fragment_http_persistent = 0,
        do_fragment_http_persistent_nowait = 0,
        do_fragment_https = 0, do_host = 0,
        do_host_removespace = 0, do_additional_space = 0,
        do_http_allports = 0,
        do_host_mixedcase = 0,
        do_dnsv4_redirect = 0, do_dnsv6_redirect = 0,
        do_dns_verb = 0, do_tcp_verb = 0, do_blacklist = 0,
        do_allow_no_sni = 0,
        do_fragment_by_sni = 0,
        do_fake_packet = 0,
        do_auto_ttl = 0,
        do_wrong_chksum = 0,
        do_wrong_seq = 0,
        do_native_frag = 0, do_reverse_frag = 0;
    unsigned int http_fragment_size = 0;
    unsigned int https_fragment_size = 0;
    unsigned int current_fragment_size = 0;
    unsigned short max_payload_size = 0;
    BYTE should_send_fake = 0;
    BYTE ttl_of_fake_packet = 0;
    BYTE ttl_min_nhops = 0;
    BYTE auto_ttl_1 = 0;
    BYTE auto_ttl_2 = 0;
    BYTE auto_ttl_max = 0;
    uint32_t dnsv4_addr = 0;
    struct in6_addr dnsv6_addr = {0};
    struct in6_addr dns_temp_addr = {0};
    uint16_t dnsv4_port = htons(53);
    uint16_t dnsv6_port = htons(53);
    char *host_addr, *useragent_addr, *method_addr;
    unsigned int host_len, useragent_len;
    int http_req_fragmented;

    char *hdr_name_addr = NULL, *hdr_value_addr = NULL;
    unsigned int hdr_value_len;

    /* Platform-specific security init */
    os_security_init();

    /* Try to register as service/daemon */
    if (service_try_register(argc, argv)) {
        return 0;
    }

    printf(
        "GoodbyeDPI " GOODBYEDPI_VERSION
        ": Passive DPI blocker and Active DPI circumvention utility\n"
        "https://github.com/iphysicc/GoodbyeDPI-Enhanced\n\n"
    );

    if (argc == 1) {
        /* enable mode -9 by default */
        do_fragment_http = do_fragment_https = 1;
        do_reverse_frag = do_native_frag = 1;
        http_fragment_size = https_fragment_size = 2;
        do_fragment_http_persistent = do_fragment_http_persistent_nowait = 1;
        do_fake_packet = 1;
        do_wrong_chksum = 1;
        do_wrong_seq = 1;
        do_block_quic = 1;
        max_payload_size = 1200;
    }

    while ((opt = getopt_long(argc, argv, "123456789pqrsaf:e:mwk:nD", long_options, NULL)) != -1) {
        switch (opt) {
            case '1':
                do_passivedpi = do_host = do_host_removespace \
                = do_fragment_http = do_fragment_https \
                = do_fragment_http_persistent \
                = do_fragment_http_persistent_nowait = 1;
                break;
            case '2':
                do_passivedpi = do_host = do_host_removespace \
                = do_fragment_http = do_fragment_https \
                = do_fragment_http_persistent \
                = do_fragment_http_persistent_nowait = 1;
                https_fragment_size = 40u;
                break;
            case '3':
                do_passivedpi = do_host = do_host_removespace \
                = do_fragment_https = 1;
                https_fragment_size = 40u;
                break;
            case '4':
                do_passivedpi = do_host = do_host_removespace = 1;
                break;
            case '5':
                do_fragment_http = do_fragment_https = 1;
                do_reverse_frag = do_native_frag = 1;
                http_fragment_size = https_fragment_size = 2;
                do_fragment_http_persistent = do_fragment_http_persistent_nowait = 1;
                do_fake_packet = 1;
                do_auto_ttl = 1;
                max_payload_size = 1200;
                break;
            case '6':
                do_fragment_http = do_fragment_https = 1;
                do_reverse_frag = do_native_frag = 1;
                http_fragment_size = https_fragment_size = 2;
                do_fragment_http_persistent = do_fragment_http_persistent_nowait = 1;
                do_fake_packet = 1;
                do_wrong_seq = 1;
                max_payload_size = 1200;
                break;
            case '9':
                do_block_quic = 1;
                /* fall through */
            case '8':
                do_wrong_seq = 1;
                /* fall through */
            case '7':
                do_fragment_http = do_fragment_https = 1;
                do_reverse_frag = do_native_frag = 1;
                http_fragment_size = https_fragment_size = 2;
                do_fragment_http_persistent = do_fragment_http_persistent_nowait = 1;
                do_fake_packet = 1;
                do_wrong_chksum = 1;
                max_payload_size = 1200;
                break;
            case 'p':
                do_passivedpi = 1;
                break;
            case 'q':
                do_block_quic = 1;
                break;
            case 'r':
                do_host = 1;
                break;
            case 's':
                do_host_removespace = 1;
                break;
            case 'a':
                do_additional_space = 1;
                do_host_removespace = 1;
                break;
            case 'm':
                do_host_mixedcase = 1;
                break;
            case 'f':
                do_fragment_http = 1;
                SET_HTTP_FRAGMENT_SIZE_OPTION(atousi(optarg, "Fragment size should be in range [0 - 0xFFFF]\n"));
                break;
            case 'k':
                do_fragment_http_persistent = 1;
                do_native_frag = 1;
                SET_HTTP_FRAGMENT_SIZE_OPTION(atousi(optarg, "Fragment size should be in range [0 - 0xFFFF]\n"));
                break;
            case 'n':
                do_fragment_http_persistent = 1;
                do_fragment_http_persistent_nowait = 1;
                do_native_frag = 1;
                break;
            case 'e':
                do_fragment_https = 1;
                https_fragment_size = atousi(optarg, "Fragment size should be in range [0 - 65535]\n");
                break;
            case 'w':
                do_http_allports = 1;
                break;
            case 'z': /* --port */
                i = atoi(optarg);
                if (i <= 0 || i > 65535) {
                    printf("Port parameter error!\n");
                    exit(ERROR_PORT_BOUNDS);
                }
                i = 0;
                break;
            case 'd': /* --dns-addr */
                if ((inet_pton(AF_INET, optarg, dns_temp_addr.s6_addr) == 1) &&
                    !do_dnsv4_redirect)
                {
                    do_dnsv4_redirect = 1;
                    if (inet_pton(AF_INET, optarg, &dnsv4_addr) != 1) {
                        puts("DNS address parameter error!");
                        exit(ERROR_DNS_V4_ADDR);
                    }
                    flush_dns_cache();
                    break;
                }
                puts("DNS address parameter error!");
                exit(ERROR_DNS_V4_ADDR);
                break;
            case '!': /* --dnsv6-addr */
                if ((inet_pton(AF_INET6, optarg, dns_temp_addr.s6_addr) == 1) &&
                    !do_dnsv6_redirect)
                {
                    do_dnsv6_redirect = 1;
                    if (inet_pton(AF_INET6, optarg, dnsv6_addr.s6_addr) != 1) {
                        puts("DNS address parameter error!");
                        exit(ERROR_DNS_V6_ADDR);
                    }
                    flush_dns_cache();
                    break;
                }
                puts("DNS address parameter error!");
                exit(ERROR_DNS_V6_ADDR);
                break;
            case 'g': /* --dns-port */
                if (!do_dnsv4_redirect) {
                    puts("--dns-port should be used with --dns-addr!");
                    exit(ERROR_DNS_V4_PORT);
                }
                dnsv4_port = htons(atousi(optarg, "DNS port parameter error!"));
                break;
            case '@': /* --dnsv6-port */
                if (!do_dnsv6_redirect) {
                    puts("--dnsv6-port should be used with --dnsv6-addr!");
                    exit(ERROR_DNS_V6_PORT);
                }
                dnsv6_port = htons(atousi(optarg, "DNS port parameter error!"));
                break;
            case 'v':
                do_dns_verb = 1;
                do_tcp_verb = 1;
                break;
            case 'b': /* --blacklist */
                do_blacklist = 1;
                if (!blackwhitelist_load_list(optarg)) {
                    printf("Can't load blacklist from file!\n");
                    exit(ERROR_BLACKLIST_LOAD);
                }
                break;
            case ']': /* --allow-no-sni */
                do_allow_no_sni = 1;
                break;
            case '>': /* --frag-by-sni */
                do_fragment_by_sni = 1;
                break;
            case '$': /* --set-ttl */
                do_auto_ttl = auto_ttl_1 = auto_ttl_2 = auto_ttl_max = 0;
                do_fake_packet = 1;
                ttl_of_fake_packet = atoub(optarg, "Set TTL parameter error!");
                break;
            case '[': /* --min-ttl */
                do_fake_packet = 1;
                ttl_min_nhops = atoub(optarg, "Set Minimum TTL number of hops parameter error!");
                break;
            case '+': /* --auto-ttl */
                do_fake_packet = 1;
                do_auto_ttl = 1;
                if (!optarg && argv[optind] && argv[optind][0] != '-')
                    optarg = argv[optind];
                if (optarg) {
                    char *autottl_copy = strdup(optarg);
                    if (strchr(autottl_copy, '-')) {
                        char *autottl_current = strtok(autottl_copy, "-");
                        auto_ttl_1 = atoub(autottl_current, "Set Auto TTL parameter error!");
                        autottl_current = strtok(NULL, "-");
                        if (!autottl_current) { puts("Set Auto TTL parameter error!"); exit(ERROR_AUTOTTL); }
                        auto_ttl_2 = atoub(autottl_current, "Set Auto TTL parameter error!");
                        autottl_current = strtok(NULL, "-");
                        if (!autottl_current) { puts("Set Auto TTL parameter error!"); exit(ERROR_AUTOTTL); }
                        auto_ttl_max = atoub(autottl_current, "Set Auto TTL parameter error!");
                    } else {
                        auto_ttl_2 = atoub(optarg, "Set Auto TTL parameter error!");
                        auto_ttl_1 = auto_ttl_2;
                    }
                    free(autottl_copy);
                }
                break;
            case '%': /* --wrong-chksum */
                do_fake_packet = 1;
                do_wrong_chksum = 1;
                break;
            case ')': /* --wrong-seq */
                do_fake_packet = 1;
                do_wrong_seq = 1;
                break;
            case '*': /* --native-frag */
                do_native_frag = 1;
                do_fragment_http_persistent = 1;
                do_fragment_http_persistent_nowait = 1;
                break;
            case '(': /* --reverse-frag */
                do_reverse_frag = 1;
                do_native_frag = 1;
                do_fragment_http_persistent = 1;
                do_fragment_http_persistent_nowait = 1;
                break;
            case '|': /* --max-payload */
                if (!optarg && argv[optind] && argv[optind][0] != '-')
                    optarg = argv[optind];
                if (optarg)
                    max_payload_size = atousi(optarg, "Max payload size parameter error!");
                else
                    max_payload_size = 1200;
                break;
            case 'u': /* --fake-from-hex */
                if (fake_load_from_hex(optarg)) {
                    printf("WARNING: bad fake HEX value %s\n", optarg);
                }
                break;
            case '}': /* --fake-with-sni */
                if (fake_load_from_sni(optarg)) {
                    printf("WARNING: bad domain name for SNI: %s\n", optarg);
                }
                break;
            case 'j': /* --fake-gen */
                if (fake_load_random(atoub(optarg, "Fake generator parameter error!"), 200)) {
                    puts("WARNING: fake generator has failed!");
                }
                break;
            case 't': /* --fake-resend */
                fakes_resend = atoub(optarg, "Fake resend parameter error!");
                break;
            case 'x': /* --debug-exit */
                debug_exit = true;
                break;
            case 'D': /* --daemon */
                /* Already handled by service_try_register */
                break;
            default:
                puts("Usage: goodbyedpi [OPTION...]\n"
                " -p          block passive DPI\n"
                " -q          block QUIC/HTTP3\n"
                " -r          replace Host with hoSt\n"
                " -s          remove space between host header and its value\n"
                " -a          additional space between Method and Request-URI\n"
                " -m          mix Host header case\n"
                " -f <value>  set HTTP fragmentation to value\n"
                " -k <value>  enable HTTP persistent (keep-alive) fragmentation\n"
                " -n          do not wait for first segment ACK when -k is enabled\n"
                " -e <value>  set HTTPS fragmentation to value\n"
                " -w          find and parse HTTP traffic on all processed ports\n"
                " --port        <value>    additional TCP port to fragment\n"
                " --dns-addr    <value>    redirect UDPv4 DNS requests to IPv4 address\n"
                " --dns-port    <value>    redirect UDPv4 DNS requests to port\n"
                " --dnsv6-addr  <value>    redirect UDPv6 DNS requests to IPv6 address\n"
                " --dnsv6-port  <value>    redirect UDPv6 DNS requests to port\n"
                " --dns-verb               print verbose DNS redirection messages\n"
                " --blacklist   <txtfile>  perform tricks only to hosts from file\n"
                " --allow-no-sni           perform circumvention if TLS SNI can't be detected\n"
                " --frag-by-sni            fragment right before SNI value\n"
                " --set-ttl     <value>    send fake request with supplied TTL\n"
                " --auto-ttl    [a1-a2-m]  automatically detect and set TTL\n"
                " --min-ttl     <value>    minimum TTL distance for fake request\n"
                " --wrong-chksum           send fake request with incorrect checksum\n"
                " --wrong-seq              send fake request with wrong SEQ/ACK\n"
                " --native-frag            split packets without shrinking Window Size\n"
                " --reverse-frag           send fragments in reversed order\n"
                " --fake-from-hex <value>  load fake packets from HEX values\n"
                " --fake-with-sni <value>  generate fake packets with given SNI\n"
                " --fake-gen <value>       generate random fake packets\n"
                " --fake-resend <value>    send each fake packet N times\n"
                " --max-payload [value]    skip packets with payload > value\n"
                " --daemon / -D            run as background daemon\n"
                "\n"
                "Presets:\n"
                " -5  -f 2 -e 2 --auto-ttl --reverse-frag --max-payload\n"
                " -6  -f 2 -e 2 --wrong-seq --reverse-frag --max-payload\n"
                " -7  -f 2 -e 2 --wrong-chksum --reverse-frag --max-payload\n"
                " -8  -f 2 -e 2 --wrong-seq --wrong-chksum --reverse-frag --max-payload\n"
                " -9  -f 2 -e 2 --wrong-seq --wrong-chksum --reverse-frag --max-payload -q (default)\n"
                );
                exit(ERROR_DEFAULT);
        }
    }

    /* Set defaults */
    if (!http_fragment_size) http_fragment_size = 2;
    if (!https_fragment_size) https_fragment_size = 2;
    if (!auto_ttl_1) auto_ttl_1 = 1;
    if (!auto_ttl_2) auto_ttl_2 = 4;
    if (do_auto_ttl) {
        if (!ttl_min_nhops) ttl_min_nhops = 3;
        if (!auto_ttl_max) auto_ttl_max = 10;
    }

    printf("Block passive: %d\nBlock QUIC: %d\n"
           "Fragment HTTP: %u\nFragment HTTPS: %u\n"
           "Native frag: %d\nReverse frag: %d\n"
           "hoSt: %d\nHost no space: %d\nMix Host: %d\n"
           "HTTP AllPorts: %d\n"
           "DNS redirect: %d\nDNSv6 redirect: %d\n"
           "Fake TTL: %s (fixed:%hu, auto:%hu-%hu-%hu, min:%hu)\n"
           "Wrong checksum: %d\nWrong SEQ: %d\n"
           "Custom fakes: %d\nFake resend: %d\n"
           "Max payload: %hu\n",
           do_passivedpi, do_block_quic,
           (do_fragment_http ? http_fragment_size : 0),
           (do_fragment_https ? https_fragment_size : 0),
           do_native_frag, do_reverse_frag,
           do_host, do_host_removespace, do_host_mixedcase,
           do_http_allports,
           do_dnsv4_redirect, do_dnsv6_redirect,
           do_auto_ttl ? "auto" : (do_fake_packet ? "fixed" : "disabled"),
           ttl_of_fake_packet, do_auto_ttl ? auto_ttl_1 : 0,
           do_auto_ttl ? auto_ttl_2 : 0, do_auto_ttl ? auto_ttl_max : 0, ttl_min_nhops,
           do_wrong_chksum, do_wrong_seq,
           fakes_count, fakes_resend,
           max_payload_size);

    /*
     * On Linux/macOS, we use a single NFQUEUE/divert socket.
     * The filter expression is platform-specific.
     * On Linux: "queue_num=0" (iptables rules handle the actual filtering)
     * On macOS: "port=1234" (pf rules handle the actual filtering)
     */
    puts("\nOpening packet capture filter...");
    filter_num = 0;

#ifdef __APPLE__
    const char *filter_expr = "port=1234";
#else
    const char *filter_expr = "queue_num=0";
#endif

    /*
     * On Linux/macOS, passive DPI blocking and QUIC blocking are handled
     * by iptables/pf DROP rules, not by the application.
     * We only need one filter for the main processing.
     */
    if (do_passivedpi) {
        printf("Passive DPI blocking: use iptables/pf rules to drop RST packets with low IP ID.\n");
    }
    if (do_block_quic) {
        printf("QUIC blocking: use iptables/pf rules to drop outbound UDP/443.\n");
    }

    /* Main filter for active DPI circumvention */
    filters[filter_num] = pkt_open(filter_expr, 0);
    w_filter = filters[filter_num];
    filter_num++;

    if (!w_filter) {
        printf("Error: Could not open packet filter!\n");
        die();
    }

    if (debug_exit) {
        printf("Debug Exit\n");
        exit(EXIT_SUCCESS);
    }

    printf("Filter activated, GoodbyeDPI is now running!\n");
    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

    /* Suppress unused variable warnings for features not yet fully ported */
    (void)do_dns_verb;
    (void)dnsv4_port;
    (void)dnsv6_port;

    /* ============================================================
     * Main packet processing loop
     * ============================================================ */
    while (1) {
        if (pkt_receive(w_filter, &pkt)) {
            debug("Got %s packet, len=%d!\n",
                   pkt.direction == PACKET_DIR_OUTBOUND ? "outbound" : "inbound",
                   pkt.raw_packet_len);

            should_reinject = 1;
            should_recalc_checksum = 0;
            sni_ok = 0;

            /* ---- TCP packet WITH DATA ---- */
            if (pkt.has_tcp && pkt.payload && pkt.payload_len > 0) {

                /* Handle INBOUND packet: find HTTP REDIRECT */
                if (pkt.direction == PACKET_DIR_INBOUND && pkt.payload_len > 16) {
                    if (do_passivedpi && is_passivedpi_redirect((char*)pkt.payload, pkt.payload_len)) {
                        if (!pkt.is_ipv6) {
                            should_reinject = 0;
                        } else if (pkt.is_ipv6 && pkt.ipv6_flow_label == 0x0) {
                            should_reinject = 0;
                        }
                    }
                }

                /* Handle OUTBOUND HTTPS: search for TLS ClientHello */
                else if (pkt.direction == PACKET_DIR_OUTBOUND &&
                        ((do_fragment_https ? pkt.payload_len == https_fragment_size : 0) ||
                         pkt.payload_len > 16) &&
                         pkt.dst_port != 80 &&
                         (do_fake_packet || do_native_frag))
                {
                    if ((pkt.payload_len == 2 && memcmp(pkt.payload, "\x16\x03", 2) == 0) ||
                        (pkt.payload_len >= 3 && (
                            memcmp(pkt.payload, "\x16\x03\x01", 3) == 0 ||
                            memcmp(pkt.payload, "\x16\x03\x03", 3) == 0)))
                    {
                        if (do_blacklist || do_fragment_by_sni) {
                            sni_ok = extract_sni((char*)pkt.payload, pkt.payload_len,
                                        &host_addr, &host_len);
                        }
                        if ((do_blacklist && sni_ok &&
                              blackwhitelist_check_hostname(host_addr, host_len)) ||
                             (do_blacklist && !sni_ok && do_allow_no_sni) ||
                             (!do_blacklist))
                        {
                            if (do_fake_packet) {
                                /* Send fake HTTPS request */
                                should_send_fake = 1;
                                if (do_auto_ttl || ttl_min_nhops) {
                                    if (tcp_handle_outgoing(pkt.src_ip, pkt.dst_ip,
                                            htons(pkt.src_port), htons(pkt.dst_port),
                                            &tcp_conn_info, pkt.is_ipv6)) {
                                        if (do_auto_ttl) {
                                            ttl_of_fake_packet = tcp_get_auto_ttl(
                                                tcp_conn_info.ttl, auto_ttl_1, auto_ttl_2,
                                                ttl_min_nhops, auto_ttl_max);
                                            if (do_tcp_verb)
                                                printf("Connection TTL=%d, Fake TTL=%d\n",
                                                       tcp_conn_info.ttl, ttl_of_fake_packet);
                                        } else if (ttl_min_nhops) {
                                            if (!tcp_get_auto_ttl(tcp_conn_info.ttl, 0, 0, ttl_min_nhops, 0))
                                                should_send_fake = 0;
                                        }
                                    }
                                }
                                if (should_send_fake)
                                    send_fake_https_request(w_filter, &pkt,
                                        ttl_of_fake_packet, do_wrong_chksum, do_wrong_seq);
                            }
                            if (do_native_frag) {
                                should_recalc_checksum = 1;
                            }
                        }
                    }
                }

                /* Handle OUTBOUND HTTP: search for Host header */
                else if (pkt.direction == PACKET_DIR_OUTBOUND &&
                        pkt.payload_len > 16 &&
                        (do_http_allports ? 1 : (pkt.dst_port == 80)) &&
                        find_http_method_end((char*)pkt.payload,
                                             (do_fragment_http ? http_fragment_size : 0u),
                                             &http_req_fragmented) &&
                        (do_host || do_host_removespace ||
                        do_host_mixedcase || do_fragment_http_persistent ||
                        do_fake_packet))
                {
                    if (find_header_and_get_info((char*)pkt.payload, pkt.payload_len,
                        http_host_find, &hdr_name_addr, &hdr_value_addr, &hdr_value_len) &&
                        hdr_value_len > 0 && hdr_value_len <= HOST_MAXLEN &&
                        (do_blacklist ? blackwhitelist_check_hostname(hdr_value_addr, hdr_value_len) : 1))
                    {
                        host_addr = hdr_value_addr;
                        host_len = hdr_value_len;

                        if (do_native_frag) {
                            should_recalc_checksum = 1;
                        }

                        if (do_fake_packet) {
                            should_send_fake = 1;
                            if (do_auto_ttl || ttl_min_nhops) {
                                if (tcp_handle_outgoing(pkt.src_ip, pkt.dst_ip,
                                        htons(pkt.src_port), htons(pkt.dst_port),
                                        &tcp_conn_info, pkt.is_ipv6)) {
                                    if (do_auto_ttl) {
                                        ttl_of_fake_packet = tcp_get_auto_ttl(
                                            tcp_conn_info.ttl, auto_ttl_1, auto_ttl_2,
                                            ttl_min_nhops, auto_ttl_max);
                                    } else if (ttl_min_nhops) {
                                        if (!tcp_get_auto_ttl(tcp_conn_info.ttl, 0, 0, ttl_min_nhops, 0))
                                            should_send_fake = 0;
                                    }
                                }
                            }
                            if (should_send_fake)
                                send_fake_http_request(w_filter, &pkt,
                                    ttl_of_fake_packet, do_wrong_chksum, do_wrong_seq);
                        }

                        if (do_host_mixedcase) {
                            mix_case(host_addr, host_len);
                            should_recalc_checksum = 1;
                        }

                        if (do_host) {
                            memcpy(hdr_name_addr, http_host_replace, strlen(http_host_replace));
                            should_recalc_checksum = 1;
                        }

                        if (do_additional_space && do_host_removespace) {
                            method_addr = find_http_method_end((char*)pkt.payload,
                                            (do_fragment_http ? http_fragment_size : 0), NULL);
                            if (method_addr) {
                                memmove(method_addr + 1, method_addr,
                                        (size_t)(host_addr - method_addr - 1));
                                should_recalc_checksum = 1;
                            }
                        } else if (do_host_removespace) {
                            if (find_header_and_get_info((char*)pkt.payload, pkt.payload_len,
                                        http_useragent_find, &hdr_name_addr,
                                        &hdr_value_addr, &hdr_value_len))
                            {
                                useragent_addr = hdr_value_addr;
                                useragent_len = hdr_value_len;
                                if (useragent_addr && useragent_len > 0) {
                                    if (useragent_addr > host_addr) {
                                        memmove(host_addr - 1, host_addr,
                                                (size_t)(useragent_addr + useragent_len - host_addr));
                                        host_addr -= 1;
                                        *(char*)((unsigned char*)useragent_addr + useragent_len - 1) = ' ';
                                        should_recalc_checksum = 1;
                                    } else {
                                        memmove(useragent_addr + useragent_len + 1,
                                                useragent_addr + useragent_len,
                                                (size_t)(host_addr - 1 - (useragent_addr + useragent_len)));
                                        *(char*)((unsigned char*)useragent_addr + useragent_len) = ' ';
                                        should_recalc_checksum = 1;
                                    }
                                }
                            }
                        }
                    }
                }

                /* Native fragmentation */
                if (should_reinject && should_recalc_checksum && do_native_frag) {
                    current_fragment_size = 0;
                    if (do_fragment_http && pkt.dst_port == 80) {
                        current_fragment_size = http_fragment_size;
                    } else if (do_fragment_https && pkt.dst_port != 80) {
                        if (do_fragment_by_sni && sni_ok) {
                            current_fragment_size = (unsigned int)((char*)host_addr - (char*)pkt.payload);
                        } else {
                            current_fragment_size = https_fragment_size;
                        }
                    }

                    if (current_fragment_size) {
                        send_native_fragment(w_filter, &pkt,
                                            current_fragment_size, do_reverse_frag);
                        send_native_fragment(w_filter, &pkt,
                                            current_fragment_size, !do_reverse_frag);
                        continue; /* Don't reinject original */
                    }
                }
            }

            /* ---- TCP packet WITHOUT DATA (SYN+ACK handling) ---- */
            else if (pkt.has_tcp && (!pkt.payload || pkt.payload_len == 0)) {
                if (pkt.direction == PACKET_DIR_INBOUND &&
                    pkt.tcp_syn == 1 && pkt.tcp_ack_flag == 1) {

                    if (do_fake_packet && (do_auto_ttl || ttl_min_nhops)) {
                        tcp_handle_incoming(pkt.src_ip, pkt.dst_ip,
                            htons(pkt.src_port), htons(pkt.dst_port),
                            pkt.is_ipv6, pkt.ip_ttl);
                    }

                    if (!do_native_frag) {
                        if (do_fragment_http && pkt.src_port == 80) {
                            pkt_set_tcp_window(&pkt, (uint16_t)http_fragment_size);
                            should_recalc_checksum = 1;
                        } else if (do_fragment_https && pkt.src_port != 80) {
                            pkt_set_tcp_window(&pkt, (uint16_t)https_fragment_size);
                            should_recalc_checksum = 1;
                        }
                    }
                }
            }

            /* ---- UDP packet with data (DNS redirection) ---- */
            else if (pkt.has_udp && pkt.payload && pkt.payload_len > 0) {
                if ((do_dnsv4_redirect && !pkt.is_ipv6) ||
                    (do_dnsv6_redirect && pkt.is_ipv6))
                {
                    if (pkt.direction == PACKET_DIR_INBOUND) {
                        if (dns_handle_incoming(pkt.dst_ip, htons(pkt.dst_port),
                                    (char*)pkt.payload, pkt.payload_len,
                                    &dns_conn_info, pkt.is_ipv6))
                        {
                            /* TODO: Modify source IP/port in packet for DNS response */
                            should_recalc_checksum = 1;
                        } else {
                            if (dns_is_dns_packet((char*)pkt.payload, pkt.payload_len, 0))
                                should_reinject = 0;
                        }
                    } else if (pkt.direction == PACKET_DIR_OUTBOUND) {
                        if (dns_handle_outgoing(pkt.src_ip, htons(pkt.src_port),
                                    pkt.dst_ip, htons(pkt.dst_port),
                                    (char*)pkt.payload, pkt.payload_len, pkt.is_ipv6))
                        {
                            /* TODO: Modify destination IP/port in packet for DNS request */
                            should_recalc_checksum = 1;
                        } else {
                            if (dns_is_dns_packet((char*)pkt.payload, pkt.payload_len, 1))
                                should_reinject = 0;
                        }
                    }
                }
            }

            /* Reinject the packet */
            if (should_reinject) {
                if (should_recalc_checksum) {
                    pkt_recalc_checksums(&pkt);
                }
                pkt_send(w_filter, &pkt);
            }
        }
        else {
            if (!exiting)
                printf("Error receiving packet!\n");
            break;
        }
    }

    return 0;
}
