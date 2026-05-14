#ifndef _FAKEPACKETS_H
#define _FAKEPACKETS_H

#include "goodbyedpi.h"

extern int fakes_count;
extern int fakes_resend;

#ifdef _WIN32
/*
 * Windows (legacy) API — used by goodbyedpi.c with WinDivert directly.
 * These are defined in fakepackets.c only when building with WinDivert.
 */
#include "windivert.h"

int send_fake_http_request(const HANDLE w_filter,
                                  const PWINDIVERT_ADDRESS addr,
                                  const char *pkt,
                                  const UINT packetLen,
                                  const BOOL is_ipv6,
                                  const BYTE set_ttl,
                                  const BYTE set_checksum,
                                  const BYTE set_seq
                                 );
int send_fake_https_request(const HANDLE w_filter,
                                   const PWINDIVERT_ADDRESS addr,
                                   const char *pkt,
                                   const UINT packetLen,
                                   const BOOL is_ipv6,
                                   const BYTE set_ttl,
                                   const BYTE set_checksum,
                                   const BYTE set_seq
                                 );
#else
/*
 * Cross-platform API — used by goodbyedpi_main.c with platform abstraction.
 */
#include "platform/platform.h"

int send_fake_http_request(pkt_handle_t w_filter,
                           packet_info_t *pkt_info,
                           const BYTE set_ttl,
                           const BYTE set_checksum,
                           const BYTE set_seq
                          );

int send_fake_https_request(pkt_handle_t w_filter,
                            packet_info_t *pkt_info,
                            const BYTE set_ttl,
                            const BYTE set_checksum,
                            const BYTE set_seq
                           );
#endif

int fake_load_from_hex(const char *data);
int fake_load_from_sni(const char *domain_name);
int fake_load_random(unsigned int count, unsigned int maxsize);

#endif /* _FAKEPACKETS_H */
