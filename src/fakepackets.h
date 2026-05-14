#ifndef _FAKEPACKETS_H
#define _FAKEPACKETS_H

#include "goodbyedpi.h"
#include "platform/platform.h"

extern int fakes_count;
extern int fakes_resend;

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

int fake_load_from_hex(const char *data);
int fake_load_from_sni(const char *domain_name);
int fake_load_random(unsigned int count, unsigned int maxsize);

#endif /* _FAKEPACKETS_H */
