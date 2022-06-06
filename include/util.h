
#ifndef __UTIL_H__
#define __UTIL_H__

#include "types.h"

/**
 * IP related stuff
 *
 */
struct ipsec_ip_addr
{
    __u32 addr;
};

struct ipsec_in_addr
{
    __u32 s_addr;
};

#define IPSEC_IP_ADDR_NONE ((__u32)0xffffffff)      /* 255.255.255.255 */
#define IPSEC_IP_ADDR_LOCALHOST ((__u32)0x7f000001) /* 127.0.0.1 */
#define IPSEC_IP4_ADDR(ipaddr, a, b, c, d) ipaddr = ipsec_htonl(((__u32)(a & 0xff) << 24) | ((__u32)(b & 0xff) << 16) | \
                                                                ((__u32)(c & 0xff) << 8) | (__u32)(d & 0xff))

#define IPSEC_IP4_ADDR_2(a, b, c, d) ((__u32)(d & 0xff) << 24) | ((__u32)(c & 0xff) << 16) | ((__u32)(b & 0xff) << 8) | (__u32)(a & 0xff)
#define IPSEC_IP4_ADDR_NET(a, b, c, d) ((__u32)(d & 0xff) << 24) | ((__u32)(c & 0xff) << 16) | ((__u32)(b & 0xff) << 8) | (__u32)(a & 0xff)

#define IPSEC_HTONL(n) (((__u32)n & 0xff) << 24) | (((__u32)n & 0xff00) << 8) | (((__u32)n & 0xff0000) >> 8) | (((__u32)n & 0xff000000) >> 24)

#define IPSEC_HTONS(n) (((__u16)n & 0xff) << 8) | (((__u16)n & 0xff00) >> 8)

__u32 ipsec_inet_addr(const char *cp);
int ipsec_inet_aton(const char *cp, struct ipsec_in_addr *addr);
__u8 *ipsec_inet_ntoa(__u32 addr);

#define ipsec_ip_addr_maskcmp(addr1, addr2, mask) ((addr1 & mask) == (addr2 & mask))
#define ipsec_ip_addr_cmp(addr1, addr2) (addr1 == addr2)

void ipsec_print_ip(ip_header *header);
void ipsec_dump_buffer(char *, unsigned char *, int, int);

__u16 ipsec_htons(__u16 n);
__u16 ipsec_ntohs(__u16 n);
__u32 ipsec_htonl(__u32 n);
__u32 ipsec_ntohl(__u32 n);

__u16 ipsec_ip_chksum(void *dataptr, __u16 len);

#endif