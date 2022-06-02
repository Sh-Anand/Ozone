#ifndef _UDP_H_
#define _UDP_H_

#include <netutil/ip.h>


//#define UDP_DEBUG_OPTION 1

#if defined(UDP_DEBUG_OPTION)
#define UDP_DEBUG(x...) debug_printf("[ip] " x);
#else
#define UDP_DEBUG(fmt, ...) ((void)0)
#endif

#define UDP_PORT_CNT 65536
#define UDP_NO_CHECKSUM 0x0000U

/**
 * UDP header
 */
#define UDP_HLEN 8
struct udp_hdr {
  uint16_t src;
  uint16_t dest;  /* src/dest UDP ports */
  uint16_t len;
  uint16_t chksum;
} __attribute__((__packed__));

/**
 * UDP/IP pseudo header
 */
#define UDP_PSEUDO_HLEN 12
struct udp_pseudo_hdr {
  ip_addr_t src;
  ip_addr_t dst;
  uint8_t zeroes;
  uint8_t protocol;
  uint16_t len;
};

#endif
