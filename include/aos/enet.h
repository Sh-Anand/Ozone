#ifndef _AOS_ENET_H_
#define _AOS_ENET_H_

#include <netutil/ip.h>

typedef uint16_t enet_udp_socket;

typedef void(*udp_listener_t)(ip_addr_t ip, uint16_t port, void *data, size_t bytes);

#define ENET_UDP_ANY_PORT 0
errval_t enet_udp_create_socket(uint16_t port, enet_udp_socket *socket, udp_listener_t listener);
errval_t enet_udp_destroy_socket(enet_udp_socket socket);
errval_t enet_udp_send(void *data, size_t bytes, ip_addr_t dst_ip, uint16_t dst_port, enet_udp_socket socket);

#endif
