#ifndef _DRIVERS_ENET_H_
#define _DRIVERS_ENET_H_

#define ENET_DRIVER_NAME "enet"

#include <aos/enet.h>
#include <netutil/ip.h>

enum __attribute__ ((__packed__)) enet_udp_msg_type {
    create, /* Name (as null-terminated string) under which the recv_handler is accesible follows */
    destroy,
    send /* struct enet_udp_endpoint and data to be sent follow */
};

struct enet_udp_msg {
    enum enet_udp_msg_type type;
    enet_udp_socket socket;
};

struct enet_udp_endpoint {
    ip_addr_t ip;
    uint16_t port;
};

struct enet_udp_res {
    errval_t err;
    enet_udp_socket socket;
};

static inline int background_listener(void *keep_spinning) {
    while(*(bool*)keep_spinning) {
        event_dispatch_non_block(get_default_waitset());
        thread_yield();
    }

    return 0;
}

#define LISTEN_DURING_RPC_CALL(rpc_call)                                                    \
    {                                                                                       \
        bool keep_spinning = true;                                                          \
        struct thread *background = thread_create(background_listener, &keep_spinning);     \
        rpc_call                                                                            \
        keep_spinning = false;                                                              \
        thread_join(background, NULL);                                                      \
    }

#endif