//
// Created by Zikai Liu on 5/14/22.
//

#ifndef AOS_NAMESERVICE_INTERNAL_H
#define AOS_NAMESERVICE_INTERNAL_H

#include "aos/aos.h"
#include "aos/waitset.h"
#include "aos/nameserver.h"
#include "aos/aos_rpc.h"

extern struct aos_rpc ns_rpc;

struct enumerate_reply_msg {
    size_t num;
    char buf[0];
};

enum msg_identifier {
    IDENTIFIER_NORMAL,
};

/*
 * The caller should ensure ns_rpc is ready before calling the following functions
 * (except client_rpc)
 */

errval_t server_register(const char *name, nameservice_receive_handler_t recv_handler,
                         void *st);
errval_t server_deregister(const char *name);
errval_t server_bind_lmp(domainid_t pid, const char *name);
errval_t server_bind_ump(domainid_t pid, const char *name, struct capref frame);
errval_t server_kill_by_pid(domainid_t pid);

struct client_side_chan;

errval_t client_lookup_service(const char *name, struct client_side_chan **ret);
errval_t client_enumerate_service(char *query, size_t *num, char ***ret);
errval_t client_rpc(struct client_side_chan *chan, void *message, size_t bytes,
                    void **response, size_t *response_bytes, struct capref tx_cap,
                    struct capref rx_cap);

errval_t client_kill_by_pid(domainid_t pid);

#endif
