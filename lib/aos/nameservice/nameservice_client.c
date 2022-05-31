//
// Created by Zikai Liu on 5/15/22.
//

#include <aos/aos.h>
#include "internal.h"

#define CLIENT_SIDE_LMP_BUF_LEN 32

struct client_side_chan {
    struct aos_rpc rpc;
    domainid_t pid;  // pid of the other side
    LIST_ENTRY(client_side_chan) link;
};

static LIST_HEAD(, client_side_chan) chans = LIST_HEAD_INITIALIZER(&chans);

// chan initialized as AOS_CHAN_TYPE_UNKNOWN, inserted into chans
static errval_t create_chan(domainid_t pid, struct client_side_chan **ret)
{
    struct client_side_chan *chan = malloc(sizeof(*chan));
    if (chan == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }
    chan->rpc.chan.type = AOS_CHAN_TYPE_UNKNOWN;
    chan->pid = pid;
    LIST_INSERT_HEAD(&chans, chan, link);
    *ret = chan;
    return SYS_ERR_OK;
}

static void delete_chan(struct client_side_chan *chan)
{
    if (chan == NULL) {
        return;
    }
    LIST_REMOVE(chan, link);
    aos_chan_destroy(&chan->rpc.chan);
    free(chan);
}

errval_t client_lookup_service(const char *name, struct client_side_chan **ret)
{
    errval_t err;

    // Query the nameserver
    struct capref ret_cap = NULL_CAP;
    void *ret_buf = NULL;
    size_t ret_size = 0;
    err = aos_rpc_call(&ns_rpc, NAMESERVICE_LOOKUP, NULL_CAP, name, strlen(name) + 1,
                       &ret_cap, &ret_buf, &ret_size);
    if (err_is_fail(err)) {
        return err;
    }

    // Sanity check
    assert(ret_size == sizeof(domainid_t));
    domainid_t pid = *((domainid_t *)ret_buf);

    // Identify the return cap
    assert(!capref_is_null(ret_cap));
    struct capability c;
    err = cap_direct_identify(ret_cap, &c);
    if (err_is_fail(err)) {
        err = err_push(err, LIB_ERR_CAP_IDENTIFY);
        goto FAILURE_IDENTIFY_CAP;
    }

    // Create a new channel
    struct client_side_chan *chan = NULL;
    err = create_chan(pid, &chan);
    if (err_is_fail(err)) {
        goto FAILURE_CREATE_CHAN;
    }

    switch (c.type) {
    case ObjType_EndPointLMP: {
        // The following call include sending the local cap to complete setup
        err = aos_chan_lmp_accept(&chan->rpc.chan, CLIENT_SIDE_LMP_BUF_LEN, ret_cap);
        if (err_is_fail(err)) {
            goto FAILURE_CHAN_SETUP;
        }
    } break;
    case ObjType_Frame: {
        err = aos_chan_ump_init(&chan->rpc.chan, ret_cap, UMP_CHAN_CLIENT, pid);
        if (err_is_fail(err)) {
            goto FAILURE_CHAN_SETUP;
        }
    } break;
    default:
        assert(!"Invalid cap to setup channel");
    }

    *ret = chan;
    free(ret_buf);
    return SYS_ERR_OK;

FAILURE_CHAN_SETUP:
    delete_chan(chan);
FAILURE_CREATE_CHAN:
FAILURE_IDENTIFY_CAP:
    free(ret_buf);
    return err;
}

errval_t client_enumerate_service(char *query, size_t *num, char **ret)
{
    errval_t err;

    // Query the nameserver
    void *ret_buf = NULL;
    size_t ret_size = 0;
    err = aos_rpc_call(&ns_rpc, NAMESERVICE_ENUMERATE, NULL_CAP, query, strlen(query) + 1, NULL, &ret_buf,
                       &ret_size);
    if (err_is_fail(err)) {
        return err;
    }

    assert(ret_size >= sizeof(struct ns_enumerate_reply_msg));
    struct ns_enumerate_reply_msg *reply_msg = (struct ns_enumerate_reply_msg *)ret_buf;

    size_t i = 0;
    char *buf = reply_msg->buf;
    while (i < reply_msg->num && i < *num) {
        ret[i] = strdup(buf);
        while(*buf != '\0') ++buf;
        ++buf;
        ++i;
    }
    *num = i;
    free(ret_buf);

    return SYS_ERR_OK;
}

errval_t client_rpc(struct client_side_chan *chan, void *message, size_t bytes,
                    void **response, size_t *response_bytes, struct capref tx_cap,
                    struct capref rx_cap)
{
    errval_t err;

    struct capref ret_cap = NULL_CAP;
    err = aos_rpc_call(&chan->rpc, DEFAULT_IDENTIFIER, tx_cap, message, bytes, &ret_cap, response, response_bytes);
    if (err_is_fail(err)) {
        return err;
    }

    if (!capref_is_null(rx_cap)) {
        if (!capref_is_null(ret_cap)) {
            err = cap_copy(rx_cap, ret_cap);
            if (err_is_fail(err)) {
                return err_push(err, LIB_ERR_CAP_COPY);
            }
            err = cap_destroy(ret_cap);
            if (err_is_fail(err)) {
                return err_push(err, LIB_ERR_CAP_DESTROY);
            }
        }
    } else {
        if (!capref_is_null(ret_cap)) {
            DEBUG_PRINTF("WARNING: client_rpc: received a cap but given up\n");
        }
    }

    return SYS_ERR_OK;
}

errval_t client_kill_by_pid(domainid_t pid) {
    return LIB_ERR_NOT_IMPLEMENTED;
}