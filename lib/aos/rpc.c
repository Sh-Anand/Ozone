//
// Created by Zikai Liu on 5/29/22.
//

#include <aos/rpc.h>
#include <rpc_priv.h>
#include <string.h>

void aos_rpc_init(struct aos_rpc *rpc)
{
    memset(rpc, 0, sizeof(*rpc));
    assert(rpc->chan.type == AOS_CHAN_TYPE_UNKNOWN);
}

void aos_rpc_destroy(struct aos_rpc *rpc)
{
    aos_chan_destroy(&rpc->chan);
}

static void aos_chan_generic_init(struct aos_chan *chan) {
    chan->handler = NULL;
    chan->arg = NULL;
    thread_mutex_init(&chan->mutex);
}

void aos_chan_lmp_init(struct aos_chan *chan)
{
    aos_chan_generic_init(chan);
    chan->type = AOS_CHAN_TYPE_LMP;
    lmp_chan_init(&chan->lc);
    assert(chan->lc.connstate == LMP_DISCONNECTED);
}

errval_t aos_chan_lmp_accept(struct aos_chan *chan, size_t buflen_words,
                             struct capref endpoint)
{
    aos_chan_generic_init(chan);
    chan->type = AOS_CHAN_TYPE_LMP;
    errval_t err = lmp_chan_accept(&chan->lc, buflen_words, endpoint);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_LMP_CHAN_ACCEPT);
    }
    assert(chan->lc.connstate == LMP_CONNECTED);

    // Send the local endpoint to the other side to finish binding
    err = rpc_lmp_call(chan, RPC_ACK, chan->lc.local_cap, NULL, 0, NULL, NULL, NULL, false);
    return err;
}

errval_t aos_chan_lmp_init_local(struct aos_chan *chan, size_t buflen_words)
{
    aos_chan_generic_init(chan);
    chan->type = AOS_CHAN_TYPE_LMP;
    return lmp_chan_init_local(&chan->lc, buflen_words);
    assert(chan->lc.connstate == LMP_BIND_WAIT);
}

errval_t aos_chan_ump_init(struct aos_chan *chan, struct capref zeroed_frame,
                           enum UMP_CHAN_ROLE role, domainid_t pid)
{
    aos_chan_generic_init(chan);
    chan->type = AOS_CHAN_TYPE_UMP;
    return ump_chan_init(&chan->uc, zeroed_frame, role, pid);
}

errval_t aos_chan_ump_init_from_buf(struct aos_chan *chan, void *zeroed_buf,
                                    enum UMP_CHAN_ROLE role, domainid_t pid)
{
    aos_chan_generic_init(chan);
    chan->type = AOS_CHAN_TYPE_UMP;
    return ump_chan_init_from_buf(&chan->uc, zeroed_buf, role, pid);
}

void aos_chan_destroy(struct aos_chan *chan)
{
    switch (chan->type) {
    case AOS_CHAN_TYPE_LMP:
        lmp_chan_destroy(&chan->lc);
        break;
    case AOS_CHAN_TYPE_UMP:
        ump_chan_destroy(&chan->uc);
        break;
    case AOS_CHAN_TYPE_ECHO:
        chan->handler = NULL;
        break;
    default:
        break;
    }
    chan->type = AOS_CHAN_TYPE_UNKNOWN;
}

errval_t aos_chan_register_recv(struct aos_chan *chan, struct waitset *ws,
                                aos_chan_handler_t handler, void *arg) {
    switch (chan->type) {
    case AOS_CHAN_TYPE_LMP:
        return rpc_lmp_chan_register_recv(chan, ws, handler, arg);
    case AOS_CHAN_TYPE_UMP:
        return rpc_ump_chan_register_recv(chan, ws, handler, arg);
    case AOS_CHAN_TYPE_ECHO:
        return LIB_ERR_NOT_IMPLEMENTED;
    default:
        assert(!"unknown aos_chan type");
    }
}

errval_t aos_chan_deregister_recv(struct aos_chan *chan) {
    switch (chan->type) {
    case AOS_CHAN_TYPE_LMP:
        return lmp_chan_deregister_recv(&chan->lc);
    case AOS_CHAN_TYPE_UMP:
        return ump_chan_deregister_recv(&chan->uc);
    case AOS_CHAN_TYPE_ECHO:
        return LIB_ERR_NOT_IMPLEMENTED;
    default:
        assert(!"unknown aos_chan type");
    }
}

bool aos_chan_can_recv(struct aos_chan *chan) {
    switch (chan->type) {
    case AOS_CHAN_TYPE_UNKNOWN:
        return false;
    case AOS_CHAN_TYPE_LMP:
        return lmp_chan_can_recv(&chan->lc);
    case AOS_CHAN_TYPE_UMP:
        return ump_chan_can_recv(&chan->uc);
    case AOS_CHAN_TYPE_ECHO:
        return chan->handler != NULL;
    default:
        assert(!"unknown aos_chan type");
    }
}

errval_t aos_chan_call(struct aos_chan *chan, rpc_identifier_t identifier,
                      struct capref call_cap, const void *call_buf, size_t call_size,
                      struct capref *ret_cap, void **ret_buf, size_t *ret_size)
{
    switch (chan->type) {
    case AOS_CHAN_TYPE_LMP:
        return rpc_lmp_call(chan, identifier, call_cap, call_buf, call_size, ret_cap,
                            ret_buf, ret_size, false);
    case AOS_CHAN_TYPE_UMP:
        return rpc_ump_call(chan, identifier, call_cap, call_buf, call_size, ret_cap,
                            ret_buf, ret_size);
    case AOS_CHAN_TYPE_ECHO:
        return LIB_ERR_NOT_IMPLEMENTED;
    default:
        assert(!"unknown aos_chan type");
    }
}

errval_t aos_chan_send(struct aos_chan *chan, rpc_identifier_t identifier,
                       struct capref cap, const void *buf, size_t size, bool no_blocking)
{
    switch (chan->type) {
    case AOS_CHAN_TYPE_LMP:
        return rpc_lmp_send(&chan->lc, identifier, cap, buf, size, no_blocking);
    case AOS_CHAN_TYPE_UMP:
        return rpc_ump_send(&chan->uc, identifier, cap, buf, size);
    case AOS_CHAN_TYPE_ECHO:
        return LIB_ERR_NOT_IMPLEMENTED;
    default:
        assert(!"unknown aos_chan type");
    }
}

errval_t aos_chan_ack(struct aos_chan *chan, struct capref cap, const void *buf,
                      size_t size)
{
    return aos_chan_send(chan, RPC_ACK, cap, buf, size, false);
}

errval_t aos_chan_nack(struct aos_chan *chan, errval_t err)
{
    return aos_chan_send(chan, RPC_ERR, NULL_CAP, &err, sizeof(errval_t), false);
}

bool aos_chan_is_connected(struct aos_chan *chan) {
    switch (chan->type) {
    case AOS_CHAN_TYPE_LMP:
        return (chan->lc.connstate == LMP_CONNECTED);
    case AOS_CHAN_TYPE_UMP:
        return true;
    case AOS_CHAN_TYPE_ECHO:
        return (chan->handler != NULL);
    default:
        assert(!"unknown aos_chan type");
    }
}