//
// Created by Zikai Liu on 5/18/22.
//

#include "init_urpc.h"
#include "rpc_handlers.h"

struct aos_chan *urpc_listen_from[MAX_COREID];
struct aos_rpc *urpc[MAX_COREID];

errval_t setup_urpc(coreid_t core, struct capref urpc_frame, bool listener_first)
{
    assert(urpc[core] == NULL);
    assert(urpc_listen_from[core] == NULL);

    errval_t err;

    // Map the urpc frame to our address space
    uint8_t *urpc_buffer;
    err = paging_map_frame(get_current_paging_state(), (void **)&urpc_buffer,
                           INIT_BIDIRECTIONAL_URPC_FRAME_SIZE, urpc_frame);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_PAGING_MAP);
    }

    // Init URPC listener
    urpc_listen_from[core] = malloc(sizeof(**urpc_listen_from));
    if (urpc_listen_from[core] == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }
    err = aos_chan_ump_init_from_buf(
        urpc_listen_from[core],
        urpc_buffer + (listener_first ? 0 : UMP_CHAN_SHARED_FRAME_SIZE), UMP_CHAN_SERVER,
        0);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_UMP_CHAN_INIT);
    }

    // Init UPRC calling point
    urpc[core] = malloc(sizeof(**urpc));
    if (urpc[core] == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }
    aos_rpc_init(urpc[core]);
    err = aos_chan_ump_init_from_buf(
        &urpc[core]->chan, urpc_buffer + (listener_first ? UMP_CHAN_SHARED_FRAME_SIZE : 0),
        UMP_CHAN_CLIENT, 0);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_UMP_CHAN_INIT);
    }

    return SYS_ERR_OK;
}

AOS_CHAN_HANDLER(init_urpc_handler)
{
    if (identifier >= INTERNAL_RPC_MSG_COUNT || rpc_handlers[identifier] == NULL) {
        DEBUG_PRINTF("%s: invalid URPC msg %u\n", __func__, identifier);
        return LIB_ERR_RPC_INVALID_MSG;
    }

    *free_out_payload = true;
    return rpc_handlers[identifier](arg, in_payload, in_size, out_payload, out_size,
                                    in_cap, out_cap);
}

errval_t urpc_call_to_core(coreid_t core, rpc_identifier_t identifier, void *in_payload,
                           size_t in_size, void **out_payload, size_t *out_size)
{
    struct aos_chan *chan = &urpc[core]->chan;
    assert(chan->type == AOS_CHAN_TYPE_UMP);
    struct ump_chan *uc = &chan->uc;

    errval_t err;

    uint8_t *recv_payload = NULL;
    size_t recv_size = 0;

    THREAD_MUTEX_ENTER(&chan->mutex)
    {
        // Make the call
        err = aos_chan_send(chan, identifier, NULL_CAP, in_payload, in_size, false);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "forward_to_core: failed to send\n");
            THREAD_MUTEX_BREAK;
        }

        // Dispatch events while waiting
        while (!ump_chan_can_recv(uc)) {
            err = event_dispatch_non_block(get_default_waitset());
            if (err_is_fail(err) && err != LIB_ERR_NO_EVENT) {
                DEBUG_ERR(err, "forward_to_core: failure in event_dispatch_non_block\n");
                break;
            }
        }
        if (err_is_fail(err) && err != LIB_ERR_NO_EVENT) {
            THREAD_MUTEX_BREAK;
        }

        // Receive acknowledgement and/or return message
        err = ump_chan_recv(uc, (void **)&recv_payload, &recv_size);
        if (err_is_fail(err)) {
            err = err_push(err, LIB_ERR_UMP_CHAN_RECV);
            DEBUG_ERR(err, "rpc_ump_call: failed to recv\n");
            THREAD_MUTEX_BREAK;
        }

        assert(recv_payload != NULL);
        assert(recv_size >= sizeof(rpc_identifier_t));
    }
    THREAD_MUTEX_EXIT(&chan->mutex)

    // Handle error happened in the critical section
    if (err_is_fail(err)) {
        goto RET;
    }

    assert(recv_payload != NULL);
    if (CAST_DEREF(rpc_identifier_t, recv_payload, 0) == RPC_ACK) {
        if (out_payload != NULL) {
            // XXX: it is annoying to malloc a new buf and make the copy just to remove
            //      the identifier. Consider moving it into ring buffer.
            MALLOC_OUT_MSG_WITH_SIZE(ret_buf, uint8_t,
                                     recv_size - sizeof(rpc_identifier_t));
            memcpy(ret_buf, recv_payload + sizeof(rpc_identifier_t), *out_size);
        }
        err = SYS_ERR_OK;
        goto RET;
    } else {
        assert(recv_size == sizeof(rpc_identifier_t) + sizeof(errval_t));
        err = *((errval_t *)(recv_payload + sizeof(rpc_identifier_t)));
        goto RET;
    }

RET:
    free(recv_payload);
    return err;
}