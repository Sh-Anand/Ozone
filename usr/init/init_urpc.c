//
// Created by Zikai Liu on 5/18/22.
//

#include "init_urpc.h"

struct aos_chan *urpc_listen_from[MAX_COREID];
struct aos_rpc *urpc[MAX_COREID];

errval_t setup_urpc(coreid_t core, struct capref urpc_frame, bool zero_frame,
                    bool listener_first)
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

    if (zero_frame) {
        // BSP core is responsible for zeroing the URPC frame
        memset(urpc_buffer, 0, INIT_BIDIRECTIONAL_URPC_FRAME_SIZE);
    }

    // Init URPC listener
    urpc_listen_from[core] = malloc(sizeof(**urpc_listen_from));
    if (urpc_listen_from[core] == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }
    err = aos_chan_ump_init_from_buf(
        urpc_listen_from[core],
        urpc_buffer + (listener_first ? 0 : UMP_CHAN_SHARED_FRAME_SIZE), UMP_CHAN_SERVER, 0);
    if (err_is_fail(err)) {
        return err;
    }

    // Init UPRC calling point
    urpc[core] = malloc(sizeof(**urpc));
    if (urpc[core] == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }
    aos_rpc_init(urpc[core]);
    err = aos_chan_ump_init_from_buf(
        &urpc[core]->chan,
        urpc_buffer + +(listener_first ? UMP_CHAN_SHARED_FRAME_SIZE : 0), UMP_CHAN_CLIENT, 0);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_UMP_CHAN_INIT);
    }

    return SYS_ERR_OK;
}