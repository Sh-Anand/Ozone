//
// Created by Zikai Liu on 5/18/22.
//

#ifndef AOS_INIT_URPC_H
#define AOS_INIT_URPC_H

#include <aos/aos_rpc.h>

#define INIT_BIDIRECTIONAL_URPC_FRAME_SIZE (UMP_CHAN_SHARED_FRAME_SIZE * 2)
extern struct aos_chan *urpc_listen_from[MAX_COREID];  // the current init should listen on them
extern struct aos_rpc *urpc[MAX_COREID];            // the current init make calls on them

errval_t setup_urpc(coreid_t core, struct capref urpc_frame, bool zero_frame, bool listener_first);

void init_urpc_handler(void *arg);

#endif  // AOS_INIT_URPC_H
