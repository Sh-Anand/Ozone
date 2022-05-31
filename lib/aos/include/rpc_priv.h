//
// Created by Zikai Liu on 5/29/22.
//

#ifndef AOS_RPC_PRIV_H
#define AOS_RPC_PRIV_H

#include <aos/rpc.h>

enum {
    RPC_ACK_CAP_CHANNEL = RPC_ERR + 1,  // on UMP: capability transfer channel is setup
    RPC_PUT_CAP,          // on LMP: this message is putting a cap in the init channel
    RPC_MSG_IN_FRAME,     // on LMP: the actual message in encode in the frame cap
    INTERNAL_RPC_IDENTIFIER_COUNT,

    RPC_SPECIAL_CAP_TRANSFER_FLAG = (1U << (sizeof(uint8_t) * 8 - 1))
};
STATIC_ASSERT(INTERNAL_RPC_IDENTIFIER_COUNT <= RPC_IDENTIFIER_USER_START,
              "RPC_IDENTIFIER_USER_START too small");
STATIC_ASSERT(RPC_SPECIAL_CAP_TRANSFER_FLAG > RPC_IDENTIFIER_USER_END,
              "RPC_IDENTIFIER_USER_END too large");
STATIC_ASSERT(RPC_SPECIAL_CAP_TRANSFER_FLAG == 0x80, "RPC_SPECIAL_CAP_TRANSFER_FLAG");

errval_t lmp_try_send(struct lmp_chan *lc, uintptr_t *send_words, struct capref send_cap,
                      bool non_blocking);

errval_t lmp_try_recv(struct lmp_chan *lc, struct lmp_recv_msg *recv_msg,
                      struct capref *recv_cap);

struct lmp_helper {
    struct capref payload_frame;
    void *mapped_frame;
};

errval_t rpc_lmp_serialize(rpc_identifier_t identifier, struct capref cap, const void *buf,
                       size_t size, uintptr_t ret_payload[LMP_MSG_LENGTH],
                       struct capref *ret_cap, struct lmp_helper *helper);

/**
 * Deserialize an LMP message
 * @param recv_msg
 * @param recv_cap_ptr   May get changed by the function (if the cap is a mapped frame).
 * @param ret_type
 * @param ret_buf        Points to somewhere in recv_msg or a mapped frame. Do NOT free.
 * @param ret_size
 * @param helper
 * @return
 */
errval_t rpc_lmp_deserialize(struct lmp_recv_msg *recv_msg, struct capref *recv_cap_ptr,
                         rpc_identifier_t *ret_type, uint8_t **ret_buf, size_t *ret_size,
                         struct lmp_helper *helper);

errval_t rpc_lmp_cleanup(struct lmp_helper *helper);

errval_t rpc_lmp_send(struct lmp_chan *lc, rpc_identifier_t identifier,
                      struct capref cap, const void *buf, size_t size,
                      bool non_blocking);

errval_t rpc_lmp_call(struct aos_chan *chan, rpc_identifier_t identifier,
                      struct capref call_cap, const void *call_buf,
                      size_t call_size, struct capref *ret_cap, void **ret_buf,
                      size_t *ret_size, bool no_lock);

errval_t rpc_lmp_chan_register_recv(struct aos_chan *chan, struct waitset *ws,
                                    aos_chan_handler_t handler, void *arg);

/**
 * Prefix an identifier to the buffer
 * @param buf         The input buffer (can be NULL if size is also 0).
 * @param size
 * @param identifier
 * @param ret
 * @return
 */
errval_t rpc_ump_prefix_identifier(const void *buf, size_t size, rpc_identifier_t identifier,
                               void **ret);

errval_t rpc_ump_send(struct ump_chan *uc, rpc_identifier_t identifier, struct capref cap,
                      const void *buf, size_t size);

errval_t rpc_ump_ack(struct ump_chan *uc, struct capref cap, const void *buf, size_t size);

errval_t rpc_ump_nack(struct ump_chan *uc, errval_t err);

errval_t rpc_ump_call(struct aos_chan *chan, rpc_identifier_t identifier,
                      struct capref call_cap, const void *call_buf, size_t call_size,
                      struct capref *ret_cap, void **ret_buf, size_t *ret_size);

errval_t rpc_ump_recv_cap(struct ump_chan *uc, struct capref *recv_cap);

errval_t rpc_ump_chan_register_recv(struct aos_chan *chan, struct waitset *ws,
                                    aos_chan_handler_t handler, void *arg);

#endif  // AOS_RPC_PRIV_H
