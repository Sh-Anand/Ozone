/**
 * \file
 * \brief RPC Bindings for AOS
 */

/*
 * Copyright (c) 2013-2016, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetstr. 6, CH-8092 Zurich. Attn: Systems Group.
 */

#ifndef _LIB_BARRELFISH_AOS_MESSAGES_H
#define _LIB_BARRELFISH_AOS_MESSAGES_H

#include <aos/aos.h>

enum aos_chan_type {
    AOS_CHAN_TYPE_UNKNOWN,
    AOS_CHAN_TYPE_LMP,
    AOS_CHAN_TYPE_UMP,
};

struct aos_chan {
    enum aos_chan_type type;
    union {
        struct lmp_chan lc;
        struct ump_chan uc;
    };
};

typedef uint8_t rpc_identifier_t;
enum rpc_identifier {
    RPC_ACK,
    RPC_ACK_CAP_CHANNEL,  // on UMP: capability transfer channel is setup
    RPC_PUT_CAP,          // on LMP: this message is putting a cap in the init channel
    RPC_ERR,
    RPC_MSG_IN_FRAME,     // on LMP: the actual message in encode in the frame cap
    RPC_TRANSFER_CAP,     // on LMP: transfer cap to the init channel of the given domain
    RPC_NUM,
    RPC_STR,
    RPC_RAM_REQUEST,
    RPC_PROCESS_SPAWN,
	RPC_PROCESS_SPAWN_WITH_STDIN,
    RPC_PROCESS_GET_NAME,
    RPC_PROCESS_GET_ALL_PIDS,
	RPC_TERMINAL_AQUIRE,
	RPC_TERMINAL_RELEASE,
	RPC_TERMINAL_HAS_STDIN,
    RPC_TERMINAL_GETCHAR,
    RPC_TERMINAL_PUTCHAR,
	RPC_TERMINAL_GETS,
	RPC_TERMINAL_PUTS,
    RPC_SHUTDOWN,
    RPC_STRESS_TEST,
    RPC_REGISTER_AS_NAMESERVER,
    RPC_BIND_NAMESERVER,
    RPC_MSG_COUNT,
    // User defined identifier cannot exceed this number
    RPC_IDENTIFIER_MAX = (1U << (sizeof(uint8_t) * 8 - 1)) - 1,
    // Internal usage
    RPC_SPECIAL_CAP_TRANSFER_FLAG = (1U << (sizeof(uint8_t) * 8 - 1))
};
STATIC_ASSERT(RPC_SPECIAL_CAP_TRANSFER_FLAG == 0x80, "RPC_SPECIAL_CAP_TRANSFER_FLAG");


struct aos_rpc_msg_ram {
    size_t size;
    size_t alignment;
};

struct aos_rpc {
    struct aos_chan chan;
    struct thread_mutex mutex;  // make one respond associated with one request
};

struct rpc_process_spawn_call_msg {
    coreid_t core;
	void* terminal_state;
    char cmdline[0];
} __attribute__((packed));

struct rpc_process_get_all_pids_return_msg {
    uint32_t count;
    domainid_t pids[0];
} __attribute__((packed));

struct lmp_helper {
    struct capref payload_frame;
    void *mapped_frame;
};

errval_t lmp_try_send(struct lmp_chan *lc, uintptr_t *send_words, struct capref send_cap, bool no_blocking);

errval_t lmp_try_recv(struct lmp_chan *lc, struct lmp_recv_msg *recv_msg,
                      struct capref *recv_cap);

errval_t lmp_serialize(rpc_identifier_t identifier, struct capref cap, const void *buf,
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
errval_t lmp_deserialize(struct lmp_recv_msg *recv_msg, struct capref *recv_cap_ptr,
                         rpc_identifier_t *ret_type, uint8_t **ret_buf, size_t *ret_size,
                         struct lmp_helper *helper);

errval_t lmp_cleanup(struct lmp_helper *helper);

errval_t lmp_put_cap(struct lmp_chan *lc, struct capref cap);

/**
 * Prefix an identifier to the buffer
 * @param buf         The input buffer (can be NULL if size is also 0).
 * @param size
 * @param identifier
 * @param ret
 * @return
 */
errval_t ump_prefix_identifier(const void *buf, size_t size, rpc_identifier_t identifier,
                               void **ret);

errval_t ump_recv_cap(struct ump_chan *uc, struct capref *recv_cap);

/**
 * \brief Initialize an aos_rpc struct.
 */
void aos_rpc_init(struct aos_rpc *rpc);

/**
 * \brief Destroy an aos_rpc struct.
 */
void aos_rpc_destroy(struct aos_rpc *rpc);

static inline void aos_chan_lmp_init(struct aos_chan *chan)
{
    chan->type = AOS_CHAN_TYPE_LMP;
    lmp_chan_init(&chan->lc);
}

static inline errval_t aos_chan_lmp_accept(struct aos_chan *chan, size_t buflen_words,
                                           struct capref endpoint)
{
    chan->type = AOS_CHAN_TYPE_LMP;
    return lmp_chan_accept(&chan->lc, buflen_words, endpoint);
}

static inline errval_t aos_chan_lmp_init_local(struct aos_chan *chan, size_t buflen_words)
{
    chan->type = AOS_CHAN_TYPE_LMP;
    return lmp_chan_init_local(&chan->lc, buflen_words);
}

static inline errval_t aos_chan_ump_init(struct aos_chan *chan, struct capref zeroed_frame,
                                         enum UMP_CHAN_ROLE role, domainid_t pid)
{
    chan->type = AOS_CHAN_TYPE_UMP;
    return ump_chan_init(&chan->uc, zeroed_frame, role, pid);
}

static inline errval_t aos_chan_ump_init_from_buf(struct aos_chan *chan, void *zeroed_buf,
                                                  enum UMP_CHAN_ROLE role, domainid_t pid)
{
    chan->type = AOS_CHAN_TYPE_UMP;
    return ump_chan_init_from_buf(&chan->uc, zeroed_buf, role, pid);
}

/**
 * \brief Destroy an aos_chan struct. Call LMP/UMP destroy function based on type.
 */
void aos_chan_destroy(struct aos_chan *chan);

/**
 * Unified interface to make an RPC call.
 * @param rpc
 * @param identifier
 * @param call_cap
 * @param call_buf
 * @param call_size
 * @param ret_cap
 * @param ret_buf     Should be freed outside.
 * @param ret_size    The call_size of ret_buf, CAN be larger than the payload actually
 * sent. Should only be used to assert safe access, rather than expecting the exact
 * call_size of the return message.
 * @return
 */
errval_t aos_rpc_call(struct aos_rpc *rpc, rpc_identifier_t identifier,
                      struct capref call_cap, const void *call_buf, size_t call_size,
                      struct capref *ret_cap, void **ret_buf, size_t *ret_size);

errval_t aos_chan_send(struct aos_chan *chan, rpc_identifier_t identifier,
                       struct capref cap, const void *buf, size_t size, bool no_blocking);

/**
 * Reply a successful RPC call.
 * @param chan
 * @param cap
 * @param buf
 * @param size
 * @return
 */
errval_t aos_chan_ack(struct aos_chan *chan, struct capref cap, const void *buf,
                      size_t size);

/**
 * Reply a failed RPC call.
 * @param chan
 * @param err
 * @return
 */
errval_t aos_chan_nack(struct aos_chan *chan, errval_t err);

/**
 * \brief Send a number.
 */
errval_t aos_rpc_send_number(struct aos_rpc *chan, uintptr_t val);

/**
 * \brief Send a number.
 */
errval_t aos_rpc_stress_test(struct aos_rpc *chan, uint8_t *val, size_t len);

/**
 * \brief Send a string.
 */
errval_t aos_rpc_send_string(struct aos_rpc *chan, const char *string);


/**
 * \brief Request a RAM capability with >= request_bits of size over the given
 * channel.
 */
errval_t aos_rpc_get_ram_cap(struct aos_rpc *chan, size_t bytes, size_t alignment,
                             struct capref *retcap, size_t *ret_bytes);


/**
 * \brief Get one character from the serial port
 */
errval_t aos_rpc_serial_getchar(struct aos_rpc *chan, char *retc);


/**
 * \brief Send one character to the serial port
 */
errval_t aos_rpc_serial_putchar(struct aos_rpc *chan, char c);

/**
 * @brief Send a string of characters to the serial port.
 */
errval_t aos_rpc_serial_puts(struct aos_rpc *rpc, const char *buf, size_t len, size_t *retlen);

/**
 * @brief Get a string of characters from the serial port.
 */
errval_t aos_rpc_serial_gets(struct aos_rpc *rpc, char *buf, size_t len, size_t *retlen);

/**
 * @brief aquire terminal session
 */
errval_t aos_rpc_serial_aquire(struct aos_rpc *chan, uint8_t use_stdin);
errval_t aos_rpc_serial_aquire_new_state(struct aos_rpc *chan, void** st, uint8_t attach_stdin);

/**
 * @brief release terminal session
 */
errval_t aos_rpc_serial_release(struct aos_rpc *chan);

/**
 * @brief check if has access to stdin
 */
errval_t aos_rpc_serial_has_stdin(struct aos_rpc *chan, bool *can_access_stdin);

/**
 * \brief Request that the process manager start a new process
 * \arg cmdline the name of the process that needs to be spawned (without a
 *           path prefix) and optionally any arguments to pass to it
 * \arg newpid the process id of the newly-spawned process
 */
errval_t aos_rpc_process_spawn(struct aos_rpc *chan, char *cmdline, coreid_t core,
                               domainid_t *newpid);

errval_t aos_rpc_process_spawn_with_terminal_state(struct aos_rpc *rpc, char *cmdline, void* st, coreid_t core, domainid_t *newpid);

/**
 * \brief Get name of process with the given PID.
 * \arg pid the process id to lookup
 * \arg name A null-terminated character array with the name of the process
 * that is allocated by the rpc implementation. Freeing is the caller's
 * responsibility.
 */
errval_t aos_rpc_process_get_name(struct aos_rpc *chan, domainid_t pid, char **name);


/**
 * \brief Get PIDs of all running processes.
 * \arg pids An array containing the process ids of all currently active
 * processes. Will be allocated by the rpc implementation. Freeing is the
 * caller's  responsibility.
 * \arg pid_count The number of entries in `pids' if the call was successful
 */
errval_t aos_rpc_process_get_all_pids(struct aos_rpc *chan, domainid_t **pids,
                                      size_t *pid_count);


/**
 * \brief Returns the RPC channel to init.
 */
struct aos_rpc *aos_rpc_get_init_channel(void);

/**
 * \brief Returns the channel to the memory server
 */
struct aos_rpc *aos_rpc_get_memory_channel(void);

/**
 * \brief Returns the channel to the process manager
 */
struct aos_rpc *aos_rpc_get_process_channel(void);

/**
 * \brief Returns the channel to the serial console
 */
struct aos_rpc *aos_rpc_get_serial_channel(void);

#endif  // _LIB_BARRELFISH_AOS_MESSAGES_H
