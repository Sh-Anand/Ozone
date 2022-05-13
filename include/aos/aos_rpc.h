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
    struct capref reserved_slot;
    struct thread_mutex reserved_slot_mutex;
    bool recv_slot_not_refilled;
};

enum rpc_msg_type {
    RPC_ACK,
    RPC_ERR,
    RPC_MSG_IN_FRAME,
    RPC_NUM,
    RPC_STR,
    RPC_RAM_REQUEST,
    RPC_PROCESS_SPAWN,
    RPC_PROCESS_GET_NAME,
    RPC_PROCESS_GET_ALL_PIDS,
    RPC_TERMINAL_GETCHAR,
    RPC_TERMINAL_PUTCHAR,
    RPC_STRESS_TEST,
    RPC_BIND_NAMESERVER,
    RPC_USER,
    RPC_MSG_COUNT
};

typedef uint8_t rpc_identifier_t;

struct aos_rpc_msg_ram {
    size_t size;
    size_t alignment;
};

struct aos_rpc {
    struct aos_chan chan;
    struct thread_mutex ongoing_call_mutex;  // not used for now
};

struct rpc_process_spawn_call_msg {
    coreid_t core;
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

errval_t lmp_serialize(rpc_identifier_t identifier, struct capref cap, void *buf,
                       size_t size, uintptr_t ret_payload[LMP_MSG_LENGTH],
                       struct capref *ret_cap, struct lmp_helper *helper);

errval_t lmp_deserialize(struct lmp_recv_msg *recv_msg, struct capref recv_cap,
                         rpc_identifier_t *ret_type, uint8_t **ret_buf, size_t *ret_size,
                         struct lmp_helper *helper);

errval_t lmp_cleanup(struct lmp_helper *helper);

/**
 * \brief Initialize an aos_rpc struct.
 */
errval_t aos_rpc_init(struct aos_rpc *rpc);

/**
 * Unified interface to make an RPC call.
 * @param chan
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
errval_t aos_chan_call(struct aos_chan *chan, rpc_identifier_t identifier,
                       struct capref call_cap, void *call_buf, size_t call_size,
                       struct capref *ret_cap, void **ret_buf, size_t *ret_size);


static inline errval_t aos_rpc_call(struct aos_rpc *rpc, rpc_identifier_t identifier,
                                    struct capref call_cap, void *call_buf,
                                    size_t call_size, struct capref *ret_cap,
                                    void **ret_buf, size_t *ret_size)
{
    return aos_chan_call(&rpc->chan, identifier, call_cap, call_buf, call_size, ret_cap,
                         ret_buf, ret_size);
}

/**
 * Reply a successful RPC call.
 * @param chan
 * @param cap
 * @param buf
 * @param size
 * @return
 */
errval_t aos_chan_ack(struct aos_chan *chan, struct capref cap, void *buf, size_t size);

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
 * \brief Request that the process manager start a new process
 * \arg cmdline the name of the process that needs to be spawned (without a
 *           path prefix) and optionally any arguments to pass to it
 * \arg newpid the process id of the newly-spawned process
 */
errval_t aos_rpc_process_spawn(struct aos_rpc *chan, char *cmdline, coreid_t core,
                               domainid_t *newpid);


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
