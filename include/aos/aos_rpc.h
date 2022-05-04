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

// For now, lmp chan can be directly cast to aos_chan
struct aos_chan {
    struct lmp_chan lc;
};

enum rpc_type {
    TYPE_LMP,
    TYPE_UMP,
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
    RPC_SHUTDOWN,
    RPC_MSG_COUNT
};

typedef uint8_t rpc_identifier_t;

struct aos_rpc_msg {
    size_t size;
    enum rpc_msg_type type;
    void *buff;
};

struct aos_rpc_msg_ram {
    size_t size;
    size_t alignment;
};

/* An RPC binding, which may be transported over LMP or UMP. */
struct aos_rpc {
    // TODO(M3): Add state
    struct lmp_chan *chan;
    enum rpc_type type;
};

struct rpc_process_spawn_call_msg {
    coreid_t core;
    char cmdline[0];
} __attribute__ ((packed));

struct rpc_process_get_all_pids_return_msg {
    uint32_t count;
    domainid_t pids[0];
} __attribute__ ((packed));

/**
 * \brief Initialize an aos_rpc struct.
 */
errval_t aos_rpc_init(struct aos_rpc *rpc);

errval_t rpc_marshall(rpc_identifier_t identifier, struct capref cap_ref, void *buf, size_t size, uintptr_t *words, struct capref *ret_cap);


/**
 * \brief Send a number.
 */
errval_t aos_rpc_send_number(struct aos_rpc *chan, uintptr_t val);

/**
 * \brief Send a string.
 */
errval_t aos_rpc_send_string(struct aos_rpc *chan, const char *string);


/**
 * \brief Request a RAM capability with >= request_bits of size over the given
 * channel.
 */
errval_t aos_rpc_get_ram_cap(struct aos_rpc *chan, size_t bytes,
                             size_t alignment, struct capref *retcap,
                             size_t *ret_bytes);


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
errval_t aos_rpc_process_spawn(struct aos_rpc *chan, char *cmdline,
                               coreid_t core, domainid_t *newpid);


/**
 * \brief Get name of process with the given PID.
 * \arg pid the process id to lookup
 * \arg name A null-terminated character array with the name of the process
 * that is allocated by the rpc implementation. Freeing is the caller's
 * responsibility.
 */
errval_t aos_rpc_process_get_name(struct aos_rpc *chan, domainid_t pid,
                                  char **name);


/**
 * \brief Get PIDs of all running processes.
 * \arg pids An array containing the process ids of all currently active
 * processes. Will be allocated by the rpc implementation. Freeing is the
 * caller's  responsibility.
 * \arg pid_count The number of entries in `pids' if the call was successful
 */
errval_t aos_rpc_process_get_all_pids(struct aos_rpc *chan,
                                      domainid_t **pids, size_t *pid_count);


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

#endif // _LIB_BARRELFISH_AOS_MESSAGES_H
