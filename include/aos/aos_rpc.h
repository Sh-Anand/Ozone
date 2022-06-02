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
#include <fs/fs.h>

typedef void *handle_t;

enum aos_rpc_identifier {
    RPC_TRANSFER_CAP = RPC_IDENTIFIER_USER_START,
    RPC_ACCEPT_CAP,
    RPC_BYE,
    RPC_NUM,
    RPC_STR,
    RPC_RAM_REQUEST,
    RPC_PROCESS_SPAWN,
	RPC_PROCESS_SPAWN_WITH_STDIN,
    RPC_PROCESS_GET_NAME,
    RPC_PROCESS_GET_ALL_PIDS,
	RPC_PROCESS_KILL_PID,
	RPC_TERMINAL_AQUIRE,
	RPC_TERMINAL_RELEASE,
	RPC_TERMINAL_HAS_STDIN,
    RPC_TERMINAL_GETCHAR,
    RPC_TERMINAL_PUTCHAR,
	RPC_TERMINAL_GETS,
	RPC_TERMINAL_PUTS,
    RPC_STRESS_TEST,
    RPC_FOPEN,
    RPC_FCREATE,
    RPC_FREAD,
    RPC_FWRITE,
    RPC_FCLOSE,
    RPC_FSEEK,
    RPC_FTELL,
    RPC_FRM,
    RPC_MKDIR,
    RPC_RMDIR,
    RPC_OPENDIR,
    RPC_READDIR,
    RPC_CLOSEDIR,
    RPC_FSTAT,
    RPC_BIND_NAMESERVER,        // may return MON_ERR_RETRY
    RPC_MSG_COUNT,
};
STATIC_ASSERT(RPC_MSG_COUNT <= RPC_IDENTIFIER_USER_END, "RPC_MSG_COUNT too large");


struct aos_rpc_msg_ram {
    size_t size;
    size_t alignment;
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
errval_t aos_rpc_serial_release_terminal_state(struct aos_rpc *chan, void* st);

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


errval_t aos_rpc_process_kill_pid(struct aos_rpc *chan, domainid_t pid);


//filesystem rpc calls
errval_t aos_rpc_fopen(struct aos_rpc *chan, const char *path, handle_t *handle);
errval_t aos_rpc_fclose(struct aos_rpc *chan, handle_t handle);
errval_t aos_rpc_fcreate(struct aos_rpc *chan, const char *path, handle_t *handle);
errval_t aos_rpc_frm(struct aos_rpc *chan, const char *path);
errval_t aos_rpc_fread(struct aos_rpc *chan, handle_t handle, void *buffer, size_t bytes, size_t *ret_bytes);
errval_t aos_rpc_fwrite(struct aos_rpc *chan, handle_t handle, void *buffer, size_t bytes, size_t *ret_bytes);
errval_t aos_rpc_fseek(struct aos_rpc *chan, handle_t handle, enum fs_seekpos fs_whence, off_t offset);
errval_t aos_rpc_ftell(struct aos_rpc *chan, handle_t handle, size_t *ret_offset);
errval_t aos_rpc_opendir(struct aos_rpc *chan, const char *path, handle_t *handle);
errval_t aos_rpc_mkdir(struct aos_rpc *chan, const char *path);
errval_t aos_rpc_rmdir(struct aos_rpc *chan, const char *path);
errval_t aos_rpc_closedir(struct aos_rpc *chan, handle_t handle);
errval_t aos_rpc_readdir_next(struct aos_rpc *chan, handle_t handle, char **name);
errval_t aos_rpc_fstat(struct aos_rpc *chan, handle_t handle, struct fs_fileinfo *info);


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
