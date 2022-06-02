/**
 * \file
 * \brief RPC Bindings for AOS
 */

/*
 * Copyright (c) 2013-2016, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached license file.
 * if you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetstr. 6, CH-8092 Zurich. attn: systems group.
 */

#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <aos/capabilities.h>

// terminal state for multiplexing terminal resource
void* terminal_state = NULL;

errval_t aos_rpc_send_number(struct aos_rpc *rpc, uintptr_t num)
{
    errval_t err = aos_rpc_call(rpc, RPC_NUM, NULL_CAP, &num, sizeof(num), NULL, NULL,
                                NULL);
    if (err_is_fail(err)) {
        return err;
    }

    return SYS_ERR_OK;
}

errval_t aos_rpc_send_string(struct aos_rpc *rpc, const char *string)
{
    errval_t err = aos_rpc_call(rpc, RPC_STR, NULL_CAP, (void *)string,
                                strlen(string) + 1, NULL, NULL, NULL);
    if (err_is_fail(err)) {
        return err;
    }

    return SYS_ERR_OK;
}

errval_t aos_rpc_stress_test(struct aos_rpc *rpc, uint8_t *val, size_t len)
{
    errval_t err = aos_rpc_call(rpc, RPC_STRESS_TEST, NULL_CAP, (void *)val, len, NULL,
                                NULL, NULL);
    if (err_is_fail(err))
        return err;

    return SYS_ERR_OK;
}

errval_t aos_rpc_get_ram_cap(struct aos_rpc *rpc, size_t bytes, size_t alignment,
                             struct capref *ret_cap, size_t *ret_bytes)
{
    // DEBUG_PRINTF("aos_rpc_get_ram_cap: start\n");
    struct aos_rpc_msg_ram msg = { .size = bytes, .alignment = alignment };
    errval_t err = aos_rpc_call(rpc, RPC_RAM_REQUEST, NULL_CAP, &msg, sizeof(msg),
                                ret_cap, NULL, NULL);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to receive RAM\n");
        return err;
    }

    if (ret_bytes != NULL) {
        // No better way as of now (mm does not return any size)
        struct capability c;
        err = cap_direct_identify(*ret_cap, &c);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "failed to get the frame info\n");
            return err_push(err, LIB_ERR_CAP_IDENTIFY);
        }
        assert(c.type == ObjType_RAM);
        assert(c.u.ram.bytes >= bytes);
        *ret_bytes = c.u.ram.bytes;
    }
    // DEBUG_PRINTF("aos_rpc_get_ram_cap: done\n");
    return SYS_ERR_OK;
}


errval_t aos_rpc_serial_getchar(struct aos_rpc *rpc, char *retc)
{
    errval_t err;
    char *ret_char = NULL;
    size_t ret_size = 0;
    err = aos_rpc_call(rpc, RPC_TERMINAL_GETCHAR, NULL_CAP, &terminal_state, sizeof(void*), NULL,
                       (void **)&ret_char, &ret_size);
    if (err_is_ok(err)) {
        assert(ret_size >= sizeof(char));
        *retc = *ret_char;
    }
	
    free(ret_char);
    return err;
}


errval_t aos_rpc_serial_putchar(struct aos_rpc *rpc, char c)
{
    // we don't care about return values or capabilities, just send this single char
    // (again, do better)
    // sys_print("aos_rpc_serial_putchar called!\n", 32);
    errval_t err = aos_rpc_call(rpc, RPC_TERMINAL_PUTCHAR, NULL_CAP, &c, sizeof(char),
                                NULL, NULL, NULL);
	

    return err;
}

errval_t aos_rpc_serial_puts(struct aos_rpc *rpc, const char *buf, size_t len, size_t *retlen)
{
	size_t *rbuf = NULL;
	size_t rlen = 0;
	char* tmp_buf = alloca(len+1);
	memcpy(tmp_buf, buf, len);
	tmp_buf[len] = 0;
	errval_t err = aos_rpc_call(rpc, RPC_TERMINAL_PUTS, NULL_CAP, tmp_buf, len+1, NULL, (void**)&rbuf, &rlen);
	
	assert(rlen >= sizeof(size_t));
	*retlen = *rbuf;
	free(rbuf);
		
	return err;
}

errval_t aos_rpc_serial_gets(struct aos_rpc *rpc, char *buf, size_t len, size_t *retlen)
{
	char* tmp_buf;
	char* inbuf[sizeof(void*) + sizeof(size_t)];
	*(void**)inbuf = terminal_state;
	*(size_t*)((void**)inbuf + 1) = len;
	errval_t err = aos_rpc_call(rpc, RPC_TERMINAL_GETS, NULL_CAP, &inbuf, sizeof(void*) + sizeof(size_t), NULL, (void**)&tmp_buf, retlen);
	memcpy(buf, tmp_buf, MIN(len, *retlen));
	
	return err;
}

errval_t aos_rpc_serial_aquire(struct aos_rpc *rpc, uint8_t use_stdin)
{
	return aos_rpc_serial_aquire_new_state(rpc, &terminal_state, use_stdin);
}

errval_t aos_rpc_serial_aquire_new_state(struct aos_rpc *rpc, void** st, uint8_t attach_stdin)
{
	size_t rlen = 0;
	void* st_ret;
	errval_t err = aos_rpc_call(rpc, RPC_TERMINAL_AQUIRE, NULL_CAP, &attach_stdin, sizeof(uint8_t), NULL, &st_ret, &rlen);
	
	*st = *(void**)st_ret;
	
	return err;
}

errval_t aos_rpc_serial_release(struct aos_rpc *rpc)
{
	errval_t err = aos_rpc_serial_release_terminal_state(rpc, terminal_state);
	terminal_state = NULL;
	return err;
}

errval_t aos_rpc_serial_release_terminal_state(struct aos_rpc *rpc, void* st)
{
	errval_t err = aos_rpc_call(rpc, RPC_TERMINAL_RELEASE, NULL_CAP, &st, sizeof(void*), NULL, NULL, NULL);
	
	return err;
}

errval_t aos_rpc_serial_has_stdin(struct aos_rpc *rpc, bool *can_access_stdin)
{
	bool* can_access;
	size_t rlen;
	errval_t err = aos_rpc_call(rpc, RPC_TERMINAL_HAS_STDIN, NULL_CAP, &terminal_state, sizeof(void*), NULL, (void**)&can_access, &rlen);
	
	if (rlen >= sizeof(bool)) *can_access_stdin = *can_access;
	
	free(can_access);
	
	return err;
}


errval_t aos_rpc_process_spawn(struct aos_rpc *rpc, char *cmdline, coreid_t core, domainid_t *newpid)
{
    return aos_rpc_process_spawn_with_terminal_state(rpc, cmdline, NULL, core, newpid);
}

errval_t aos_rpc_process_spawn_with_terminal_state(struct aos_rpc *rpc, char *cmdline, void* st, coreid_t core, domainid_t *newpid)
{
	size_t call_msg_size = sizeof(struct rpc_process_spawn_call_msg) + strlen(cmdline) + 1;
    struct rpc_process_spawn_call_msg *call_msg = calloc(call_msg_size, 1);
    call_msg->core = core;
	call_msg->terminal_state = st;
    strcpy(call_msg->cmdline, cmdline);

    domainid_t *return_pid = NULL;
    errval_t err = aos_rpc_call(rpc, RPC_PROCESS_SPAWN_WITH_STDIN, NULL_CAP, call_msg, call_msg_size,
                                NULL, (void **)&return_pid, NULL);
    if (err_is_ok(err)) {
        *newpid = *return_pid;
    }  // on failure, fall through

    free(call_msg);
    free(return_pid);
    return err;
}


errval_t aos_rpc_process_get_name(struct aos_rpc *rpc, domainid_t pid, char **name)
{
    char *return_msg = NULL;
    errval_t err = aos_rpc_call(rpc, RPC_PROCESS_GET_NAME, NULL_CAP, &pid,
                                sizeof(domainid_t), NULL, (void **)&return_msg, NULL);
    if (err_is_fail(err)) {
        free(return_msg);
        return err;
    }
    *name = return_msg;
    return SYS_ERR_OK;
}


errval_t aos_rpc_process_get_all_pids(struct aos_rpc *rpc, domainid_t **pids,
                                      size_t *pid_count)
{
    struct rpc_process_get_all_pids_return_msg *return_msg = NULL;
    size_t return_size = 0;
    errval_t err = aos_rpc_call(rpc, RPC_PROCESS_GET_ALL_PIDS, NULL_CAP, NULL, 0, NULL,
                                (void **)&return_msg, &return_size);
    if (err_is_ok(err)) {
        *pid_count = return_msg->count;
        *pids = malloc(return_msg->count * sizeof(domainid_t));
        if (*pids == NULL) {
            return LIB_ERR_MALLOC_FAIL;
        }
        memcpy(*pids, return_msg->pids, return_msg->count * sizeof(domainid_t));
    }  // on failure, fall through

    free(return_msg);
    return err;
}


errval_t aos_rpc_process_kill_pid(struct aos_rpc *rpc, domainid_t pid)
{
	return aos_rpc_call(rpc, RPC_PROCESS_KILL_PID, NULL_CAP, &pid, sizeof(domainid_t), NULL, NULL, NULL);
}

errval_t aos_rpc_fopen(struct aos_rpc *rpc, const char *path, handle_t *handle) 
{
    void *return_msg = NULL;
    size_t return_size = 0;

    errval_t err = aos_rpc_call(rpc, RPC_FOPEN, NULL_CAP, path, strlen(path), NULL, &return_msg, &return_size);
    if(err_is_ok(err)) {
        *handle = *(handle_t *)(return_msg);
        free(return_msg);
    }

    return err;
}

errval_t aos_rpc_fclose(struct aos_rpc *rpc, handle_t handle)
{
    void *return_msg = NULL;
    size_t return_size = 0;

    errval_t err = aos_rpc_call(rpc, RPC_FCLOSE, NULL_CAP, (void *)&handle, sizeof(lvaddr_t), NULL, &return_msg, &return_size);

    return err;
}

errval_t aos_rpc_fcreate(struct aos_rpc *rpc, const char *path, handle_t *handle)
{
    void *return_msg = NULL;
    size_t return_size = 0;

    errval_t err = aos_rpc_call(rpc, RPC_FCREATE, NULL_CAP, path, strlen(path), NULL, &return_msg, &return_size);
    if(err_is_ok(err)) {
        *handle = *(handle_t *)(return_msg);
        free(return_msg);
    }

    return err;
}

errval_t aos_rpc_frm(struct aos_rpc *rpc, const char *path)
{
    void *return_msg = NULL;
    size_t return_size = 0;

    errval_t err = aos_rpc_call(rpc, RPC_FRM, NULL_CAP, path, strlen(path), NULL, &return_msg, &return_size);

    return err;
}

errval_t aos_rpc_fread(struct aos_rpc *rpc, handle_t handle, void *buffer, size_t bytes, size_t *ret_bytes)
{
    void *return_msg = NULL;
    size_t return_size = 0;

    size_t send_size = sizeof(lvaddr_t) + sizeof(size_t);
    void *send_msg = malloc(sizeof(lvaddr_t) + sizeof(size_t));
    memcpy(send_msg, &handle, sizeof(lvaddr_t));
    memcpy(send_msg + sizeof(lvaddr_t), &bytes, sizeof(size_t));

    errval_t err = aos_rpc_call(rpc, RPC_FREAD, NULL_CAP, send_msg, send_size, NULL, &return_msg, &return_size);

    free(send_msg);
    if(err_is_ok(err)) {
        *ret_bytes = *(size_t *)(return_msg);
        memcpy(buffer, return_msg + sizeof(size_t), *ret_bytes);
        free(return_msg);
    }

    return err;
}

errval_t aos_rpc_fwrite(struct aos_rpc *rpc, handle_t handle, void *buffer, size_t bytes, size_t *ret_bytes)
{
    void *return_msg = NULL;
    size_t return_size = 0;

    size_t send_size = sizeof(lvaddr_t) + sizeof(size_t) + bytes;
    void *send_msg = malloc(send_size);
    memcpy(send_msg, &handle, sizeof(lvaddr_t));
    memcpy(send_msg + sizeof(lvaddr_t), &bytes, sizeof(size_t));
    memcpy(send_msg + sizeof(lvaddr_t) + sizeof(size_t), buffer, bytes);

    errval_t err = aos_rpc_call(rpc, RPC_FWRITE, NULL_CAP, send_msg, send_size, NULL, &return_msg, &return_size);
    free(send_msg);
    if(err_is_ok(err)) {
        *ret_bytes = *(size_t *)(return_msg);
        free(return_msg);
    }

    return err;
}

errval_t aos_rpc_fseek(struct aos_rpc *rpc, handle_t handle, enum fs_seekpos whence, off_t offset)
{
    void *return_msg = NULL;
    size_t return_size = 0;

    size_t send_size = sizeof(lvaddr_t) + sizeof(enum fs_seekpos) + sizeof(off_t);
    void *send_msg = malloc(send_size);
    memcpy(send_msg, &handle, sizeof(lvaddr_t));
    memcpy(send_msg + sizeof(lvaddr_t), &whence, sizeof(enum fs_seekpos));
    memcpy(send_msg + sizeof(lvaddr_t) + sizeof(enum fs_seekpos), &offset, sizeof(off_t));

    errval_t err = aos_rpc_call(rpc, RPC_FSEEK, NULL_CAP, send_msg, send_size, NULL, &return_msg, &return_size);
    free(send_msg);

    return err;
}

errval_t aos_rpc_ftell(struct aos_rpc *rpc, handle_t handle, size_t *ret_offset)
{
    void *return_msg = NULL;
    size_t return_size = 0;

    errval_t err = aos_rpc_call(rpc, RPC_FTELL, NULL_CAP, &handle, sizeof(lvaddr_t), NULL, &return_msg, &return_size);
    if(err_is_ok(err)) {
        *ret_offset = *(size_t *)(return_msg);
        free(return_msg);
    }

    return err;
}

errval_t aos_rpc_opendir(struct aos_rpc *rpc, const char *path, handle_t *handle)
{
    void *return_msg = NULL;
    size_t return_size = 0;
    errval_t err = aos_rpc_call(rpc, RPC_OPENDIR, NULL_CAP, path, strlen(path), NULL, &return_msg, &return_size);
    if(err_is_ok(err)) {
        *handle = *(handle_t *)(return_msg);
        free(return_msg);  
    }

    return err;
}

errval_t aos_rpc_mkdir(struct aos_rpc *rpc, const char *path)
{
    void *return_msg = NULL;
    size_t return_size = 0;

    errval_t err = aos_rpc_call(rpc, RPC_MKDIR, NULL_CAP, path, strlen(path), NULL, &return_msg, &return_size);

    return err;
}

errval_t aos_rpc_rmdir(struct aos_rpc *rpc, const char *path)
{
    void *return_msg = NULL;
    size_t return_size = 0;

    errval_t err = aos_rpc_call(rpc, RPC_RMDIR, NULL_CAP, path, strlen(path), NULL, &return_msg, &return_size);

    return err;
}

errval_t aos_rpc_closedir(struct aos_rpc *rpc, handle_t handle)
{
    void *return_msg = NULL;
    size_t return_size = 0;

    errval_t err = aos_rpc_call(rpc, RPC_CLOSEDIR, NULL_CAP, (void *)&handle, sizeof(lvaddr_t), NULL, &return_msg, &return_size);

    return err;
}

errval_t aos_rpc_readdir_next(struct aos_rpc *rpc, handle_t handle, char **name)
{
    void *return_msg = NULL;
    size_t return_size = 0;

    errval_t err = aos_rpc_call(rpc, RPC_READDIR, NULL_CAP, (void *)&handle, sizeof(lvaddr_t), NULL, &return_msg, &return_size);
    if(err_is_ok(err)) {
        size_t length = *(size_t *)(return_msg);
        *name = malloc(length + 1);
        memcpy(*name, return_msg + sizeof(size_t), length);
        (*name)[length] = '\0';
        free(return_msg);
    }

    return err;
}

errval_t aos_rpc_fstat(struct aos_rpc *rpc, handle_t handle, struct fs_fileinfo *info)
{
    void *return_msg = NULL;
    size_t return_size = 0;

    errval_t err = aos_rpc_call(rpc, RPC_FSTAT, NULL_CAP, (void *)&handle, sizeof(lvaddr_t), NULL, &return_msg, &return_size);
    if(err_is_ok(err)) {
        *info = *(struct fs_fileinfo *)(return_msg);
        free(return_msg);
    }

    return err;
}


/**
 * \brief Returns the RPC channel to init.
 */
struct aos_rpc *aos_rpc_get_init_channel(void)
{
    return get_init_rpc();
}

/**
 * \brief Returns the channel to the memory server
 */
struct aos_rpc *aos_rpc_get_memory_channel(void)
{
    return aos_rpc_get_init_channel();
}

/**
 * \brief Returns the channel to the process manager
 */
struct aos_rpc *aos_rpc_get_process_channel(void)
{
    return aos_rpc_get_init_channel();
}

/**
 * \brief Returns the channel to the serial console
 */
struct aos_rpc *aos_rpc_get_serial_channel(void)
{
    // TODO: Return channel to talk to serial driver/terminal process (whoever
    // implements print/read functionality)
    // debug_printf("aos_rpc_get_serial_channel NYI\n");
    return aos_rpc_get_init_channel();  // XXX: For now return the init channel, since the
                                        // current serial driver is handled in init
}