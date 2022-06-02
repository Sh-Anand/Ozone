//
// Created by Zikai Liu on 4/27/22.
//

#include "init_urpc.h"
#include "rpc_handlers.h"
#include "mem_alloc.h"
#include "mm/mm.h"
#include <aos/kernel_cap_invocations.h>
#include <spawn/spawn.h>
#include <grading.h>
#include <aos/ump_chan.h>

#include "terminal.h"

extern size_t (*local_terminal_write_function)(const char*, size_t);
extern size_t (*local_terminal_read_function)(char*, size_t);

extern spinlock_t* global_print_lock;
//spinlock_t* terminal_read_lock;
volatile domainid_t terminal_read_recipient;

#define DEBUG_RPC_HANDLERS 0

/*
 * Init values: *out_payload = NULL, *out_size = 0, *out_cap = NULL_CAP (nothing to reply)
 *
 * XXX: maybe init *out_payload to the buffer of LMP message, so that small message can
 * directly write to this buffer without using malloc.
 *
 * If *out_payload != NULL after return, it will be freed.
 *
 * Notice that in_size can be larger than the protocol payload (an LMP message or a page)
 * and therefore should only be used to assert out-of-bound access (check size is enough
 * rather than exact).
 */

#include <fs/fat32.h>

typedef void *handle_t;

// Does not allow cap sending or receiving
static errval_t forward_to_core(coreid_t core, void *in_payload, size_t in_size,
                                void **out_payload, size_t *out_size)
{
    // XXX: trick to retrieve the rpc identifier by -1
    rpc_identifier_t identifier = CAST_DEREF(rpc_identifier_t, in_payload, -1);

    return urpc_call_to_core(core, identifier, in_payload, in_size, out_payload, out_size);
}

RPC_HANDLER(stress_test_handler)
{
    if (disp_get_current_core_id() == 0) {
        CAST_IN_MSG_NO_CHECK(vals, uint8_t);
        size_t len = in_size;
        for (uint8_t i = 0; len < in_size; i++, len++) {
            if (vals[len] != i) {
                goto error;
            }
        }
        return SYS_ERR_OK;
    error:
        DEBUG_PRINTF("STRESS TEST RECEIVED CORRUPTED DATA!\n");
        return SYS_ERR_OK;
    } else {
        return forward_to_core(0, in_payload, in_size, out_payload, out_size);
    }
}

RPC_HANDLER(num_msg_handler)
{
    if (disp_get_current_core_id() == 0) {
        CAST_IN_MSG_EXACT_SIZE(num, uintptr_t);
        grading_rpc_handle_number(*num);
        DEBUG_PRINTF("Received number %lu\n", *num);
        return SYS_ERR_OK;
    } else {
        return forward_to_core(0, in_payload, in_size, out_payload, out_size);
    }
}

static size_t strlen_s(const char *s, size_t max)
{
    size_t i = 0;
    while (*s != '\0' && i < max) {
        i++;
        s++;
    }
    return i;
}

RPC_HANDLER(str_msg_handler)
{
    if (disp_get_current_core_id() == 0) {
        CAST_IN_MSG_NO_CHECK(str, char);

        // Check in_size against wrong or malicious calls with non-terminating str
        if (strlen_s(str, in_size) >= in_size) {
            DEBUG_PRINTF("ERROR received non-terminating string (in_size = %lu)\n",
                         in_size);
            return ERR_INVALID_ARGS;
        }

        grading_rpc_handler_string(str);
        // DEBUG_PRINTF("in_size = %lu\n", in_size);
        DEBUG_PRINTF("Received string: \"%s\"\n", str);
        int len = printf("Received string: \"%s\"\n", str);
        printf("Printed %d characters\n", len);
        return SYS_ERR_OK;
    } else {
        // DEBUG_PRINTF("in_size = %lu\n", in_size);
        return forward_to_core(0, in_payload, in_size, out_payload, out_size);
    }
}

RPC_HANDLER(ram_request_msg_handler)
{
    CAST_IN_MSG_EXACT_SIZE(ram_msg, struct aos_rpc_msg_ram);
    grading_rpc_handler_ram_cap(ram_msg->size, ram_msg->alignment);

    // Try to get frame
    errval_t err = aos_ram_alloc_aligned(out_cap, ram_msg->size, ram_msg->alignment);
    if (err == MM_ERR_NO_MEMORY) {
        // Request RAM from core 0
        DEBUG_PRINTF("no enough memory locally, requesting core 0...\n");

        // XXX: trick to rewrite identifier
        *(((uint8_t *)in_payload) - 1) = INTERNAL_RPC_REMOTE_RAM_REQUEST;

        // Request for max(twice size, RAM_PER_CORE)
        size_t original_request_size = ram_msg->size;
        ram_msg->size = MAX(ram_msg->size * 2, RAM_PER_CORE);

        // Request RAM from core 0
        void *reply_payload = NULL;
        size_t reply_size = 0;
        err = forward_to_core(0, in_payload, in_size, &reply_payload, &reply_size);
        if (err_is_fail(err)) {
            goto RET;
        }

        // Decode reply
        if (reply_size < sizeof(struct RAM)) {
            DEBUG_PRINTF("%s: invalid payload size %lu < sizeof(%s) = %lu\n", __func__,
                         reply_size, "struct RAM", sizeof(struct RAM));
            err = LIB_ERR_RPC_INVALID_PAYLOAD_SIZE;
            goto RET;
        }
        struct RAM *ram = reply_payload;

        // Forge ram
        struct capref ram_cap;
        err = slot_alloc(&ram_cap);
        if (err_is_fail(err)) {
            err = err_push(err, LIB_ERR_SLOT_ALLOC);
            goto RET;
        }
        err = ram_forge(ram_cap, ram->base, ram->bytes,
                        disp_get_current_core_id());  // XXX: owner?
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "ram_request_msg_handler: failed to forge RAM");
            goto RET;
        }

        err = mm_add(&aos_mm, ram_cap);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "ram_request_msg_handler: mm_add failed");
            goto RET;
        }

        DEBUG_PRINTF("add RAM of size 0x%lx/0x%lx from core 0\n", ram->base, ram->bytes);

        err = aos_ram_alloc_aligned(out_cap, original_request_size, ram_msg->alignment);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "ram_request_msg_handler: aos_ram_alloc_aligned still failed");
            goto RET;
        }

        err = SYS_ERR_OK;
    RET:
        free(reply_payload);
        return err;

    } else {
        return err;
    }
}

RPC_HANDLER(remote_ram_request_handler)
{
    CAST_IN_MSG_EXACT_SIZE(ram_msg, struct aos_rpc_msg_ram);
    errval_t err;

#if DEBUG_RPC_HANDLERS
    DEBUG_PRINTF("> received remote RAM request, size = 0x%lx, alignment = 0x%lx\n",
                 ram_msg->size, ram_msg->alignment);
#endif

    // Allocate RAM locally
    struct capref cap;
    err = aos_ram_alloc_aligned(&cap, ram_msg->size, ram_msg->alignment);
    if (err_is_fail(err)) {
        return err;
    }

    // out_cap will be discarded by UMP, must serialize
    struct capability c;
    err = cap_direct_identify(cap, &c);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_CAP_IDENTIFY);
    }
    assert(c.type == ObjType_RAM);


#if DEBUG_RPC_HANDLERS
    DEBUG_PRINTF("< giving out RAM 0x%lx/0x%lx\n", c.u.ram.base, c.u.ram.bytes);
#endif

    MALLOC_OUT_MSG(reply, struct RAM);
    reply->base = c.u.ram.base;
    reply->bytes = c.u.ram.bytes;
    reply->pasid = c.u.ram.pasid;

    return SYS_ERR_OK;
}

RPC_HANDLER(spawn_msg_handler)
{
    CAST_IN_MSG_AT_LEAST_SIZE(msg, struct rpc_process_spawn_call_msg);
    grading_rpc_handler_process_spawn(msg->cmdline, msg->core);

    if (msg->core == disp_get_core_id()) {
        // Spawn on the current core

        struct spawninfo info;
        domainid_t pid;
        errval_t err = spawn_load_cmdline(msg->cmdline, &info, &pid);
        if (err_is_fail(err)) {
            return err;
        }

        MALLOC_OUT_MSG(reply, domainid_t);
        *reply = pid;
        return SYS_ERR_OK;
    } else {
        return forward_to_core(msg->core, in_payload, in_size, out_payload, out_size);
    }
}

RPC_HANDLER(spawn_msg_stdin_handler)
{
	CAST_IN_MSG_AT_LEAST_SIZE(msg, struct rpc_process_spawn_call_msg);
    grading_rpc_handler_process_spawn(msg->cmdline, msg->core);

    if (msg->core == disp_get_core_id()) {
        // Spawn on the current core

        struct spawninfo info;
        domainid_t pid;
        errval_t err = spawn_load_cmdline_complete(msg->cmdline, NULL_CAP, msg->terminal_state, &info, &pid);
        if (err_is_fail(err)) {
            return err;
        }

        MALLOC_OUT_MSG(reply, domainid_t);
        *reply = pid;
        return SYS_ERR_OK;
    } else {
        return forward_to_core(msg->core, in_payload, in_size, out_payload, out_size);
    }
}

RPC_HANDLER(process_get_name_handler)
{
    CAST_IN_MSG_EXACT_SIZE(pid, domainid_t);

    coreid_t core = pid_get_core(*pid);
    if (disp_get_current_core_id() == core) {
        grading_rpc_handler_process_get_name(*pid);

        char *name = NULL;
        errval_t err = spawn_get_name(*pid, &name);
        if (err_is_fail(err)) {
            return err;
        }

        *out_payload = name;  // will be freed outside
        *out_size = strlen(name) + 1;
        return SYS_ERR_OK;
    } else {
        return forward_to_core(core, in_payload, in_size, out_payload, out_size);
    }
}

RPC_HANDLER(get_local_pids_handler)
{
    ASSERT_ZERO_IN_SIZE;

    size_t count;
    domainid_t *pids;
    errval_t err = spawn_get_all_pids(&pids, &count);
    if (err_is_fail(err)) {
        return err;
    }

    MALLOC_OUT_MSG_WITH_SIZE(reply, struct rpc_process_get_all_pids_return_msg,
                             sizeof(struct rpc_process_get_all_pids_return_msg)
                                 + count * sizeof(domainid_t));
    reply->count = count;
    if (pids) {
        memcpy(reply->pids, pids, count * sizeof(domainid_t));
        free(pids);
    }
    return SYS_ERR_OK;
}

RPC_HANDLER(process_get_all_pids_handler)
{
    ASSERT_ZERO_IN_SIZE;
    grading_rpc_handler_process_get_all_pids();

    errval_t err;

    struct rpc_process_get_all_pids_return_msg *msg[MAX_COREID];
    memset(msg, 0, sizeof(msg));

    size_t count = 0;

    for (coreid_t core = 0; core < MAX_COREID; ++core) {
        size_t msg_size = 0;
        if (core == disp_get_current_core_id()) {
            err = get_local_pids_handler(arg, NULL, 0, (void **)&msg[core], &msg_size,
                                         NULL_CAP, NULL);
            if (err_is_fail(err)) {
                return err;
            }
        } else if (urpc[core] != NULL) {
            err = urpc_call_to_core(core, INTERNAL_RPC_GET_LOCAL_PIDS, NULL, 0,
                                    (void **)&msg[core], &msg_size);
            if (err_is_fail(err)) {
                return err;
            }
        } else {
            continue;  // core not booted
        }
        assert(msg_size >= sizeof(struct rpc_process_get_all_pids_return_msg));
        count += msg[core]->count;
    }

    MALLOC_OUT_MSG_WITH_SIZE(reply, struct rpc_process_get_all_pids_return_msg,
                             sizeof(struct rpc_process_get_all_pids_return_msg)
                                 + count * sizeof(domainid_t));
    reply->count = count;

    size_t offset = 0;
    for (coreid_t core = 0; core < MAX_COREID; ++core) {
        if (msg[core] != NULL) {
            memcpy(reply->pids + offset, msg[core]->pids,
                   msg[core]->count * sizeof(domainid_t));
            offset += msg[core]->count;

            free(msg[core]);
        }
    }
    assert(offset == count);

    return SYS_ERR_OK;
}

static errval_t clean_nameservice_by_pid(domainid_t pid) {
    errval_t err;
    if (aos_chan_is_connected(&nameserver_rpc.chan)) {
        // XXX: magic number, put it in a shared header
        err = aos_chan_send(&nameserver_rpc.chan, 1, NULL_CAP, &pid, sizeof(domainid_t),
                            true);
        if (err_is_fail(err)) {
            if (lmp_err_is_transient(err)) {
                thread_yield();
                return MON_ERR_RETRY;
            }
            return err;  // expose transient error to the user
        }
    }
    return SYS_ERR_OK;
}

RPC_HANDLER(remote_clean_nameserver_handler) {
    CAST_IN_MSG_EXACT_SIZE(pid, domainid_t);
    return clean_nameservice_by_pid(*pid);
}

static errval_t kill_process_and_clean(domainid_t pid) {
    errval_t err = spawn_kill(pid);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "in spawn_kill");
    }

    if (disp_get_current_core_id() == 0) {
        return clean_nameservice_by_pid(pid);
    } else {
        return urpc_call_to_core(0, INTERNAL_RPC_REMOTE_CLEAN_NAMESERVER, &pid,
                                 sizeof(domainid_t), NULL, NULL);
    }
}

RPC_HANDLER(process_kill_pid_handler)
{
    CAST_IN_MSG_EXACT_SIZE(pid, domainid_t);

    coreid_t core = pid_get_core(*pid);
    if (disp_get_current_core_id() == core) {
        return kill_process_and_clean(*(domainid_t*)in_payload);
    } else {
        return forward_to_core(core, in_payload, in_size, out_payload, out_size);
    }
}

RPC_HANDLER(terminal_getchar_handler)
{
    assert(in_size >= sizeof(void*));
    if (disp_get_current_core_id() == 0) {
		void* st = *(void**)in_payload;
        grading_rpc_handler_serial_getchar();
        MALLOC_OUT_MSG(reply, char);
        errval_t err = terminal_getchar(st, reply);
        return err;
    } else {
        return forward_to_core(0, in_payload, in_size, out_payload, out_size);
    }
}

RPC_HANDLER(terminal_putchar_handler)
{
    if (disp_get_current_core_id() == 0) {
        CAST_IN_MSG_NO_CHECK(c, char);
		acquire_spinlock(global_print_lock);
        grading_rpc_handler_serial_putchar(*c);
		terminal_putchar(*c);
		release_spinlock(global_print_lock);
		return SYS_ERR_OK;
    } else {
        return forward_to_core(0, in_payload, in_size, out_payload, out_size);
    }
}

RPC_HANDLER(terminal_gets_handler)
{
	if (disp_get_core_id() == 0) {
		assert(in_size == sizeof(size_t));
		CAST_IN_MSG_NO_CHECK(st, void*);
		size_t len = *(size_t*)((void**)in_payload + 1);
		char *buf = (char*)malloc(len);
		size_t i = 0;
		errval_t err = SYS_ERR_OK;
		for (; i < len; i++) {
			err = terminal_getchar(st, buf + i);
			if (err == TERM_ERR_TERMINAL_IN_USE) {
				break;
			}
			if (err == TERM_ERR_RECV_CHARS) {
				break;
			}
			//if (buf[i] == '\0' || buf[i] == 0x03 || buf[i] == 0x04 || buf[i] == 0x17) break; // terminate if EOF like characters are read
		}
		*out_payload = realloc(buf, i); // in case there has been less read than requested
		if (!*out_payload) *out_payload = buf; // in case realloc failed
		*out_size = i;
		
		return err;
	} else {
		return forward_to_core(0, in_payload, in_size, out_payload, out_size);
	}
}

RPC_HANDLER(terminal_puts_handler)
{
	if (disp_get_core_id() == 0) {
		CAST_IN_MSG_NO_CHECK(c, char);
		acquire_spinlock(global_print_lock);
		size_t i = 0;
		for (; i < in_size; i++) {
			if (c[i] == 0) {
				break;
			}
			grading_rpc_handler_serial_putchar(c[i]);
			terminal_putchar(c[i]);
		}
		release_spinlock(global_print_lock);
		MALLOC_OUT_MSG_WITH_SIZE(len, size_t, sizeof(size_t));
		*len = in_size;
		return SYS_ERR_OK;
	} else {
		return forward_to_core(0, in_payload, in_size, out_payload, out_size);
	}
}

RPC_HANDLER(terminal_aquire_handler)
{
	if (disp_get_core_id() == 0) {
		CAST_IN_MSG_AT_LEAST_SIZE(use_stdin, uint8_t);
		
		void* st = terminal_aquire(*use_stdin);
		MALLOC_OUT_MSG_WITH_SIZE(reply, void*, sizeof(void*));
		*reply = st;
		
		return SYS_ERR_OK;
	} else {
		return forward_to_core(0, in_payload, in_size, out_payload, out_size);
	}
}

RPC_HANDLER(terminal_release_handler)
{
	if (disp_get_core_id() == 0) {
		CAST_IN_MSG_AT_LEAST_SIZE(st, void*);
		
		terminal_release(*st);
		
		return SYS_ERR_OK;
	} else {
		return forward_to_core(0, in_payload, in_size, out_payload, out_size);
	}
}

RPC_HANDLER(terminal_has_stdin_handler)
{
	if (disp_get_core_id() == 0) {
		CAST_IN_MSG_AT_LEAST_SIZE(st, void*);
		
		bool has_access = terminal_can_use_stdin(*st);
		
		MALLOC_OUT_MSG_WITH_SIZE(reply, bool, sizeof(bool));
		*reply = has_access;
		return SYS_ERR_OK;
	} else {
		return forward_to_core(0, in_payload, in_size, out_payload, out_size);
	}
}



RPC_HANDLER(fopen_handler)
{
    if (disp_get_current_core_id() == 0) {
        CAST_IN_MSG_STRING;
        handle_t handle;
        errval_t err = fat32_open(path, &handle);
        free(path);
        if(err_is_fail(err)) return err;
        MALLOC_OUT_MSG_WITH_HANDLE(var, lvaddr_t, handle);
        return SYS_ERR_OK;
    } else {
        return forward_to_core(0, in_payload, in_size, out_payload, out_size);
    }
}

RPC_HANDLER(opendir_handler)
{   
    if (disp_get_current_core_id() == 0) {
        CAST_IN_MSG_STRING;
        handle_t handle;
        errval_t err = fat32_opendir(path, &handle);
        free(path);
        if(err_is_fail(err)) return err;
        MALLOC_OUT_MSG_WITH_HANDLE(var, lvaddr_t, handle);
        return SYS_ERR_OK;
    } else {
        return forward_to_core(0, in_payload, in_size, out_payload, out_size);
    }
}

RPC_HANDLER(fclose_handler)
{
    if (disp_get_current_core_id() == 0) {
        handle_t handle = *(handle_t *) in_payload;
        errval_t err = fat32_close(handle);
        *out_payload = NULL;
        return err;
    } else {
        return forward_to_core(0, in_payload, in_size, out_payload, out_size);
    }
}

RPC_HANDLER(closedir_handler)
{
    if (disp_get_current_core_id() == 0) {
        handle_t handle = *(handle_t *) in_payload;
        errval_t err = fat32_closedir(handle);
        *out_payload = NULL;
        return err;
    } else {
        return forward_to_core(0, in_payload, in_size, out_payload, out_size);
    }
}

RPC_HANDLER(fcreate_handler)
{
    if (disp_get_current_core_id() == 0) {
        CAST_IN_MSG_STRING;
        handle_t handle;
        errval_t err = fat32_create(path, &handle);
        free(path);
        if(err_is_fail(err)) return err;
        MALLOC_OUT_MSG_WITH_HANDLE(var, lvaddr_t, handle);
        return SYS_ERR_OK;
    } else {
        return forward_to_core(0, in_payload, in_size, out_payload, out_size);
    }
}

RPC_HANDLER(frm_handler)
{
    if (disp_get_current_core_id() == 0) {
        CAST_IN_MSG_STRING;
        errval_t err = fat32_remove(path);
        free(path);
        *out_payload = NULL;
        return err;
    } else {
        return forward_to_core(0, in_payload, in_size, out_payload, out_size);
    }
}

RPC_HANDLER(mkdir_handler)
{
    if (disp_get_current_core_id() == 0) {
        CAST_IN_MSG_STRING;
        errval_t err = fat32_mkdir(path);
        free(path);
        *out_payload = NULL;
        return err;
    } else {
        return forward_to_core(0, in_payload, in_size, out_payload, out_size);
    }
}

RPC_HANDLER(rmdir_handler)
{
    if (disp_get_current_core_id() == 0) {
        CAST_IN_MSG_STRING;
        errval_t err = fat32_rmdir(path);
        free(path);
        *out_payload = NULL;
        return err;
    } else {
        return forward_to_core(0, in_payload, in_size, out_payload, out_size);
    }
}

RPC_HANDLER(fread_handler)
{
    if (disp_get_current_core_id() == 0) {
        handle_t handle = *(handle_t *) in_payload;
        size_t bytes = *(size_t *)(in_payload + sizeof(lvaddr_t));

        *out_payload = malloc(sizeof(size_t) + bytes);
        size_t ret_size = 0;

        errval_t err = fat32_read(handle, *out_payload + sizeof(size_t), bytes, &ret_size);

        if(err_is_fail(err)) { return err; }
        memcpy(*out_payload, &ret_size, sizeof(size_t));
        *out_size = sizeof(size_t) + bytes;
        return SYS_ERR_OK;
    } else {
        return forward_to_core(0, in_payload, in_size, out_payload, out_size);
    }
}

RPC_HANDLER(fwrite_handler)
{
    if (disp_get_current_core_id() == 0) {
        handle_t handle = (handle_t) *(lvaddr_t *) in_payload;
        size_t bytes = *(size_t *)(in_payload + sizeof(lvaddr_t));

        size_t ret_size = 0;
        errval_t err = fat32_write(handle, in_payload + sizeof(lvaddr_t) + sizeof(size_t), bytes, &ret_size);
        if(err_is_fail(err)) return err;
        MALLOC_OUT_MSG(ret, size_t);
        *ret = ret_size;
        return SYS_ERR_OK;
    } else {
        return forward_to_core(0, in_payload, in_size, out_payload, out_size);
    }
}

RPC_HANDLER(fstat_handler)
{
	if (disp_get_current_core_id() == 0) {
        handle_t handle = *(handle_t *) in_payload;
		
		MALLOC_OUT_MSG(finfo, struct fs_fileinfo);
		
        errval_t err = fat32_stat(handle, finfo);
		
		if (err_is_fail(err)) return err;
		
		*out_size = sizeof(struct fs_fileinfo);

        return SYS_ERR_OK;
    } else {
        return forward_to_core(0, in_payload, in_size, out_payload, out_size);
    }
}

RPC_HANDLER(readdir_handler)
{
	if (disp_get_current_core_id() == 0) {
		handle_t handle = *(handle_t *) in_payload;
		
		char *name;
		errval_t err = fat32_dir_read_next(handle, &name, NULL);
		
		if (err_is_fail(err)) return err;
        size_t length = strlen(name);
		*out_size = sizeof(size_t) + length;
		*out_payload = malloc(*out_size);
        memcpy(*out_payload, &length, sizeof(size_t));
		memcpy(*out_payload + sizeof(size_t), name, length);
		return SYS_ERR_OK;
    } else {
        return forward_to_core(0, in_payload, in_size, out_payload, out_size);
    }
}

RPC_HANDLER(fseek_handler)
{
    if(disp_get_core_id() == 0) {
        handle_t handle = *(handle_t *) in_payload;
        enum fs_seekpos whence = *(enum fs_seekpos *)(in_payload + sizeof(lvaddr_t));
        off_t offset = *(off_t *)(in_payload + sizeof(lvaddr_t) + sizeof(enum fs_seekpos));
        *out_payload = NULL;
        return fat32_seek(handle, whence, offset);
    } else {
        return forward_to_core(0, in_payload, in_size, out_payload, out_size);
    }
}

RPC_HANDLER(ftell_handler)
{
    if(disp_get_core_id() == 0) {
        handle_t handle = *(handle_t *) in_payload;

        size_t pos;
        errval_t err = fat32_tell(handle, &pos);
        if(err_is_fail(err)) return err;

        MALLOC_OUT_MSG(retpos, size_t);
        *retpos = pos;
        return SYS_ERR_OK;
    } else {
        return forward_to_core(0, in_payload, in_size, out_payload, out_size);
    }
}

RPC_HANDLER(bind_core_urpc_handler)
{
    CAST_IN_MSG_EXACT_SIZE(msg, struct internal_rpc_bind_core_urpc_msg);
    errval_t err;

#if DEBUG_RPC_HANDLERS
    DEBUG_PRINTF("> setup urpc binding with core %u (listener_first = %u)\n", msg->core,
                 msg->listener_first);
#endif

    // Forge frame
    assert(msg->frame.bytes == (UMP_CHAN_SHARED_FRAME_SIZE * 2));
    struct capref urpc_frame;
    err = slot_alloc(&urpc_frame);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_SLOT_ALLOC);
    }
    err = frame_forge(urpc_frame, msg->frame.base, msg->frame.bytes,
                      disp_get_current_core_id());  // XXX: owner?
    if (err_is_fail(err)) {
        return err;
    }

    // Setup URPC
    err = setup_urpc(msg->core, urpc_frame, msg->listener_first);
    if (err_is_fail(err)) {
        return err;
    }

    // Start handling URPCs
    err = aos_chan_register_recv(urpc_listen_from[msg->core], get_default_waitset(),
                                 init_urpc_handler, NULL);
    if (err_is_fail(err)) {
        return err;
    }

#if DEBUG_RPC_HANDLERS
    DEBUG_PRINTF("< setup urpc binding with core %u done\n", msg->core);
#endif


    return SYS_ERR_OK;
}

RPC_HANDLER(cap_transfer_handler)
{
    CAST_IN_MSG_EXACT_SIZE(pid, domainid_t);
    if (capref_is_null(in_cap)) {
        return ERR_INVALID_ARGS;
    }

#if DEBUG_RPC_HANDLERS
    DEBUG_PRINTF("> transfer cap to %u\n", *pid);
#endif

    errval_t err;

    coreid_t core = pid_get_core(*pid);
    if (core == disp_get_current_core_id()) {
        struct aos_chan *chan;
        err = spawn_get_chan(*pid, &chan);
        if (err_is_fail(err)) {
            return err;
        }
        assert(chan->type == AOS_CHAN_TYPE_LMP);

        struct proc_node *p = spawn_get_proc_node(*pid);
        if (p->accepting_cap <= 0) {
            return MON_ERR_CAP_SEND;
        }


        err = rpc_lmp_put_cap(&chan->lc, in_cap);  // not blocking, may return failure
        if (err_is_fail(err)) {
            if (lmp_err_is_transient(err)) {
                return MON_ERR_RETRY;
            } else {
                return err;
            }
        }

        p->accepting_cap--;
    } else {
        struct internal_rpc_remote_cap_msg msg;
        msg.pid = *pid;

        // Serialize the cap
        err = cap_direct_identify(in_cap, &msg.cap);
        if (err_is_fail(err)) {
            return err_push(err, LIB_ERR_CAP_IDENTIFY);
        }

        // Check and send
        switch (msg.cap.type) {
        case ObjType_Frame:
        case ObjType_DevFrame:
        case ObjType_RAM:
            err = urpc_call_to_core(core, INTERNAL_RPC_REMOTE_CAP_TRANSFER, &msg,
                                    sizeof(msg), NULL, NULL);
            if (err_is_fail(err)) {
                return err;
            }
            break;
        default:
            return MON_ERR_CAP_SEND;
        }
    }

#if DEBUG_RPC_HANDLERS
    DEBUG_PRINTF("< transfer cap to %u done\n", *pid);
#endif

    return SYS_ERR_OK;
}

RPC_HANDLER(cap_accept_handler)
{
    struct proc_node *proc = arg;
    proc->accepting_cap++;
    return SYS_ERR_OK;
}

RPC_HANDLER(remote_cap_transfer_handler)
{
    CAST_IN_MSG_EXACT_SIZE(msg, struct internal_rpc_remote_cap_msg);
    assert(pid_get_core(msg->pid) == disp_get_current_core_id());

    errval_t err;

    struct capref cap;
    err = slot_alloc(&cap);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_SLOT_ALLOC);
    }

    switch (msg->cap.type) {
    case ObjType_Frame:
        err = frame_forge(cap, msg->cap.u.frame.base, msg->cap.u.frame.bytes,
                          disp_get_current_core_id());  // XXX: owner?
        if (err_is_fail(err)) {
            return err_push(err, MON_ERR_CAP_CREATE);
        }
        break;
    case ObjType_DevFrame:
        err = devframe_forge(cap, msg->cap.u.devframe.base, msg->cap.u.devframe.bytes,
                             disp_get_current_core_id());  // XXX: owner?
        if (err_is_fail(err)) {
            return err_push(err, MON_ERR_CAP_CREATE);
        }
    case ObjType_RAM:
        err = ram_forge(cap, msg->cap.u.ram.base, msg->cap.u.ram.bytes,
                        disp_get_current_core_id());  // XXX: owner?
        if (err_is_fail(err)) {
            return err_push(err, MON_ERR_CAP_CREATE);
        }
        break;
    default:
        return MON_ERR_CAP_CREATE;
    }

    // Put the cap
    struct aos_chan *chan;
    err = spawn_get_chan(msg->pid, &chan);
    if (err_is_fail(err)) {
        return err;
    }
    assert(chan->type == AOS_CHAN_TYPE_LMP);
    err = rpc_lmp_put_cap(&chan->lc, cap);  // not blocking
    if (err_is_fail(err)) {
        return err;  // expose transient error to the caller
    }

#if DEBUG_RPC_HANDLERS
    DEBUG_PRINTF("< put cap to %u done\n", msg->pid);
#endif

    return SYS_ERR_OK;
}

static errval_t coordinate_nameserver_binding(domainid_t client_pid,
                                              struct capref *out_frame)
{
    // Wait for the nameserver to online
    if (!aos_chan_is_connected(&nameserver_rpc.chan)) {
        thread_yield();
        return MON_ERR_RETRY;
    }

    errval_t err;
    struct capref frame;
    // The input frame contains two UMP channels: first for RPC, second for listener
    err = frame_alloc(&frame, INIT_BIDIRECTIONAL_URPC_FRAME_SIZE, NULL);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_FRAME_ALLOC);
    }

    // XXX: magic number, put it in a shared header
    err = aos_chan_send(&nameserver_rpc.chan, 0, frame, &client_pid, sizeof(domainid_t),
                        true);
    if (err_is_fail(err)) {
        cap_destroy(frame);
        if (lmp_err_is_transient(err)) {
            thread_yield();
            return MON_ERR_RETRY;
        }
        return err;  // expose transient error to the user
    }

    *out_frame = frame;
    return SYS_ERR_OK;
}

RPC_HANDLER(bind_nameserver_handler)
{
    struct proc_node *proc = arg;
    assert(proc != NULL);

    // DEBUG_PRINTF("process %u tries to bind nameserver\n", proc->pid);

    errval_t err;

    if (disp_get_core_id() == 0) {
        // Return the frame as out_cap
        err = coordinate_nameserver_binding(proc->pid, out_cap);
        if (err_is_fail(err)) {
            return err;
        }

    } else {
        // Allocate a slot for the frame cap
        struct capref frame;
        err = slot_alloc(&frame);
        if (err_is_fail(err)) {
            return err_push(err, LIB_ERR_SLOT_ALLOC);
        }

        // Forward the message to core 0
        void *reply_payload = NULL;
        size_t reply_size = 0;
        err = urpc_call_to_core(0, INTERNAL_RPC_REMOTE_BIND_NAMESERVER, &proc->pid,
                                sizeof(domainid_t), &reply_payload, &reply_size);
        if (err_is_fail(err)) {
            free(reply_payload);
            return err;
        }

        // Forge the frame
        CAST_EXACT_SIZE(reply_payload, reply_size, msg, struct capability);
        err = frame_forge(frame, msg->u.frame.base, msg->u.frame.bytes,
                          disp_get_current_core_id());  // XXX: owner?
        if (err_is_fail(err)) {
            return err_push(err, MON_ERR_CAP_CREATE);
        }

        *out_cap = frame;
    }

    // DEBUG_PRINTF(">> process %u tries to bind nameserver\n", proc->pid);
    return SYS_ERR_OK;
}

RPC_HANDLER(remote_bind_nameserver_handler)
{
    CAST_IN_MSG_EXACT_SIZE(pid, domainid_t);

    // DEBUG_PRINTF("process %u remote bind nameserver\n", *pid);
    errval_t err;

    struct capref frame = NULL_CAP;
    err = coordinate_nameserver_binding(*pid, &frame);
    if (err_is_fail(err)) {
        return err;
    }
    // DEBUG_PRINTF("> process %u remote bind nameserver\n", *pid);

    // Serialize
    MALLOC_OUT_MSG(msg, struct capability);
    err = cap_direct_identify(frame, msg);
    if (err_is_fail(err)) {
        cap_destroy(frame);
        return err_push(err, LIB_ERR_CAP_IDENTIFY);
    }

    // DEBUG_PRINTF(">> process %u remote bind nameserver\n", *pid);
    return SYS_ERR_OK;
}

RPC_HANDLER(process_exit_handler)
{
    struct proc_node *proc = arg;
    assert(proc != NULL);

//     DEBUG_PRINTF("bye process %u!\n", proc->pid);

    return kill_process_and_clean(proc->pid);
}

// Unfilled slots are NULL since global variables are initialized to 0
rpc_handler_t const rpc_handlers[INTERNAL_RPC_MSG_COUNT] = {
    [RPC_TRANSFER_CAP] = cap_transfer_handler,
    [RPC_ACCEPT_CAP] = cap_accept_handler,
    [RPC_BYE] = process_exit_handler,
    [RPC_NUM] = num_msg_handler,
    [RPC_STR] = str_msg_handler,
    [RPC_RAM_REQUEST] = ram_request_msg_handler,
    [RPC_PROCESS_SPAWN] = spawn_msg_handler,
    [RPC_PROCESS_SPAWN_WITH_STDIN] = spawn_msg_stdin_handler,
    [RPC_PROCESS_GET_NAME] = process_get_name_handler,
    [RPC_PROCESS_GET_ALL_PIDS] = process_get_all_pids_handler,
	[RPC_PROCESS_KILL_PID] = process_kill_pid_handler,
	[RPC_TERMINAL_AQUIRE] = terminal_aquire_handler,
	[RPC_TERMINAL_RELEASE] = terminal_release_handler,
    [RPC_TERMINAL_GETCHAR] = terminal_getchar_handler,
    [RPC_TERMINAL_PUTCHAR] = terminal_putchar_handler,
	[RPC_TERMINAL_GETS] = terminal_gets_handler,
	[RPC_TERMINAL_PUTS] = terminal_puts_handler,
	[RPC_TERMINAL_AQUIRE] = terminal_aquire_handler,
	[RPC_TERMINAL_RELEASE] = terminal_release_handler,
	[RPC_TERMINAL_HAS_STDIN] = terminal_has_stdin_handler,
    [RPC_STRESS_TEST] = stress_test_handler,
    [RPC_BIND_NAMESERVER] = bind_nameserver_handler,
    [INTERNAL_RPC_BIND_CORE_URPC] = bind_core_urpc_handler,
    [INTERNAL_RPC_REMOTE_CAP_TRANSFER] = remote_cap_transfer_handler,
    [INTERNAL_RPC_REMOTE_RAM_REQUEST] = remote_ram_request_handler,
    [INTERNAL_RPC_REMOTE_BIND_NAMESERVER] = remote_bind_nameserver_handler,
    [INTERNAL_RPC_REMOTE_CLEAN_NAMESERVER] = remote_clean_nameserver_handler,
    [INTERNAL_RPC_GET_LOCAL_PIDS] = get_local_pids_handler,
    [RPC_FOPEN] = fopen_handler,
    [RPC_OPENDIR] = opendir_handler,
    [RPC_FCLOSE] = fclose_handler,
    [RPC_CLOSEDIR] = closedir_handler,
    [RPC_FCREATE] = fcreate_handler,
    [RPC_MKDIR] = mkdir_handler,
    [RPC_FREAD] = fread_handler,
    [RPC_FWRITE] = fwrite_handler,
	[RPC_FSTAT] = fstat_handler,
	[RPC_READDIR] = readdir_handler,
    [RPC_FSEEK] = fseek_handler,
    [RPC_FTELL] = ftell_handler,
    [RPC_FRM]   = frm_handler,
    [RPC_RMDIR] = rmdir_handler,
};