/**
 * \file
 * \brief Barrelfish library initialization.
 */

/*
 * Copyright (c) 2007-2019, ETH Zurich.
 * Copyright (c) 2014, HP Labs.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, CAB F.78, Universitaetstr. 6, CH-8092 Zurich,
 * Attn: Systems Group.
 */

#include <stdio.h>

#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <aos/dispatch.h>
#include <aos/curdispatcher_arch.h>
#include <aos/dispatcher_arch.h>
#include <barrelfish_kpi/dispatcher_shared.h>
#include <aos/morecore.h>
#include <aos/paging.h>
#include <aos/systime.h>
#include <barrelfish_kpi/domain_params.h>
#include <aos/aos_rpc.h>
#include <aos/debug.h>


#include "threads_priv.h"
#include "init.h"

#define DIRECT_PRINTF 0

/// Are we the init domain (and thus need to take some special paths)?
static bool init_domain;

#define LOCAL_ENDPOINT_BUF_SIZE 256  // XXX: a good number?

extern size_t (*_libc_terminal_read_func)(char *, size_t);
extern size_t (*_libc_terminal_write_func)(const char *, size_t);
extern void (*_libc_exit_func)(int);
extern void (*_libc_assert_func)(const char *, const char *, const char *, int);

extern void* terminal_state;

size_t (*local_terminal_write_function)(const char*, size_t) = NULL;
size_t (*local_terminal_read_function)(char*, size_t) = NULL;

void libc_exit(int);

__weak_reference(libc_exit, _exit);
void libc_exit(int status)
{
	// release the terminal
	//errval_t err = aos_rpc_serial_release(aos_rpc_get_serial_channel());
	//DEBUG_ERR(err, "terminal release (err: %s)", err_getcode(err));
	
    debug_printf("libc exit NYI!\n");
	
	aos_rpc_serial_release(aos_rpc_get_serial_channel());
	
    thread_exit(status);
    // If we're not dead by now, we wait
    while (1) {
    }
}

static void libc_assert(const char *expression, const char *file, const char *function,
                        int line)
{
    char buf[512];
    size_t len;

    /* Formatting as per suggestion in C99 spec 7.2.1.1 */
    len = snprintf(buf, sizeof(buf),
                   "Assertion failed on core %d in %.*s: %s,"
                   " function %s, file %s, line %d.\n",
                   disp_get_core_id(), DISP_NAME_LEN, disp_name(), expression, function,
                   file, line);
    sys_print(buf, len < sizeof(buf) ? len : sizeof(buf));
}

__attribute__((__used__)) static size_t syscall_terminal_write(const char *buf, size_t len)
{
    if (len) {
        errval_t err = sys_print(buf, len);
        if (err_is_fail(err)) {
            return 0;
        }
    }
    return len;
}

__attribute__((__used__)) static size_t aos_terminal_write(const char *buf, size_t len)
{
	errval_t err;
	struct aos_rpc *serial_rpc = aos_rpc_get_serial_channel();
	//assert (serial_rpc);
	if (!serial_rpc) return 0;
	
	// NO LONGER TODO : this is probably very inefficient, so maybe do this for whole strings instead
	/*or (sent = 0; sent < len;) {
		err = aos_rpc_serial_putchar(serial_rpc, buf[sent]);
		
		if (err_is_fail(err)) {
			// sending failed, so return
			break;
		}
		
		sent++;
	}*/
	
	//DEBUG_PRINTF("str: '%s' (%d)\n", buf, strlen(buf));
	
	// this is the way
	size_t ret_len;
	err = aos_rpc_serial_puts(serial_rpc, buf, len, &ret_len);
	if (err_is_fail(err)) {
		DEBUG_ERR(err, "Failed to print!");
		return 0;
	}
	
	//if (ret_len > len) DEBUG_PRINTF("ret_len: %llu, len: %llu\n", ret_len, len);
	
	// return the number of characters sent
	return ret_len;
}

__attribute__((__used__)) static size_t dummy_terminal_read(char *buf, size_t len)
{
    debug_printf("Terminal read NYI!\n");
    return 0;
}

__attribute__((__used__)) static size_t aos_terminal_read(char *buf, size_t len)
{
	size_t read = 0;
	errval_t err;
	char c;
	struct aos_rpc *serial_rpc = aos_rpc_get_serial_channel();
	
	
	
	assert(serial_rpc);
	
	// wait for access to stdin
	bool can_access_stdin = false;
	do {
		err = aos_rpc_serial_has_stdin(serial_rpc, &can_access_stdin);
		if (!can_access_stdin) thread_yield();
	} while (!can_access_stdin);
	
	for (; read < len;) {
		do {
			err = aos_rpc_serial_getchar(serial_rpc, &c);
			if (err == TERM_ERR_RECV_CHARS) thread_yield();
		} while (err == TERM_ERR_RECV_CHARS);
		
		if (err_is_fail(err)) {
			// cannot receive so exit
			break;
		}
		
		buf[read++] = c;
	}
	
	buf[read] = 0;
	
    return read;
}
static size_t local_terminal_write(const char* buf, size_t len) __attribute__((unused));
static size_t local_terminal_write(const char* buf, size_t len)
{
	if (local_terminal_write_function) return local_terminal_write_function(buf, len);
	return 0;
}

static size_t local_terminal_read(char* buf, size_t len)
{
	if (local_terminal_read_function) return local_terminal_read_function(buf, len);
	return 0;
}

extern errval_t fs_libc_init(void*);

/* Set libc function pointers */
void barrelfish_libc_glue_init(void)
{
    // XXX: FIXME: Check whether we can use the proper kernel serial, and
    // what we need for that
    // TODO: change these to use the user-space serial driver if possible
    // TODO: set these functions
    _libc_terminal_read_func = !init_domain || !disp_get_current_core_id() ? aos_terminal_read : local_terminal_read;
    _libc_terminal_write_func = !init_domain || !disp_get_current_core_id() ? aos_terminal_write : local_terminal_write;
    _libc_exit_func = libc_exit;
    _libc_assert_func = libc_assert;
    /* morecore func is setup by morecore_init() */
	
	if (!init_domain) {
		errval_t err = fs_libc_init(aos_rpc_get_init_channel());
		if(err_is_fail(err)) {
			DEBUG_PRINTF("Failed to initialized filesystem (err: %s)\n", err_getcode(err));
		}
	}

    // XXX: set a static buffer for stdout
    // this avoids an implicit call to malloc() on the first printf
    static char buf[BUFSIZ];
    setvbuf(stdout, buf, _IOLBF, sizeof(buf));
}

/** \brief Initialise libbarrelfish.
 *
 * This runs on a thread in every domain, after the dispatcher is setup but
 * before main() runs.
 */
errval_t barrelfish_init_onthread(struct spawn_domain_params *params)
{
    errval_t err;

    // do we have an environment?
    if (params != NULL && params->envp[0] != NULL) {
        extern char **environ;
        environ = params->envp;
    }

    // Init default waitset for this dispatcher
    struct waitset *default_ws = get_default_waitset();
    waitset_init(default_ws);

    // Initialize ram_alloc state
    ram_alloc_init();
    /* All domains use smallcn to initialize */
    err = ram_alloc_set(ram_alloc_fixed);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_RAM_ALLOC_SET);
    }

    err = paging_init();
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_VSPACE_INIT);
    }

    err = slot_alloc_init();
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_SLOT_ALLOC_INIT);
    }

    err = morecore_init(BASE_PAGE_SIZE);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_MORECORE_INIT);
    }

    lmp_endpoint_init();

    // HINT: Use init_domain to check if we are the init domain.


    /* create local endpoint */
    err = cap_retype(cap_selfep, cap_dispatcher, 0, ObjType_EndPointLMP, 0, 1);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_ENDPOINT_CREATE);
    }
    assert(!capref_is_null(cap_selfep));

    if (!init_domain) {
        /* allocate rpc structure */
        struct aos_rpc *init_rpc = malloc(sizeof(*init_rpc));
        if (init_rpc == NULL) {
            return err_push(err, LIB_ERR_MALLOC_FAIL);
        }
        aos_rpc_init(init_rpc);

        /* initialize init RPC client with lmp channel */
        aos_chan_lmp_init(&init_rpc->chan);
        struct lmp_chan *init_lc = &init_rpc->chan.lc;

        /* set remote endpoint to init's endpoint */
        assert(!capref_is_null(cap_initep) && "init ep not available");
        err = lmp_chan_accept(init_lc, LOCAL_ENDPOINT_BUF_SIZE, cap_initep);
        if (err_is_fail(err)) {
            return err_push(err, LIB_ERR_LMP_CHAN_ACCEPT);
        }
        init_lc->connstate = LMP_BIND_WAIT;

        /* send local ep to init */
        err = lmp_chan_send1(init_lc, LMP_SEND_FLAGS_DEFAULT, init_lc->local_cap,
                             get_dispatcher_generic(curdispatcher())->domain_id);
        if (err_is_fail(err)) {
            return err_push(err, LIB_ERR_BIND_INIT_SEND_EP);
        }

        /* wait for init to acknowledge receiving the endpoint */
        DEBUG_PRINTF("binding with init\n");
        while (true) {
            struct lmp_recv_msg msg = LMP_RECV_MSG_INIT;
            err = lmp_chan_recv(init_lc, &msg, NULL);
            if (err == LIB_ERR_NO_LMP_MSG) {
                thread_yield();
            } else if (err_is_fail(err)) {
                if (lmp_err_is_transient(err)) {
                    thread_yield() ;
                }
                return err_push(err, LIB_ERR_BIND_INIT_WAITING);
            } else {
                break;
            }
        }
        init_lc->connstate = LMP_CONNECTED;

        /* alloc recv for init_rpc */
        err = lmp_chan_alloc_recv_slot(&init_rpc->chan.lc);
        if (err_is_fail(err)) {
            return err;
        }

        /* init rpc is ready for use */
        set_init_chan(&init_rpc->chan);
        set_init_rpc(init_rpc);

        ram_alloc_set(NULL);  // use RAM allocation over RPC
		if (params->terminal_state) {
			terminal_state = params->terminal_state;
		} else {
			aos_rpc_serial_aquire(aos_rpc_get_serial_channel(), false);
		}
		
		DEBUG_PRINTF("Received terminal state: %p\n", terminal_state);
		
    }
	
    // right now we don't have the nameservice & don't need the terminal
    // and domain spanning, so we return here
    return SYS_ERR_OK;
}


/**
 *  \brief Initialise libbarrelfish, while disabled.
 *
 * This runs on the dispatcher's stack, while disabled, before the dispatcher is
 * setup. We can't call anything that needs to be enabled (ie. cap invocations)
 * or uses threads. This is called from crt0.
 */
void barrelfish_init_disabled(dispatcher_handle_t handle, bool init_dom_arg);
void barrelfish_init_disabled(dispatcher_handle_t handle, bool init_dom_arg)
{
    init_domain = init_dom_arg;
    disp_init_disabled(handle);
    thread_init_disabled(handle, init_dom_arg);
}
