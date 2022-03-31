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
#include <aos/dispatch.h>
#include <aos/curdispatcher_arch.h>
#include <aos/dispatcher_arch.h>
#include <barrelfish_kpi/dispatcher_shared.h>
#include <aos/morecore.h>
#include <aos/paging.h>
#include <aos/systime.h>
#include <barrelfish_kpi/domain_params.h>
#include <aos/aos_rpc.h>

#include "threads_priv.h"
#include "init.h"

/// Are we the init domain (and thus need to take some special paths)?
static bool init_domain;

#define LOCAL_ENDPOINT_BUF_SIZE  256  // XXX: a good number?

extern size_t (*_libc_terminal_read_func)(char *, size_t);
extern size_t (*_libc_terminal_write_func)(const char *, size_t);
extern void (*_libc_exit_func)(int);
extern void (*_libc_assert_func)(const char *, const char *, const char *, int);

void libc_exit(int);

__weak_reference(libc_exit, _exit);
void libc_exit(int status)
{
    debug_printf("libc exit NYI!\n");
    thread_exit(status);
    // If we're not dead by now, we wait
    while (1) {}
}

static void libc_assert(const char *expression, const char *file,
                        const char *function, int line)
{
    char buf[512];
    size_t len;

    /* Formatting as per suggestion in C99 spec 7.2.1.1 */
    len = snprintf(buf, sizeof(buf), "Assertion failed on core %d in %.*s: %s,"
                   " function %s, file %s, line %d.\n",
                   disp_get_core_id(), DISP_NAME_LEN,
                   disp_name(), expression, function, file, line);
    sys_print(buf, len < sizeof(buf) ? len : sizeof(buf));
}

__attribute__((__used__))
static size_t syscall_terminal_write(const char *buf, size_t len)
{
    if(len) {
        errval_t err = sys_print(buf, len);
        if (err_is_fail(err)) {
            return 0;
        }
    }
    return len;
}

__attribute__((__used__))
static size_t dummy_terminal_read(char *buf, size_t len)
{
    debug_printf("Terminal read NYI!\n");
    return 0;
}

/* Set libc function pointers */
void barrelfish_libc_glue_init(void)
{
    // XXX: FIXME: Check whether we can use the proper kernel serial, and
    // what we need for that
    // TODO: change these to use the user-space serial driver if possible
    // TODO: set these functions
    _libc_terminal_read_func = dummy_terminal_read;
    _libc_terminal_write_func = syscall_terminal_write;
    _libc_exit_func = libc_exit;
    _libc_assert_func = libc_assert;
    /* morecore func is setup by morecore_init() */

    // XXX: set a static buffer for stdout
    // this avoids an implicit call to malloc() on the first printf
    static char buf[BUFSIZ];
    setvbuf(stdout, buf, _IOLBF, sizeof(buf));
}

static void init_ack_handler(void *arg)
{
    struct lmp_chan *lc = arg;
    struct lmp_recv_msg msg = LMP_RECV_MSG_INIT;
    struct capref cap;
    errval_t err;

    // Try to receive a message
    err = lmp_chan_recv(lc, &msg, &cap);
    if (err_is_fail(err)) {
        if (lmp_err_is_transient(err)) {
            // Re-register
            err = lmp_chan_register_recv(lc, get_default_waitset(),
                                         MKCLOSURE(init_ack_handler, arg));
            if (err_is_ok(err)) return;  // otherwise, fall through
        }
        USER_PANIC_ERR(err_push(err, LIB_ERR_BIND_INIT_SET_RECV),
                       "unhandled error in init_ack_handler");
    }

    assert(capcmp(lc->remote_cap, cap_initep));  // should be the original one
    lc->remote_cap = cap;
    lc->connstate = LMP_CONNECTED;
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

        /* allocate lmp channel structure */
        struct lmp_chan *init_chan = malloc(sizeof(*init_chan));
        if (init_chan == NULL) {
            return err_push(err, LIB_ERR_MALLOC_FAIL);
        }
        lmp_chan_init(init_chan);

        /* set remote endpoint to init's endpoint */
        assert(!capref_is_null(cap_initep) && "init ep not available");
        err = lmp_chan_accept(init_chan, LOCAL_ENDPOINT_BUF_SIZE, cap_initep);
        if (err_is_fail(err)) {
            return err_push(err, LIB_ERR_BIND_INIT_ACCEPT);
        }
        init_chan->connstate = LMP_BIND_WAIT;

        /* set receive handler */
        struct capref new_init_ep_slot;
        err = slot_alloc(&new_init_ep_slot);
        if (err_is_fail(err)) {
            return err_push(err, LIB_ERR_BIND_INIT_SET_RECV);
        }
        lmp_chan_set_recv_slot(init_chan, new_init_ep_slot);
        err = lmp_chan_register_recv(init_chan, get_default_waitset(),
                                     MKCLOSURE(init_ack_handler, init_chan));
        if (err_is_fail(err)) {
            return err_push(err, LIB_ERR_BIND_INIT_SET_RECV);
        }

        /* send local ep to init */
        // TODO: change to special format since we are reusing
        err = lmp_chan_send1(init_chan, LMP_SEND_FLAGS_DEFAULT, init_chan->local_cap,
                             get_dispatcher_generic(curdispatcher())->domain_id);
        if (err_is_fail(err)) {
            return err_push(err, LIB_ERR_BIND_INIT_SEND_EP);
        }

        /* wait for init to acknowledge receiving the endpoint */
        while (init_chan->connstate != LMP_CONNECTED) {
            err = event_dispatch(get_default_waitset());
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "in init event_dispatch loop");
                return err_push(err, LIB_ERR_BIND_INIT_WAITING);
            }
        }

        // XXX: For now, lmp chan can be directly cast to aos_chan
        set_init_chan((struct aos_chan *) init_chan);

        /* initialize init RPC client with lmp channel */
        struct aos_rpc *init_rpc = malloc(sizeof(*init_rpc));
        if (init_rpc == NULL) {
            return err_push(err, LIB_ERR_MALLOC_FAIL);
        }
        init_rpc->type = TYPE_LMP;
        init_rpc->chan = init_chan;
        struct capref init_rpc_slot;
        err = slot_alloc(&init_rpc_slot);
        if (err_is_fail(err)) {
            return err;
        }
        lmp_chan_set_recv_slot(init_rpc->chan, init_rpc_slot);

        /* set init RPC client in our program state */
        set_init_rpc(init_rpc);
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
