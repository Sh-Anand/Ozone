#include <stdio.h>
#include <aos/aos_rpc.h>
#include <aos/waitset.h>
#include <arch/aarch64/aos/dispatcher_arch.h>


static errval_t terminal_rpc_setup(void)
{
	errval_t err;
	struct aos_rpc *init_rpc_new = (struct aos_rpc*)malloc(sizeof(struct aos_rpc));
	if (!init_rpc_new) {
		DEBUG_PRINTF("Failed to allocate space for rpc channel in terminal server.\n");
		return LIB_ERR_MALLOC_FAIL;
	}
	
	init_rpc_new->chan = (struct lmp_chan*)malloc(sizeof(struct lmp_chan));
	if (!init_rpc_new) {
		DEBUG_PRINTF("Failed to allocate space for lmp channel in terminal server.\n");
		return LIB_ERR_MALLOC_FAIL;
	}
	
	lmp_chan_init(init_rpc_new->chan);
	
	if (capref_is_null(cap_initep)) {
		DEBUG_PRINTF("Terminal Server cap_initep is null!\n");
		return SYS_ERR_CAP_NOT_FOUND;
	}
		/* set receive handler */
	struct capref rcap;
	err = slot_alloc(&rcap);
	if (err_is_fail(err)) {
		return err_push(err, LIB_ERR_BIND_INIT_SET_RECV);
	}
	struct lmp_recv_msg *rmsg = (struct lmp_recv_msg*)malloc(sizeof(struct lmp_recv_msg));
	
	lmp_chan_alloc_recv_slot(init_rpc_new->chan);

	while (!lmp_chan_can_recv(init_rpc_new->chan)) event_dispatch(get_default_waitset());
	
	lmp_chan_recv(init_rpc_new->chan, rmsg, &rcap);
	
	err = lmp_chan_accept(init_rpc_new->chan, 256, rcap);
	if (err_is_fail(err)) {
		return err_push(err, LIB_ERR_BIND_INIT_ACCEPT);
	}
	init_rpc_new->chan->connstate = LMP_BIND_WAIT;
	
	free(rmsg);


	/* send local ep to init */
	// TODO: change to special format since we are reusing
	err = lmp_chan_send1(init_rpc_new->chan, LMP_SEND_FLAGS_DEFAULT, init_rpc_new->chan->local_cap,
							get_dispatcher_generic(curdispatcher())->domain_id);
	if (err_is_fail(err)) {
		return err_push(err, LIB_ERR_BIND_INIT_SEND_EP);
	}

	/* wait for init to acknowledge receiving the endpoint */
	while (init_rpc_new->chan->connstate != LMP_CONNECTED) {
		err = event_dispatch(get_default_waitset());
		if (err_is_fail(err)) {
			DEBUG_ERR(err, "error in init event_dispatch loop");
			return err_push(err, LIB_ERR_BIND_INIT_WAITING);
		}
	}

	// XXX: For now, lmp chan can be directly cast to aos_chan?
	set_init_chan((struct aos_chan*)init_rpc_new->chan);
	
	DEBUG_PRINTF("Uart driver accepted channel\n");
	
	init_rpc_new->type = TYPE_LMP;

	ram_alloc_set(NULL); // Use Ram allocation over RPC
	
	return SYS_ERR_OK;
}

int main(int argc, char** argv)
{
	errval_t err;
	err = terminal_rpc_setup();
}