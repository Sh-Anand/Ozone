#include <stdio.h>

#include <aos/nameserver.h>





static void terminal_handler(void *st, void *message, size_t bytes, void **response, size_t *response_bytes, struct capref tx_cap, struct capref *rx_cap)
{
	assert(bytes > 0);
	char* data = message;
	
	printf("Recv: 0x%X\n", data[0]);
}

int main(int argc, char** argv)
{
	errval_t err;
	DEBUG_PRINTF("Terminal service starting...\n");
	
	err = nameservice_register("terminal_server", terminal_handler, NULL /* For Now */);
	if (err_is_fail(err)) {
		USER_PANIC_ERR(err, "Could not register terminal server!");
	}
	
	// enter wait loop
	while (1) {
		event_dispatch(get_default_waitset());
	}
}