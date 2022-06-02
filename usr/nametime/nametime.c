#include <stdio.h>

#include <aos/nameserver.h>
#include <aos/systime.h>
#include <aos/aos_rpc.h>

static void time_handler(void *st, void *message, size_t bytes, void **response, size_t *response_bytes, struct capref tx_cap, struct capref *rx_cap)
{
	systime_t stop = systime_now();
	
	assert(bytes >= sizeof(systime_t));
	
	systime_t start = *(systime_t*)message;
	*response = malloc(sizeof(uint64_t));
	*response_bytes = sizeof(uint64_t);
	
	*(uint64_t*)*response = systime_to_us(stop - start);
}

int main(int argc, char** argv) {
	errval_t err;
	if (argc >= 2 && strcmp(argv[1], "server") == 0) {
		// server
		err = nameservice_register("nametime", time_handler, NULL);
		if (err_is_fail(err)) {
			printf("cannot start server, err: %s\n", err_getstring(err));
			return 1;
		}
		
		aos_rpc_serial_release(aos_rpc_get_serial_channel());
		
		while (1) event_dispatch(get_default_waitset());
	} else {
		// client
		nameservice_chan_t ntchan;
		err = nameservice_lookup("nametime", &ntchan);
		if (err_is_fail(err)) {
			printf("cannot connect to server, err: %s\n", err_getstring(err));
			return 1;
		}
		
		size_t size;
		uint64_t *one_way;
		uint64_t two_way;
		systime_t start = systime_now();
		err = nameservice_rpc(ntchan, &start, sizeof(systime_t), (void**)&one_way, &size, NULL_CAP, NULL_CAP);
		systime_t stop = systime_now();
		two_way = systime_to_us(stop - start);
		
		if (err_is_fail(err)) {
			printf("cannot time round trip, err: %s\n", err_getstring(err));
		} else {
			printf("One Way: %ldus, Two way: %ldus\n", *one_way, two_way);
		}
		
		free(one_way);
	}
	
	return 0;
}