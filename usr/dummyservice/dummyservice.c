

#include <stdio.h>
#include <aos/aos.h>
#include <aos/nameserver.h>

#define PANIC_IF_FAIL(err, msg)                                                          \
    if (err_is_fail(err)) {                                                              \
        USER_PANIC_ERR(err, msg);                                                        \
    }

static void server_recv_handler(void *st, void *message, size_t bytes, void **response,
                                size_t *response_bytes, struct capref rx_cap,
                                struct capref *tx_cap)
{
    debug_printf("got a request \"%s\"\n", (char *)message);
}

int main(int argc, char *argv[]) {

    if (argc != 2) {
        printf("Usage: %s service_name\n", argv[0]);
        return EXIT_FAILURE;

    } else {
        printf("register with nameservice '%s'\n", argv[1]);
        errval_t err = nameservice_register(argv[1], server_recv_handler, NULL);
        PANIC_IF_FAIL(err, "failed to register...\n");

        while (1) {
            event_dispatch(get_default_waitset());
        }
    }
}