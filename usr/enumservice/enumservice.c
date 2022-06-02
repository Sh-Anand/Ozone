

#include <stdio.h>
#include <aos/aos.h>
#include <aos/nameserver.h>

#define PANIC_IF_FAIL(err, msg)                                                          \
    if (err_is_fail(err)) {                                                              \
        USER_PANIC_ERR(err, msg);                                                        \
    }

int main(int argc, char *argv[])
{
    char *query;
    if (argc > 2) {
        DEBUG_PRINTF("Usage: %s [query]\n", argv[0]);
        return EXIT_FAILURE;

    } else if (argc == 2) {
        query = argv[1];
    } else {
        query = "";
    }

    size_t count = 256;
    char *names[256];
    errval_t err = nameservice_enumerate(query, &count, names);
    PANIC_IF_FAIL(err, "failed to enumerate service\n");
    debug_printf("server: enumerate \"%s\" got %lu services:\n", query, count);
    for (size_t i = 0; i < count; i++) {
        debug_printf("%lu. %s\n", i + 1, names[i]);
        free(names[i]);
    }
}