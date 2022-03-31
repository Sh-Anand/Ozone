#include <stdarg.h>
#include <stdio.h>

#include <aos/aos.h>
#include <aos/sys_debug.h>
#include <grading.h>


void grading_rpc_handle_number(uintptr_t val) 
{
}

void grading_rpc_handler_string(const char* string)
{
}

void grading_rpc_handler_serial_getchar(void)
{
}

void grading_rpc_handler_serial_putchar(char c)
{
}

void grading_rpc_handler_ram_cap(size_t bytes, size_t alignment)
{
}

void grading_rpc_handler_process_spawn(char* cmdline, coreid_t core)
{
    DEBUG_PRINTF("grading_rpc_handler_process_spawn: %s, %d\n", cmdline, core);
}

void grading_rpc_handler_process_get_name(domainid_t pid)
{
    DEBUG_PRINTF("grading_rpc_handler_process_get_name: %u\n", pid);
}

void grading_rpc_handler_process_get_all_pids(void)
{
    DEBUG_PRINTF("grading_rpc_handler_process_get_all_pids\n");
}
