#include "exec_binary.h"

#include <aos/domain.h>
#include <aos/aos_rpc.h>


void exec_binary(struct shell_env *env)
{
	//struct spawninfo si;
	domainid_t pid;
	errval_t err;
	
	err = aos_rpc_serial_release(aos_rpc_get_serial_channel());
	
	err = aos_rpc_process_spawn(aos_rpc_get_process_channel(), env->command_buffer, 0, &pid);
	//err = spawn_load_argv(env->argc, env->argv, &si, &pid);
	
	if (err_is_fail(err)) {
		printf("Error: could not spawn process: %s\n", err_getstring(err));
		return;
	}
	
	printf("Started process: %x\n", pid);
	
	do {
		event_dispatch(get_default_waitset());
		err = aos_rpc_serial_aquire(aos_rpc_get_serial_channel());
	} while (err_is_fail(err));
	
	printf("Shell resuming...\n");
}