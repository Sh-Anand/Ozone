#include "exec_binary.h"

#include <aos/domain.h>
#include <aos/aos_rpc.h>


int exec_binary(struct shell_env *env)
{
	//struct spawninfo si;
	domainid_t pid;
	errval_t err;
	void* child_terminal_state;
	
	err = aos_rpc_serial_aquire_new_state(aos_rpc_get_serial_channel(), &child_terminal_state, true);
	err = aos_rpc_process_spawn_with_terminal_state(aos_rpc_get_process_channel(), env->command_buffer, child_terminal_state, env->next_core, &pid);
	//err = spawn_load_argv(env->argc, env->argv, &si, &pid);
	
	if (err_is_fail(err)) {
		aos_rpc_serial_release_terminal_state(aos_rpc_get_serial_channel(), child_terminal_state);
		return 0;
	}
	
	env->next_core = (env->next_core + 1) % NUMBER_OF_CORES;
	
	bool can_access_stdin = false;
	do {
		thread_yield();
		err = aos_rpc_serial_has_stdin(aos_rpc_get_serial_channel(), &can_access_stdin);
	} while (!can_access_stdin);
	
	return 1;
}