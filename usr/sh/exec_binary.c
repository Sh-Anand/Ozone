#include "exec_binary.h"

#include <aos/domain.h>
#include <aos/aos_rpc.h>


void exec_binary(struct shell_env *env)
{
	//struct spawninfo si;
	domainid_t pid;
	errval_t err;
	
	err = aos_rpc_process_spawn(aos_rpc_get_process_channel(), env->command_buffer, 0, &pid);
	//err = spawn_load_argv(env->argc, env->argv, &si, &pid);
	
	if (err_is_fail(err)) {
		printf("Error: could not spawn process: %s\n", err_getstring(err));
		return;
	}
	
	printf("Started process: %x\n", pid);
	
	// crude way of blocking shell until child exists
	uint8_t child_running;
	domainid_t *all_pids;
	size_t n_pids;
	char pidstr[1024];
	int offset = 0;
	do {
		err = aos_rpc_process_get_all_pids(aos_rpc_get_process_channel(), &all_pids, &n_pids);
		child_running = 0;
		offset = 0;
		if (err_is_ok(err)) {
			for (size_t i = 0; i < n_pids; i++) {
				offset += sprintf(pidstr + offset, "%lx ", all_pids[i]);
				if (all_pids[i] == pid) child_running |= 1;
			}
			printf("all_pids: %s\n", pidstr);
			//event_dispatch(get_default_waitset());
			thread_yield();
		}
	} while (child_running);
	
	printf("Shell resuming...\n");
}