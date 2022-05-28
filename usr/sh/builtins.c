#include "builtins.h"
#include "strutil.h"

#include <assert.h>
#include <string.h>
#include <stdio.h>

#include <fs/fat32.h>

#include <aos/aos_rpc.h>

#define REGISTER_BUILTIN(name, ...) if (strcmp(env->argv[0], #name) == 0) { sh_##name(env, ##__VA_ARGS__); return 1; }

static void sh_exit(struct shell_env *env)
{
	env->active = 0;
	env->last_return_status = 0;
}

static void sh_echo(struct shell_env *env)
{
	if (env->argc > 1) {
		printf("%s", env->argv[1]); // ignore element 0 (name of the command)
	}
	for (int i = 2; i < env->argc; i++) {
		printf(" %s", env->argv[i]); // prefix a space to separate words from previous ones
	}
	
	printf("\n");
	env->last_return_status = 0;
	
}

static void sh_mkdir(struct shell_env *env)
{
	DEBUG_PRINTF("enter sh_mkdir\n");
	env->last_return_status = 1;
	if (env->argc != 2) {
		printf("usage: mkdir <path>\n");
		return;
	}
	
	char *path = env-> argv[1]; // TODO: add flags like -p
	errval_t err = fat32_mkdir(path);
	DEBUG_PRINTF("fat32_mkdir done\n");
	
	if (err_is_fail(err)) {
		printf("mkdir failed\n");
		return;
	}
	
	env->last_return_status = 0;
	DEBUG_PRINTF("exit sh_mkdir\n");
}

static void sh_ls(struct shell_env *env)
{
	char* path;
	if (env->argc == 1) {
		path = env->current_path;
	}
	
}

static void sh_ps(struct shell_env *env)
{
	env->last_return_status = 1;
	struct aos_rpc *rpc = aos_rpc_get_process_channel();
	
	domainid_t *pids;
	const char* line_format = "  % 6d   %s\n";
	size_t npids, out_size = 1024, out_offset = 0, overhead_length = strlen(line_format);
	char* name;
	char* out_text = (char*)malloc(sizeof(char) * out_size);
	errval_t err = aos_rpc_process_get_all_pids(rpc, &pids, &npids);
	
	if (err_is_fail(err)) {
		printf("ps failed: cannot contact process manager.\n");
		free(out_text);
		return;
	}
	
	out_offset += snprintf(out_text, out_size - 1, "Running processes:\n");
	
	for (size_t i = 0; i < npids; i++) {
		name = NULL;
		bool free_needed = false;
		
		err = aos_rpc_process_get_name(rpc, pids[i], &name);
		if (err_is_ok(err)) free_needed = true;
		else name = "N/A";
		
		size_t line_len = strlen(name) + overhead_length;
		if (out_offset + line_len + 1 >= out_size) {
			out_size *= 2;
			out_text = (char*)realloc(out_text, out_size);
		}
		out_offset += snprintf(out_text + out_offset, out_size - out_offset - 1, line_format, pids[i], name);
		if (free_needed) free(name);
	}
	
	printf(out_text);
	free(out_text);
	free(pids);
	
	env->last_return_status = 0;
}

static void sh_kill(struct shell_env *env)
{
	env->last_return_status = 1;
	//struct aos_rpc *rpc = aos_rpc_get_process_channel();
	
	// TODO: implement killing over rpc
	
	env->last_return_status = 0;
}


int builtin(struct shell_env *env)
{
	assert(env->argc > 0); // sanity check
	
	REGISTER_BUILTIN(exit);
	REGISTER_BUILTIN(echo);
	REGISTER_BUILTIN(ls);
	REGISTER_BUILTIN(mkdir);
	REGISTER_BUILTIN(ps);
	REGISTER_BUILTIN(kill);
	
	return 0; // no builtin has been found
}
