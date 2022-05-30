#include "sh.h"
#include "builtins.h"
#include "strutil.h"
#include "exec_binary.h"

#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <dirent.h>

#include <errno.h>

#include <aos/aos_rpc.h>
#include <aos/systime.h>

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
	env->last_return_status = 1;
	if (env->argc != 2) {
		printf("usage: mkdir <path>\n");
		return;
	}
	
	char *path = env-> argv[1]; // TODO: add flags like -p
	errval_t err = aos_rpc_mkdir(aos_rpc_get_init_channel(), path);
	
	if (err_is_fail(err)) {
		printf("mkdir failed\n");
		return;
	}
	
	env->last_return_status = 0;
}

static void sh_ls(struct shell_env *env)
{
	env->last_return_status = 1;
	char* path;
	if (env->argc == 1) {
		path = env->current_path;
	} else {
		path = env->argv[1]; // TODO: add ability for flags
	}
	
	struct aos_rpc *init_rpc = aos_rpc_get_init_channel();
	handle_t dir;
	errval_t err = aos_rpc_opendir(init_rpc, path, &dir);
	if (err_is_fail(err)) goto error;
	
	struct fs_fileinfo finfo;
	err = aos_rpc_fstat(init_rpc, dir, &finfo);
	if (err_is_fail(err)) goto error;
	
	if (finfo.type == FS_FILE) {
		printf("target is not a directory\n");
		env->last_return_status = 0;
		return;
	}
	
	char* name;
	while ((err = aos_rpc_readdir_next(init_rpc, dir, &name)) != FS_ERR_INDEX_BOUNDS) {
		if (err_is_fail(err) || name == NULL) goto error;
		printf("  %s\n", name);
		free(name);
	}
	
	
	printf("ls succeeded!\n");
	env->last_return_status = 0;
	return;
error:
	printf("ls failed: %s\n", err_getcode(err));
	
	/*
	DIR* dir = opendir(path);
	struct dirent *de;
	if (dir == NULL) {
		printf("Error: cannot open directory '%s'\n", path);
		env->last_return_status = 1;
		return;
	}
	
	while ((de = readdir(dir)) != NULL) {
		printf("    %s\n", de->d_name);
	}
	
	env->last_return_status = 0;*/
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
	domainid_t pid;
	errval_t err;
	env->last_return_status = 1;
	
	if (env->argc <= 1) {
		printf("No pids given to kill\n");
		env->last_return_status = 0;
		return;
	}
	for (int i = 1; i < env->argc; i++) {
		int r = sscanf(env->argv[i], "%d", &pid);
		if (r > 0) {
			err = aos_rpc_process_kill_pid(aos_rpc_get_process_channel(), pid);
			if (err_is_fail(err)) {
				printf("Failed to kill process '%s': %s\n", env->argv[i], err_getcode(err));
			}
		} else {
			printf("Invalied PID: '%s'\n", env->argv[i]);
		}
	}
	
	
	
	env->last_return_status = 0;
}

static void sh_oncore(struct shell_env *env)
{
	if (env->argc < 3) {
		printf("Usage: oncore <core id> <command>...\n");
		env->last_return_status = 1;
		return;
	}
	
	uint8_t core;
	if (sscanf(env->argv[1], "%d", &core) < 1) {
		printf("Failed to parse core id!\n");
		env->last_return_status = 1;
		return;
	}
	
	char* tmp_cmd_buffer = (char*)calloc(strlen(env->command_buffer), 1);
	size_t offset = 0;
	for (size_t i = 2; i < env->argc; i++) {
		size_t sl = strlen(env->argv[i]);
		memcpy(tmp_cmd_buffer + offset, env->argv[i], sl);
		tmp_cmd_buffer[sl] = ' ';
		offset += sl + 1;
	}
	
	printf("Running '%s' on core %d\n", tmp_cmd_buffer, core);
	
	struct shell_env tmp_env = {
		.active = false,
		.argc = env->argc - 2,
		.argv = env->argv + 2,
		.command_buffer = tmp_cmd_buffer,
		.current_path = env->current_path,
		.next_core = core
	};
	
	if (!exec_binary(&tmp_env)) {
		printf("Error cannot run '%s', no such binary!\n", tmp_env.argv[0]);
	}
	
	free(tmp_cmd_buffer);
}

static void sh_time(struct shell_env *env)
{
	if (env->argc < 2) {
		printf("Usage: time <command>...\n");
		env->last_return_status = 1;
		return;
	}
	
	char* tmp_cmd_buffer = (char*)calloc(strlen(env->command_buffer), 1);
	size_t offset = 0;
	for (size_t i = 1; i < env->argc; i++) {
		size_t sl = strlen(env->argv[i]);
		memcpy(tmp_cmd_buffer + offset, env->argv[i], sl);
		tmp_cmd_buffer[sl] = ' ';
		offset += sl + 1;
	}
	
	struct shell_env tmp_env = {
		.active = false,
		.argc = env->argc - 1,
		.argv = env->argv + 1,
		.command_buffer = tmp_cmd_buffer,
		.current_path = env->current_path,
		.next_core = env->next_core
	};
	
	systime_t start = systime_now();
	if (builtin(&tmp_env)) {}
	else if (exec_binary(&tmp_env)) {}
	else {
		printf("Error: cannot run '%s'!\n", tmp_env.argv[0]);
		env->last_return_status = 1;
		goto exit;
	}
	
	systime_t stop = systime_now();
	uint64_t duration_us = systime_to_us(stop - start);
	env->last_return_status = 0;
	printf("Executed successfully! Took %0.3fms\n", (double)duration_us / (double)1000);
exit:
	free(tmp_cmd_buffer);
}


int builtin(struct shell_env *env)
{
	assert(env->argc > 0); // sanity check
	
	REGISTER_BUILTIN(exit);
	REGISTER_BUILTIN(echo);
	
	// process management
	REGISTER_BUILTIN(ps);
	REGISTER_BUILTIN(kill);
	REGISTER_BUILTIN(oncore);
	REGISTER_BUILTIN(time);
	
	// file system utilities
	REGISTER_BUILTIN(ls);
	REGISTER_BUILTIN(mkdir);
	
	return 0; // no builtin has been found
}
