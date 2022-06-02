#include "sh.h"
#include "builtins.h"
#include "strutil.h"
#include "exec_binary.h"

#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <fs/dirent.h>

#include <errno.h>

#include <aos/aos_rpc.h>
#include <aos/systime.h>

#define REGISTER_BUILTIN(name, ...) if (strcmp(env->argv[0], #name) == 0) { sh_##name(env, ##__VA_ARGS__); return 1; }

static char* sanitize_path(struct shell_env *env, const char* inpath)
{
	char* prefix;
	if (inpath[0] == '/') {
		// absolute path
		prefix = "";
	} else {
		// relative path
		prefix = env->current_path;
	}
	
	bool endsinslash = inpath[strlen(inpath) - 1] == '/';
	
	size_t len = strlen(prefix) + strlen(inpath) + 2;
	char* buffer = (char*)malloc(len);
	size_t ndirs = 0;
	size_t maxdirs = 64;
	char** dirs = (char**)malloc(sizeof(char*) * maxdirs);
	snprintf(buffer, len, "%s/%s", prefix, inpath);
	
	dirs[0] = strtok(buffer, "/");
	if (dirs[0] == NULL) {
		// empty path, return current directors, but this should not happen technically
		return env->current_path;
	}
	
	// tokenise as list of directory names
	while ((dirs[++ndirs] = strtok(NULL, "/")) != NULL) {
		if (ndirs == maxdirs) dirs = (char**)realloc(dirs, maxdirs *= 2);
	}
	
	endsinslash |= strcmp(dirs[ndirs-1], ".") == 0 || strcmp(dirs[ndirs-1], "..") == 0;
	
	// remove . and .. entries along with parents if necessary
	for (int i = 0; i < ndirs; i++) {
		if (strcmp(dirs[i], ".") == 0 || (i == 1 && strcmp(dirs[i], "..") == 0)) { // in case there is .. out of the mount point, ignore it
			// . found, remove from list
			for (int j = i; j < ndirs - 1; j++) dirs[j] = dirs[j+1];
			i--;
			ndirs--;
		} else if (strcmp(dirs[i], "..") == 0) {
			// .. found, remove with parent
			assert(i != 0 && ".. cannot be root of absolute directory");
			for (int j = i-1; j < ndirs - 2; j++) dirs[j] = dirs[j+2];
			i -= 2;
			ndirs -= 2;
		}
	}
	
	// rebuilt path string
	size_t offset = 0;
	for (size_t i = 0; i < ndirs; i++) offset += sprintf(buffer + offset, "/%s", dirs[i]);
	if (endsinslash) sprintf(buffer + offset, "/");
	
	free(dirs);
	return buffer;
}

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

static void sh_cat(struct shell_env *env)
{
	if (env->argc < 2) {
		printf("usage: cat <path...>\n");
		goto error;
	}
	
	for (size_t i = 1; i < env->argc; i++) {
		char *path = sanitize_path(env, env->argv[i]);
		
		FILE* f = fopen(path, "r");
		if (f == NULL) {
			printf("\nerror: could not open %s\n", path);
			continue;
		}
		
		printf("\nReading file %s:\n", path);
		int res = fseek(f, 0, SEEK_END);
		if (res) {
			printf("error: invalid filehandle\n");
			continue;
		}
		size_t size = ftell(f);
		fseek(f, 0, 0);
		size_t offset = 0;
		size_t read = 0;
		char *buffer = (char*)malloc(size+1);
		while ((read = fread(buffer + offset, 1, size - offset, f)) < size - offset) {
			offset += read;
			if (feof(f)) {
				free(path);
				printf("Error, unexpected end of file.\n");
				goto error;
			}
			if (ferror(f)) {
				free(path);
				printf("Error occured during file read: %d\n", ferror(f));
			}
		}
		buffer[size] = 0; // null terminate to be sure
		
		int err;
		if ((err = ferror(f))) {
			printf("An error occured while reading: %d\n", err);
		} else {
			puts(buffer);
		}
		
		free(path);
		fclose(f);
	}
	
	env->last_return_status = 0;
	return;
error:
	env->last_return_status = 1;
	return;
}

static void sh_mkdir(struct shell_env *env)
{
	env->last_return_status = 1;
	errval_t err;
	if (env->argc < 2) {
		printf("usage: mkdir <path...>\n");
		return;
	}
	
	for (size_t i = 1; i < env->argc; i++) {
		char *path = sanitize_path(env, env->argv[i]); // TODO: add flags like -p
		
		err = mkdir(path);
		
		if (err_is_fail(err)) {
			printf("mkdir failed: %s cannot be created (%s)!\n", path, err_getcode(err));
		}
		
		free(path);
	}
	
	env->last_return_status = 0;
}

static void sh_rm(struct shell_env *env)
{
	if (env->argc < 2) {
		printf("usage: rm <path...>\n");
		env->last_return_status = 0;
		return;
	}
	
	errval_t err;
	for (size_t i = 1; i < env->argc; i++) {
		char* path = sanitize_path(env, env->argv[i]);
		
		err = rm(path);
		
		if (err_is_fail(err)) printf("Failed to delete %s (err: %s)\n", path, err_getcode(err));
		
		free(path);
	}
	
	env->last_return_status = 0;
	return;
}

static void sh_rmdir(struct shell_env *env)
{
	if (env->argc < 2) {
		printf("usage: rmdir <path...>\n");
		env->last_return_status = 0;
		return;
	}
	
	errval_t err;
	for (size_t i = 1; i < env->argc; i++) {
		char* path = sanitize_path(env, env->argv[i]);
		
		err = rmdir(path);
		
		if (err_is_fail(err)) printf("Failed to delete %s (err: %s)\n", path, err_getcode(err));
		
		free(path);
	}
	
	env->last_return_status = 0;
	return;
}

static void sh_touch(struct shell_env *env)
{
	if (env->argc < 2) {
		printf("usage: touch <path...>\n");
		env->last_return_status = 0;
		return;
	}
	
	//errval_t err;
	for (size_t i = 1; i < env->argc; i++) {
		char* path = sanitize_path(env, env->argv[i]);
		
		FILE* f = fopen(path, "w");
		fclose(f);
		
		//if (err_is_fail(err)) printf("Failed to create %s (err: %s)\n", path, err_getcode(err));
		
		free(path);
	}
	
	env->last_return_status = 0;
	return;
}

static void sh_write(struct shell_env *env)
{
	if (env->argc < 2) {
		printf("usage: write <path> <tokens>\n");
		env->last_return_status = 0;
		return;
	}
	
	//errval_t err;
	char* path = sanitize_path(env, env->argv[1]);
	FILE* f = fopen(path, "w");
	
	if (env->argc > 2) { // if there are more arguments, print them line by line
		for (int i = 2; i < env->argc; i++) {
			fprintf(f, "%s\n", env->argv[i]);
		}
	}
	fflush(f);
	fclose(f);
	
	//if (err_is_fail(err)) printf("Failed to create %s (err: %s)\n", path, err_getcode(err));
	
	free(path);
	
	env->last_return_status = 0;
	return;
}

static void sh_append(struct shell_env *env)
{
	if (env->argc < 2) {
		printf("usage: append <path> <tokens>\n");
		env->last_return_status = 0;
		return;
	}
	
	//errval_t err;
	char* path = sanitize_path(env, env->argv[1]);
	FILE* f = fopen(path, "a");
	
	if (env->argc > 2) { // if there are more arguments, print them line by line
		for (int i = 2; i < env->argc; i++) {
			fprintf(f, "%s\n", env->argv[i]);
		}
	}
	fflush(f);
	fclose(f);
	
	//if (err_is_fail(err)) printf("Failed to create %s (err: %s)\n", path, err_getcode(err));
	
	free(path);
	
	env->last_return_status = 0;
	return;
}

static void sh_ls(struct shell_env *env)
{
	env->last_return_status = 1;
	char* path;
	if (env->argc == 1) {
		path = sanitize_path(env, env->current_path);
	} else {
		path = sanitize_path(env, env->argv[1]); // TODO: add ability for flags
	}
	
	fs_dirhandle_t dir;
	errval_t err = opendir(path, &dir);
	if (dir == NULL) {
		printf("Error: cannot open directory '%s'\n", path);
		goto error;
	}
	
	char *name;
	while (readdir(dir, &name) == SYS_ERR_OK) {
		printf(" %s\n", name);
		free(name);
	}
	
	err = closedir(dir);
	if (err_is_fail(err)) {
		printf("Error closing directory handle: %s\n", err_getcode(err));
		goto error;
	}
	
	free(path);	
	env->last_return_status = 0;
	return;
error:
	env->last_return_status = 1;
	free(path);
	return;
}

static void sh_cd(struct shell_env *env)
{
	char* path = NULL;
	if (env->argc == 1) {
		free(env->current_path);
		env->current_path = (char*)malloc(strlen(env->home_path) + 1);
		memcpy(env->current_path, env->home_path, strlen(env->home_path) + 1);
	} else if (env->argc == 2) {
		path = sanitize_path(env, env->argv[1]);
		
		errval_t err;
		fs_dirhandle_t fi;
		err = opendir(path, &fi);

		if (err == FS_ERR_NOTFOUND) {
			printf("error: no such directory\n");
			goto error;
		} else if (err == FS_ERR_NOTDIR) {
			printf("error: target is not a directory\n");
			goto error;
		} else {
			free(env->current_path);
			env->current_path = path;
		}
	} else {
		printf("usage: cd <path>\n");
		goto error;
	}
	
	env->last_return_status = 0;
	return;
error:
	if (path != NULL) free(path);
	env->last_return_status = 1;
	return;
}

static void sh_pwd(struct shell_env *env)
{
	puts(env->current_path);
	env->last_return_status = 0;
}

static void sh_ps(struct shell_env *env)
{
	env->last_return_status = 1;
	struct aos_rpc *rpc = aos_rpc_get_process_channel();
	
	domainid_t *pids;
	const char* line_format = "% 12d   %s\n";
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
		tmp_cmd_buffer[offset + sl] = ' ';
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

static void sh_san(struct shell_env *env)
{
	if (env->argc != 2) return;
	
	char* sanitized = sanitize_path(env, env->argv[1]);
	
	printf("Sanitized path: '%s'\n", sanitized);
	
	free(sanitized);
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
	REGISTER_BUILTIN(cat);
	REGISTER_BUILTIN(cd);
	REGISTER_BUILTIN(pwd);
	REGISTER_BUILTIN(rm);
	REGISTER_BUILTIN(rmdir);
	REGISTER_BUILTIN(touch);
	REGISTER_BUILTIN(write);
	REGISTER_BUILTIN(append);
	
	// path sanitizer
	REGISTER_BUILTIN(san);
	
	return 0; // no builtin has been found
}
