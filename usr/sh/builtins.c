#include "builtins.h"
#include "strutil.h"

#include <assert.h>
#include <string.h>
#include <stdio.h>

#define REGISTER_BUILTIN(name, func, ...) if (strcmp(env->argv[0], #name) == 0) return func(env, ##__VA_ARGS__) 

static int sh_exit(struct shell_env *env)
{
	env->active = 0;
	env->last_return_status = 0;
	return 1;
}

static int sh_echo(struct shell_env *env)
{
	if (env->argc > 1) {
		printf("%s", env->argv[1]); // ignore element 0 (name of the command)
	}
	for (int i = 2; i < env->argc; i++) {
		printf(" %s", env->argv[i]); // prefix a space to separate words from previous ones
	}
	
	printf("\n");
	
	return 1;
}


int builtin(struct shell_env *env)
{
	assert(env->argc > 0); // sanity check
	
	REGISTER_BUILTIN(exit, sh_exit);
	REGISTER_BUILTIN(echo, sh_echo);
	
	return 0; // no builtin has been found
}
