#include "builtins.h"

#include <string.h>

#define REGISTER_BUILTIN(name, func, ...) if (strcmp(command, #name) == 0) return func(env, ##__VA_ARGS__) 

static int exit(struct shell_env *env)
{
	env->active = 0;
	env->last_return_status = 0;
	return 1;
}


int builtin(struct shell_env *env, const char* command)
{
	REGISTER_BUILTIN(exit, exit);
	
	return 0; // no builtin has been found
}