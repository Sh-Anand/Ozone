#ifndef _BUILTINS_H
#define _BUILTINS_H

#include "sh.h"

int builtin(struct shell_env *env, const char* command);

#endif // _BUILTINS_H