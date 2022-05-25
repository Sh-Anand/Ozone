
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <aos/debug.h>

#include "strutil.h"
#include "sh.h"
#include "builtins.h"
#include "exec_binary.h"

#include <aos/nameserver.h>


// environment of the shell
static struct shell_env env;


/**
 * @brief Grows the command buffer by a factor of 2
 */
inline static void allocate_command_buffer(void)
{
	env.command_buffer_size *= 2;
	env.command_buffer = (char*)realloc(env.command_buffer, env.command_buffer_size);
}

inline static void allocate_argv(void)
{
	env.max_args *= 2;
	env.argv = (char**)realloc(env.argv, sizeof(char*) * env.max_args);
}

/**
 * @brief Set the up environment
 */
static void setup_environment(void)
{
	// allocate buffers
	env.command_buffer_size = 64;
	allocate_command_buffer();
	env.max_args = 16;
	allocate_argv();
	
	// set stdin to unbuffered
	setbuffer(stdin, NULL, 0);
	
	// mark the shell as active
	env.active = true;
}

/**
 * @brief Reads a character from stdin and handles the terminals reaction to it (i.e. echo/deletion, etc)
 * 
 * @return uint8_t 1 if the command has not been terminated, 0 if more characters are expected.
 */
static uint8_t read_from_input(void)
{
	if (env.command_buffer_offset >= env.command_buffer_size) allocate_command_buffer();
	
	char c = getchar();
	
	if (c == '\n' || c == '\r') { // enter was pressed
		env.command_buffer[env.command_buffer_offset++] = 0;
		printf("\r\n");
		return 0;
	} else if (c == 0x08 || c == 0x7f) { // backspace
		if (env.command_buffer_offset) {
			env.command_buffer[--env.command_buffer_offset] = 0;
			printf("\b \b");
		}
		return 1;
	} else if (c == '\x1b') { // this is an escape sequence
		size_t max_i = 64;
		char *escape_sequence = (char*)malloc(max_i);
		escape_sequence[0] = c;
		uint8_t active = 1;
		size_t i = 1;
		while (active) {
			if (i >= max_i) escape_sequence = (char*)realloc(escape_sequence, max_i *= 2);
			c = getchar();
			escape_sequence[i++] = c;
			if (is_alpha(c)) {
				escape_sequence[i] = 0;
				active = 0;
			}
		}
		
		// TODO: handle escape sequences...
		
		return 1;
	} else { // nothing interesting, just another character, so add it to the pile
		env.command_buffer[env.command_buffer_offset++] = c;
		putchar(c);
		return 1;
	}
}

static void shell_print_prefix(void)
{
	// TODO: this should be more sophisticated
	printf("AOS shell $> \0");
}

int main(int argc, char **argv)
{
	puts("AOS Team 1 shell starting...\n");
	
	setup_environment();
	
	while (env.active) {
		// setup new command prompt
		env.command_buffer_offset = 0;
		shell_print_prefix();
		
		// read the input
		while (read_from_input());
		if (env.command_buffer_offset == 0 || env.command_buffer[0] == 0) continue;
		
		// split the command line into tokens
		env.argc = 0;
		char* state;
		
		//TODO: support quoted strings
		
		// split string into tokens and store in env.argv
		char* token = strtok_r(env.command_buffer, " \r\n\t", &state);
		do {
			if (argc == env.max_args) allocate_argv();
			env.argv[env.argc++] = token;
		} while ((token = strtok_r(NULL, " \r\n\t", &state)));
		
		if (env.argc == 0) continue;
		
		if (builtin(&env)) continue;
		
		exec_binary(&env);
	}
	
	puts("Shell terminating...\n");
}