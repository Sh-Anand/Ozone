
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <aos/debug.h>

#include "sh.h"
#include "builtins.h"

static char* command_buffer = NULL;
static size_t command_buffer_size = 128; // default value
static size_t command_buffer_offset = 0;


// environment of the shell
static struct shell_env env;


/**
 * @brief Grows the command buffer by a factor of 2
 */
inline static void allocate_command_buffer(void)
{
	command_buffer_size *= 2;
	command_buffer = (char*)realloc(command_buffer, command_buffer_size);
}

/**
 * @brief Set the up environment
 */
static void setup_environment(void)
{
	// allocate command buffer space
	command_buffer_size /= 2;
	allocate_command_buffer();
	
	// set stdin to unbuffered
	setbuffer(stdin, NULL, 0);
	
	// mark the shell as active
	env.active = true;
}

inline static bool is_alpha(char c) {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

/**
 * @brief Reads a character from stdin and handles the terminals reaction to it (i.e. echo/deletion, etc)
 * 
 * @return uint8_t 1 if the command has not been terminated, 0 if more characters are expected.
 */
static uint8_t read_from_input(void)
{
	if (command_buffer_offset >= command_buffer_size) allocate_command_buffer();
	
	char c = getchar();
	
	if (c == '\n' || c == '\r') {
		command_buffer[command_buffer_offset++] = 0;
		printf("\r\n");
		return 0;
	} else if (c == 0x08 || c == 0x7f) {
		if (command_buffer_offset) {
			command_buffer[--command_buffer_offset] = 0;
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
	} else {
		command_buffer[command_buffer_offset++] = c;
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
		command_buffer_offset = 0;
		shell_print_prefix();
		while (read_from_input());
		
		if (builtin(&env, command_buffer)) continue;
	}
	
	puts("Shell terminating...\n");
}