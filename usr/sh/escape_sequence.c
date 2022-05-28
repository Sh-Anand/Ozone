#include "escape_sequence.h"

#include "strutil.h"

#include <stdbool.h>
#include <string.h>
#include <stdio.h>

// define selection of escape sequences
const char *arrow_up = "\e[A";
const char *arrow_down = "\e[B";
//const char *arrow_right = "\e[C";
//const char *arrow_left = "\e[D";

static bool ends_with(char* str, char end)
{
	size_t len = strlen(str);
	if (len == 0) return false;
	return str[len-1] == end;
}

static void handle_keyboard_string(struct shell_env *env, char* seq)
{
	printf("keyboard string\n");
}

static void prev_command(struct shell_env *env)
{
	// if already at the beginning of the history, don't do anything
	if (env->history->current == env->history->first) {
		bell();
		return;
	}
	
	// decrement the current pointer
	if (env->history_active) {
		env->history->current = (env->history->current + env->history->max_size - 1) % env->history->max_size;
	} else {
		env->history_active = true;
	}
	
	// reallocate env->command_buffer if necessary
	if (strlen(env->history->command_history[env->history->current]) >= env->command_buffer_size) {
		env->command_buffer_size = 2 * strlen(env->command_buffer);
		env->command_buffer = (char*)realloc(env->command_buffer, env->command_buffer_size);
	}
	
	// copy data from from history
	env->command_buffer_offset = strlen(env->history->command_history[env->history->current]);
	memcpy(env->command_buffer, env->history->command_history[env->history->current], env->command_buffer_offset);
	env->command_buffer[env->command_buffer_offset] = 0;
	
	// clear the line on the terminal
	printf("\e[2K");
	
	// set cursor position to beginning of line
	printf("\e[0E");
	
	// print the line
	shell_print_prefix(env);
	printf("%s", env->command_buffer);
}

static void next_command(struct shell_env *env)
{
	// if already at the end of the history, don't do anything
	if (env->history->current == env->history->last) {
		bell();
		return;
	}
	
	// increment the current pointer, if history is already active
	if (env->history_active) {
		env->history->current = (env->history->current + 1) % env->history->max_size;
	} else {
		env->history_active = true;
	}
	
	// reallocate env->command_buffer if necessary
	if (strlen(env->history->command_history[env->history->current]) >= env->command_buffer_size) {
		env->command_buffer_size = 2 * strlen(env->command_buffer);
		env->command_buffer = (char*)realloc(env->command_buffer, env->command_buffer_size);
	}
	
	// copy data from from history
	env->command_buffer_offset = strlen(env->history->command_history[env->history->current]);
	memcpy(env->command_buffer, env->history->command_history[env->history->current], env->command_buffer_offset);
	env->command_buffer[env->command_buffer_offset] = 0;
	
	// clear the line on the terminal
	printf("\e[2K");
	
	// set cursor position
	printf("\e[0E");
	
	// print the line
	shell_print_prefix(env);
	printf("%s", env->command_buffer);
}

void handle_escape_sequence(struct shell_env *env, char* seq)
{
	if (strcmp(seq, arrow_up) == 0) prev_command(env);
	else if (strcmp(seq, arrow_down) == 0) next_command(env);
	else if (ends_with(seq, 'p')) handle_keyboard_string(env, seq);
	else {
		// nothing to do ?
		char tmp[256]; // should always be enough
		size_t offset = 0;
		size_t c = 0;
		while (c < strlen(seq) && offset < 256) offset += make_printable(tmp + offset, 255 - offset, seq[c++]); // forgive me for this line
		printf("unknown escape sequence: '%s'\n", tmp);
	}
}