#include "escape_sequence.h"

#include "strutil.h"

#include <stdbool.h>
#include <string.h>
#include <stdio.h>

// define selection of escape sequences
const char *esc_arrow_up = "\e[A";
const char *esc_arrow_down = "\e[B";
const char *esc_arrow_right = "\e[C";
const char *esc_arrow_left = "\e[D";

const char *esc_end = "\e[F";
const char *esc_home = "\e[H";

#define IS(o) strcmp(seq, o) == 0

static bool ends_with(char* str, char end)
{
	size_t len = strlen(str);
	if (len == 0) return false;
	return str[len-1] == end;
}

static void handle_keyboard_string(struct shell_env *env, char* seq)
{
	printf("escape sequence: keyboard string nyi!\n");
}

static void prev_command(struct shell_env *env)
{
	// if already at the beginning of the history, don't do anything
	if ((env->history_active && env->history->current == env->history->first) || env->history->command_history[env->history->current] == NULL) {
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
	env->command_buffer_cursor = env->command_buffer_offset;
	memcpy(env->command_buffer, env->history->command_history[env->history->current], env->command_buffer_offset);
	env->command_buffer[env->command_buffer_offset] = 0;
}

static void next_command(struct shell_env *env)
{
	// if already at the end of the history, don't do anything
	if (env->history->current == env->history->last || env->history->command_history[env->history->last] == NULL) {
		if (env->history_active) {
			env->command_buffer_offset = 0;
			env->command_buffer_cursor = 0;
			env->command_buffer[0] = 0;
			env->history_active = false;
			return;
		} else {
			bell();
			return;
		}
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
	env->command_buffer_cursor = env->command_buffer_offset;
	memcpy(env->command_buffer, env->history->command_history[env->history->current], env->command_buffer_offset);
	env->command_buffer[env->command_buffer_offset] = 0;
}

static void cursor_left(struct shell_env *env)
{
	if (env->command_buffer_cursor == 0) {
		bell();
		return;
	}
	
	env->command_buffer_cursor--;
}

static void cursor_right(struct shell_env *env)
{
	if (env->command_buffer_cursor == env->command_buffer_offset) {
		bell();
		return;
	}
	
	env->command_buffer_cursor++;
	

}

static void cursor_end(struct shell_env *env)
{
	env->command_buffer_cursor = env->command_buffer_offset;
}

static void cursor_home(struct shell_env *env)
{
	env->command_buffer_cursor = 0;
}

void handle_escape_sequence(struct shell_env *env, char* seq)
{
	if (IS(esc_arrow_up)) prev_command(env);
	else if (IS(esc_arrow_down)) next_command(env);
	else if (IS(esc_arrow_left)) cursor_left(env);
	else if (IS(esc_arrow_right)) cursor_right(env);
	else if (IS(esc_end)) cursor_end(env);
	else if (IS(esc_home)) cursor_home(env);
	else if (ends_with(seq, 'p')) handle_keyboard_string(env, seq);
	else {
		// nothing to do ?
		char tmp[256]; // should always be enough
		size_t offset = 0;
		size_t c = 0;
		while (c < strlen(seq) && offset < 256) offset += make_printable(tmp + offset, 255 - offset, seq[c++]); // forgive me for this line
		printf("unknown escape sequence: '%s'\n", tmp);
	}
	
	shell_print_current_line(env);
}