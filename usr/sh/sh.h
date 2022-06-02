#ifndef _SH_H
#define _SH_H

#include <stdint.h>
#include <stdlib.h>

#define NUMBER_OF_CORES 4

struct shell_command_history {
	char** command_history;
	size_t first;
	size_t last;
	size_t current;
	size_t size;
	size_t max_size;
};

struct shell_env {
	char** argv;
	char* command_buffer;
	char* zero_sep_command_line;
	char* prefix;
	size_t command_buffer_offset;
	size_t command_buffer_cursor;
	size_t command_buffer_size;
	size_t default_command_buffer_size;
	size_t prefix_length;
	size_t max_prefix_length;
	int argc;
	int max_args;
	int last_return_status;
	char* current_path;
	char* home_path;
	struct shell_command_history *history;
	
	uint8_t next_core;
	
	// flags
	uint8_t active : 1;
	uint8_t history_active : 1;
	uint8_t attach_terminal : 1;
};

void shell_delete_character(struct shell_env *env);
void shell_insert_character(struct shell_env *env, char c);
void shell_print_current_line(struct shell_env *env);
void shell_print_prefix(struct shell_env *env);
void bell(void);

#endif // _SH_H