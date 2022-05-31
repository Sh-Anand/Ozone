
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <aos/debug.h>

#include "strutil.h"
#include "sh.h"
#include "builtins.h"
#include "exec_binary.h"
#include "escape_sequence.h"

#include <aos/nameserver.h>

#define SHELL_HISTORY_MAX_SIZE 1024

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
	env.default_command_buffer_size = 64;
	env.zero_sep_command_line = NULL;
	allocate_command_buffer();
	env.max_args = 16;
	allocate_argv();
	env.max_prefix_length = 64;
	env.prefix = (char*)malloc(env.max_prefix_length);
	
	// set stdin to unbuffered
	setbuffer(stdin, NULL, 0);
	
	env.current_path = "/";
	env.home_path = "/";
	
	env.next_core = 1;
	
	//initialize history
	env.history = (struct shell_command_history*)malloc(sizeof(struct shell_command_history));
	env.history->max_size = SHELL_HISTORY_MAX_SIZE;
	env.history->current = 0;
	env.history->first = 0;
	env.history->last = env.history->max_size-1;
	env.history->size = 0;
	env.history->command_history = (char**)calloc(sizeof(char*), env.history->max_size);
	
	// mark the shell as active
	env.active = true;
}

/**
 * this code is taken from the spawn library in lib/aos/spawn to facilitate handling the commandline here without linking the library (as it should be used through rpc)
 * \brief Tokenize the command line arguments and count them
 * 
 * \param cmdline The string to be parsed. Must not be NULL.
 * \param _argc Will be filled out with the number of arguments
 * found in 'cmdline'. Must not be NULL.
 * \param buf Will be filled out with a char array that contains 
 * the continuously in memory arranged arguments separated by '\0'.
 * (Note that there might also be some extra whitespace intbetween
 * the arguments.)
 * \return If 'cmdline' was parsed and tokenized successfully, argv
 * (an array of the arguments) will be returned, NULL otherwise.
 */
static char ** make_argv(const char *cmdline, int *_argc, char **buf) {
    char **argv= calloc(MAX_CMDLINE_ARGS+1, sizeof(char *));
    if(!argv) return NULL;

    /* Carefully calculate the length of the command line. */
    size_t len= strnlen(cmdline, PATH_MAX+1);
    if(len > PATH_MAX) return NULL;

    /* Copy the command line, as we'll chop it up. */
    *buf= malloc(len + 1);
    if(!*buf) {
        free(argv);
        return NULL;
    }
    strncpy(*buf, cmdline, len + 1);
    (*buf)[len]= '\0';

    int argc= 0;
    size_t i= 0;
    while(i < len && argc < MAX_CMDLINE_ARGS) {
        /* Skip leading whitespace. */
        while(i < len && is_whitespace((unsigned char)(*buf)[i])) i++;

        /* We may have just walked off the end. */
        if(i >= len) break;

        if((*buf)[i] == '"') {
            /* If the first character is ", then we need to scan until the
             * closing ". */

            /* The next argument starts *after* the opening ". */
            i++;
            argv[argc]= &(*buf)[i];
            argc++;

            /* Find the closing ". */
            while(i < len && (*buf)[i] != '"') i++;

            /* If we've found a ", overwrite it to null-terminate the string.
             * Otherwise, let the argument be terminated by end-of-line. */
            if(i < len) {
                (*buf)[i]= '\0';
                i++;
            }
        }
        else {
            /* Otherwise grab everything until the next whitespace
             * character. */

            /* The next argument starts here. */
            argv[argc]= &(*buf)[i];
            argc++;

            /* Find the next whitespace (if any). */
            while(i < len && !is_whitespace((unsigned char)(*buf)[i])) i++;

            /* Null-terminate the string by overwriting the first whitespace
             * character, unless we're at the end, in which case the null at
             * the end of buf will terminate this argument. */
            if(i < len) {
                (*buf)[i]= '\0';
                i++;
            }
        }
    }
    /* (*buf)[argc] == NULL */

    *_argc= argc;
    return argv;
}

static void add_to_command_history(void)
{
	char* cmd = env.command_buffer;
	
	size_t index = env.history->last = (env.history->last + 1) % env.history->max_size; // get the index
	
	// handle full history
	if (env.history->command_history[index]) {
		free(env.history->command_history[index]);
		env.history->first = (env.history->first + 1) % env.history->max_size;
	}
	env.history->command_history[index] = cmd;
	
	// current is back at the end
	env.history->current = env.history->last;
	env.history_active = false;
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
		shell_delete_character(&env);
		return 1;
	} else if (c == '\x1b') { // this is an escape sequence
		size_t max_i = 64;
		char *escape_sequence = (char*)malloc(max_i);
		escape_sequence[0] = c;
		uint8_t active = 1;
		size_t i = 1;
		while (active) {
			if (i+1 >= max_i) escape_sequence = (char*)realloc(escape_sequence, max_i *= 2);
			c = getchar();
			escape_sequence[i++] = c;
			if (is_alpha(c)) { // escape sequences are terminated by an alpha character
				escape_sequence[i] = 0;
				active = 0;
			}
		}
		
		// TODO: handle escape sequences...
		handle_escape_sequence(&env, escape_sequence);
		
		free(escape_sequence);
		
		return 1;
	} else { // nothing interesting, just another character, so add it to the pile
		shell_insert_character(&env, c);
		return 1;
	}
}

void shell_delete_character(struct shell_env *shenv)
{
	// in case cursor is at beginning of line, bell and return
	if (shenv->command_buffer_cursor == 0) {
		bell();
		return;
	}
	
	// shift rest of command buffer
	for (size_t i = shenv->command_buffer_cursor; i <= shenv->command_buffer_offset; i++)
		shenv->command_buffer[i-1] = shenv->command_buffer[i];
	
	shenv->command_buffer_cursor--;
	shenv->command_buffer_offset--;
	
	shenv->command_buffer[shenv->command_buffer_offset] = 0; // terminate the string
	shell_print_current_line(shenv);
}

void shell_insert_character(struct shell_env *shenv, char c)
{
	// in case the cursor is at the end, simply append
	if (shenv->command_buffer_cursor != shenv->command_buffer_offset) {
		size_t len = strlen(shenv->command_buffer);
		if (len >= shenv->command_buffer_size - 2) allocate_command_buffer();
		
		for (size_t i = len; i >= shenv->command_buffer_cursor; i--) shenv->command_buffer[i+1] = shenv->command_buffer[i];
	}
	
	shenv->command_buffer[shenv->command_buffer_cursor] = c;
	
	shenv->command_buffer_cursor++;
	shenv->command_buffer_offset++;
	
	shenv->command_buffer[shenv->command_buffer_offset] = 0; // terminate the string
	shell_print_current_line(shenv);
}

void shell_print_current_line(struct shell_env *shenv)
{
	// the following is done in a single printf statement in order to reduce terminal flickering with multiple consecutive prints on the same line
	// move to beginning of line
	// print the prefix
	// print the command buffer
	// clear the rest of the line
	// set the cursor position
	printf("\e[0E%s%s\e[0K\e[0E\e[%dC", shenv->prefix, shenv->command_buffer, shenv->prefix_length + shenv->command_buffer_cursor);
	fflush(stdout);
}

void shell_print_prefix(struct shell_env *shenv)
{
	// TODO: this should be more sophisticated
	shenv->prefix_length = snprintf(shenv->prefix, shenv->max_prefix_length - 1, "team01@AOS %s> ", shenv->current_path);
	if (shenv->prefix_length == shenv->max_prefix_length) {
		shenv->max_prefix_length *= 2;
		shenv->prefix = (char*)realloc(shenv->prefix, shenv->max_prefix_length);
		shell_print_prefix(shenv);
	}
}

void bell(void)
{
	putchar(0x07); // the ascii bell character
}

int main(int argc, char **argv)
{
	puts("AOS Team 1 shell starting...");
	
	setup_environment();
	
	while (env.active) {
		// setup new command prompt
		env.command_buffer_size = env.default_command_buffer_size;
		env.command_buffer = (char*)malloc(env.command_buffer_size);
		env.command_buffer_offset = 0;
		env.command_buffer_cursor = 0;
		if (env.zero_sep_command_line != NULL) {
			free(env.zero_sep_command_line);
			env.zero_sep_command_line = NULL;
		}
		shell_print_prefix(&env);
		shell_print_current_line(&env);
		
		// read the input
		while (read_from_input());
		if (env.command_buffer_offset == 0 || env.command_buffer[0] == 0) continue;
		
		add_to_command_history();
		
		// split the command line into tokens
		env.argc = 0;
		
		//TODO: support quoted strings
		
		// split string into tokens and store in env.argv
		env.argv = make_argv(env.command_buffer, &(env.argc), &(env.zero_sep_command_line));
		if (!env.argv) {
			printf("Error: Failed to parse command line!\n");
			continue;
		}
		
		/*char* token = strtok_r(env.command_buffer, " \r\n\t", &state);
		do {
			if (argc == env.max_args) allocate_argv();
			env.argv[env.argc++] = token;
		} while ((token = strtok_r(NULL, " \r\n\t", &state)));*/
		
		if (env.argc == 0) continue; // nothing was entered
		
		if (builtin(&env)) continue;
		else if (exec_binary(&env)) continue;
		else {
			printf("Error: '%s' not builtin and not a known program!\n", env.argv[0]);
		}
	}
	
	puts("Shell terminating...\n");
}