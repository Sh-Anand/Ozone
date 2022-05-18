#ifndef _SH_H
#define _SH_H

#include <stdint.h>
#include <stdlib.h>

struct shell_env {
	char** argv;
	char* command_buffer;
	size_t command_buffer_offset;
	size_t command_buffer_size;
	int argc;
	int max_args;
	int last_return_status;
	
	// flags
	uint8_t active : 1;
};

#endif // _SH_H