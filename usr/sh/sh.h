#ifndef _SH_H
#define _SH_H

#include <stdint.h>

struct shell_env {
	int last_return_status;
	// flags
	uint8_t active : 1;
};

#endif // _SH_H