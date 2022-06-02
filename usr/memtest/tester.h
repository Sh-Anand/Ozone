#ifndef _TESTER_H
#define _TESTER_H

#include <stdlib.h>
#include <stdint.h>

struct test_data {
	size_t mem_size;
	size_t n_data;
	uint32_t *data;
	size_t thread_id;
	uint32_t *mem;
};

int mem_test_thread(void* data);

#endif // _TESTER_H