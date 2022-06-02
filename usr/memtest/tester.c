#include "tester.h"

#include <stdlib.h>
#include <stdio.h>


int mem_test_thread(void* arg)
{
	struct test_data *data = arg;
	int errors = 0;
	printf("memtest thread %d starting...\n", data->thread_id);
	uint32_t *mem = data->mem;
	
	for (size_t i = 0; i < data->mem_size; i++) {
		mem[i] = data->data[i % data->n_data];
	}
	
	for (size_t i = 0; i < data->mem_size; i++) {
		if (mem[i] != data->data[i % data->n_data]) {
			errors++;
			printf("found memory error at: %p\n", mem + i);
		}
	}
	
	printf("memtest thread %d exiting...\n", data->thread_id);
	return errors;
}