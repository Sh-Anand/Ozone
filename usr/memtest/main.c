#include <stdio.h>
#include <aos/aos_rpc.h>

#include "tester.h"

const static uint32_t default_data = 0xdeafbeef;

static struct config_data {
	size_t mem_size_per_thread;
	size_t n_threads;
	size_t n_data;
	uint32_t *data;
	
	uint8_t background : 1;
	uint8_t failed : 1;
} config;

static int custom_strcmp(const char* a, const char* b) {
	size_t la, lb;
	la = strlen(a);
	lb = strlen(b);
	return strncmp(a, b, la < lb ? la : lb);
}

static void defaults(void)
{
	config.mem_size_per_thread = 64*1024; // 64 kb
	config.n_threads = 1; // only a single thread
	config.n_data = 1;
	config.data = NULL;
	
	config.background = 0;
	config.failed = 0;
}

static void parse_arg(const char* arg)
{
	DEBUG_PRINTF("Parsing arg: %s\n", arg);
	if (custom_strcmp(arg, "-background") == 0) config.background = 1;
	else if (custom_strcmp(arg, "-size=") == 0) config.mem_size_per_thread = strtol(arg + 6, NULL, 10);
	else if (custom_strcmp(arg, "-hex-size=") == 0) config.mem_size_per_thread = strtol(arg + 10, NULL, 16);
	else if (custom_strcmp(arg, "-pages=") == 0) config.mem_size_per_thread = strtol(arg + 7, NULL, 10) * 4096 / sizeof(uint32_t);
	else if (custom_strcmp(arg, "-threads=") == 0) config.n_threads = strtol(arg + 9, NULL, 10);
	else if (custom_strcmp(arg, "-data=") == 0) {
		char* list = (char*)malloc(strlen(arg));
		strcpy(list, arg+6);
		config.n_data = 1;
		for (int i = 0; list[i] != 0; i++) if (list[i] == ',') config.n_data++;
		config.data = (uint32_t*)malloc(config.n_data * sizeof(uint32_t));
		size_t i = 0;
		for (char* token = strtok(list, ","); token != NULL; token = strtok(NULL, ","), i++) {
			config.data[i] = strtol(token, NULL, 16);
		}
		free(list);
	}
	else {
		config.failed = 1;
		printf("Error: Unknown option: '%s'\n", arg);
	}
}

int main(int argc, char** argv)
{
	printf("memtest starting...\n");
	defaults();
	for (int i = 1; !config.failed && i < argc; i++) parse_arg(argv[i]);
	if (config.failed) {
		free(config.data);
		return 1;
	}
	
	if (config.data == NULL) {
		config.data = (uint32_t*)malloc(sizeof(uint32_t));
		*config.data = default_data;
	}
	printf("memtest started: threads: %d, memory per thread: %d, background: %d\n", config.n_threads, config.mem_size_per_thread, config.background);
	
	struct thread **threads = (struct thread**)malloc(config.n_threads * sizeof(struct thread*));
	struct test_data* test_data = (struct test_data*)malloc(config.n_threads * sizeof(struct test_data));
	
	for (size_t i = 0; i < config.n_threads; i++) {
		test_data[i].data = config.data;
		test_data[i].n_data = config.n_data;
		test_data[i].mem_size = config.mem_size_per_thread;
		test_data[i].thread_id = i;
		test_data[i].mem = (uint32_t*)malloc(sizeof(uint32_t) * config.mem_size_per_thread);
		
		threads[i] = thread_create(mem_test_thread, &(test_data[i]));
	}
	
	fflush(stdout);
	if (config.background) aos_rpc_serial_release(aos_rpc_get_serial_channel());
	
	for (size_t i = 0; i < config.n_threads; i++) {
		int retval = 0;
		thread_join(threads[i], &retval);
		free(test_data[i].mem);
		if (retval) printf("memtest thread %d found %d memory corruption errors\n", i, retval);
	}
	
	free(threads);
	free(test_data);
	free(config.data);
	return 0;
}