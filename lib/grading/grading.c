#include <stdio.h>

#include <aos/aos.h>
#include <aos/capabilities.h>
#include <aos/ram_alloc.h>
#include <aos/aos_rpc.h>
#include <grading.h>
#include <spawn/spawn.h>


void
grading_setup_bsp_init(int argc, char **argv) {
}

void
grading_setup_app_init(struct bootinfo * bi) {
}

void
grading_setup_noninit(int *argc, char ***argv) {
}

void
grading_test_mm(struct mm *test) {
}

__attribute__((unused)) static struct capref test_mem_map_fixed(lvaddr_t addr, size_t size) {
	assert(size % 4 == 0); // be sure to map multiples of int size
	struct slot_allocator *ca = get_default_slot_allocator();
	errval_t err;
	size_t actual;
	
	int *values = (void*)addr;
	struct capref frame;
	
	ca->alloc(ca, &frame);
	frame_create(frame, size, &actual);
	assert(actual >= size);
	err = paging_map_fixed_attr(get_current_paging_state(), addr, frame, size, VREGION_FLAGS_READ_WRITE);
	if (err_is_fail(err)) {
		DEBUG_ERR(err, "paging_map_fixed_attr");
		return frame;
	}
	
	for (long int i = 0; i < size/4; i += 1024) {
		values[i] = 0xdeadbeef;
		debug_printf("Write and Read at address %010p complete: %p\n", (size_t)&(values[i]), values[i]);
	}
	
	return frame;
}


__attribute__((unused)) static struct capref test_mem_alloc(lvaddr_t *addr, size_t size) {
	assert(size % 4 == 0); // be sure to map multiples of int size
	struct slot_allocator *ca = get_default_slot_allocator();
	errval_t err;
	size_t actual;
	
	struct capref frame;
	
	ca->alloc(ca, &frame);
	frame_create(frame, size, &actual);
	assert(actual >= size);
	err = paging_map_frame_attr(get_current_paging_state(), (void**)addr, size, frame, VREGION_FLAGS_READ_WRITE);
	if (err_is_fail(err)) {
		DEBUG_ERR(err, "paging_map_fixed_attr");
		return frame;
	}
	
	__attribute__((unused)) int *values = (void*)*addr;
	debug_printf("mapped address: %020p, values: %020p\n", *addr, values);
	
	
	long int n_pages = size / 4096;
	long int out_condition = (n_pages+9) / 10;
	for (long int i = 0; i < size/4; i += 1024) {
		values[i] = 0xdeadbeef;
		if ((i / 1024) % out_condition == 0)
			debug_printf("Write and Read at address %010p complete: %p\n", (size_t)&(values[i]), values[i]);
	}
	
	return frame;
}

void
grading_test_early(void) {
	// test some fixed memory mapping (freeing not yet tested)
	__attribute__((unused)) lvaddr_t base = 3UL << 39;
	__attribute__((unused)) lvaddr_t addr0, addr1, addr2, addr3, addr4, addr5;
	__attribute__((unused)) struct capref fixed_frame0 = test_mem_map_fixed(base, 8192);
	
	__attribute__((unused)) struct capref frame0 = test_mem_alloc(&addr0, 4096);
	__attribute__((unused)) struct capref frame1 = test_mem_alloc(&addr1, 8192);
	__attribute__((unused)) struct capref frame2 = test_mem_alloc(&addr2, 16384);
	__attribute__((unused)) struct capref frame3 = test_mem_alloc(&addr3, 2097152+8192);
	__attribute__((unused)) struct capref frame4 = test_mem_alloc(&addr4, 3145728);
	__attribute__((unused)) struct capref frame5 = test_mem_alloc(&addr5, 3145728+8192);
	
	
}

void
grading_test_late(void) {
}
