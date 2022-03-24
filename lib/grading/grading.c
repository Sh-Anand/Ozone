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
	printf("aaaa\n");
	err = paging_map_fixed_attr(get_current_paging_state(), addr, frame, size, VREGION_FLAGS_READ_WRITE);
	if (err_is_fail(err)) {
		DEBUG_ERR(err, "paging_map_fixed_attr");
		return frame;
	}
	
	for (int i = 0; i < size/4; i++) {
		values[i] = 2 * i + 5;
		if (values[i] != 2 * i + 5) {
			printf("Instantly read %d instead of %d at %d (fixed)\n", values[i], i, i);
			while(1);
		}
	}

	for (int i = 0; i < size/4; i++) {
		if (values[i] != 2 * i + 5) {
			printf("Read %d instead of %d at %d (fixed)\n", values[i], i, i);
			while(1);
		}
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
	printf("a\n");
	err = paging_map_frame_attr(get_current_paging_state(), (void**)addr, size, frame, VREGION_FLAGS_READ_WRITE);
	if (err_is_fail(err)) {
		DEBUG_ERR(err, "paging_map_fixed_attr");
		return frame;
	}
	
	__attribute__((unused)) int *values = (void*)*addr;
	debug_printf("mapped address: %020p, values: %020p\n", *addr, values);
	
	

	for (long int i = 0; i < size/4; i++) {
		values[i] = i;
	}

	for (long int i = 0; i < size/4; i++) {
		if (values[i] != i) {
			printf("Read %d instead of %d at %d\n", values[i], i, i);
			while(1);
		}
	}
	
	return frame;
}

void
grading_test_early(void) {
	// test some fixed memory mapping (freeing not yet tested)
	__attribute__((unused)) lvaddr_t base = 3UL << 39;
	__attribute__((unused)) lvaddr_t addr0, addr1, addr2, addr3, addr4, addr5;
	// __attribute__((unused)) struct capref fixed_frame0 = test_mem_map_fixed(base, 8192);
	// __attribute__((unused)) struct capref fixed_frame1 = test_mem_map_fixed(base + 8192, 1 << 21);
	
	// __attribute__((unused)) struct capref frame0 = test_mem_alloc(&addr0, 4096);
	// __attribute__((unused)) struct capref frame1 = test_mem_alloc(&addr1, 8192);
	// __attribute__((unused)) struct capref frame2 = test_mem_alloc(&addr2, 16384);
	// __attribute__((unused)) struct capref frame3 = test_mem_alloc(&addr3, 2097152+8192);
	// __attribute__((unused)) struct capref frame4 = test_mem_alloc(&addr4, 3145728);
	// __attribute__((unused)) struct capref frame5 = test_mem_alloc(&addr5, 3145728+8192); // TODO: there seems to be an issue still here, where something causes a pagefault
	// //while(1);

	debug_printf("tests complete\n");
}

void
grading_test_late(void) {
    struct spawninfo info;
    domainid_t pid = -1;
    errval_t err;
    DEBUG_PRINTF("Start spawn test...\n");
    err = spawn_load_by_name("hello", &info, &pid);
    assert(err_is_ok(err));
    assert(pid != -1);  // TODO: will fail now
}
