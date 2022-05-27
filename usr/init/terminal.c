#include "terminal.h"

#include <stdio.h>
#include <aos/aos_rpc.h>
#include <aos/waitset.h>
#include <arch/aarch64/aos/dispatcher_arch.h>
#include <drivers/lpuart.h>
#include <drivers/gic_dist.h>
#include <aos/inthandler.h>

#include <grading.h>

struct terminal_state {
	uint32_t magic_word; // serves as a sanity check, to prevent memory corruption
	struct terminal_state *next;
	struct terminal_state *prev;
	// TODO: implement structures for redirecting output
	
	struct {
		uint8_t use_stdin : 1;
	} flags;
} __attribute__((packed));


extern spinlock_t* global_print_lock;
extern struct capref dev_cap_uart3;
extern struct capref dev_cap_gic;

extern size_t (*local_terminal_write_function)(const char*, size_t);
extern size_t (*local_terminal_read_function)(void* st, char*, size_t);

struct capref int_cap_uart3;

static struct lpuart_s *lp_uart_3;
static struct gic_dist_s *gic_dist;

static void *lp_uart_3_base_address;
static void *gic_dist_base_address;

static bool uart3_avail;
static bool gic_avail;

const char* str = "UART3 is working!";

// datastructure for multiplexing resources
struct terminal_state *stdin_stack;
struct terminal_state *non_stdin_stack;


// ringbuffer for input buffering
static char char_buffer[4096];
static uint16_t buffer_head = 0;
static uint16_t buffer_tail = 0;
static uint16_t buffer_size = 0;

size_t local_read_function(void *st, char* buf, size_t len);
size_t local_write_function(const char* buf, size_t len);



static void stack_remove(struct terminal_state **stack, struct terminal_state *st)
{
	if (st == NULL) return;
	
	if (st->next) st->next->prev = st->prev;
	if (st->prev) st->prev->next = st->next;
	else *stack = st->next;
}


static void uart3_int_handler(void* arg)
{
	//DEBUG_PRINTF("Key Interrupt Received!\n");
	char c;
	errval_t err = lpuart_getchar(lp_uart_3, &c);
	while (err == LPUART_ERR_NO_DATA) {
		event_dispatch(get_default_waitset());
		err = lpuart_getchar(lp_uart_3, &c);
	}
	
	// insert into buffer if not full
	if (buffer_size < 4096){
		char_buffer[buffer_head++] = c;
		buffer_size++;
		buffer_head %= sizeof(char_buffer);
	}
	
	//DEBUG_PRINTF("Key Interrupt Handled: %c, size: %d\n", char_buffer[(4096 + buffer_head - 1) % 4096], buffer_size);
}

void gic_setup(void)
{
	errval_t err;
	
	err = paging_map_frame_attr(get_current_paging_state(), &gic_dist_base_address, BASE_PAGE_SIZE, dev_cap_gic, VREGION_FLAGS_READ_WRITE_NOCACHE);
	if (err_is_fail(err)) {
		DEBUG_ERR(err, "Failed to map memory for GIC!\n");
		gic_avail = false;
		return;
	}
	
	err = gic_dist_init(&gic_dist, gic_dist_base_address);
	if (err_is_fail(err)) {
		DEBUG_ERR(err, "Failed to initialize GIC!\n");
		gic_avail = false;
		return;
	}
	
	// get irq dest cap
	err = inthandler_alloc_dest_irq_cap(IMX8X_UART3_INT, &int_cap_uart3);
	DEBUG_ERR(err, "inthandler_alloc_dest_irq_cap");
	
	err = inthandler_setup(int_cap_uart3, get_default_waitset(), MKCLOSURE(uart3_int_handler, NULL));
	DEBUG_ERR(err, "inthandler_setup");
	
	err = gic_dist_enable_interrupt(gic_dist, IMX8X_UART3_INT, 0x01, 0);
	DEBUG_ERR(err, "gic_dist_enable_interrupt");
	
	gic_avail = true;
}

void terminal_setup_lpuart(void)
{
	errval_t err;
	
	// map the frame
	err = paging_map_frame_attr(get_current_paging_state(), &lp_uart_3_base_address, BASE_PAGE_SIZE, dev_cap_uart3, VREGION_FLAGS_READ_WRITE_NOCACHE);
	if (err_is_fail(err)) {
		DEBUG_ERR(err, "Failed to map memory for UART3!\n");
		uart3_avail = false;
		return;
	}
	
	err = lpuart_init(&lp_uart_3, lp_uart_3_base_address);
	if (err_is_fail(err)) {
		DEBUG_ERR(err, "Failed to initialize UART3!");
		uart3_avail = false;
		return;
	}
	
	err = lpuart_enable_interrupt(lp_uart_3);
	DEBUG_ERR(err, "lpuart_enable_interrupt");
	
	local_terminal_read_function = local_read_function;
	local_terminal_write_function = local_write_function;
	
	uart3_avail = true;
}

void terminal_putchar(char c)
{
	if (uart3_avail) {// don't do anything if no uart is available
		if (c == '\n') {
			lpuart_putchar(lp_uart_3, '\r'); // some terminals have a crisis if you don't include carriage returns
			lpuart_putchar(lp_uart_3, '\n');
		} else {
			lpuart_putchar(lp_uart_3, c); // returns errval_t, but can only be SYS_ERR_OK, so ignore it.
		}
	}
}


bool terminal_can_use_stdin(void* stptr)
{
	DEBUG_PRINTF("Checking stdin access for %p\n", stptr);
	if (stptr == NULL) return ERR_INVALID_ARGS;
	// check that stdin is available
	struct terminal_state *st = stptr;
	if (st->magic_word != 0xDEADBEEF) return ERR_INVALID_ARGS;
	
	return stdin_stack == st;
}

errval_t terminal_getchar(void* stptr, char* c)
{
	if (stptr == NULL) return ERR_INVALID_ARGS;
	// check that stdin is available
	struct terminal_state *st = stptr;
	if (st->magic_word != 0xDEADBEEF) return ERR_INVALID_ARGS;
	if (stdin_stack != st) return TERM_ERR_TERMINAL_IN_USE;
	
	// return error if no characters are available
	if (buffer_size == 0) return TERM_ERR_RECV_CHARS;
	
	*c = char_buffer[buffer_tail++];
	buffer_tail %= sizeof(char_buffer);
	buffer_size--;
	
	return SYS_ERR_OK;
}

size_t local_read_function(void* stptr, char* buf, size_t len)
{
	if (stptr == NULL) return 0;
	errval_t err;
	for (size_t i = 0; i < len; i++) {
		grading_rpc_handler_serial_getchar();
		err = terminal_getchar(stptr, buf + i);
		if (err == TERM_ERR_TERMINAL_IN_USE) return i;
		if (err == TERM_ERR_RECV_CHARS) return i;
	}
	return len;
}
size_t local_write_function(const char* buf, size_t len)
{
	acquire_spinlock(global_print_lock);
	for (size_t i = 0; i < len; i++) {
		if (buf[i] == 0) break;
		grading_rpc_handler_serial_putchar(buf[i]);
		terminal_putchar(buf[i]);
	}
	release_spinlock(global_print_lock);
	
	return len;
}


void* terminal_aquire(bool use_stdin)
{
	// create new terminal state
	struct terminal_state *st = (struct terminal_state*)malloc(sizeof(struct terminal_state));
	
	st->magic_word = 0xDEADBEEF; // write known value here
	
	// set flags
	st->flags.use_stdin = use_stdin;
	
	DEBUG_PRINTF("Aquiring terminal session %p, %d\n", st, use_stdin);
	
	// add state to to the stack
	if (use_stdin) {
		st->next = stdin_stack;
		stdin_stack = st;
	} else {
		st->next = non_stdin_stack;
		non_stdin_stack = st;
	}
	
	return st;
}

void terminal_release(void* ptr)
{
	if (ptr == NULL) return;
	struct terminal_state *st = ptr;
	if (st->magic_word != 0xDEADBEEF) return;
	
	if (st->flags.use_stdin) {
		// remove from strin stack
		stack_remove(&stdin_stack, st);
	} else {
		// remove from non stdin stack
		stack_remove(&non_stdin_stack, st);
	}
}