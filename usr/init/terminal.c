#include "terminal.h"

#include <stdio.h>
#include <aos/aos_rpc.h>
#include <aos/waitset.h>
#include <arch/aarch64/aos/dispatcher_arch.h>
#include <drivers/lpuart.h>
#include <drivers/gic_dist.h>
#include <aos/inthandler.h>

#include <grading.h>


extern spinlock_t* global_print_lock;
extern struct capref dev_cap_uart3;
extern struct capref dev_cap_gic;

extern size_t (*local_terminal_write_function)(const char*, size_t);
extern size_t (*local_terminal_read_function)(char*, size_t);

struct capref int_cap_uart3;

static struct lpuart_s *lp_uart_3;
static struct gic_dist_s *gic_dist;

static void *lp_uart_3_base_address;
static void *gic_dist_base_address;

static bool uart3_avail;
static bool gic_avail;

const char* str = "UART3 is working!";


// ringbuffer for input buffering
static char char_buffer[4096];
static uint16_t buffer_head = 0;
static uint16_t buffer_tail = 0;
static uint16_t buffer_size = 0;

size_t local_read_function(char* buf, size_t len);
size_t local_write_function(const char* buf, size_t len);

static void uart3_int_handler(void* arg)
{
	DEBUG_PRINTF("Key Interrupt Received!\n");
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
	
	DEBUG_PRINTF("Key Interrupt Handled: %c, size: %d\n", char_buffer[(4096 + buffer_head - 1) % 4096], buffer_size);
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

void terminal_setup_pl011(void)
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

char terminal_getchar(void)
{
	// wait for the buffer to contain some characters, giving the cpu time to do other stuff
	while (buffer_size == 0) event_dispatch(get_default_waitset());
	
	char c = char_buffer[buffer_tail++];
	buffer_tail %= sizeof(char_buffer);
	buffer_size--;
	
	return c;
}

size_t local_read_function(char* buf, size_t len)
{
	for (size_t i = 0; i < len; i++) {
		grading_rpc_handler_serial_getchar();
		buf[i] = terminal_getchar();
	}
	return len;
}
size_t local_write_function(const char* buf, size_t len)
{
	acquire_spinlock(global_print_lock);
	for (size_t i = 0; i < len; i++) {
		grading_rpc_handler_serial_putchar(buf[i]);
		terminal_putchar(buf[i]);
	}
	release_spinlock(global_print_lock);
	
	return len;
}

/**
 * @brief Temporary main function for the terminal. configures the uart and setup necessary capabilities
 * 
 * @param argc 
 * @param argv 
 * @return int 
 */
int terminal_main(int argc, char** argv) __attribute__((unused));
int terminal_main(int argc, char** argv)
{
	return 0;
}