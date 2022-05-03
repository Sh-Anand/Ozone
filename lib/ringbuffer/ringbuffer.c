#include <ringbuffer/ringbuffer.h>

#include <aos/threads.h>
#include <string.h>
#include <stdlib.h>
#include <aos/debug.h>
#include <arch/aarch64/aos/cache.h>

#define RINGBUFFER_CAPACITY ((4096 / CACHE_LINE_SIZE) - 1)
#define ENTRY_DATA_CAPACITY (CACHE_LINE_SIZE - sizeof(size_t))

#define INDEX(x) (x % RINGBUFFER_CAPACITY)
#define INCR(x) x = (x+1) % RINGBUFFER_CAPACITY;

struct ringbuffer_entry { // one cacheline (on our machine 64 bytes)
	uint8_t data[CACHE_LINE_SIZE - sizeof(size_t)]; // the data contained in this block
	size_t ready: 1; // whether this block is ready to be read
};

struct ringbuffer { // head, tail, size, list of cachelines
	struct ringbuffer_entry entries[RINGBUFFER_CAPACITY]; // make sure that the cachelines are pagealigned
	size_t head: 6;
	size_t tail: 6;
};


errval_t ring_init(void *buffer)
{
	//struct ringbuffer *rb = (struct ringbuffer *)malloc(sizeof(struct ringbuffer));
	if (buffer == NULL) {
		DEBUG_PRINTF("Could not initialze ringbuffer: recieved null pointer.\n");
		return ERR_INVALID_ARGS;
	}
	
	// make sure that the address is page aligned
	assert(((uint64_t)buffer) % PAGE_SIZE == 0);
	
	// zero the memory to clear all flags
	memset(buffer, 0, PAGE_SIZE);
	
	return SYS_ERR_OK;
}

/* 
 * TODO: define protocol
 * Protocol for transferring data:
 * 
 * 8 bytes: size
 * ${size} bytes: message
 * 
 * This is very simple and enough for a unidirectional channel from one endpoint to another.
 * This is implemented in the producer and consumer functions.
 * 
 * 
 */

/**
 * @brief Inserts a block of exactly CACHE_LINE_SIZE - sizeof(size_t) bytes into the ringbuffer (on our machine that is 56 bytes).
 * 
 * @param rb A non null ringbuffer.
 * @param payload exactly 56 bytes of memory to be inserted into the buffer.
 * @return An error code indicating a failure, or SYS_ERR_OK.
 */
static errval_t ring_insert(void *rb, void *payload) {
	
	// check for null-pointer
	if (rb == NULL) {
		DEBUG_PRINTF("Cannot insert into ringbuffer: buffer is null pointer.\n");
		return ERR_INVALID_ARGS;
	}
	
	struct ringbuffer *rbuf = rb;
	int head = INDEX(rbuf->head);
	
	// wait for the buffer entry to be free
	while (rbuf->entries[head].ready) thread_yield();
	dmb();
	
	// insert data into entry
	memcpy(&(rbuf->entries[head]), payload, ENTRY_DATA_CAPACITY);
	INCR(rbuf->head); // increment head pointer
	
	dmb(); // wait for the write to complete
	rbuf->entries[head].ready = 1;
	// TODO: does the writebuffer need flushing here?
	
	return SYS_ERR_OK;
}

/**
 * @brief Consumes a block of exactly 64 bytes from the ringbuffer
 * This function blocks until an element can be read from the buffer.
 * 
 * @param rb A non null ringbuffer
 * @param payload exactly ENTRY_DATA_CAPACITY bytes of space to write the data (on our machine this is 56 bytes)
 * @return An error code indicating a failure, or SYS_ERR_OK. 
 */
static errval_t ring_consume(void *rb, void *payload)
{
	// check for null-pointer
	if (rb == NULL) {
		DEBUG_PRINTF("Cannot consume from ringbuffer: buffer is null pointer.\n");
		return ERR_INVALID_ARGS;
	}
	
	struct ringbuffer *rbuf = rb;
	int tail = INDEX(rbuf->tail);
	
	// wait for the data to be ready
	while (! rbuf->entries[tail].ready) thread_yield();
	dmb();
	
	// read value from buffer
	memcpy(payload, &(rbuf->entries[tail]), ENTRY_DATA_CAPACITY);
	INCR(rbuf->tail); // increment the tail pointer
	
	dmb();
	rbuf->entries[tail].ready = 0;
	
	// TODO: does the writebuffer need flushing?
	
	return SYS_ERR_OK;
}


/**
 * @brief Consumes a block of exactly 64 bytes from the ringbuffer.
 * This function will not block, but return RING_NO_MSG when buffer is empty
 * 
 * @param rb A non null ringbuffer
 * @param payload exactly ENTRY_DATA_CAPACITY bytes of space to write the data (on our machine this is 56 bytes)
 * @return An error code indicating a failure, LIB_ERR_RING_NO_MSG if buffer is empty, or SYS_ERR_OK. 
 */
static errval_t ring_consume_non_blocking(void *rb, void *payload) __attribute__((unused));
static errval_t ring_consume_non_blocking(void *rb, void *payload)
{
	// check for null-pointer
	if (rb == NULL) {
		DEBUG_PRINTF("Cannot consume from ringbuffer: buffer is null pointer.\n");
		return ERR_INVALID_ARGS;
	}
	
	struct ringbuffer *rbuf = rb;
	int tail = INDEX(rbuf->tail);
	
	// wait for the data to be ready
	if (! rbuf->entries[tail].ready) return LIB_ERR_RING_NO_MSG;
	dmb();
	
	// read value from buffer
	memcpy(payload, &(rbuf->entries[tail]), ENTRY_DATA_CAPACITY);
	INCR(rbuf->tail); // increment the tail pointer
	
	dmb();
	rbuf->entries[tail].ready = 0;
	
	// TODO: does the writebuffer need flushing?
	
	return SYS_ERR_OK;
}

/**
 * @brief Tests whether the buffer currently holds data ready to be read.
 * @param rb A non null ringbuffer
 * @param empty is written to 1 if buffer is empty, 0 otherwise
 * @return ERR_INVALID_ARGS if rb is null, SYS_ERR_OK otherwise.
 * 
 */
static errval_t ring_is_empty(void *rb, uint8_t *empty) __attribute__((unused));
static errval_t ring_is_empty(void *rb, uint8_t *empty)
{
	if (rb == NULL) {
		DEBUG_PRINTF("Cannot check if buffer is empty for null buffer!\n");
		return ERR_INVALID_ARGS;
	}
	
	struct ringbuffer *rbuf = rb;
	int tail = INDEX(rbuf->tail);
	*empty = !rbuf->entries[tail].ready;
	
	return SYS_ERR_OK;
}

errval_t ring_producer_init(struct ring_producer *rp, void *ring_buffer)
{
	// check for null-pointer
	if (rp == NULL) {
		DEBUG_PRINTF("Cannot initialize ringbuffer producer: producer is null-ptr.\n");
		return ERR_INVALID_ARGS;
	}
	if (ring_buffer == NULL) {
		DEBUG_PRINTF("Cannot initialize ringbuffer producer: ring_buffer is null-ptr.\n");
		return ERR_INVALID_ARGS;
	}
	
	rp->ringbuffer = ring_buffer;
	// TODO: do necessary setup
	
	return SYS_ERR_OK;
}


errval_t ring_producer_transmit(struct ring_producer *rp, const void *payload, size_t size)
{
	errval_t err;
	
	// check for null-pointer
	if (rp == NULL) {
		DEBUG_PRINTF("Ringbuffer producer cannot transmit: producer is null-ptr.\n");
		return ERR_INVALID_ARGS;
	}
	if (rp->ringbuffer == NULL) {
		DEBUG_PRINTF("Ringbuffer producer cannot transmit: ringbuffer is null-ptr.\n");
		return  ERR_INVALID_ARGS;
	}
	
	// insert into buffer (this part should block until complete, or irrecoverable error happens)
	uint8_t tmp[ENTRY_DATA_CAPACITY];
	size_t offset = 0;
	size_t start = sizeof(size_t);
	size_t cap = ENTRY_DATA_CAPACITY - start;
	
	while (offset < size) {
		// clear the temporary storage
		memset(tmp, 0, ENTRY_DATA_CAPACITY);
		*((size_t*)tmp) = size;
		memcpy(tmp + start, (void*)((size_t)payload + offset), MIN(size - offset, cap)); // copy the first part of this message into the buffer
		
		offset += cap;
		start = 0;
		cap = ENTRY_DATA_CAPACITY - start;
		
		err = ring_insert(rp->ringbuffer, tmp); // this error can only be SYS_ERR_OK
		assert(err == SYS_ERR_OK);
	
	}
	
	// if no errors happened, return OK
	return SYS_ERR_OK;
}

errval_t ring_consumer_init(struct ring_consumer *rc, void *ring_buffer)
{
		// check for null-pointer
	if (rc == NULL) {
		DEBUG_PRINTF("Cannot initialize ringbuffer consumer: consumer is null-ptr.\n");
		return ERR_INVALID_ARGS;
	}
	if (ring_buffer == NULL) {
		DEBUG_PRINTF("Cannot initialize ringbuffer consumer: ringbuffer is null-ptr.\n");
		return ERR_INVALID_ARGS;
	}
	
	rc->ringbuffer = ring_buffer;
	// TODO: do necessary setup
	
	return SYS_ERR_OK;
}

errval_t ring_consumer_recv(struct ring_consumer *rc, void **payload, size_t *size)
{
	errval_t err;
	
	// check for null-pointer
	if (rc == NULL) {
		DEBUG_PRINTF("Ringbuffer consumer cannot consume: consumer is null-ptr.\n");
		return ERR_INVALID_ARGS;
	}
	if (rc->ringbuffer == NULL) {
		DEBUG_PRINTF("Ringbuffer consumer cannot consume: ring_buffer is null-ptr.\n");
		return ERR_INVALID_ARGS;
	}
	
	// consume from buffer (this part should block until complete, or irrecoverable error happens)
	uint8_t tmp[ENTRY_DATA_CAPACITY];
	
	err = ring_consume(rc->ringbuffer, tmp); // this error can only be SYS_ERR_OK
	assert(err == SYS_ERR_OK);
	
	*size = *((size_t*)tmp);
	*payload = malloc(*size);
	
	memcpy(*payload, (void*)((size_t)tmp + sizeof(size_t)), MIN(ENTRY_DATA_CAPACITY - sizeof(size_t), *size));
	
	size_t offset = ENTRY_DATA_CAPACITY - sizeof(size_t);
	
	while (offset < *size) {
		err = ring_consume(rc->ringbuffer, tmp); // this error can only be SYS_ERR_OK
		assert(err == SYS_ERR_OK);
		
		memcpy((void*)((size_t)*payload + offset), tmp, MIN(*size - offset, ENTRY_DATA_CAPACITY));
		
		offset += ENTRY_DATA_CAPACITY;
	}
	
	// if no errors happened, return OK
	return SYS_ERR_OK;
}