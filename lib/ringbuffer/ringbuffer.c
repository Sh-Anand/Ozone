#include <ringbuffer/ringbuffer.h>

#include <string.h>
#include <stdlib.h>
#include <aos/debug.h>
#include <arch/aarch64/aos/cache.h>

#include <stdio.h>

#define RINGBUFFER_CAPACITY ((4096 - 3) / CACHE_LINE_SIZE)

#define INDEX(x) (x % RINGBUFFER_CAPACITY)

struct ringbuffer_entry { // one cacheline (64 bytes)
	uint8_t data[CACHE_LINE_SIZE];
};

struct ringbuffer { // head, tail, size, list of cachelines
	struct ringbuffer_entry entries[RINGBUFFER_CAPACITY]; // make sure that the cachelines are pagealigned
	uint8_t head;
	uint8_t tail;
	uint8_t elements;
};


errval_t ring_init(void *buffer)
{
	//struct ringbuffer *rb = (struct ringbuffer *)malloc(sizeof(struct ringbuffer));
	if (buffer == NULL) {
		DEBUG_PRINTF("Could not initialze ringbuffer: failed to allocate struct ringbuffer.\n");
		return LIB_ERR_MALLOC_FAIL;
	}
	
	memset(buffer, 0, sizeof(struct ringbuffer));
	
	return SYS_ERR_OK;
}

/* 
 * TODO: define protocol
 * Protocol for transferring data:
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 * 
 */


// TODO: this should be atomic, ideally
/**
 * @brief Inserts a block of exactly 64 bytes into the ringbuffer.
 * 
 * @param rb A non null ringbuffer.
 * @param payload exactly 64 bytes of memory to be inserted into the buffer.
 * @return An error code indicating a failure, or SYS_ERR_OK.
 */
static errval_t ring_insert(void *rb, void *payload) {
	errval_t err;
	
	// check for null-pointer
	if (rb == NULL) {
		DEBUG_PRINTF("Cannot insert into ringbuffer: buffer is null pointer.\n");
		err = ERR_INVALID_ARGS;
		goto exit;
	}
	
	struct ringbuffer *rbuf = rb;
	
	// check if buffer is full
	if (rbuf->elements == RINGBUFFER_CAPACITY) {
		// TODO: implement blocking here
		DEBUG_PRINTF("Cannot insert into ringbuffer: out of space.\n");
		err = LIB_ERR_NOT_IMPLEMENTED;
		goto exit;
	}
	
	// insert into buffer
	void* dest = &(rbuf->entries[INDEX(rbuf->tail)]);
	memcpy(dest, payload, CACHE_LINE_SIZE);
	rbuf->tail = INDEX(rbuf->tail + 1);
	rbuf->elements++;
	
	// write back to main memory
	cpu_dcache_wb_range((vm_offset_t)dest, CACHE_LINE_SIZE); // write data back to memory
	cpu_dcache_wb_range((vm_offset_t)&(rbuf->entries[RINGBUFFER_CAPACITY]), CACHE_LINE_SIZE); // write meta info at the end of the ringbuffer struct back to memory
	
	err = SYS_ERR_OK;
exit:
	return err;
}

// TODO: this should be atomic, ideally
/**
 * @brief Consumes a block of exactly 64 bytes from the ringbuffer
 * 
 * @param rb A non null ringbuffer
 * @param payload exactly 64 bytes of space to write the data
 * @return An error code indicating a failure, or SYS_ERR_OK. 
 */
static errval_t ring_consume(void *rb, void *payload)
{
	errval_t err;
	
	// check for null-pointer
	if (rb == NULL) {
		DEBUG_PRINTF("Cannot consume from ringbuffer: buffer is null pointer.\n");
		err = ERR_INVALID_ARGS;
		goto exit;
	}
	
	struct ringbuffer *rbuf = rb;
	// check if buffer is empty
	if (rbuf->elements == 0) {
		DEBUG_PRINTF("Cannot consume from buffer: buffer empty\n");
		err = LIB_ERR_NOT_IMPLEMENTED;
		goto exit;
	}
	
	// read value from buffer
	memcpy(payload, &(rbuf->entries[INDEX(rbuf->head)]), CACHE_LINE_SIZE);
	
	// remove element from buffer
	rbuf->head = INDEX(rbuf->head + 1);
	rbuf->elements--;
	
	// writeback to memory
	cpu_dcache_wb_range((vm_offset_t)&(rbuf->entries[RINGBUFFER_CAPACITY]), CACHE_LINE_SIZE); // write meta info at the end of the ringbuffer struct back to memory
	
	err = SYS_ERR_OK;
exit:
	
	return err;
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
		err = ERR_INVALID_ARGS;
		goto exit;
	}
	if (rp->ringbuffer == NULL) {
		DEBUG_PRINTF("Ringbuffer producer cannot transmit: ringbuffer is null-ptr.\n");
		err = ERR_INVALID_ARGS;
		goto exit;
	}
	
	// insert into buffer (this part should block until complete, or irrecoverable error happens)
	uint8_t tmp[64];
	assert(size <= CACHE_LINE_SIZE - sizeof(size_t)); // for now, assert that the message is small enough to fit into CACHE_LINE_SIZE - sizeof(size_t) bytes to avoid fragmentation
	
	memset(tmp, 0, CACHE_LINE_SIZE);
	*((size_t*)tmp) = size;
	memcpy(tmp + sizeof(size_t), payload, size);
	
	do {
		err = ring_insert(rp->ringbuffer, tmp); // retry until success (cannot produce irrecoverable error for now)
	} while (err == LIB_ERR_NOT_IMPLEMENTED);
	
	// if no errors happened, return OK
	err = SYS_ERR_OK;
	
exit:
	
	return err;
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
		err = ERR_INVALID_ARGS;
		goto exit;
	}
	if (rc->ringbuffer == NULL) {
		DEBUG_PRINTF("Ringbuffer consumer cannot consume: ring_buffer is null-ptr.\n");
		err = ERR_INVALID_ARGS;
		goto exit;
	}
	
	// consume from buffer (this part should block until complete, or irrecoverable error happens)
	uint8_t tmp[CACHE_LINE_SIZE];
	do {
		err = ring_consume(rc->ringbuffer, tmp); // retry until success (cannot produce irrecoverable error for now)
	} while (err == LIB_ERR_NOT_IMPLEMENTED);
	
	*size = *((size_t*)tmp);
	assert(*size <= CACHE_LINE_SIZE - sizeof(size_t)); // for now, assert that the message is small enough to fit into CACHE_LINE_SIZE - sizeof(size_t) bytes to avoid fragmentation
	
	*payload = malloc(*size);
	memcpy(*payload, tmp + 8, *size);
	
	// if no errors happened, return OK
	err = SYS_ERR_OK;
	
exit:
	
	return err;
}