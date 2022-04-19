#include <ringbuffer/ringbuffer.h>

#include <malloc.h>
#include <aos/debug.h>

struct ringbuffer_entry {
	void *payload;
	size_t size;
};

struct ringbuffer {
	struct ringbuffer_entry *entries;
	size_t next;
	size_t last;
	size_t capacity;
	size_t n_elements;
};

errval_t ring_init(void **buffer, size_t size)
{
	struct ringbuffer *rb;
	rb = (struct ringbuffer*)malloc(sizeof(struct ringbuffer));
	if (rb == NULL) {
		DEBUG_PRINTF("Could not initialze ringbuffer: failed to allocate struct ringbuffer.\n");
		return LIB_ERR_MALLOC_FAIL;
	}
	
	rb->capacity = size;
	rb->next = 0;
	rb->last = 0;
	
	rb->entries = (void**)calloc(size, sizeof(struct ringbuffer_entry));
	if (rb->entries == NULL) {
		DEBUG_PRINTF("Could not initialize ringbuffer: failed to allocate struct ringbuffer->entries.\n");
		return LIB_ERR_MALLOC_FAIL;
	}
	
	*buffer = rb;
	return SYS_ERR_OK;
}

errval_t ring_insert(void *rb, void *payload, size_t size) {
	// check for null-pointer
	if (rb == NULL) {
		DEBUG_PRINTF("Cannot insert into ringbuffer: buffer is null pointer.\n");
		return ERR_INVALID_ARGS;
	}
	
	struct ringbuffer *rbuf = rb;
	// check if buffer is full
	if (rbuf->n_elements == rbuf->capacity) {
		// TODO: implement buffer resizeing here
		DEBUG_PRINTF("Cannot insert into ringbuffer: out of space.\n");
		return SYS_ERR_NOT_IMPLEMENTED;
	}
	
	// insert into buffer
	rbuf->entries[rbuf->last].payload = payload;
	rbuf->entries[rbuf->last].size = size;
	rbuf->n_elements++;
	rbuf->last = (rbuf->last + 1) % rbuf->capacity;
	return SYS_ERR_OK;
}

errval_t ring_consume(void *rb, void **payload, size_t *size)
{
	// check for null-pointer
	if (rb == NULL) {
		DEBUG_PRINTF("Cannot consume from ringbuffer: buffer is null pointer.\n");
		return ERR_INVALID_ARGS;
	}
	
	struct ringbuffer *rbuf = rb;
	// check if buffer is empty
	if (rbuf->n_elements == 0) {
		DEBUG_PRINTF("Cannot consume from buffer: buffer empty\n");
		return SYS_ERR_NOT_IMPLEMENTED;
	}
	
	// read payload and size into return values
	*payload = rbuf->entries[rbuf->next].payload;
	*size = rbuf->entries[rbuf->next].size;
	
	// remove entry from buffer
	rbuf->entries[rbuf->next].payload = NULL;
	rbuf->entries[rbuf->next].size = 0;
	rbuf->next = (rbuf->next + 1) % rbuf->capacity;
	rbuf->n_elements--;
	
	return SYS_ERR_OK;
}

errval_t ring_empty(void *rb, uint8_t *empty)
{
	// check for null-pointer
	if (rb == NULL) {
		DEBUG_PRINTF("Cannot consume from ringbuffer: buffer is null pointer.\n");
		return ERR_INVALID_ARGS;
	}
	
	// check if the buffer is empty
	*empty = ((struct ringbuffer*)rb)->n_elements == 0;
	return SYS_ERR_OK;
}

errval_t ring_full(void *rb, uint8_t *full)
{
	// check for null-pointer
	if (rb == NULL) {
		DEBUG_PRINTF("Cannot consume from ringbuffer: buffer is null pointer.\n");
		return ERR_INVALID_ARGS;
	}
	
	// check if the buffer is full
	*full = ((struct ringbuffer*)rb)->n_elements == ((struct ringbuffer*)rb)->capacity;
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


errval_t ring_producer_transmit(struct ring_producer *rp, void *payload, size_t size)
{
	// check for null-pointer
	if (rp == NULL) {
		DEBUG_PRINTF("Ringbuffer producer cannot transmit: producer is null-ptr.\n");
		return ERR_INVALID_ARGS;
	}
	if (rp->ringbuffer == NULL) {
		DEBUG_PRINTF("Ringbuffer producer cannot transmit: ringbuffer is null-ptr.\n");
		return ERR_INVALID_ARGS;
	}
	
	uint8_t full;
	errval_t err;
		
	// check if buffer is full TODO: this is only necessary, while the buffer cannot resize itself
	err = ring_full(rp->ringbuffer, &full);
	if (full) {
		DEBUG_PRINTF("Ringbuffer producer cannot transmit: buffer is full.\n");
		return SYS_ERR_NOT_IMPLEMENTED;
	}
	
	// insert into buffer
	err = ring_insert(rp->ringbuffer, payload, size);
	if (err_is_fail(err)) {
		DEBUG_PRINTF("Ringbuffer producer cannot transmit: insertion into buffer failed.\n");
		return err;
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

errval_t ring_consumer_recv(struct ring_producer *rc, void **payload, size_t *size)
{
	// check for null-pointer
	if (rc == NULL) {
		DEBUG_PRINTF("Ringbuffer consumer cannot consume: consumer is null-ptr.\n");
		return ERR_INVALID_ARGS;
	}
	if (rc->ringbuffer == NULL) {
		DEBUG_PRINTF("Ringbuffer consumer cannot consume: ring_buffer is null-ptr.\n");
		return ERR_INVALID_ARGS;
	}
	
	uint8_t empty;
	errval_t err;
		
	// check if buffer is empty
	err = ring_empty(rc->ringbuffer, &empty);
	if (empty) {
		DEBUG_PRINTF("Ringbuffer consumer cannot transmit: buffer is empty.\n");
		return SYS_ERR_NOT_IMPLEMENTED;
	}
	
	// consume from buffer
	err = ring_consume(rc->ringbuffer, payload, size);
	if (err_is_fail(err)) {
		DEBUG_PRINTF("Ringbuffer consumer cannot consume: consume from buffer failed.\n");
		return err;
	}
	
	// if no errors happened, return OK
	return SYS_ERR_OK;
}