//
// Created by Zikai Liu on 4/12/22.
//

#ifndef AOS_RINGBUFFER_H
#define AOS_RINGBUFFER_H

#include <errors/errno.h>
#include <strings.h>

/**
 * @brief Initializes a ringbuffer of size 63, which each element being equal to a single cacheline. The resulting structure will be pagealigned.
 * 
 * @param buffer Pointer wto at least one page of memory.
 * @return LIB_ERR_MALLOC_FAIL if the memory allocation failed, SYS_ERR_OK otherwise. 
 */
errval_t ring_init(void *buffer);

struct ring_producer {
	void *ringbuffer;
	// TODO: necessary data
};

errval_t ring_producer_init(struct ring_producer *rp, void *ring_buffer);
errval_t ring_producer_transmit(struct ring_producer *rp, const void *payload, size_t size);

struct ring_consumer {
	void *ringbuffer;
	// TODO: necessary fields
};

errval_t ring_consumer_init(struct ring_consumer *rc, void *ring_buffer);
errval_t ring_consumer_recv(struct ring_consumer *rc, void **payload, size_t *size);

#endif  // AOS_RINGBUFFER_H
