//
// Created by Zikai Liu on 4/12/22.
//

#ifndef AOS_RINGBUFFER_H
#define AOS_RINGBUFFER_H

#include <errors/errno.h>
#include <strings.h>

errval_t ring_init(void **buffer, size_t size);
errval_t ring_insert(void *buffer, void* payload, size_t size);
errval_t ring_consume(void *buffer, void **payload, size_t *size);
errval_t ring_empty(void *buffer, uint8_t *empty);
errval_t ring_full(void *buffer, uint8_t *full);

struct ring_producer {
	void *ringbuffer;
	// TODO: necessary data
};

errval_t ring_producer_init(struct ring_producer *rp, void *ring_buffer);

errval_t ring_producer_transmit(struct ring_producer *rp, void *payload, size_t size);

struct ring_consumer {
	void *ringbuffer;
	// TODO: necessary fields
};

errval_t ring_consumer_init(struct ring_consumer *rc, void *ring_buffer);

errval_t ring_consumer_recv(struct ring_producer *rc, void **payload, size_t *size);

#endif  // AOS_RINGBUFFER_H
