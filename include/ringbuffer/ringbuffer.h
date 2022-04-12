//
// Created by Zikai Liu on 4/12/22.
//

#ifndef AOS_RINGBUFFER_H
#define AOS_RINGBUFFER_H

#include <errors/errno.h>
#include <strings.h>

struct ring_producer {

};

errval_t ring_producer_init(struct ring_producer *rp, void *ring_buffer);

errval_t ring_producer_transmit(struct ring_producer *rp, void *payload, size_t size);

struct ring_consumer {

};

errval_t ring_consumer_init(struct ring_consumer *rp, void *ring_buffer);

errval_t ring_consumer_recv(struct ring_producer *rp, void **payload, size_t *size);

#endif  // AOS_RINGBUFFER_H
