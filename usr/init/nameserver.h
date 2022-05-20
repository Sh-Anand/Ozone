//
// Created by Zikai Liu on 5/12/22.
//

#ifndef AOS_NAMESERVER_H
#define AOS_NAMESERVER_H

#include <aos/aos.h>
#include <aos/nameserver.h>

errval_t nameserver_bind(domainid_t pid, struct capref urpc_frame);

#endif  // AOS_NAMESERVER_H
