Ozone
=====
> "OS one", O3

Ozone is a [multikernel](https://en.wikipedia.org/wiki/Multikernel) operating system running on the ARM-based Toradex
iMX.8 board as the project of the [Advance Operating Systems](README.AOS) at ETHZ.
It is built on a simplified version of [Barrelfish](barrelfish.org), an open-source multikernel developed at ETHZ.

> :warning: **If you are enrolled in the course, do not proceed further.** Coming up with your own design is part of the
> project and the course. You might violate the academic integrity regulations by referring to the code here.

=> [Our design report](report/AOS22-Team1-Ozone.pdf)

## Authors
Team 1:
* Emil Schätzle (eschaetzle@student.ethz.ch)
* Linus Vogel (linvogel@student.ethz.ch)
* Shashank Anand (sanand@student.ethz.ch)
* Zikai Liu (liuzik@student.ethz.ch)

## Features and Highlights
* Physical memory manager
  * The buddy allocation algorithm
  * Binary search tree
* Virtual memory manager
  * The buddy allocation algorithm + free list
  * Support mappings to fixed and dynamic addresses
  * Demand paging
  * Unmapping
  * Thread safe
* Process spawning
* Process management
  * Killing processes
* Intra-core Local Message Passing (LMP)
  * Passing large messages in frame
* User-Level Message Passing (UMP)
  * Efficient ringbuffer
  * Waitset Integration
  * Indirect UMP Capability Transfer
* Remote Procedure Call (RPC)
  * Unifying LMP and UMP channels
  * Easy to use interface
* Multicore
  * Bringing up all four cores on iMX.8
* Shell
  * Thread-safe terminal server
  * Command history and Command Line Editing
  * Built-in commands
* Filesystem
  * FAT32 specification with read and write support
  * High speed access
  * Shell integration
* Nameservice
  * Unified interface for RPCs
  * Deregister dead services
* Networking
  * Low-latency on UDP connections
  * Clear user-interface to simple listen on ports and send out UDP messages
  * nchat to chat with another host using UDP

## Compile and Deployment

Please refer to the [book](main-toradex.pdf) and the [AOS README](README.AOS).