#ifndef _TERMINAL_H
#define _TERMINAL_H

#include <stdbool.h>
#include <stdint.h>

void gic_setup(void);
void terminal_setup_lpuart(void);
void terminal_putchar(char c);
uint64_t terminal_getchar(void* st, char* c); // WHY ON EARTH IS errval_t here unknown???

void* terminal_aquire(bool use_stdin);
void terminal_release(void* st);

bool terminal_can_use_stdin(void* st);

#endif // _TERMINAL_H