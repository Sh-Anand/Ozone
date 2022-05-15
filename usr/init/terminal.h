#ifndef _TERMINAL_H
#define _TERMINAL_H

void gic_setup(void);
void terminal_setup_pl011(void);
void terminal_putchar(char c);
char terminal_getchar(void);

#endif // _TERMINAL_H