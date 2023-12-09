#ifndef PANIC_H
#define PANIC_H

/* panic occurs when assertion fails in kernel */
void panic(const char *s);
void write_in_console(const char *s);
#endif
