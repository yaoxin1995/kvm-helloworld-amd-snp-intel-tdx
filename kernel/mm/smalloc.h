#ifndef KMALLOC_H
#define KMALLOC_H

#include <stdint.h>

void init_sallocator(void *addr, uint64_t len);

void *smalloc(uint64_t len, int align);
void sfree(void *addr);

#endif
