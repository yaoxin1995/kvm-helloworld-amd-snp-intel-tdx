#ifndef SMALLOC_H
#define SMALLOC_H

#include <stdint.h>
#define MALLOC_NO_ALIGN 0x0

void init_allocator_shared(void *addr, uint64_t len);

void *smalloc(uint64_t len, int align);
void sfree(void *addr);

#endif
