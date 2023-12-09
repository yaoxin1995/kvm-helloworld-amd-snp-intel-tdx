#ifndef UACCESS_H
#define UACCESS_H

#include <stdint.h>

#define VERIFY_READ 0
#define VERIFY_WRITE 1

int access_ok(int type, const void* addr, uint64_t size);
int access_string_ok(const void *addr);
void *copy_str_from_user_to_shared(const char *s);
void *copy_str_from_user_to_private(const char *s);

#endif
