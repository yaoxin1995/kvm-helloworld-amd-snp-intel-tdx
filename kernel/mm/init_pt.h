#ifndef INIT_PT
#define INIT_PT
#include <mm/translate.h>
#include <mm/kframe.h>
#include <stdbool.h>
#include <utils/panic.h>
#include <mm/td-hob.h>
#include <utils/string.h>
#define STACK_SIZE 0x800000
uint64_t get_usable(uint64_t size);

#endif