#ifndef TD_HOB
#define TD_HOB
#include <stdint.h>
#include <mm/e820_memory_layout.h>

struct e820_table{
    int num_entries;
    struct e820_entry * e820_entry;
    
} ;

uint64_t parse_hob_get_size(uint64_t ptr);
struct e820_table get_e820_table_from_hob(uint8_t *hob,uint64_t hob_size);
uint64_t get_usable(uint64_t size);
#endif