#ifndef _KFRAME_H
#define _KFRAME_H
#include <stdint.h>

#define KFRAME_CACHE_SIZE 16
#define KFRAME_CACHE_AVAILABLE 0x0
#define KFRAME_CACHE_EMPTY 0xFF
#define KFRAME_SIZE 0x1000

/* frame_start ==> physical address of frame to manage
 * size ==> size in bytes from frame_start to the end of frames region
 * */
int kframe_allocator_init_shared(uint64_t frame_start, uint64_t size);
/* *
 * request a contigous frames from a fixed address with frame count count
 * start --> start physical address
 * count --> number of frames to allocate 
 *
 * */
uint64_t kframe_allocate_fixed_shared(uint64_t start, uint64_t count);

/* 
 * request a contigous frames with frame count
 * start --> start physical address
 * count --> number of frames to allocate
 *
 * */
uint64_t kframe_allocate_range_shared(uint64_t count);
/*
 * get a single frame at any address
 */
uint64_t kframe_allocate_shared();
/*
 * free frame allocation from address (address)
 *
 * */

void kframe_free_shared(uint64_t address);

uint64_t kframe_allocate_fixed_pt(uint64_t start, uint64_t count);

uint64_t kframe_allocate_range_pt(uint64_t count);

int kframe_allocator_init_pt(uint64_t frame_start, uint64_t size);

void kframe_free_pt(uint64_t address);



#endif
