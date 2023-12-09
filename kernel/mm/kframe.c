#include "kframe.h"

typedef struct kframe_allocator {
	uint64_t frame_count;
	uint64_t frame_start;
	uint8_t *bitmap_frame;
	uint64_t bitmap_count;	
	uint64_t frame_lock;
	uint64_t available_frame_count;
	uint64_t kframe_cache[KFRAME_CACHE_SIZE];
	uint8_t  kframe_cache_used[KFRAME_CACHE_SIZE];
} kframe_alloc_t;

#define SHARED_BITMAP_SIZE 4096
#define PAGE_TABLE_BITMAP_SIZE 0x800
static kframe_alloc_t shared_allocator;
static kframe_alloc_t page_table_allocator;
uint8_t shared_bitmap[SHARED_BITMAP_SIZE];
uint8_t page_table_bitmap[PAGE_TABLE_BITMAP_SIZE];

int kframe_allocator_init(kframe_alloc_t *fa, uint64_t bitmap_frame, uint64_t bitmap_count, uint64_t frame_start, uint64_t size)
{
	if (size == 0 || !fa) return 0;

	fa->frame_start  = frame_start;
	fa->frame_count  = size / KFRAME_SIZE;
	fa->bitmap_frame = (uint8_t*) bitmap_frame;
	fa->available_frame_count = fa->bitmap_count = bitmap_count;

	for(uint64_t i=0; i < fa->bitmap_count; i++) {
		fa->bitmap_frame[i] = 0x0;//Should be 0x0?
	}

	for(int i=0; i < KFRAME_CACHE_SIZE; i++) {
		fa->kframe_cache_used[i] = 0x0;
		fa->kframe_cache[i] = 0x0;
	}
	//allocate cache
	//atomic_lock(&frame_lock);
	for (uint64_t i=0; i < KFRAME_CACHE_SIZE && i < fa->frame_count; i++) {
		fa->kframe_cache[i] = fa->bitmap_frame[i];
		fa->kframe_cache_used[i] = KFRAME_CACHE_AVAILABLE;
	}
	//atomic_unlock(&frame_lock);
	return 1;
}
uint64_t kframe_allocate_single_frame(kframe_alloc_t *fa)
{
	uint64_t start = 0;
	if (!fa) goto kfa_error;
	if (fa->available_frame_count == 0) return 0;
	//atomic_lock(&frame_lock);
	for(; start < fa->frame_count; start++) {
		if( fa->bitmap_frame[start] == 0x0 ) {
			fa->available_frame_count--;
			fa->bitmap_frame[start] = 0x1;
			//atomic_unlock(&frame_lock);
			return ((uint64_t)fa->frame_start) + (start  * KFRAME_SIZE);
		}
	}
	//atomic_unlock(&frame_lock);
kfa_error:
	return (uint64_t)(-1);
}

uint64_t kframe_allocate(kframe_alloc_t *fa)
{
	uint64_t in_cache = 0;
	uint64_t t_frame = 0;

	if (!fa) return 0x0;
	//search the cache for available frames
	for(uint64_t i = 0; i < KFRAME_CACHE_SIZE; i++) {
		if (fa->kframe_cache_used[i] == KFRAME_CACHE_AVAILABLE) {
			t_frame = fa->kframe_cache[i];
			fa->kframe_cache_used[i] = KFRAME_CACHE_EMPTY;
			fa->bitmap_frame[ t_frame / KFRAME_SIZE] = 0x1;
			fa->available_frame_count--;
			return t_frame;
		}
	}
	//the cache is empty
	if (in_cache == 0) {

	}

	for(int i=0; i < KFRAME_CACHE_SIZE; i++) {//Should it be if()
		t_frame = kframe_allocate_single_frame(fa);
		if (t_frame == 0) break;
		fa->kframe_cache[in_cache] = t_frame;
		fa->kframe_cache_used[in_cache] = KFRAME_CACHE_AVAILABLE;
		in_cache++;
	}

	if (in_cache == 0) return 0x0;
	//Get a frame in cache.
	for(uint64_t i = 0; i < KFRAME_CACHE_AVAILABLE; i++) {//i<0? should be KFRAME_CACHE_SIZE?
		if (fa->kframe_cache_used[i] == KFRAME_CACHE_EMPTY) {
			t_frame = fa->kframe_cache[i];
			fa->kframe_cache_used[i] = KFRAME_CACHE_AVAILABLE;
			fa->bitmap_frame[ t_frame / KFRAME_SIZE] = 0x1;
			fa->available_frame_count--;
			return t_frame;
		}
	}
	return 0x0;
}

void kframe_free(kframe_alloc_t *fa, uint64_t address) 
{
	uint64_t index;
	if (!fa) return;
	index = (address - fa->frame_start)/ KFRAME_SIZE;
	if ( (address < fa->frame_start ) ||
	     (address > (fa->frame_start + (fa->frame_count * KFRAME_SIZE))) )
		return;

	for(uint64_t i = 0; i < KFRAME_CACHE_SIZE; i++) {
		if ( fa->kframe_cache_used[i] == KFRAME_CACHE_EMPTY) {
			fa->kframe_cache[i] = address;
			fa->kframe_cache_used[i] = KFRAME_CACHE_AVAILABLE;
			break;
		}
	}

	//the cache is full, look for it in the frame
	fa->bitmap_frame[index] = 0;
	fa->available_frame_count++;
	return;
}

uint64_t kframe_allocate_fixed(kframe_alloc_t *fa, uint64_t start, uint64_t count)
{
	uint64_t index;
	uint64_t end;

	if (!fa) return (-1ULL);

	end = (fa->frame_start + (fa->frame_count*KFRAME_SIZE));

	if ((start < fa->frame_start) || (end < (start + (count*KFRAME_SIZE))))
		return  (-1ULL);

	index = (start - (uint64_t)fa->frame_start) / KFRAME_SIZE;

	//atomic_lock(&fa->frame_lock);
	for (uint64_t i=0; i < count; i++) {
		if (fa->bitmap_frame[index + i] == 0x1) {
			//atomic_unlock(&fa->frame_lock)
			return (-1ULL);
		}
	}
	//available
	for (uint64_t i=0; i < count; i++ ) {
		fa->bitmap_frame[index + i] = 0x1;
		fa->available_frame_count++;
	}
	//clear addresses in cache
	for (int i=0; i < KFRAME_CACHE_SIZE; i++) {
		fa->kframe_cache[i] = 0x0;
		fa->kframe_cache_used[i] = KFRAME_CACHE_EMPTY;
	}
	//atomic_unlock(&fa->frame_lock);
	return start;
}

uint64_t kframe_allocate_range(kframe_alloc_t *fa, uint64_t count)
{
	uint64_t target = (-1ULL);
	uint64_t l_count = 0;
	if (!fa) return (-1ULL);

	if (count > fa->available_frame_count) return (-1ULL);

	//empty frame cache and search
	//atomic_lock(&fa->frame_lock);
	for (int i=0; i < KFRAME_CACHE_SIZE; i++) {
		fa->kframe_cache_used[i] = KFRAME_CACHE_EMPTY;
		fa->kframe_cache[i] = 0x0;
	}
	//search the frame bitmap
	for (uint64_t i=0; i < fa->frame_count; i++) {
		if (fa->bitmap_frame[i] == 0x0) {
			target = (target == (-1ULL)) ? (i*KFRAME_SIZE + fa->frame_start): target;
			l_count++;
		} else {
			target = (-1ULL);
			l_count = 0;
		}
		if (l_count == count)
			break;
	}
	if (l_count == count) {
		for(uint64_t i=0, l_count = (target - fa->frame_start) /KFRAME_SIZE; i<count; i++) {
			fa->bitmap_frame[l_count + i] = 0x01;
		}
	}
	//atomic_unlock(&fa->frame_lock);
	return target;
}

uint64_t kframe_allocate_fixed_shared(uint64_t start, uint64_t count)
{
	return kframe_allocate_fixed(&shared_allocator, start, count);
}

uint64_t kframe_allocate_range_shared(uint64_t count)
{
	return kframe_allocate_range(&shared_allocator, count);
}

int kframe_allocator_init_shared(uint64_t frame_start, uint64_t size)
{
	return kframe_allocator_init(&shared_allocator, (uint64_t)shared_bitmap, SHARED_BITMAP_SIZE, frame_start, size);
}
void kframe_free_shared(uint64_t address) 
{
	kframe_free(&shared_allocator, address);
}


uint64_t kframe_allocate_fixed_pt(uint64_t start, uint64_t count)
{
	return kframe_allocate_fixed(&page_table_allocator, start, count);
}

uint64_t kframe_allocate_range_pt(uint64_t count)
{
	return kframe_allocate_range(&page_table_allocator, count);
}

int kframe_allocator_init_pt(uint64_t frame_start, uint64_t size)
{
	return kframe_allocator_init(&page_table_allocator, (uint64_t)page_table_bitmap, PAGE_TABLE_BITMAP_SIZE, frame_start, size);
}

void kframe_free_pt(uint64_t address) 
{
	kframe_free(&page_table_allocator, address);
}


