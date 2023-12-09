#include <mm/smalloc.h>
#include <mm/translate.h>
#include <utils/panic.h>
#include <utils/string.h>

#define MALLOC_NO_ALIGN 0x0
#define MALLOC_PAGE_ALIGN 0x1000

struct smalloc_arena {
  void *top;
  uint64_t top_size;
  void *min_addr;
  struct chunk {
    uint64_t size;
    uint64_t pad;
    struct chunk *next;
  } sorted_bin;
};
static struct smalloc_arena shared_arena;

#define offsetof(TYPE, MEMBER) ((uint64_t) &((TYPE *)0)->MEMBER)

#define chunk2mem(c) ((void*) ((uint8_t*)(c) + offsetof(struct chunk, next)))
#define mem2chunk(m) ((struct chunk*) ((uint8_t*)(m) - offsetof(struct chunk, next)))

void init_allocator_shared(void *addr, uint64_t len) {
  if(len == 0 || (len & 0xfff) != 0) panic("smalloc.c#init_allocator: invalid length");

  shared_arena.top = addr;
  shared_arena.top_size = len;
  shared_arena.min_addr = addr;
  memset(&shared_arena.sorted_bin, 0, sizeof(shared_arena.sorted_bin));
}

static inline int invalid_chunk_size(uint64_t s) {
  if(s == 0) return 1;
  if(s >= (1ull << 32)) return 1;
  if(s & 0xf) return 1;
  return 0;
}

static inline void insert_sorted(struct chunk *c) {
  struct chunk *now = shared_arena.sorted_bin.next, *prev = &shared_arena.sorted_bin;
  while(now != 0 && now->size < c->size) {
    prev = now;
    now = now->next;
  }
  // either now == 0 or now->size >= c->size
  prev->next = c;
  c->next = now;
}

static void *fetch_sorted_bin(uint64_t nb) {
  struct chunk *now = shared_arena.sorted_bin.next, *prev = &shared_arena.sorted_bin;
  while(now != 0) {
    if(invalid_chunk_size(now->size)) panic("smalloc.c: invalid size of sorted bin");
    // best fit because this is the 'sorted' bin.
    if(now->size >= nb) {
      // remove it first
      prev->next = now->next;
      // exactly same size, just return it
      if(now->size == nb) {}
      else {
        // split!
        struct chunk *r = (struct chunk*) ((uint8_t*)now + nb);
        r->size = now->size - nb;
        insert_sorted(r);
      }
      memset(now, 0, sizeof(struct chunk));
      now->size = nb;
      return chunk2mem(now);
    }
    else {
      prev = now;
      now = now->next;
    }
  }
  return 0;
}

static void *smalloc_top(uint64_t nb) {
  if(shared_arena.top_size < nb) return 0;
  shared_arena.top_size -= nb;
  struct chunk* c = (struct chunk*) shared_arena.top;
  c->size = nb;
  shared_arena.top += nb;
  return chunk2mem(c);
}

static void *int_smalloc(uint64_t nb, int align) {
  if(align == MALLOC_NO_ALIGN) {
    void *ret = fetch_sorted_bin(nb);
    if(!ret) ret = smalloc_top(nb);
    return ret;
  }
  if(align != MALLOC_PAGE_ALIGN) panic("smalloc.c#smalloc: invalid alignment");
  // address to be returned must be aligned
  // calculate the size of chunk to be split such that
  // remain_top & (ALIGN - 1) == ALIGN-offsetof(chunk, next)
  uint64_t cur = (uint64_t) shared_arena.top & (align - 1);
  uint64_t consume = (((align - offsetof(struct chunk, next)) - cur) & (align - 1));
  void *gap = 0;
  if(consume == 0) ; /* already been fulfilled */
  else {
    gap = smalloc_top(consume);
    if(gap == 0) return 0; // no enough memory
  }
  void *ret = smalloc_top(nb); // this should satisfy the alignment
  sfree(gap);
  return ret;
}

#define alignup(v, p) (((v) & ((p)-1)) ? (((v) & (-(p))) + (p)) : (v))
void *smalloc(uint64_t len, int align) {
  if(len >= (1ull << 32)) return 0; // fast fail
  uint64_t nb = alignup(len + offsetof(struct chunk, next), 0x80);
  void *victim = int_smalloc(nb, align);
  if(align != MALLOC_NO_ALIGN &&
    ((uint64_t) victim & (align - 1))
    ) panic("smalloc.c#smalloc: alignment request failed");
  /* always clean up */
  memset(victim, 0, len);
  return victim;
}

void sfree(void *mem) {
  if(mem == 0) return;
  struct chunk* c = mem2chunk(mem);
  if(invalid_chunk_size(c->size)) panic("smalloc.c#sfree: invalid size");
  if(c->size + (void*)c == shared_arena.top) {
    shared_arena.top = (void*) c;
    shared_arena.top_size += c->size;
    c->size = 0;
  }
  else insert_sorted(c);
}
