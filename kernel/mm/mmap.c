#include <mm/kmalloc.h>
#include <mm/mmap.h>
#include <mm/translate.h>
#include <utils/errno.h>
#include <utils/misc.h>
#include <utils/panic.h>
#include <utils/string.h>
/* returns user-accessible page-aligned block
 * if addr == 0, use the last_mmapped address
 */
void *mmap(void *addr, uint64_t len, int prot) {
  write_in_console("enter mmap\n");
  unsigned char buffer[20] = {0};
  uint64_to_string((uint64_t)addr,buffer); 
  write_in_console("addr: 0x");
  write_in_console((char*)buffer);
  write_in_console("\n");

  uint64_to_string((uint64_t)len,buffer); 
  write_in_console("len: 0x");
  write_in_console((char*)buffer);
  write_in_console("\n");

  uint64_to_string((uint64_t)prot,buffer); 
  write_in_console("prot: 0x");
  write_in_console((char*)buffer);
  write_in_console("\n");

  if(len == 0 || len & 0xfff) panic("mmap.c: invalid length");
  void *ret = kmalloc(len, MALLOC_PAGE_ALIGN);
  if(ret == 0) return 0; // no memory
  write_in_console("mmap  1\n");
  static void *last_mmapped = (void*) -1;
  /* no ASLR */
  if(last_mmapped == (void*) -1) last_mmapped = (void*) 0x00007ffff7fff000ull;

  if(addr == 0) last_mmapped = addr = last_mmapped - len;
  for(uint64_t i = 0; i < len; i += 0x1000)
    add_trans_user(addr + i, ret + i, prot);  
  write_in_console("mmap  2\n");
  return addr;
}

int mprotect(void *addr, uint64_t len, int prot) {
  if(!alignok(addr)) return -EINVAL;
  for(uint64_t i = 0; i < len; i += 0x1000) {
    if(!USER_MEM_RANGE_OK(addr + i) ||
      modify_permission(addr + i, prot) != 0)
      return -EACCES;
  }
  return 0;
}
