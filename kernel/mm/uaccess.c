#include <mm/smalloc.h>
#include <mm/kmalloc.h>
#include <mm/translate.h>
#include <mm/uaccess.h>
#include <utils/misc.h>
#include <utils/string.h>
#include <utils/panic.h>
int access_ok(int type, const void* addr_, uint64_t size) {
  uint64_t addr = (uint64_t) addr_;
  if(!USER_MEM_RANGE_OK(addr)){write_in_console("failed 1\n"); return 0;} 
  if(!USER_MEM_RANGE_OK(addr + size - 1)) {write_in_console("failed 2\n"); return 0;}
  for(uint64_t v = aligndown(addr); v < alignup(addr + size); v += 0x1000)
    if(translate((void*) v, 1, type) == (uint64_t) -1) {write_in_console("failed 3\n"); return 0;}
  return 1;
}

/* check if addr ~ addr+strlen(addr) are all accessible */
int access_string_ok(const void *addr_) {
  unsigned char buffer[20] = {0};
  write_in_console("access_string_ok check address: 0x");
  uint64_to_string((uint64_t)addr_,buffer);
  write_in_console((char*)buffer);
  write_in_console("\n"); 

  if(!access_ok(VERIFY_READ, addr_, 1)) return 0;
  uint64_t addr = (uint64_t) addr_;
  uint64_t remain_size = 0x1000 - (addr & 0xfff);
  /* we have checked the whole page of addr is accessible */
  uint64_t l = strnlen(addr_, remain_size);
  /* length not enough.. recursive it */
  if(l == remain_size) return access_string_ok((void*) (addr + l));
  write_in_console("access_string_ok check passed\n");
  return 1;
}

void *copy_str_from_user_to_shared(const char *s) {
  unsigned char buffer[20] = {0};
  int len = strlen(s);
  void *dst = smalloc(len + 1, MALLOC_NO_ALIGN);
  uint64_to_string((uint64_t)dst,buffer);
  write_in_console("copy_str_from_user dst: 0x");
  write_in_console((char*)buffer);
  write_in_console("\n");
  if(dst == 0) return 0;
  memcpy(dst, s, len + 1);
  return dst;
}

void *copy_str_from_user_to_private(const char *s) {
  unsigned char buffer[20] = {0};
  int len = strlen(s);
  void *dst = kmalloc(len + 1, MALLOC_NO_ALIGN);
  uint64_to_string((uint64_t)dst,buffer);
  write_in_console("copy_str_from_user dst: 0x");
  write_in_console((char*)buffer);
  write_in_console("\n");
  if(dst == 0) return 0;
  memcpy(dst, s, len + 1);
  return dst;
}
