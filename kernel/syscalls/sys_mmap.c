#include <hypercalls/hp_lseek.h>
#include <hypercalls/hp_read.h>
#include <mm/mmap.h>
#include <mm/translate.h>
#include <mm/smalloc.h>
#include <syscalls/sys_mmap.h>
#include <utils/errno.h>
#include <utils/misc.h>
#include <utils/string.h>
void *sys_mmap(
  void *addr, uint64_t len, int prot,
  int flags, int fd, uint64_t offset) {
  unsigned char buffer[20] = {0};
  uint64_to_string((uint64_t)addr,buffer); 
  write_in_console("addr: 0x");
  write_in_console((char*)buffer);
  write_in_console("\n");

  uint64_to_string(len,buffer); 
  write_in_console("len: 0x");
  write_in_console((char*)buffer);
  write_in_console("\n");

  uint64_to_string((uint64_t)prot,buffer); 
  write_in_console("prot: 0x");
  write_in_console((char*)buffer);
  write_in_console("\n");

  uint64_to_string((uint64_t)flags,buffer); 
  write_in_console("flags: 0x");
  write_in_console((char*)buffer);
  write_in_console("\n");

  uint64_to_string((uint64_t)fd,buffer); 
  write_in_console("fd: 0x");
  write_in_console((char*)buffer);
  write_in_console("\n");

  uint64_to_string(offset,buffer); 
  write_in_console("offset: 0x");
  write_in_console((char*)buffer);
  write_in_console("\n");

  if(!alignok(addr)) return (void*) -EINVAL;
  if(len == 0) return (void*) -EINVAL;
  if(!(flags & MAP_FIXED)) addr = 0; // no MAP_FIXED, address decided by kernel
  else if(addr != 0 && !USER_MEM_RANGE_OK(addr)) return (void*) -EINVAL;

  uint64_t aligned_len = alignup(len); 
  addr = mmap(addr, aligned_len, prot | PROT_RW); // temporary mark it read/writable
  void *tmp_buffer = smalloc(len,MALLOC_PAGE_ALIGN);
  if(addr == 0) return (void*) -ENOMEM;
  if(fd >= 0) {
    int ret = hp_lseek(fd, offset, SEEK_SET);
    if(ret < 0) return (void*) (int64_t) ret;
    uint64_t tmp_buffer_address = translate(tmp_buffer, 0, 1)&~SHARED_BIT;
    uint64_to_string(tmp_buffer_address,buffer); 
    write_in_console("reading to tmp buffer physical address: 0x");
    write_in_console((char*)buffer);
    write_in_console("\n");
    hp_read(fd, (uint64_t)tmp_buffer&~KERNEL_BASE_OFFSET, len);
    memcpy(addr,tmp_buffer,len);
    sfree(tmp_buffer);
    for(int i=0;i<len/8;i++){
      write_in_console("value: 0x");
      uint64_to_string(*(uint64_t*)(addr+i*8),buffer);
      write_in_console((char*)buffer);
      write_in_console("\n");
    }
  }

  /* this should never fail */
  mprotect(addr, aligned_len, prot); // correct protection

  return addr;
}
