#include <hypercalls/hp_open.h>
#include <mm/smalloc.h>
#include <mm/translate.h>
#include <mm/uaccess.h>
#include <syscalls/sys_open.h>
#include <utils/errno.h>
#include <utils/string.h>
int sys_open(const char *path) {
  write_in_console("In function sys_open, path: ");
  write_in_console(path);
  write_in_console("\n");
  if(!access_string_ok(path)) return -EFAULT;
  void *dst = copy_str_from_user_to_shared(path);
   write_in_console("Have copied from user\n");
  if(dst == 0) return -ENOMEM;
  int fd = hp_open(physical(dst));
  asm("hlt");
  unsigned char buffer[20] = {0};
  uint64_to_string((uint64_t)fd,buffer);
  write_in_console("fd get: 0x");
  write_in_console((char*)buffer);
  write_in_console("\n");
  write_in_console("hp_open returned\n");
  sfree(dst);
  return fd;
}
