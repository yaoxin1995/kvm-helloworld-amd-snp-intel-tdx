#include <hypercalls/hp_write.h>
#include <mm/smalloc.h>
#include <mm/translate.h>
#include <mm/uaccess.h>
#include <syscalls/sys_write.h>
#include <utils/errno.h>
#include <utils/string.h>

int64_t sys_write(int fildes, void *buf, uint64_t nbyte) {
  if(fildes < 0) return -EBADF;
  if(!access_ok(VERIFY_READ, buf, nbyte)) return -EFAULT;
  void *dst = smalloc(nbyte, MALLOC_NO_ALIGN);
  memcpy(dst, buf, nbyte);
  int64_t ret = hp_write(fildes, physical(dst), nbyte);
  sfree(dst);
  return ret;
}
