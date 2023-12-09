#include <hypercalls/hp_lseek.h>
#include <mm/smalloc.h>
#include <mm/translate.h>

int hp_lseek(int fildes, uint32_t offset, int whence) {
  uint32_t *kbuf = smalloc(sizeof(int) * 3, MALLOC_NO_ALIGN);
  kbuf[0] = fildes;
  kbuf[1] = offset;
  kbuf[2] = whence;
  int ret = hypercall(NR_HP_lseek, physical(kbuf));
  sfree(kbuf);
  return ret;
}
