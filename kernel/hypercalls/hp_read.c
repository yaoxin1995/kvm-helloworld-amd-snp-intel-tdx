#include <hypercalls/hp_read.h>
#include <mm/smalloc.h>
#include <mm/translate.h>

int hp_read(int fildes, uint64_t phy_addr, uint64_t nbyte) {
  uint64_t *kbuf = smalloc(sizeof(uint64_t) * 3, MALLOC_NO_ALIGN);
  kbuf[0] = fildes;
  kbuf[1] = phy_addr;
  kbuf[2] = nbyte;
  int ret = hypercall(NR_HP_read, physical(kbuf));
  sfree(kbuf);
  return ret;
}
