#include <hypercalls/hp_open.h>
#include <mm/translate.h>

int hp_open(uint64_t paddr) {
  write_in_console("In function hp_open\n");
  return hypercall(NR_HP_open, (uint32_t) paddr);
}
