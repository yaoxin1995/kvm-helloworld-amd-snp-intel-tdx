#include <hypercalls/hypercall.h>
#include <utils/string.h>
int hypercall(uint16_t port, uint32_t data) {
  write_in_console("Start hypercall \n");
  int ret = 0;
  asm(
    "mov dx, %[port];"
    "mov eax, %[data];"
    "out dx, eax;"
    "in eax, dx;"
    "mov %[ret], eax;"
    : [ret] "=r"(ret)
    : [port] "r"(port), [data] "r"(data)
    : "rax", "rdx"
    );
  write_in_console("End hypercall \n");
  return ret;
}
