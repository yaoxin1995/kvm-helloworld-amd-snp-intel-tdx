.globl hlt
.extern kernel_main_tdx
.extern kernel_test

_start:
#  mov rdx, [rsp] /* argc */
#  lea rcx, [rsp + 8] /* argv */
  leaq   kernel_main_tdx(%rip), %rax
  callq *%rax;/*call kernel_main_tdx*/
hlt:
  hlt
  jmp hlt
