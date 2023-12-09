.globl hlt
.extern kernel_main_tdx
.extern kernel_test
.intel_syntax noprefix
_start:
#  mov rdx, [rsp] /* argc */
#  lea rcx, [rsp + 8] /* argv */
  call kernel_main_tdx
hlt:
  hlt
  jmp hlt
