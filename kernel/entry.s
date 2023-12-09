.globl hlt
.extern kernel_main_tdx
.extern kernel_test
.extern init_kernel_page_tables
_start:
#  mov rdx, [rsp] /* argc */
#  lea rcx, [rsp + 8] /* argv */
#  assumes we already have a working stack
#  preserve arguments from hob
#  calling convention is amd_64

  pushq %rdi; #arg0
  pushq %rsi; #arg1

#  stack should be 16 byte aligned

  leaq   init_kernel_page_tables(%rip), %rax
  callq *%rax;/*call set_page_tables*/

  leaq   kernel_main_tdx(%rip), %rax
  callq *%rax;/*call kernel_main_tdx*/

hlt:
  hlt
  jmp hlt
