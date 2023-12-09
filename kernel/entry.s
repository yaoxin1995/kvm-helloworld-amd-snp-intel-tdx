.globl hlt, init_kernel_page_tables
.extern kernel_main_tdx
.extern kernel_test
.extern init_kernel_page_tables
.intel_syntax noprefix
_start:
#  mov rdx, [rsp] /* argc */
#  lea rcx, [rsp + 8] /* argv */
#  assumes we already have a working stack
#  preserve arguments from hob
#  calling convention is amd_64

  pushq rdi; #arg0
  pushq rsi; #arg1
#  stack should be 16 byte aligned

   callq [rip + init_kernel_page_tables];

# enable page tables
# enable cache
# all is good. now go to the kernel start

  callq [rip + kernel_main_tdx];

hlt:
  hlt
  jmp [rip + hlt];
