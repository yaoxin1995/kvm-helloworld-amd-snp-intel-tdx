.globl hlt, init_kernel_page_tables, pml4
.extern kernel_main_sev_snp
.extern init_kernel_page_tables
.extern pml4
.intel_syntax noprefix
_start:

#  mov rdx, [rsp] /* argc */
#  lea rcx, [rsp + 8] /* argv */
#  assumes we already have a working stack
#  preserve arguments from hob
#  calling convention is amd_64

#  pushq rdi; #arg0
#  pushq rsi; #arg1
#  stack should be 16 byte aligned
   lea rax, [rip + init_kernel_page_tables]
   callq rax;
   
# enable page tables
   mov rax, QWORD PTR [rip+pml4]
   mov cr3, rax
# enable cache
# all is good. now go to the kernel start
  lea rax, [rip + kernel_main_sev_snp]
  callq rax;

hlt:
  hlt
  jmp [rip + hlt];


