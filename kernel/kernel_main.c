#include <hypercalls/hp_open.h>
#include <mm/kmalloc.h>
#include <mm/kframe.h>
#include <mm/translate.h>
#include <syscalls/sys_execve.h>
#include <utils/string.h>
#include <mm/init_pt.h>
#include <mm/smalloc.h>
#include <utils/tdx.h>
#include <mm/gdt.h>
#include <mm/idt.h>
#include <utils/panic.h>
#include "../../.parameters"

#define MSR_STAR 0xc0000081 /* legacy mode SYSCALL target */
#define MSR_LSTAR 0xc0000082 /* long mode SYSCALL target */
#define MSR_CSTAR 0xc0000083 /* compat mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084
#define HEAP_SIZE 0x1F400000 //500MB 
#define DMA_SIZE 0x100000
#define STACK_SIZE 0x800000

//extern uint64_t kernel_stack;
int register_syscall() {
  asm(
    "xor rax, rax;"
    "mov rdx, 0x00200008;"
    "mov ecx, %[msr_star];"
    "wrmsr;"

    "mov eax, %[fmask];"
    "xor rdx, rdx;"
    "mov ecx, %[msr_fmask];"
    "wrmsr;"

    "lea rax, [rip + syscall_entry];"
    "mov rdx, %[base] >> 32;"
    "mov ecx, %[msr_syscall];"
    "wrmsr;"
    :: [msr_star]"i"(MSR_STAR),
       [fmask]"i"(0x3f7fd5), [msr_fmask]"i"(MSR_SYSCALL_MASK),
       [base]"i"(KERNEL_BASE_OFFSET), [msr_syscall]"i"(MSR_LSTAR)
    : "rax", "rdx", "rcx");
  return 0;
}

void switch_user(uint64_t argc, char *argv[]) {
  unsigned char buffer[20] = {0};
  int total_len = (argv[argc - 1] + strlen(argv[argc - 1]) + 1) - (char*) argv;
  /* temporary area for putting user-accessible data */
  write_in_console("switch user total_len: 0x");
  uint64_to_string(total_len,buffer);
  write_in_console((char*)buffer);
  write_in_console("\n");
  char *s = kmalloc(total_len, MALLOC_PAGE_ALIGN);
  uint64_t sp = physical(s);
  add_trans_user((void*) sp, (void*) sp, PROT_RW); /* sp is page aligned */
  /* copy strings and argv onto user-accessible area */
  for(int i = 0; i < argc; i++)
    argv[i] = (char*) (argv[i] - (char*) argv + sp);
  memcpy(s, argv, total_len);
  sys_execve(argv[0], (char**) sp, (char**) (sp + argc * sizeof(char*)));
}

int kernel_main(void* addr, uint64_t len, uint64_t argc, char *argv[]) {
  //init_pagetable();
  /* new paging enabled! */
  init_allocator((void*) ((uint64_t) addr | KERNEL_BASE_OFFSET), len);
  if(register_syscall() != 0) return 1;
  switch_user(argc, argv);
  return 0;
}

void enable_apic_interrupt() {
    // Enable the local APIC by setting bit 8 of the APIC spurious vector region (SVR)
    // Ref: Intel SDM Vol3. 8.4.4.1
    // In x2APIC mode, SVR is mapped to MSR address 0x80f.
    // Since SVR(SIVR) is not virtualized, before we implement the handling in #VE of MSRRD/WR,
    // use tdvmcall instead direct read/write operation.
    uint64_t svr = tdvmcall_rdmsr(0x80f);
    tdvmcall_wrmsr(0x80f, svr | (0x1 << 8));
}

int kernel_test(uint64_t hob, uint64_t _payload){
  tdvmcall_io_write_8(0x3f8,'s');
  return 0;
}
int kernel_main_tdx(uint64_t hob, uint64_t _payload) {

  //unsigned char buffer[20] = {0};
  
  write_in_console("Setting up page table finished.\n");

  write_in_console("Start setting up heap.\n");
  uint64_t heap = get_usable(HEAP_SIZE);
  init_allocator((void*) ( heap | KERNEL_BASE_OFFSET), HEAP_SIZE);

  write_in_console("Start setting up dma.\n");
  uint64_t dma = get_usable(DMA_SIZE);
  set_shared_bit((uint64_t*)(dma | KERNEL_BASE_OFFSET),DMA_SIZE);
  tdvmcall_mapgpa(true,dma,DMA_SIZE);
  init_allocator_shared((void*)( dma | KERNEL_BASE_OFFSET), DMA_SIZE);
  memset((void*)( dma | KERNEL_BASE_OFFSET),0x0,DMA_SIZE);
  
  write_in_console("Start setting gdt.\n");
  gdt = (struct gdt_entry *)(get_usable(PAGE_SIZE)|KERNEL_BASE_OFFSET);
  tss = (struct tss *)(get_usable(PAGE_SIZE)|KERNEL_BASE_OFFSET);
  memset((uint64_t*)gdt,0x0,PAGE_SIZE);
  memset((uint64_t*)tss,0x0,PAGE_SIZE);
  init_gdt(gdt,tss);

  write_in_console("Start setting idt.\n");
  idt = (struct idt_entry*)(get_usable(PAGE_SIZE)|KERNEL_BASE_OFFSET);
  memset(idt,0x0,PAGE_SIZE);
  idt_init(idt);
  write_in_console("Start enabling apic interrupt.\n");
  enable_apic_interrupt();

  write_in_console("Start setting up stack and jump to new stack.\n");
  //stack initialization
  uint64_t stack = get_usable(STACK_SIZE)|KERNEL_BASE_OFFSET;
  uint64_t stack_top = stack + STACK_SIZE;

  asm("mov rsp, %0;"
      "mov rbp, rsp;"
       ::"r"(stack_top));
  int parameters_argc = ARGC;
  int parameters_argv_len = ARGV_LEN;
  char* parameters = PARAMETERS;
  struct argv_struct{
    char *argv[parameters_argc];
    char buffer[parameters_argv_len];
  };
  struct argv_struct argvs;
  memset(argvs.buffer,0x0,sizeof(argvs.buffer));
  memcpy(argvs.buffer,parameters,parameters_argv_len);

  int buffer_count = 0;
  for(int i=0;i<parameters_argc;i++){
    argvs.argv[i] = &argvs.buffer[buffer_count];
    buffer_count = strlen(&argvs.buffer[buffer_count])+1;
  }
  
  switch_user(parameters_argc, argvs.argv);
  return 0;
}
