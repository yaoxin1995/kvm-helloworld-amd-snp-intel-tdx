#include <hypercalls/hp_open.h>
#include <mm/kmalloc.h>
#include <mm/kframe.h>
#include <mm/translate.h>
#include <syscalls/sys_execve.h>
#include <utils/string.h>
#include <mm/td-hob.h>
#include <mm/smalloc.h>
#include <utils/tdx.h>
#include <mm/gdt.h>
#include <mm/idt.h>
#include <utils/panic.h>

#define MSR_STAR 0xc0000081 /* legacy mode SYSCALL target */
#define MSR_LSTAR 0xc0000082 /* long mode SYSCALL target */
#define MSR_CSTAR 0xc0000083 /* compat mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084
#define HEAP_SIZE 0x1F400000 //500MB 
#define DMA_SIZE 0x100000
#define STACK_SIZE 0x800000

static struct e820_entry memory_map[128];
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
  init_pagetable();
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

  write_in_console("Strat hob parsing to get e820 table in kernel.\n");
  unsigned char buffer[20] = {0};
  uint64_to_string(hob,buffer);
  write_in_console("Parameters: hob: 0x");
  write_in_console((char*)buffer);
  write_in_console(", _payload: 0x");
  uint64_to_string(_payload,buffer);
  write_in_console((char*)buffer);
  write_in_console("\n");


  uint64_t hob_size =  parse_hob_get_size(hob);

  write_in_console("Get hob size: 0x");
  uint64_to_string(hob_size,buffer);
  write_in_console((char*)buffer);
  write_in_console("\n");

  struct e820_table parsed_e820_table = get_e820_table_from_hob((uint8_t *)hob,hob_size);

  write_in_console("Get parsed_e820_table, number of entries: 0x");
  uint64_to_string(parsed_e820_table.num_entries,buffer);
  write_in_console((char*)buffer);
  write_in_console("\n");

  uint64_to_string((uint64_t)&memory_map,buffer);
  write_in_console("Memory map location: 0x");
  write_in_console((char*)buffer);
  write_in_console("\n");

  memcpy(memory_map,parsed_e820_table.e820_entry,parsed_e820_table.num_entries * sizeof(struct e820_entry));
  write_in_console("Parsing e820 table finished.Memory map was initialized.\n");
  
  write_in_console("Start setting up page table.\n");
  uint64_t page_table = get_usable(KERNEL_PAGING_SIZE,memory_map,parsed_e820_table.num_entries);
  kframe_allocator_init_pt(page_table,KERNEL_PAGING_SIZE);
  memset((uint64_t*)page_table,0x0,KERNEL_PAGING_SIZE);
  init_pagetable();
  write_in_console("Setting up page table finished.\n");
  uint64_to_string((uint64_t)&memory_map,buffer);
  write_in_console("Memory map location: 0x");
  write_in_console((char*)buffer);
  write_in_console("\n");
  
  write_in_console("Start setting up heap.\n");
  uint64_t heap = get_usable(HEAP_SIZE,memory_map,parsed_e820_table.num_entries);
  init_allocator((void*) ( heap | KERNEL_BASE_OFFSET), HEAP_SIZE);

  write_in_console("Start setting up dma.\n");
  uint64_t dma = get_usable(DMA_SIZE,memory_map,parsed_e820_table.num_entries);
  set_shared_bit((uint64_t*)(dma | KERNEL_BASE_OFFSET),DMA_SIZE);
  tdvmcall_mapgpa(true,dma,DMA_SIZE);
  init_allocator_shared((void*)( dma | KERNEL_BASE_OFFSET), DMA_SIZE);

  write_in_console("Start setting gdt.\n");
  gdt = (struct gdt_entry *)(get_usable(PAGE_SIZE,memory_map,parsed_e820_table.num_entries)|KERNEL_BASE_OFFSET);
  tss = (struct tss *)(get_usable(PAGE_SIZE,memory_map,parsed_e820_table.num_entries)|KERNEL_BASE_OFFSET);
  memset((uint64_t*)gdt,0x0,PAGE_SIZE);
  memset((uint64_t*)tss,0x0,PAGE_SIZE);
  init_gdt(gdt,tss);

  write_in_console("Start setting idt.\n");
  idt = (struct idt_entry*)(get_usable(PAGE_SIZE,memory_map,parsed_e820_table.num_entries)|KERNEL_BASE_OFFSET);
  memset(idt,0x0,PAGE_SIZE);
  idt_init(idt);
  write_in_console("Start enabling apic interrupt.\n");
  enable_apic_interrupt();

  write_in_console("Start setting up stack and jump to new stack.\n");
  //stack initialization
  uint64_t stack = get_usable(STACK_SIZE,memory_map,parsed_e820_table.num_entries)|KERNEL_BASE_OFFSET;
  uint64_t stack_top = stack + STACK_SIZE;

  asm("mov rsp, %0"::"r"(stack_top));
  struct argv_struct{
    char *argv[2];
    char buffer[30];
  };
  struct argv_struct argvs;
  memset(argvs.buffer,0x0,sizeof(argvs.buffer));
  char * string = "./orw.elf\0./test_output";
  memcpy(argvs.buffer,string,24);
  argvs.argv[0] = argvs.buffer;
  argvs.argv[1] = &argvs.buffer[11];
  switch_user(2, argvs.argv);
  return 0;
}