#define _GNU_SOURCE
#include <fcntl.h>
#include <linux/kvm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <errno.h>
#include "debug.h"
#include "definition.h"
#include "hypercall.h"


#define MSR_IA32_APICBASE  0x1b
#define X2APIC 21
#define XAPIC_ENABLE 10
#define X2APIC_ENABLE 11
#define MSR_IA32_APICBASE_BSP 8
#define APIC_DEFAULT_ADDRESS 0xfee00000
#define PS_LIMIT (0x200000)
#define KERNEL_STACK_SIZE (0x4000)
/*
 * setup_paging() and init_pagetable() in kernel/mm/translate.c uses 5 pages in total
 */
#define PAGE_TABLE_SIZE (0x5000)
#define MAX_KERNEL_SIZE (PS_LIMIT - PAGE_TABLE_SIZE - KERNEL_STACK_SIZE)
#define MEM_SIZE (PS_LIMIT * 0x2)
#define BIT(nr)			(UL(1) << (nr))



void read_file(const char *filename, uint8_t** content_ptr, size_t* size_ptr) {
  FILE *f = fopen(filename, "rb");
  if(f == NULL) error("Open file '%s' failed.\n", filename);
  if(fseek(f, 0, SEEK_END) < 0) pexit("fseek(SEEK_END)");

  size_t size = ftell(f);
  if(size == 0) error("Empty file '%s'.\n", filename);
  if(fseek(f, 0, SEEK_SET) < 0) pexit("fseek(SEEK_SET)");

  uint8_t *content = (uint8_t*) malloc(size);
  if(content == NULL) error("read_file: Cannot allocate memory\n");
  if(fread(content, 1, size, f) != size) error("read_file: Unexpected EOF\n");

  fclose(f);
  *content_ptr = content;
  *size_ptr = size;
}

/* set rip = entry point
 * set rsp = PS_LIMIT (the max address can be used)
 *
 * set rdi = PS_LIMIT (start of free (unpaging) physical pages)
 * set rsi = MEM_SIZE - rdi (total length of free pages)
 * Kernel could use rdi and rsi to initialize its memory allocator.
 */
void setup_regs(VM *vm, size_t entry) {
  struct kvm_regs regs;
  if(ioctl(vm->vcpufd, KVM_GET_REGS, &regs) < 0) pexit("ioctl(KVM_GET_REGS)");
  regs.rip = entry;
  regs.rsp = PS_LIMIT; /* temporary stack */
  regs.rdi = PS_LIMIT; /* start of free pages */
  regs.rsi = MEM_SIZE - regs.rdi; /* total length of free pages */
  regs.rflags = 0x2;
  if(ioctl(vm->vcpufd, KVM_SET_REGS, &regs) < 0) pexit("ioctl(KVM_SET_REGS");
}

/* Maps:
 * 0 ~ 0x200000 -> 0 ~ 0x200000 with kernel privilege
 */
void setup_paging(VM *vm) {
  struct kvm_sregs sregs;
  if(ioctl(vm->vcpufd, KVM_GET_SREGS, &sregs) < 0) pexit("ioctl(KVM_GET_SREGS)");
  uint64_t pml4_addr = MAX_KERNEL_SIZE;
  uint64_t *pml4 = (void*) (vm->mem + pml4_addr);

  uint64_t pdp_addr = pml4_addr + 0x1000;
  uint64_t *pdp = (void*) (vm->mem + pdp_addr);

  uint64_t pd_addr = pdp_addr + 0x1000;
  uint64_t *pd = (void*) (vm->mem + pd_addr);

  pml4[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pdp_addr;
  pdp[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pd_addr;
  pd[0] = PDE64_PRESENT | PDE64_RW | PDE64_PS; /* kernel only, no PED64_USER */

  sregs.cr3 = pml4_addr;
  sregs.cr4 = CR4_PAE;
  sregs.cr4 |= CR4_OSFXSR | CR4_OSXMMEXCPT; /* enable SSE instruction */
  sregs.cr0 = CR0_PE | CR0_MP | CR0_ET | CR0_NE | CR0_WP | CR0_AM | CR0_PG;
  sregs.efer = EFER_LME | EFER_LMA;
  sregs.efer |= EFER_SCE; /* enable syscall instruction */

  if(ioctl(vm->vcpufd, KVM_SET_SREGS, &sregs) < 0) pexit("ioctl(KVM_SET_SREGS)");
}

void setup_seg_regs(VM *vm) {
  struct kvm_sregs sregs;
  if(ioctl(vm->vcpufd, KVM_GET_SREGS, &sregs) < 0) pexit("ioctl(KVM_GET_SREGS)");
  struct kvm_segment seg = {
    .base = 0,
    .limit = 0xffffffff,
    .selector = 1 << 3,
    .present = 1,
    .type = 0xb, /* Code segment */
    .dpl = 0, /* Kernel: level 0 */
    .db = 0,
    .s = 1,
    .l = 1, /* long mode */
    .g = 1
  };
  sregs.cs = seg;
  seg.type = 0x3; /* Data segment */
  seg.selector = 2 << 3;
  sregs.ds = sregs.es = sregs.fs = sregs.gs = sregs.ss = seg;
  if(ioctl(vm->vcpufd, KVM_SET_SREGS, &sregs) < 0) pexit("ioctl(KVM_SET_SREGS)");
}

/*
 * Switching to long mode usually done by kernel.
 * We put the task in hypervisor because we want our KVM be able to execute
 * normal x86-64 assembled code as well. Which let us easier to debug and test.
 *
 */
void setup_long_mode(VM *vm) {
  setup_paging(vm);
  setup_seg_regs(vm);
}


VM* kvm_init(uint8_t code[], size_t len) {
  struct kvm_tdx_capabilities *caps;
  int kvmfd = open("/dev/kvm", O_RDWR | O_CLOEXEC);
  if(kvmfd < 0) pexit("open(/dev/kvm)");

  //Check which vm type in KVM is supported, now first bit is legacy vm, second bit is protected vm
  int tdx_is_supported = ioctl(kvmfd, KVM_CHECK_EXTENSION, KVM_CAP_VM_TYPES);
  if(!(tdx_is_supported& BIT(KVM_X86_PROTECTED_VM))) pexit("Protected VM is not supported in kvm");

  //Check KVM version
  int api_ver = ioctl(kvmfd, KVM_GET_API_VERSION, 0);
	if(api_ver < 0) pexit("KVM_GET_API_VERSION");
  if(api_ver != KVM_API_VERSION) {
    error("Got KVM api version %d, expected %d\n",
      api_ver, KVM_API_VERSION);
  }

  //Create VM
  int vmfd = ioctl(kvmfd, KVM_CREATE_VM, 0);
  if(vmfd < 0) pexit("ioctl(KVM_CREATE_VM)");
  //Query if TDX is supported on the platform
  if(get_tdx_capabilities(vmfd,caps) < 0) pexit("Get TDX capabilities failed");
  //Set kvm max vcpu
  if(set_kvm_max_vcpu(vmfd, KVM_CAP_MAX_VCPUS) < 0) pexit("Set max vcpus failed");
  //Set TSC frequency
  int frequency;
  if(iotctl(vmfd, KVM_SET_TSC_KHZ, frequency) < 0) pexit("Set TSC freqeuncy failed");
  //Initialize TDX VM,attributes,mrconfigid,mrowner,mrownerconfig,cpuid should be initialized here.
  //For cpuid, should use caps to mask the unconfigurable cpuid to keep local cpuid settings same with TDX Module inside.
  struct kvm_tdx_init_vm vm_paras;
  //todo initialization
  if(initialize_tdx_vm(vmfd,&vm_paras) < 0) pexit("Initialize TDX VM failed");

  //Create vcpu
  //Assume there is only one vcpu
  int vcpufd = ioctl(vmfd, KVM_CREATE_VCPU, 0);
  if(vcpufd < 0) pexit("ioctl(KVM_CREATE_VCPU)");
  //Pass TDX specific VCPU parameters, the TD HOB address, TD HOB should be created below TDVF
  __u64 vcpu_rcx ;
  if(tdx_vcpu_init(vcpufd, vcpu_rcx)<0) pexit("TDX vcpu initialized failed");
  // Enable CPUID[0x1].ECX.X2APIC(bit 21)=1 so that the following setting of MSR_IA32_APIC_BASE success.
  if(enalbe_x2apic(vcpufd)<0) pexit("Enable x2apic in set kvm cpuid failed");
  //Set the initial reset value of MSR_IA32_APIC
  struct kvm_msrs *msrs = (struct kvm_msrs *) malloc(sizeof(struct kvm_msrs)+sizeof(struct kvm_msr_entry));
  msrs->nmsrs=1;
  msrs->pad=0;
  msrs->entries->index=MSR_IA32_APICBASE;//MSR_IA32_APICBASE is in header msr-index.h, not in usr/include,hould add a own difiniction header or define directly
  msrs->entries->data = APIC_DEFAULT_ADDRESS| BIT(XAPIC_ENABLE)| BIT(X2APIC_ENABLE);   //MSR_IA32_APICBASE_BSP can be add optionally
  msrs->entries->reserved=0;
  if(ioctl(vcpufd,KVM_SET_MSRS,msrs)<0) pexit("Set apic base failed");
  free(msrs);

  //Initializing guest memory
  //TDVF should be copy to the memory,allocate memory for TDVF
  //BVF,CVF
  void *mem = mmap(NULL,
    MEM_SIZE,
    PROT_READ | PROT_WRITE,
    MAP_SHARED | MAP_ANONYMOUS,
    -1, 0);
  if(mem == NULL) pexit("mmap(MEM_SIZE)");
  size_t entry = 0;
  memcpy((void*) mem + entry, code, len);
  struct kvm_userspace_memory_region region = {
    .slot = 0,
    .flags = 0,
    .guest_phys_addr = 0,
    .memory_size = MEM_SIZE,
    .userspace_addr = (size_t) mem
  };
  if(ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, &region) < 0) {
    pexit("ioctl(KVM_SET_USER_MEMORY_REGION)");
  }
  //Encrypt a memory continuous region which corresponding to TDH.MEM.PAGE.ADD TDX SEAM call.
  //Should call several times to encrypt separate memory regions parsed from TDVF.
  if(encrypt_tdx_memory(vcpufd,mem,len) < 0) pexit("TDX memory initialization failed");
  //Finalize td
  if(finalize_td(vmfd)< 0) pexit("TDX finalization failed");

  size_t vcpu_mmap_size = ioctl(kvmfd, KVM_GET_VCPU_MMAP_SIZE, NULL);
  struct kvm_run *run = (struct kvm_run*) mmap(0,
    vcpu_mmap_size,
    PROT_READ | PROT_WRITE,
    MAP_SHARED,
    vcpufd, 0);

  VM *vm = (VM*) malloc(sizeof(VM));
  *vm = (struct VM){
    .mem = mem,
    .mem_size = MEM_SIZE,
    .vcpufd = vcpufd,
    .run = run
  };

  //registers are set by TDX Module, long mode is switched in TDVF
  //setup_regs(vm, entry);
  //setup_long_mode(vm);

  return vm;
}

int check_iopl(VM *vm) {
  struct kvm_regs regs;
  struct kvm_sregs sregs;
  if(ioctl(vm->vcpufd, KVM_GET_REGS, &regs) < 0) pexit("ioctl(KVM_GET_REGS)");
  if(ioctl(vm->vcpufd, KVM_GET_SREGS, &sregs) < 0) pexit("ioctl(KVM_GET_SREGS)");
  return sregs.cs.dpl <= ((regs.rflags >> 12) & 3);
}

void execute(VM* vm) {
  while(1) {
    ioctl(vm->vcpufd, KVM_RUN, NULL);
    //dump_regs(vm->vcpufd);
    switch (vm->run->exit_reason) {
    case KVM_EXIT_HLT:
      fprintf(stderr, "KVM_EXIT_HLT\n");
      return;
    case KVM_EXIT_IO:
      if(!check_iopl(vm)) error("KVM_EXIT_SHUTDOWN\n");
      if(vm->run->io.port & HP_NR_MARK) {
        if(hp_handler(vm->run->io.port, vm) < 0) error("Hypercall failed\n");
      }
      else error("Unhandled I/O port: 0x%x\n", vm->run->io.port);
      break;
    case KVM_EXIT_FAIL_ENTRY:
      error("KVM_EXIT_FAIL_ENTRY: hardware_entry_failure_reason = 0x%llx\n",
        vm->run->fail_entry.hardware_entry_failure_reason);
    case KVM_EXIT_INTERNAL_ERROR:
      error("KVM_EXIT_INTERNAL_ERROR: suberror = 0x%x\n",
        vm->run->internal.suberror);
    case KVM_EXIT_SHUTDOWN:
      error("KVM_EXIT_SHUTDOWN\n");
    //handle tdx specific exit
    case KVM_EXIT_TDX:
    //todo
      tdx_handle_exit(vm->run->tdx);
    default:
      error("Unhandled reason: %d\n", vm->run->exit_reason);
    }
  }
}

/* copy argv onto kernel's stack */
void copy_argv(VM* vm, int argc, char *argv[]) {
  struct kvm_regs regs;
  if(ioctl(vm->vcpufd, KVM_GET_REGS, &regs) < 0) pexit("ioctl(KVM_GET_REGS)");
  char *sp = (char*)vm->mem + regs.rsp;
  char **copy = (char**) malloc(argc * sizeof(char*));
#define STACK_ALLOC(sp, len) ({ sp -= len; sp; })
  for(int i = argc - 1; i >= 0; i--) {
    int len = strlen(argv[i]) + 1;
    copy[i] = STACK_ALLOC(sp, len);
    memcpy(copy[i], argv[i], len);
  }
  sp = (char*) ((uint64_t) sp & -0x10);
  /* push argv */
  *(uint64_t*) STACK_ALLOC(sp, sizeof(char*)) = 0;
  for(int i = argc - 1; i >= 0; i--)
    *(uint64_t*) STACK_ALLOC(sp, sizeof(char*)) = copy[i] - (char*)vm->mem;
  /* push argc */
  *(uint64_t*) STACK_ALLOC(sp, sizeof(uint64_t)) = argc;
  free(copy);
#undef STACK_ALLOC
  regs.rsp = sp - (char*) vm->mem;
  if(ioctl(vm->vcpufd, KVM_SET_REGS, &regs) < 0) pexit("ioctl(KVM_SET_REGS)");
}

int main(int argc, char *argv[]) {
  if(argc < 3) {
    printf("Usage: %s kernel.bin user.elf [user_args...]\n", argv[0]);
    exit(EXIT_FAILURE);
  }
  uint8_t *code;
  size_t len;
  //Load TDVF here
  read_file(argv[1], &code, &len);
  /*if(len > MAX_KERNEL_SIZE)
    error("Kernel size exceeded, %p > MAX_KERNEL_SIZE(%p).\n",
      (void*) len,
      (void*) MAX_KERNEL_SIZE);*/
  VM* vm = kvm_init(code, len);
  copy_argv(vm, argc - 2, &argv[2]);
  execute(vm);
}

int get_tdx_capabilities(int vmfd,struct kvm_tdx_capabilities *caps){
  int r,nr_cpuid_configs;
  nr_cpuid_configs = 6;//Tdx first generation;
  struct kvm_tdx_cmd cmd;
  memset(&cmd,0x0,sizeof(cmd));
  cmd.id=KVM_TDX_CAPABILITIES;
  cmd.data = caps;
  do{
    int size = sizeof(struct kvm_tdx_capabilities) +
              nr_cpuid_configs * sizeof(struct kvm_tdx_cpuid_config);
    caps = (struct kvm_tdx_capabilities * )malloc(size);
    memset(caps,0x0,size);
    r = ioctl(vmfd,KVM_MEMORY_ENCRYPT_OP,cmd);
    caps->nr_cpuid_configs = nr_cpuid_configs;
    if(r == -E2BIG){
      free(caps);
      nr_cpuid_configs *= 2;
    }
  }while(r==-E2BIG);
  if(r) free(caps);
  return r;
}

int set_kvm_max_vcpu(int vmfd, int max_vcpu){
  struct kvm_enable_cap enabled_cap;
  memset(&enabled_cap,0x0,sizeof(enabled_cap));
  enabled_cap.cap=KVM_CAP_MAX_VCPUS;
  enabled_cap.args[0] = max_vcpu;
  int r =ioctl(vmfd,KVM_ENABLE_CAP,enabled_cap);
  return r;
}

int initialize_tdx_vm(int vmfd,struct kvm_tdx_init_vm *vm_paras){
  struct kvm_tdx_cmd cmd;
  memset(&cmd,0x0,sizeof(cmd));
  cmd.id = KVM_TDX_INIT_VM;
  cmd.data = vm_paras;
  int r = ioctl(vmfd,KVM_MEMORY_ENCRYPT_OP,cmd);
  return r;
}

int tdx_vcpu_init(int vcpufd, __u64 vcpu_rcx){
  struct kvm_tdx_cmd cmd;
  memset(&cmd,0x0,sizeof(cmd));
  cmd.id=KVM_TDX_INIT_VCPU;
  cmd.data = vcpu_rcx;
  int r = ioctl(vcpufd,KVM_MEMORY_ENCRYPT_OP,cmd);
  return r;
}

//should be written in asm to get host cpuid and update it based on caps, todo
struct kvm_cpuid2 get_tdx_cpuid(){
  struct kvm_cpuid2 cpuid;
  return cpuid;
}

int enalbe_x2apic(int vcpufd){
  struct kvm_cpuid2 cpuid = get_tdx_cpuid();
  cpuid.entries[0x1].ecx |= BIT(X2APIC);
  int r = ioctl(vcpufd, KVM_SET_CPUID2, cpuid);
  return r;
}


//todo, gpa should parsed from metadata of tdvf
int encrypt_tdx_memory(int vcpufd, void* mem,int len){
  struct kvm_tdx_init_mem_region mem_region = {
            .source_addr = (__u64)mem,
            .gpa = 0,
            .nr_pages = (__u64)len / 4096,
        };
  struct kvm_tdx_cmd cmd;
  memset(&cmd,0x0,sizeof(cmd));
  cmd.id=KVM_TDX_INIT_VCPU;
  cmd.data = &mem_region;
  cmd.flags = KVM_TDX_MEASURE_MEMORY_REGION;
  int r = ioctl(vcpufd,KVM_MEMORY_ENCRYPT_OP,cmd);
  return r;
}

int finalize_td(int vmfd){
  struct kvm_tdx_cmd cmd;
  memset(&cmd,0x0,sizeof(cmd));
  cmd.id=KVM_TDX_FINALIZE_VM;
  int r = ioctl(vmfd,KVM_MEMORY_ENCRYPT_OP,cmd);
  return r;
}