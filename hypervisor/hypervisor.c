#define _GNU_SOURCE
#define TDHOB
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
#include "tdvf-hob.h"
#include <glib.h>
#include "pc_sysfw_ovmf.h"
#include "e820_memory_layout.h"
#include "cpuid.c"
#include <sys/eventfd.h>

#define MSR_IA32_APICBASE 0x1b
#define X2APIC 21
#define XAPIC_ENABLE 10
#define X2APIC_ENABLE 11
#define MSR_IA32_APICBASE_BSP 8
#define MSR_IA32_UCODE_REV              0x8b
#define APIC_DEFAULT_ADDRESS 0xfee00000
#define PS_LIMIT (0x200000)
#define KERNEL_STACK_SIZE (0x4000)
#define PAGE_ALIGN(address) ((__u64)address)%4096==0?((__u64)address):((((__u64)address)/4096)+1)*4096
#define MSR_IA32_MISC_ENABLE 0x1a0
#define MSR_KVM_POLL_CONTROL 0x4b564d05
#define MSR_IA32_TSC_DEADLINE		0x000006E0
#define TDG_VP_VMCALL_SUCCESS           0x0000000000000000ULL
#define TDG_VP_VMCALL_RETRY             0x0000000000000001ULL
#define TDG_VP_VMCALL_INVALID_OPERAND   0x8000000000000000ULL
#define TDG_VP_VMCALL_ALIGN_ERROR       0x8000000000000002ULL

#define TDG_VP_VMCALL_MAP_GPA 0x10001ULL
#define TDG_VP_VMCALL_GET_QUOTE 0x10002ULL
#define TDG_VP_VMCALL_REPORT_FATAL_ERROR 0x10003ULL
#define TDG_VP_VMCALL_SETUP_EVENT_NOTIFY_INTERRUPT 0x10004ULL
/*
 * setup_paging() and init_pagetable() in kernel/mm/translate.c uses 5 pages in total
 */
#define PAGE_TABLE_SIZE (0x5000)
#define MAX_KERNEL_SIZE (PS_LIMIT - PAGE_TABLE_SIZE - KERNEL_STACK_SIZE)
#define MEM_SIZE 0x80000000 
#define BIT(nr) (0x1UL << (nr))

#define __X32_SYSCALL_BIT	0x40000000
#define __NR_memfd_restricted 451

#define ALIGN_DOWN(n, m) ((n) / (m) * (m))
#define ALIGN_UP(n, m) ALIGN_DOWN((n) + (m) - 1, (m))

#define QEMU_MAP_READONLY   (1 << 0)
#define QEMU_MAP_SHARED     (1 << 1)
#define QEMU_MAP_SYNC       (1 << 2)
#define QEMU_MAP_NORESERVE  (1 << 3)

static TdxGuest *tdx_guest;
static struct kvm_tdx_capabilities *tdx_caps;
void read_file(const char *filename, uint8_t **content_ptr, size_t *size_ptr)
{
  FILE *f = fopen(filename, "rb");
  if (f == NULL)
    error("Open file '%s' failed.\n", filename);
  if (fseek(f, 0, SEEK_END) < 0)
    pexit("fseek(SEEK_END)");

  size_t size = ftell(f);
  if (size == 0)
    error("Empty file '%s'.\n", filename);
  if (fseek(f, 0, SEEK_SET) < 0)
    pexit("fseek(SEEK_SET)");

  uint8_t *content = (uint8_t *)malloc(size);
  if (content == NULL)
    error("read_file: Cannot allocate memory\n");
  if (fread(content, 1, size, f) != size)
    error("read_file: Unexpected EOF\n");

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
void setup_regs(VM *vm, size_t entry)
{
  struct kvm_regs regs;
  if (ioctl(vm->vcpufd, KVM_GET_REGS, &regs) < 0)
    pexit("ioctl(KVM_GET_REGS)");
  regs.rip = entry;
  regs.rsp = PS_LIMIT;            /* temporary stack */
  regs.rdi = PS_LIMIT;            /* start of free pages */
  regs.rsi = MEM_SIZE - regs.rdi; /* total length of free pages */
  regs.rflags = 0x2;
  if (ioctl(vm->vcpufd, KVM_SET_REGS, &regs) < 0)
    pexit("ioctl(KVM_SET_REGS");
}

/* Maps:
 * 0 ~ 0x200000 -> 0 ~ 0x200000 with kernel privilege
 */
void setup_paging(VM *vm)
{
  struct kvm_sregs sregs;
  if (ioctl(vm->vcpufd, KVM_GET_SREGS, &sregs) < 0)
    pexit("ioctl(KVM_GET_SREGS)");
  uint64_t pml4_addr = MAX_KERNEL_SIZE;
  uint64_t *pml4 = (void *)(vm->mem + pml4_addr);

  uint64_t pdp_addr = pml4_addr + 0x1000;
  uint64_t *pdp = (void *)(vm->mem + pdp_addr);

  uint64_t pd_addr = pdp_addr + 0x1000;
  uint64_t *pd = (void *)(vm->mem + pd_addr);

  pml4[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pdp_addr;
  pdp[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pd_addr;
  pd[0] = PDE64_PRESENT | PDE64_RW | PDE64_PS; /* kernel only, no PED64_USER */

  sregs.cr3 = pml4_addr;
  sregs.cr4 = CR4_PAE;
  sregs.cr4 |= CR4_OSFXSR | CR4_OSXMMEXCPT; /* enable SSE instruction */
  sregs.cr0 = CR0_PE | CR0_MP | CR0_ET | CR0_NE | CR0_WP | CR0_AM | CR0_PG;
  sregs.efer = EFER_LME | EFER_LMA;
  sregs.efer |= EFER_SCE; /* enable syscall instruction */

  if (ioctl(vm->vcpufd, KVM_SET_SREGS, &sregs) < 0)
    pexit("ioctl(KVM_SET_SREGS)");
}

void setup_seg_regs(VM *vm)
{
  struct kvm_sregs sregs;
  if (ioctl(vm->vcpufd, KVM_GET_SREGS, &sregs) < 0)
    pexit("ioctl(KVM_GET_SREGS)");
  struct kvm_segment seg = {
      .base = 0,
      .limit = 0xffffffff,
      .selector = 1 << 3,
      .present = 1,
      .type = 0xb, /* Code segment */
      .dpl = 0,    /* Kernel: level 0 */
      .db = 0,
      .s = 1,
      .l = 1, /* long mode */
      .g = 1};
  sregs.cs = seg;
  seg.type = 0x3; /* Data segment */
  seg.selector = 2 << 3;
  sregs.ds = sregs.es = sregs.fs = sregs.gs = sregs.ss = seg;
  if (ioctl(vm->vcpufd, KVM_SET_SREGS, &sregs) < 0)
    pexit("ioctl(KVM_SET_SREGS)");
}

/*
 * Switching to long mode usually done by kernel.
 * We put the task in hypervisor because we want our KVM be able to execute
 * normal x86-64 assembled code as well. Which let us easier to debug and test.
 *
 */
void setup_long_mode(VM *vm)
{
  setup_paging(vm);
  setup_seg_regs(vm);
}
int64_t get_image_size(const char *filename)
{
    int fd;
    int64_t size;
    fd = open(filename, O_RDONLY | 0);
    if (fd < 0)
        return -1;
    size = lseek(fd, 0, SEEK_END);
    close(fd);
    return size;
}
ssize_t load_image_size(const char *filename, void *addr, size_t size)
{
    int fd;
    ssize_t actsize, l = 0;

    fd = open(filename, O_RDONLY | 0);
    if (fd < 0) {
        return -1;
    }

    while ((actsize = read(fd, addr + l, size - l)) > 0) {
        l += actsize;
    }

    close(fd);

    return actsize < 0 ? -1 : l;
}

int get_tdx_capabilities(int vmfd)
{ 
  struct kvm_tdx_capabilities *caps;
  int r, nr_cpuid_configs;
  nr_cpuid_configs = 6; // Tdx first generation;
  struct kvm_tdx_cmd cmd;
  memset(&cmd, 0x0, sizeof(cmd));
  cmd.id = KVM_TDX_CAPABILITIES;
  
  do
  {
    int size = sizeof(struct kvm_tdx_capabilities) +
               nr_cpuid_configs * sizeof(struct kvm_tdx_cpuid_config);
    caps = (struct kvm_tdx_capabilities *)malloc(size);
    memset(caps, 0x0, size);
    cmd.data = (__u64)caps;
    caps->nr_cpuid_configs = nr_cpuid_configs;
    r = ioctl(vmfd, KVM_MEMORY_ENCRYPT_OP, &cmd);
    if( r == -1){
        r = -errno;
    }
    if (r == -E2BIG)
    {
      free(caps);
      nr_cpuid_configs *= 2;
    }
  } while (r == -E2BIG);
  if (r)
    free(caps);
  tdx_caps = caps;
  return r;
}

int set_kvm_max_vcpu(int vmfd, int max_vcpu)
{
  struct kvm_enable_cap enabled_cap;
  memset(&enabled_cap, 0x0, sizeof(enabled_cap));
  enabled_cap.cap = KVM_CAP_MAX_VCPUS;
  enabled_cap.args[0] = max_vcpu;
  int r = ioctl(vmfd, KVM_ENABLE_CAP, &enabled_cap);
  return r;
}

int initialize_tdx_vm(int vmfd, struct kvm_tdx_init_vm *vm_paras)
{
  struct kvm_tdx_cmd cmd;
  memset(&cmd, 0x0, sizeof(cmd));
  cmd.id = KVM_TDX_INIT_VM;
  cmd.data = (__u64)vm_paras;
  int r = ioctl(vmfd, KVM_MEMORY_ENCRYPT_OP, &cmd);
  return r;
}

int kvm_vm_enable_cap(int fd,unsigned int cap, unsigned long long arg0){
  struct kvm_enable_cap enabled_cap;
  memset(&enabled_cap, 0x0, sizeof(enabled_cap));
  enabled_cap.cap = cap;
  enabled_cap.args[0] = arg0;
  int r = ioctl(fd, KVM_ENABLE_CAP, &enabled_cap);
  return r;
}

int tdx_vcpu_init(int vcpufd, __u64 vcpu_rcx)
{
  struct kvm_tdx_cmd cmd;
  memset(&cmd, 0x0, sizeof(cmd));
  cmd.id = KVM_TDX_INIT_VCPU;
  cmd.data = vcpu_rcx;
  int r = ioctl(vcpufd, KVM_MEMORY_ENCRYPT_OP, &cmd);
  return r;
}


int get_tdx_cpuid(int kvmfd,struct kvm_cpuid2 **cpuid)
{
  struct kvm_cpuid2 *cpuid_try;
  int number = 1;
  int r;
  do{
    cpuid_try = (struct kvm_cpuid2 *)malloc(sizeof(struct kvm_cpuid2)+sizeof(struct kvm_cpuid_entry2)*number);
    cpuid_try->nent = number;
    r = ioctl(kvmfd,KVM_GET_SUPPORTED_CPUID,cpuid_try);
    if(r < 0){
        r = -errno;
        if(r == -E2BIG){
            free(cpuid_try);
            number *=2;
        }
        else if(r == -ENOMEM){
            free(cpuid_try);
            number -= 10;
        }
        else{
            free(cpuid_try);
            return -1;
        }
    }
  }while(r < 0);
  *cpuid = cpuid_try;
  return 0;
}

int enable_x2apic(int vcpufd, int kvmfd)
{
  struct kvm_cpuid2 *cpuid;
  int r = get_tdx_cpuid(kvmfd, &cpuid);
  if(r < 0){
    pexit("Get supported CPUID failed");
  }
  cpuid->entries[0x1].ecx |= BIT(X2APIC);
  r = ioctl(vcpufd, KVM_SET_CPUID2, cpuid);
  printf("nent: %d\n",cpuid->nent);
  free(cpuid);
  return r;
}


int kvm_encrypt_reg_region(int vmfd, hwaddr start, hwaddr size, bool reg_region)
{
    int r;
    struct kvm_memory_attributes  attr;
    attr.attributes = reg_region ? KVM_MEMORY_ATTRIBUTE_PRIVATE : 0;

    attr.address = start;
    attr.size = size;
    attr.flags = 0;

    r = ioctl(vmfd, KVM_SET_MEMORY_ATTRIBUTES, &attr);
    if (r || attr.size != 0) {
        warn_report("%s: failed to set memory attr (0x%lx+%#zx) error '%s'",
                     __func__, start, size, strerror(errno));
    }
    return r;
}

int encrypt_tdx_memory(int vmfd, void *mem_region, int flag)
{
  
  struct kvm_tdx_cmd cmd;
  memset(&cmd, 0x0, sizeof(cmd));
  cmd.id = KVM_TDX_INIT_MEM_REGION;
  cmd.data = (__u64)mem_region;
  cmd.flags = flag;
  int r = ioctl(vmfd, KVM_MEMORY_ENCRYPT_OP, &cmd);
  return r;
}

int finalize_td(int vmfd)
{
  struct kvm_tdx_cmd cmd;
  memset(&cmd, 0x0, sizeof(cmd));
  cmd.id = KVM_TDX_FINALIZE_VM;
  int r = ioctl(vmfd, KVM_MEMORY_ENCRYPT_OP, &cmd);
  return r;
}

memory_region find_memory_region(VM *vm, hwaddr start, hwaddr size){
  memory_region mr1 = vm->regions[0];
  memory_region mr2 = vm->regions[1];
  if(start>= mr1.kvm_mr->region.guest_phys_addr&&(start+size<=mr1.kvm_mr->region.guest_phys_addr+mr1.kvm_mr->region.memory_size)){
    return mr1;
  }else{
    return mr2;
  }
}

static int memory_region_discard_range_fd(memory_region mr, uint64_t start,
                                      size_t length, int fd)

{
    int ret = -1;

    uint8_t *host_startaddr = (uint8_t *)(mr.kvm_mr->region.userspace_addr + start);

    if (!((uintptr_t)host_startaddr%0x1000==0)) {
        error_report("%s: Unaligned start address: %p",
                     __func__, host_startaddr);
        goto err;
    }

    if ((start + length) <= mr.kvm_mr->region.userspace_addr+mr.kvm_mr->region.memory_size) {
        bool need_madvise, need_fallocate;
        if (!(length%0x1000==0)) {
            error_report("%s: Unaligned length: %zx", __func__, length);
            goto err;
        }

        errno = ENOTSUP; /* If we are missing MADVISE etc */

        /* The logic here is messy;
         *    madvise DONTNEED fails for hugepages
         *    fallocate works on hugepages and shmem
         *    shared anonymous memory requires madvise REMOVE
         */
        //need_madvise =  (mr.fd == fd);
        need_fallocate = fd != -1;
        if (need_fallocate) {
            /* For a file, this causes the area of the file to be zero'd
             * if read, and for hugetlbfs also causes it to be unmapped
             * so a userfault will trigger.
             */

            ret = fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
                            start, length);
            if (ret) {
                ret = -errno;
                error_report("%s: Failed to fallocate:%lx +%zx (%d)",
                             __func__, start, length, ret);
                goto err;
            }

        }
        /*if (need_madvise) {
            ret = madvise(host_startaddr, length, MADV_DONTNEED);
            
            if (ret) {
                ret = -errno;
                error_report("%s: Failed to discard range "
                             ":%lx +%zx (%d)",
                             __func__, start, length, ret);
                goto err;
            }
        }*/
    } else {
        error_report("%s: Overrun block,start:%lu,length:%lu,memory_size:%llu", __func__,start,length,mr.kvm_mr->region.memory_size);
    }

err:
    return ret;
}

static int kvm_set_ioeventfd_pio(int vmfd,int fd, uint16_t addr, uint16_t val,
                                 bool assign, uint32_t size, bool datamatch)
{
    struct kvm_ioeventfd kick = {
        .datamatch = datamatch ? val : 0,
        .addr = addr,
        .flags = KVM_IOEVENTFD_FLAG_PIO,
        .len = size,
        .fd = fd,
    };
    int r;
    if (datamatch) {
        kick.flags |= KVM_IOEVENTFD_FLAG_DATAMATCH;
    }
    if (!assign) {
        kick.flags |= KVM_IOEVENTFD_FLAG_DEASSIGN;
    }
    r = ioctl(vmfd,KVM_IOEVENTFD,&kick);
    if (r < 0) {
        return r;
    }
    return 0;
}

int memory_region_convert_range(memory_region mr, uint64_t start, size_t length, bool shared_to_private)
{
    int fd, ret;
    if ( mr.kvm_mr->restricted_fd <= 0) {
        return -1;
    }

    if (!(start%0x1000==0) || !(length%0x1000==0)) {
        return -1;
    }
    if (mr.fd < 0){
      return -1;
    }
    if (shared_to_private) {
        fd = mr.fd;
    } else {
        fd = mr.kvm_mr->restricted_fd;
    }

    ret = memory_region_discard_range_fd(mr, start, length, fd);

    return ret;
}

int kvm_convert_memory(VM *vm,hwaddr start, hwaddr size, bool shared_to_private){
  int ret = -1;
  int offset = start;
  ret = kvm_encrypt_reg_region(vm->vmfd, offset,size, shared_to_private);
  memory_region mr =find_memory_region(vm, offset, size);
  if(memory_region_convert_range(mr,offset,size,shared_to_private)<0){
        pexit("memory_region_convert_range error");
      };
  return ret;
}
int tdx_handle_get_quote(struct kvm_tdx_vmcall *vmcall, VM *vm){
  return 0;
}
int tdx_handle_report_fatal_error(struct kvm_tdx_vmcall *vmcall, VM *vm){
  return 0;
}
int tdx_handle_setup_event_notify_interrupt(struct kvm_tdx_vmcall *vmcall, VM *vm){
  return 0;
}
static int tdx_handle_map_gpa(struct kvm_tdx_vmcall *vmcall,VM *vm)
{
    hwaddr addr_mask = (1ULL << 52) - 1;
    hwaddr shared_bit = 1ULL << 51;
    hwaddr gpa = vmcall->in_r12 & ~shared_bit;
    bool private = !(vmcall->in_r12 & shared_bit);
    hwaddr size = vmcall->in_r13;
    int ret = 0;

    vmcall->status_code = TDG_VP_VMCALL_INVALID_OPERAND;

    if (gpa & ~addr_mask) {
        return ret;
    }
    if (!(gpa%4096==0) || !(size%4096==0)) {
        vmcall->status_code = TDG_VP_VMCALL_ALIGN_ERROR;
        return ret;
    }

    if (size > 0) {
      
      ret = kvm_convert_memory(vm, gpa, size, private);
    }

    if (!ret) {
        vmcall->status_code = TDG_VP_VMCALL_SUCCESS;
    }
    return ret;
}



int tdx_handle_vmcall(VM *vm, struct kvm_tdx_vmcall *vmcall)
{ 
  int ret = -1;
  vmcall->status_code = TDG_VP_VMCALL_INVALID_OPERAND;
  if (vmcall->type != 0)
  {
    warn_report("unknown tdg.vp.vmcall type 0x%llx subfunction 0x%llx\n",
                vmcall->type, vmcall->subfunction);
    return ret;
  }
  
  switch (vmcall->subfunction)
  {
  case TDG_VP_VMCALL_MAP_GPA:
    ret = tdx_handle_map_gpa(vmcall, vm);
    break;
  case TDG_VP_VMCALL_GET_QUOTE:
    tdx_handle_get_quote(vmcall, vm);
    printf("Get Quote\n");
    break;
  case TDG_VP_VMCALL_REPORT_FATAL_ERROR:
    tdx_handle_report_fatal_error(vmcall, vm);
    printf("Fatal Error\n");
    break;
  case TDG_VP_VMCALL_SETUP_EVENT_NOTIFY_INTERRUPT:
    tdx_handle_setup_event_notify_interrupt(vmcall, vm);
    printf("Set event notify interrupt\n");
    break;
  default:
    warn_report("unknown tdg.vp.vmcall type 0x%llx subfunction 0x%llx\n",
                vmcall->type, vmcall->subfunction);
    printf("rcx 0x%llx,in_r12 0x%llx,in_r13 0x%llx,in_r14 0x%llx,in_r15 0x%llx,in_rbx 0x%llx,in_rdi 0x%llx,in_rsi 0x%llx,in_r8 0x%llx, in_r9 0x%llx,in_rdx 0x%llx", 
    vmcall->reg_mask, vmcall->in_r12, vmcall->in_r13, vmcall->in_r14,vmcall->in_r15, vmcall->in_rbx, vmcall->in_rdi,vmcall->in_rsi,vmcall->in_r8,vmcall->in_r9,vmcall->in_rdx);
    break;
  }
  return ret;
}

int tdx_handle_exit(VM *vm, struct kvm_tdx_exit *tdx_exit)
{   
    int ret=-1;
    switch (tdx_exit->type) {
    case KVM_EXIT_TDX_VMCALL:
        ret = tdx_handle_vmcall(vm, &tdx_exit->u.vmcall);
        break;
    default:
        warn_report("unknown tdx exit type 0x%x", tdx_exit->type);
        break;
    }
    return ret;
}

void * ram_mmap(int fd,
                    size_t size,
                    size_t align,
                    uint32_t qemu_map_flags,
                    off_t map_offset){
  size_t total = size+align;
  void *ram_try_ptr = mmap(0, total, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
  if(ram_try_ptr<0){
    pexit("ram_try_ptr mmap failed");
  }
  size_t offset = ALIGN_UP((uintptr_t)ram_try_ptr, align) - (uintptr_t)ram_try_ptr;
  const bool noreserve = qemu_map_flags & QEMU_MAP_NORESERVE;
  const bool readonly = qemu_map_flags & QEMU_MAP_READONLY;
  const bool shared = qemu_map_flags & QEMU_MAP_SHARED;
  const bool sync = qemu_map_flags & QEMU_MAP_SYNC;
  const int prot = PROT_READ | (readonly ? 0 : PROT_WRITE);
  int map_sync_flags = 0;
  int flags = MAP_FIXED;
  flags |= fd == -1 ? MAP_ANONYMOUS : 0;
  flags |= shared ? MAP_SHARED : MAP_PRIVATE;
  flags |= noreserve ? MAP_NORESERVE : 0;
  if (shared && sync) {
        map_sync_flags = MAP_SYNC | MAP_SHARED_VALIDATE;
    }
  void *ram_ptr = mmap(ram_try_ptr+offset,size, prot, flags|map_sync_flags,fd, map_offset);
  if (ram_ptr == NULL)
    pexit("mmap ram_ptr failed");
  if (offset > 0) {
        munmap(ram_try_ptr, offset);
    }
  total -= offset;
    if (total > size + align) {
        munmap(ram_ptr + size + align, total - size - align);
    }
    return ram_ptr;
}

static void tdx_init_ram_entries(void)
{
    unsigned i, j, nr_e820_entries;

    nr_e820_entries = e820_get_num_entries();
    tdx_guest->ram_entries = g_new(TdxRamEntry, nr_e820_entries);

    for (i = 0, j = 0; i < nr_e820_entries; i++) {
        uint64_t addr, len;

        if (e820_get_entry(i, E820_RAM, &addr, &len)) {
            tdx_guest->ram_entries[j].address = addr;
            tdx_guest->ram_entries[j].length = len;
            tdx_guest->ram_entries[j].type = TDX_RAM_UNACCEPTED;
            j++;
        }
    }
    tdx_guest->nr_ram_entries = j;
}

static TdxRamEntry *tdx_find_ram_range(uint64_t address, uint64_t length)
{
    TdxRamEntry *e;
    int i;

    for (i = 0; i < tdx_guest->nr_ram_entries; i++) {
        e = &tdx_guest->ram_entries[i];

        if (address + length <= e->address ||
            e->address + e->length <= address) {
                continue;
        }

        /*
         * The to-be-accepted ram range must be fully contained by one
         * RAM entry.
         */
        if (e->address > address ||
            e->address + e->length < address + length) {
            return NULL;
        }

        if (e->type == TDX_RAM_ADDED) {
            return NULL;
        }

        break;
    }

    if (i == tdx_guest->nr_ram_entries) {
        return NULL;
    }

    return e;
}

static void tdx_add_ram_entry(uint64_t address, uint64_t length, uint32_t type)
{
    uint32_t nr_entries = tdx_guest->nr_ram_entries;
    tdx_guest->ram_entries = g_renew(TdxRamEntry, tdx_guest->ram_entries,
                                     nr_entries + 1);

    tdx_guest->ram_entries[nr_entries].address = address;
    tdx_guest->ram_entries[nr_entries].length = length;
    tdx_guest->ram_entries[nr_entries].type = type;
    tdx_guest->nr_ram_entries++;
}

static int tdx_accept_ram_range(uint64_t address, uint64_t length)
{
    uint64_t head_start, tail_start, head_length, tail_length;
    uint64_t tmp_address, tmp_length;
    TdxRamEntry *e;

    e = tdx_find_ram_range(address, length);
    if (!e) {
        return -EINVAL;
    }

    tmp_address = e->address;
    tmp_length = e->length;

    e->address = address;
    e->length = length;
    e->type = TDX_RAM_ADDED;

    head_length = address - tmp_address;
    if (head_length > 0) {
        head_start = tmp_address;
        tdx_add_ram_entry(head_start, head_length, TDX_RAM_UNACCEPTED);
    }

    tail_start = address + length;
    if (tail_start < tmp_address + tmp_length) {
        tail_length = tmp_address + tmp_length - tail_start;
        tdx_add_ram_entry(tail_start, tail_length, TDX_RAM_UNACCEPTED);
    }

    return 0;
}


static int tdx_ram_entry_compare(const void *lhs_, const void* rhs_)
{
    const TdxRamEntry *lhs = lhs_;
    const TdxRamEntry *rhs = rhs_;

    if (lhs->address == rhs->address) {
        return 0;
    }
    if (le64_to_cpu(lhs->address) > le64_to_cpu(rhs->address)) {
        return 1;
    }
    return -1;
}

static TdxFirmwareEntry *tdx_get_hob_entry(TdxGuest *tdx)
{
    TdxFirmwareEntry *entry;

    for_each_tdx_fw_entry(&tdx->tdvf, entry) {
        if (entry->type == TDVF_SECTION_TYPE_TD_HOB) {
            return entry;
        }
    }
    error_report("TDVF metadata doesn't specify TD_HOB location.");
    exit(1);
}



void dump_caps(){
  printf("attrs fixed 0: %llu\n",tdx_caps->attrs_fixed0);
  printf("attrs fixed 1: %llu\n",tdx_caps->attrs_fixed1);
  printf("xfam fixed 0: %llu\n",tdx_caps->xfam_fixed0);
  printf("xfam fixed 1: %llu\n",tdx_caps->xfam_fixed1);
  printf("nr_cpuid_configs: %u\n",tdx_caps->nr_cpuid_configs);
  for(int i=0;i<tdx_caps->nr_cpuid_configs;i++){
    printf("page %d, cpuid:leaf %u subleaf %u eax %u ebx %u ecx %u edx %u \n",i,tdx_caps->cpuid_configs[i].leaf,
    tdx_caps->cpuid_configs[i].sub_leaf,tdx_caps->cpuid_configs[i].eax,tdx_caps->cpuid_configs[i].ebx,tdx_caps->cpuid_configs[i].ecx
    ,tdx_caps->cpuid_configs[i].edx);
  }
}

void dump_vm_paras(struct kvm_tdx_init_vm *vm_paras){
  printf("attributes: %llu\n",vm_paras->attributes);
  printf("mrconfigid: ");
  for(int i = 0; i < 6; i++){
    printf("%llu ",vm_paras->mrconfigid[i]);
  }
  printf("\n");
  printf("mrowner: ");
  for(int i = 0; i < 6; i++){
    printf("%llu ",vm_paras->mrowner[i]);
  }
  printf("\n");
  printf("mrownerconfig: ");
  for(int i = 0; i < 6; i++){
    printf("%llu ",vm_paras->mrownerconfig[i]);
  }
  printf("\n");
  for(int i=0;i<vm_paras->cpuid.nent;i++){
    printf("page %d, cpuid:leaf %u subleaf %u eax %u ebx %u ecx %u edx %u flag %d \n",i,vm_paras->cpuid.entries[i].function,
    vm_paras->cpuid.entries[i].index,vm_paras->cpuid.entries[i].eax,vm_paras->cpuid.entries[i].ebx,vm_paras->cpuid.entries[i].ecx
    ,vm_paras->cpuid.entries[i].edx,vm_paras->cpuid.entries[i].flags);
  }
}

int register_coalesced_mmio(int vmfd,__u64 addr, __u32 size, __u32 pio){
  struct kvm_coalesced_mmio_zone zone;
  zone.addr = addr;
  zone.size = size;
  zone.pio = pio;
  int ret = ioctl(vmfd,KVM_REGISTER_COALESCED_MMIO, &zone);
  return ret;
}





VM *kvm_init(const char * bios_name, const char* kernel_name )
{

  int kvmfd = open("/dev/kvm", O_RDWR | O_CLOEXEC);
  if (kvmfd < 0)
    pexit("open(/dev/kvm)");

  // Check which vm type in KVM is supported, now first bit is legacy vm, second bit is protected vm
  int tdx_is_supported = ioctl(kvmfd, KVM_CHECK_EXTENSION, KVM_CAP_VM_TYPES);
  printf("VM Type supported bitmap: %d \n",tdx_is_supported);
  if (!(tdx_is_supported & BIT(KVM_X86_TDX_VM)))
    pexit("Protected VM is not supported in kvm");

  // Check KVM version
  int api_ver = ioctl(kvmfd, KVM_GET_API_VERSION, 0);
  if (api_ver < 0)
    pexit("KVM_GET_API_VERSION");
  if (api_ver != KVM_API_VERSION)
  {
    error("Got KVM api version %d, expected %d\n",
          api_ver, KVM_API_VERSION);
  }
  printf("KVM version: %d\n", KVM_API_VERSION);

  
  if (get_tdx_capabilities(kvmfd) < 0)
    pexit("Get TDX capabilities failed");
  dump_caps();
  // Create VM
  int vmfd = ioctl(kvmfd, KVM_CREATE_VM, 1);
  if (vmfd < 0)
    pexit("ioctl(KVM_CREATE_VM)");
  // Query if TDX is supported on the platform
  // Set kvm max vcpu
  if (set_kvm_max_vcpu(vmfd, 1) < 0)
    pexit("Set max vcpus failed");
  int max_vcpu = ioctl(vmfd, KVM_CHECK_EXTENSION, KVM_CAP_MAX_VCPUS);
  if (max_vcpu<0){
    pexit("Check max vcpus failed");
  }
  printf("Max vcpus: %d \n",max_vcpu);

  //Set dirty log protect
  __u64 dirty_log_manual_caps = ioctl(kvmfd, KVM_CHECK_EXTENSION, KVM_CAP_MANUAL_DIRTY_LOG_PROTECT2);
  dirty_log_manual_caps &= (KVM_DIRTY_LOG_MANUAL_PROTECT_ENABLE | KVM_DIRTY_LOG_INITIALLY_SET);
  if(kvm_vm_enable_cap(vmfd, KVM_CAP_MANUAL_DIRTY_LOG_PROTECT2, dirty_log_manual_caps)<0)
    pexit("Enable dirty log manual failed");

  //enable KVM_CAP_EXCEPTION_PAYLOAD
  if(kvm_vm_enable_cap(vmfd, KVM_CAP_EXCEPTION_PAYLOAD, true)<0)
    pexit("Enable KVM_CAP_EXCEPTION_PAYLOAD failed");
  
  if(kvm_vm_enable_cap(vmfd, KVM_CAP_X86_TRIPLE_FAULT_EVENT, true)<0)
    pexit("Enable KVM_CAP_X86_TRIPLE_FAULT_EVENT failed");

  uint64_t notify_window_flags =
                KVM_X86_NOTIFY_VMEXIT_ENABLED |
                KVM_X86_NOTIFY_VMEXIT_USER;
  if(kvm_vm_enable_cap(vmfd, KVM_CAP_X86_NOTIFY_VMEXIT, notify_window_flags)<0)
    pexit("Enable KVM_CAP_X86_NOTIFY_VMEXIT failed");

  //Enable userspace MSR
  if(kvm_vm_enable_cap(vmfd,KVM_CAP_X86_USER_SPACE_MSR,KVM_MSR_EXIT_REASON_FILTER)<0)
    pexit("Enable KVM_CAP_X86_USER_SPACE_MSR failed");
  
  //msr handler filter 
  struct kvm_msr_filter *filter = malloc(sizeof(struct kvm_msr_filter));
  memset(filter, 0x0, sizeof(struct kvm_msr_filter));
  uint64_t zero = 0;
  filter->ranges[0].flags = KVM_MSR_FILTER_READ;
  filter->ranges[0].nmsrs = 1;
  filter->ranges[0].base = 0x35;
  filter->ranges[0].bitmap = (__u8 *)&zero;
  if(ioctl(vmfd, KVM_X86_SET_MSR_FILTER, filter)<0)
    pexit("KVM_X86_SET_MSR_FILTER failed");
  free(filter);
  //Enable irq split
  if (kvm_vm_enable_cap(vmfd,KVM_CAP_SPLIT_IRQCHIP,24) < 0){
    pexit("Enable irq split failed");
  };
  //Initiate irq routing
  struct kvm_irq_routing * irq_routing = malloc(sizeof(struct kvm_irq_routing)+24*sizeof(struct kvm_irq_routing_entry));
  memset(irq_routing,0x0,sizeof(struct kvm_irq_routing)+24*sizeof(struct kvm_irq_routing_entry));
  irq_routing->nr=24;
  for(int i=0;i<24;i++){
    irq_routing->entries[i].gsi=i;
    irq_routing->entries[i].type=2;
  }
  if(ioctl(vmfd, KVM_SET_GSI_ROUTING, irq_routing)<0){
    pexit("KVM_SET_GSI_ROUTING failed");
  }
  free(irq_routing);
  //assign and design ioeventfds
/*
  int ioeventfds[7];
  for (int i = 0; i < 7; i++) {
        ioeventfds[i] = eventfd(0, EFD_CLOEXEC);
        if (ioeventfds[i] < 0) {
            pexit("Create eventfd failed");
        }
        int ret = kvm_set_ioeventfd_pio(vmfd,ioeventfds[i], 0, i, true, 2, true);
        if (ret < 0) {
            close(ioeventfds[i]);
            break;
        }
    }
*/
  if (kvm_vm_enable_cap(vmfd,KVM_CAP_MAX_VCPU_ID,0x1)<0){
    pexit("Set max apic failed.");
   };

  if (kvm_vm_enable_cap(vmfd,KVM_CAP_MAX_VCPUS,0x1)<0){
    pexit("Set max cpus number failed.");
   };
  // Set TSC frequency, optional
  int frequency = 1000000; //1 GHZ
  if (ioctl(vmfd, KVM_SET_TSC_KHZ, frequency) < 0)
    pexit("Set TSC freqeuncy failed");
  // Initialize TDX VM,attributes,mrconfigid,mrowner,mrownerconfig,cpuid should be initialized here.
  // For cpuid, should use caps to mask the unconfigurable cpuid to keep local cpuid settings same with TDX Module inside.
  struct kvm_tdx_init_vm *vm_paras = (struct kvm_tdx_init_vm *)malloc(sizeof(struct kvm_tdx_init_vm));
  memset(vm_paras, 0x0, sizeof(struct kvm_tdx_init_vm));
  vm_paras->attributes=0x10000000;
  set_para_cpuid(vm_paras);

  dump_vm_paras(vm_paras);
  
  if (initialize_tdx_vm(vmfd, vm_paras) < 0){
    pexit("Initialize TDX VM failed");
  }  
  
  


  // Create vcpu
  // Assume there is only one vcpu
  int vcpufd = ioctl(vmfd, KVM_CREATE_VCPU, 0);
  if (vcpufd < 0)
    pexit("ioctl(KVM_CREATE_VCPU)");
  struct cpuid_data * cpuid_data = malloc(sizeof(struct cpuid_data));
  memset(cpuid_data, 0, sizeof(struct cpuid_data));
  initialize_cpuid2(cpuid_data,vm_paras);
  if(ioctl(vcpufd,KVM_SET_CPUID2,cpuid_data)<0){
    pexit("KVM_SET_CPUID2 failed");
  };
  free(vm_paras);

  struct kvm_msrs * msr = malloc(sizeof(struct kvm_msrs)+sizeof(struct kvm_msr_entry));
  msr->nmsrs=1;
  msr->pad=0;
  msr->entries[0].index = MSR_IA32_UCODE_REV;
  msr->entries[0].data = 0x2b00046100000000;
  msr->entries[0].reserved=0;

  if(ioctl(vcpufd,KVM_SET_MSRS,msr)<0){
    pexit("msr initialization failed");
  }
  free(msr);
  // TDVF should be copy to the memory,allocate memory for TDVF
  // BVF,CVF
  tdx_guest = g_new(TdxGuest,1);
  int ram_fd = memfd_create("backend_ram", MFD_CLOEXEC);
  if(ram_fd<0){
    pexit("ram_fd created failed");
  }
  int ram_fd_priv = syscall(__NR_memfd_restricted,0);
  if(ram_fd_priv<0){
    pexit("ram_fd_priv created failed");
  }
  if (ftruncate(ram_fd_priv, MEM_SIZE) == -1){
    pexit("ram_fd_priv truncate failed");
  }
  //allocate ram from fd
  void *ram_ptr = ram_mmap(ram_fd,MEM_SIZE,0X1000,QEMU_MAP_NORESERVE,0);
  struct kvm_userspace_memory_region_ext * mem_region_ram = malloc(sizeof(struct kvm_userspace_memory_region_ext));
  mem_region_ram->region.slot = 0;
  mem_region_ram->region.flags = KVM_MEM_PRIVATE;
  mem_region_ram->region.guest_phys_addr = 0;
  mem_region_ram->region.memory_size = MEM_SIZE;
  mem_region_ram->region.userspace_addr = (size_t)ram_ptr;
  mem_region_ram->restricted_fd=ram_fd_priv;
  mem_region_ram->restricted_offset=0;

  if (ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, mem_region_ram) < 0)
  {
    pexit("ioctl(KVM_SET_USER_MEMORY_REGION) ram failed");
  }

  e820_add_entry(0, MEM_SIZE, E820_RAM);
  int bios_size = get_image_size(bios_name);
  printf("BIOS size: %d\n",bios_size);
  int bios_fd_priv = syscall(__NR_memfd_restricted,0);
  if(bios_fd_priv<0){
    pexit("bios_fd_priv created failed");
  }
  if (ftruncate(bios_fd_priv, bios_size) == -1){
    pexit("bios_fd_priv truncate failed");
  }
  void *bios_ptr = ram_mmap(-1,bios_size,1,0,0);
  if (bios_ptr == NULL)
    pexit("mmap bios_ptr failed");
  struct kvm_userspace_memory_region_ext * mem_region_bios = malloc(sizeof(struct kvm_userspace_memory_region_ext));
  mem_region_bios->region.slot = 1;
  mem_region_bios->region.flags = KVM_MEM_PRIVATE;
  mem_region_bios->region.guest_phys_addr = 0xff000000;
  mem_region_bios->region.memory_size = bios_size;
  mem_region_bios->region.userspace_addr = (size_t)bios_ptr;
  mem_region_bios->restricted_fd=bios_fd_priv;
  mem_region_bios->restricted_offset=0;

  if (ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, mem_region_bios) < 0)
  {
    pexit("ioctl(KVM_SET_USER_MEMORY_REGION) ram failed");
  }
  register_coalesced_mmio(vmfd,0xcf8,0x1,0x1);
  register_coalesced_mmio(vmfd,0xcfa,0x2,0x1);
  register_coalesced_mmio(vmfd,0x70,0x1,0x1);

  struct kvm_msrs * msrs = malloc(sizeof(struct kvm_msrs)+3*sizeof(struct kvm_msr_entry));
  msrs->nmsrs=3;
  msrs->pad=0;
  msrs->entries[0].index = MSR_IA32_MISC_ENABLE;
  msrs->entries[0].data = 0x1;
  msrs->entries[0].reserved=0;

  msrs->entries[0].index = MSR_KVM_POLL_CONTROL;
  msrs->entries[0].data = 0x1;
  msrs->entries[0].reserved=0;

  msrs->entries[0].index = MSR_IA32_TSC_DEADLINE;
  msrs->entries[0].data = 0x0;
  msrs->entries[0].reserved=0;

  if(ioctl(vcpufd,KVM_SET_MSRS,msrs)<0){
    pexit("msrs setting failed");
  }
  free(msrs);
  load_image_size(bios_name,bios_ptr,bios_size);
  //parse tdvf and create td hob
  tdx_guest->tdvf = *g_new(TdxFirmware, 1);
  TdxFirmware *tdvf = &tdx_guest->tdvf;
  TdxFirmwareEntry *entry;    
  tdx_init_ram_entries();
  pc_system_parse_ovmf_flash(bios_ptr, bios_size);
  tdvf_parse_metadata(tdvf, bios_ptr, bios_size);
  //void *kernel_mem;
  for_each_tdx_fw_entry(tdvf, entry)
  {
    switch (entry->type)
    {
    case TDVF_SECTION_TYPE_BFV:
    case TDVF_SECTION_TYPE_CFV:
      entry->mem_ptr = tdvf->mem_ptr + entry->data_offset;
      break;
    case TDVF_SECTION_TYPE_TD_HOB:
    case TDVF_SECTION_TYPE_TEMP_MEM:
      entry->mem_ptr = ram_mmap(-1, entry->size,0X1000, 0, 0);
      tdx_accept_ram_range(entry->address, entry->size);
      break;
    case TDVF_SECTION_TYPE_PAYLOAD:
      break;
    case TDVF_SECTION_TYPE_PERM_MEM:

      break;
    case TDVF_SECTION_TYPE_PAYLOAD_PARAM:
      if (!tdx_find_ram_range(entry->address, entry->size)) {
                error_report("Failed to reserve ram for TDVF section %d",
                             entry->type);
                exit(1);
      }
      break;
      
    default:
      error_report("Unsupported TDVF section %d", entry->type);
      exit(1);
    }
  }

  qsort(tdx_guest->ram_entries, tdx_guest->nr_ram_entries,
          sizeof(TdxRamEntry), &tdx_ram_entry_compare);
  tdvf_hob_create(tdx_guest, tdx_get_hob_entry(tdx_guest));

  // Pass TDX specific VCPU parameters, the TD HOB address, TD HOB should be created below TDVF
  TdxFirmwareEntry *hob;
  hob = tdx_get_hob_entry(tdx_guest);
  if (tdx_vcpu_init(vcpufd, hob->address) < 0)
    pexit("TDX vcpu initialized failed");
  // Enable CPUID[0x1].ECX.X2APIC(bit 21)=1 so that the following setting of MSR_IA32_APIC_BASE success.
  if (enable_x2apic(vcpufd,kvmfd) < 0)
    pexit("Enable x2apic in set kvm cpuid failed");
  // Set the initial reset value of MSR_IA32_APIC
  struct kvm_msrs *msr_apic = (struct kvm_msrs *)malloc(sizeof(struct kvm_msrs) + sizeof(struct kvm_msr_entry));
  msr_apic->nmsrs = 1;
  msr_apic->pad = 0;
  msr_apic->entries[0].index = MSR_IA32_APICBASE;                                            // MSR_IA32_APICBASE is in header msr-index.h, not in usr/include,hould add a own difiniction header or define directly
  msr_apic->entries[0].data = APIC_DEFAULT_ADDRESS | BIT(XAPIC_ENABLE) | BIT(X2APIC_ENABLE)|BIT(MSR_IA32_APICBASE_BSP); // MSR_IA32_APICBASE_BSP can be add optionally
  msr_apic->entries[0].reserved = 0;
  if (ioctl(vcpufd, KVM_SET_MSRS, msr_apic) < 0)
    pexit("Set apic base failed");
  free(msr_apic);

  // Initializing guest memory
  //encrypt memory
  for_each_tdx_fw_entry(tdvf, entry) {
      struct kvm_tdx_init_mem_region mem_region = {
          .source_addr = (__u64)entry->mem_ptr,
          .gpa = entry->address,
          .nr_pages = entry->size / 4096,
      };
       //set kvm attribute to convert memory to private
      int r = kvm_encrypt_reg_region(vmfd,entry->address, entry->size, true);
      if (r < 0) {
            error_report("Reserve initial private memory failed %s", strerror(-r));
            exit(1);
      }
      if (entry->type == TDVF_SECTION_TYPE_PERM_MEM) {
            continue;
        }
      __u32 flags = entry->attributes & TDVF_SECTION_ATTRIBUTES_MR_EXTEND ?
                    KVM_TDX_MEASURE_MEMORY_REGION : 0;

      if (encrypt_tdx_memory(vmfd, &mem_region, flags) < 0)
      pexit("TDX memory initialization failed");


  }


  // Finalize td
  if (finalize_td(vmfd) < 0)
    pexit("TDX finalization failed");

  size_t vcpu_mmap_size = ioctl(kvmfd, KVM_GET_VCPU_MMAP_SIZE, NULL);
  struct kvm_run *run = (struct kvm_run *)mmap(0,
                                               vcpu_mmap_size,
                                               PROT_READ | PROT_WRITE,
                                               MAP_SHARED,
                                               vcpufd, 0);

  VM *vm = (VM *)malloc(sizeof(VM)+10*sizeof(memory_region));
  *vm = (struct VM){
      .mem = ram_ptr,
      .mem_size = MEM_SIZE,
      .vcpufd = vcpufd,
      .vmfd = vmfd,
      .run = run
      };
  vm->regions[0].kvm_mr = mem_region_ram;
  vm->regions[0].fd = ram_fd;
  vm->regions[1].kvm_mr = mem_region_bios;
  vm->regions[1].fd = -1;
  // registers are set by TDX Module, long mode is switched in TDVF
  // setup_regs(vm, entry);
  // setup_long_mode(vm);

  return vm;
}

int check_iopl(VM *vm)
{
  struct kvm_regs regs;
  struct kvm_sregs sregs;
  if (ioctl(vm->vcpufd, KVM_GET_REGS, &regs) < 0)
    pexit("ioctl(KVM_GET_REGS)");
  if (ioctl(vm->vcpufd, KVM_GET_SREGS, &sregs) < 0)
    pexit("ioctl(KVM_GET_SREGS)");
  return sregs.cs.dpl <= ((regs.rflags >> 12) & 3);
}

void execute(VM *vm)
{
  int ret, run_ret;
  vm->run->ready_for_interrupt_injection = 0;
  do{
    ret = -1;
    run_ret=ioctl(vm->vcpufd, KVM_RUN, NULL);


    if (run_ret < 0) {
      fprintf(stderr, "error: kvm run failed %s\n", strerror(-run_ret));
      break;
    }
    struct kvm_lapic_state kapic;
    if(ioctl(vm->vcpufd,KVM_GET_LAPIC,&kapic)<0){
      pexit("Get lapic failed");
    }
    for(int i=0;i<KVM_APIC_REG_SIZE;i++){
      printf("index: %d, reg_value:%c",i,kapic.regs[i]);
    }

    // dump_regs(vm->vcpufd);
    switch (vm->run->exit_reason)
    {
    case KVM_EXIT_HLT:
      fprintf(stderr, "KVM_EXIT_HLT\n");
      break;
    case KVM_EXIT_IO:
      pexit("vmexit io\n");
      if (!check_iopl(vm))
        error("KVM_EXIT_SHUTDOWN\n");
      if (vm->run->io.port & HP_NR_MARK)
      {
        if (hp_handler(vm->run->io.port, vm) < 0)
          error("Hypercall failed\n");
      }
      else
        error("Unhandled I/O port: 0x%x\n", vm->run->io.port);
      break;
    case KVM_EXIT_FAIL_ENTRY:
      error("KVM_EXIT_FAIL_ENTRY: hardware_entry_failure_reason = 0x%llx\n",
            vm->run->fail_entry.hardware_entry_failure_reason);
      break;
    case KVM_EXIT_INTERNAL_ERROR:
      error("KVM_EXIT_INTERNAL_ERROR: suberror = 0x%x\n",
            vm->run->internal.suberror);
      break;
    case KVM_EXIT_SHUTDOWN:
      error("KVM_EXIT_SHUTDOWN\n");
      break;
    // handle tdx specific exit
    case KVM_EXIT_TDX:
      ret = tdx_handle_exit(vm, &vm->run->tdx);
      break;
    case KVM_EXIT_MEMORY_FAULT:
      hwaddr start = vm->run->memory.gpa;
      hwaddr size = vm->run->memory.size;
      bool private = vm->run->memory.flags & KVM_MEMORY_EXIT_FLAG_PRIVATE;
      ret = kvm_convert_memory(vm,start,size,private);
      
      break;
    default:
      error("Unhandled reason: %d\n", vm->run->exit_reason);
      break;
    }
  }while (ret == 0);

  
}

/* copy argv onto kernel's stack */
void copy_argv(VM *vm, int argc, char *argv[])
{
  struct kvm_regs regs;
  if (ioctl(vm->vcpufd, KVM_GET_REGS, &regs) < 0)
    pexit("ioctl(KVM_GET_REGS)");
  char *sp = (char *)vm->mem + regs.rsp;
  char **copy = (char **)malloc(argc * sizeof(char *));
#define STACK_ALLOC(sp, len) ({ sp -= len; sp; })
  for (int i = argc - 1; i >= 0; i--)
  {
    int len = strlen(argv[i]) + 1;
    copy[i] = STACK_ALLOC(sp, len);
    memcpy(copy[i], argv[i], len);
  }
  sp = (char *)((uint64_t)sp & -0x10);
  /* push argv */
  *(uint64_t *)STACK_ALLOC(sp, sizeof(char *)) = 0;
  for (int i = argc - 1; i >= 0; i--)
    *(uint64_t *)STACK_ALLOC(sp, sizeof(char *)) = copy[i] - (char *)vm->mem;
  /* push argc */
  *(uint64_t *)STACK_ALLOC(sp, sizeof(uint64_t)) = argc;
  free(copy);
#undef STACK_ALLOC
  regs.rsp = sp - (char *)vm->mem;
  if (ioctl(vm->vcpufd, KVM_SET_REGS, &regs) < 0)
    pexit("ioctl(KVM_SET_REGS)");
}

int main(int argc, char *argv[])
{

  if (argc < 3)
  {
    printf("Usage: %s kernel.bin user.elf [user_args...]\n", argv[0]);
    exit(EXIT_FAILURE);
  }
  // Load TDVF here

  /*if(len > MAX_KERNEL_SIZE)
    error("Kernel size exceeded, %p > MAX_KERNEL_SIZE(%p).\n",
      (void*) len,
      (void*) MAX_KERNEL_SIZE);*/
  VM *vm = kvm_init(argv[1],argv[2]);
  //copy_argv(vm, argc - 2, &argv[2]);
  execute(vm);
}

