#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include "definition.h"
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <elf.h>
#include "sev_snp.h"
#include "definition.h"
#include "hypercall.h"

#define ALIGN_DOWN(n, m) ((n) / (m) * (m))
#define ALIGN_UP(n, m) ALIGN_DOWN((n) + (m) - 1, (m))
#define KERNEL_ADDRESS 0x7DDDE000 //same position as tdx
#define KERNEL_SIZE 0x2222000     //kernel+ram =2gb

#define QEMU_MAP_READONLY   (1 << 0)
#define QEMU_MAP_SHARED     (1 << 1)
#define QEMU_MAP_SYNC       (1 << 2)
#define QEMU_MAP_NORESERVE  (1 << 3)
#define BIOS_SIZE (0x1000000)
#define PAGE_SIZE (0x1000)
#define RAM_SIZE (0x80000000)

#define MAKE_64BIT_MASK(shift, length) \
    (((~0ULL) >> (64 - (length))) << (shift))

#define GHCB_MSR_INFO_POS           0
#define GHCB_MSR_INFO_MASK          MAKE_64BIT_MASK(GHCB_MSR_INFO_POS, 12)

#define GHCB_MSR_PSC_GFN_POS        12
#define GHCB_MSR_PSC_GFN_MASK       MAKE_64BIT_MASK(GHCB_MSR_PSC_GFN_POS, 39)
#define GHCB_MSR_PSC_ERROR_POS      32
#define GHCB_MSR_PSC_ERROR_MASK     MAKE_64BIT_MASK(GHCB_MSR_PSC_ERROR_POS, 32)
#define GHCB_MSR_PSC_ERROR          GHCB_MSR_PSC_ERROR_MASK /* all error bits set */
#define GHCB_MSR_PSC_OP_POS         52
#define GHCB_MSR_PSC_OP_MASK        MAKE_64BIT_MASK(GHCB_MSR_PSC_OP_POS, 4)
#define GHCB_MSR_PSC_OP_PRIVATE     1
#define GHCB_MSR_PSC_OP_SHARED      2
#define GHCB_MSR_GPA_REQ            0X12
#define GHCB_MSR_GPA_RESP           0X13
#define GHCB_MSR_PSC_REQ            0x14
#define GHCB_MSR_PSC_RESP           0x15


#define error_report(fmt, ...) do { \
  fprintf(stderr, fmt, ##__VA_ARGS__); \
} while(0)

#define warn_report(fmt, ...) do { \
  fprintf(stderr, fmt, ##__VA_ARGS__); \
} while(0)

typedef uint64_t hwaddr;
struct ghcb *ghcb;

int kvm_vm_enable_cap(int fd,unsigned int cap, unsigned long long arg0){
  struct kvm_enable_cap enabled_cap;
  memset(&enabled_cap, 0x0, sizeof(enabled_cap));
  enabled_cap.cap = cap;
  enabled_cap.args[0] = arg0;
  int r = ioctl(fd, KVM_ENABLE_CAP, &enabled_cap);
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
    if (r) {
        warn_report("%s: failed to set memory attr (0x%lx+%#zx) error '%s'",
                     __func__, start, size, strerror(errno));
    }
    return r;
}


int kvm_convert_memory(int vmfd,hwaddr start, hwaddr size, bool shared_to_private){
  int ret = -1;
  hwaddr offset = start;
  ret = kvm_encrypt_reg_region(vmfd, offset,size, shared_to_private);
  return ret;
}


int get_supported_cpuid(int kvmfd,struct kvm_cpuid2 **cpuid)
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

void fill_cpuid_page(struct kvm_cpuid2 *supported_cpuid,void *cpuid_page){
  SnpCpuidInfo* cpuid_info = (SnpCpuidInfo *)cpuid_page;
  int i;
  for (i = 0; i < supported_cpuid->nent; i++) {
        const struct kvm_cpuid_entry2 *kvm_cpuid_entry;
        SnpCpuidFunc *snp_cpuid_entry;

        kvm_cpuid_entry = &supported_cpuid->entries[i];
        snp_cpuid_entry = &cpuid_info->entries[i];

        snp_cpuid_entry->eax_in = kvm_cpuid_entry->function;
        if (kvm_cpuid_entry->flags == KVM_CPUID_FLAG_SIGNIFCANT_INDEX) {
            snp_cpuid_entry->ecx_in = kvm_cpuid_entry->index;
        }
        snp_cpuid_entry->eax = kvm_cpuid_entry->eax;
        snp_cpuid_entry->ebx = kvm_cpuid_entry->ebx;
        snp_cpuid_entry->ecx = kvm_cpuid_entry->ecx;
        snp_cpuid_entry->edx = kvm_cpuid_entry->edx;

        /*
         * Guest kernels will calculate EBX themselves using the 0xD
         * subfunctions corresponding to the individual XSAVE areas, so only
         * encode the base XSAVE size in the initial leaves, corresponding
         * to the initial XCR0=1 state.
         */
        if (snp_cpuid_entry->eax_in == 0xD &&
            (snp_cpuid_entry->ecx_in == 0x0 || snp_cpuid_entry->ecx_in == 0x1)) {
            snp_cpuid_entry->ebx = 0x240;
            snp_cpuid_entry->xcr0_in = 1;
            snp_cpuid_entry->xss_in = 0;
        }
    }

    cpuid_info->count = i;
}

int sev_ioctl(int fd, int vmfd, int cmd, void *data, int *error)
{
    int r;
    struct kvm_sev_cmd input;

    memset(&input, 0x0, sizeof(input));

    input.id = cmd;
    input.sev_fd = fd;
    input.data = (__u64)(unsigned long)data;

    r = ioctl(vmfd, KVM_MEMORY_ENCRYPT_OP, &input);

    if (error) {
        *error = input.error;
    }

    return r;
}

int snp_update_memory(int sevfd,int vmfd, struct kvm_userspace_memory_region2* memory_region,int page_type){
  int ret=0;
  struct kvm_sev_snp_launch_update * update = (struct kvm_sev_snp_launch_update*)malloc(sizeof(struct kvm_sev_snp_launch_update));
  memset(update,0x0,sizeof(struct kvm_sev_snp_launch_update));
  update->start_gfn = memory_region->guest_phys_addr/0x1000;
  update->uaddr = memory_region->userspace_addr;
  update->len = memory_region->memory_size;
  update->page_type = page_type;
  int error = 0;
  ret = sev_ioctl(sevfd,vmfd,KVM_SEV_SNP_LAUNCH_UPDATE,(void*)update,&error);
  if(ret < 0 &&page_type!=0x6){
    pexit("KVM_SEV_SNP_LAUNCH_UPDATE failed");
  }
  if(ret==0){
    ret =kvm_convert_memory(vmfd,memory_region->guest_phys_addr,memory_region->memory_size,true);
  }
  return ret;
}

int snp_update_kernel(int sevfd,int vmfd, struct kvm_userspace_memory_region2* memory_region,int page_type){
  int ret=0;
  struct kvm_sev_snp_launch_update * update = (struct kvm_sev_snp_launch_update*)malloc(sizeof(struct kvm_sev_snp_launch_update));
  memset(update,0x0,sizeof(struct kvm_sev_snp_launch_update));
  update->start_gfn = KERNEL_ADDRESS/0x1000;
  update->uaddr = memory_region->userspace_addr+KERNEL_ADDRESS;
  update->len = KERNEL_SIZE;
  update->page_type = page_type;
  int error = 0;
  if(sev_ioctl(sevfd,vmfd,KVM_SEV_SNP_LAUNCH_UPDATE,(void*)update,&error)<0){
    pexit("KVM_SEV_SNP_LAUNCH_UPDATE kernel failed");
  }
  ret =kvm_convert_memory(vmfd,memory_region->guest_phys_addr,RAM_SIZE,true);
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

void read_file(const char *filename, uint8_t *content_ptr, size_t *size_ptr)
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

  if (fread(content_ptr, 1, size, f) != size)
    error("read_file: Unexpected EOF\n");

  fclose(f);
  *size_ptr = size;
}


static int kvm_handle_vmgexit_msr_protocol(VM *vm, __u64 *ghcb_msr)
{
    uint64_t op, gfn;
    int ret;
    switch (*ghcb_msr & GHCB_MSR_INFO_MASK)
    {
    case GHCB_MSR_PSC_REQ:
      op = (*ghcb_msr & GHCB_MSR_PSC_OP_MASK) >> GHCB_MSR_PSC_OP_POS;
      gfn = (*ghcb_msr & GHCB_MSR_PSC_GFN_MASK) >> GHCB_MSR_PSC_GFN_POS;
      *ghcb_msr = 0;

      ret = kvm_convert_memory(vm->vmfd,gfn << 12, 0x1000,
                              op == GHCB_MSR_PSC_OP_PRIVATE);

      if (ret) {
          *ghcb_msr |= GHCB_MSR_PSC_ERROR;
      }

      *ghcb_msr |= GHCB_MSR_PSC_RESP;

      return 0;
      break;
    
    /*case GHCB_MSR_GPA_REQ:
      gfn = (*ghcb_msr & GHCB_MSR_PSC_GFN_MASK) >> GHCB_MSR_PSC_GFN_POS;
      *ghcb_msr = 0;
      bool found = false;
      uint64_t ghcb_gpa = gfn<<12;
      for(int i = 0; i < vm->region_num; i++){
        if(vm->regions[i]->guest_phys_addr<ghcb_gpa && (vm->regions[i]->guest_phys_addr+vm->regions[i]->memory_size) > (ghcb_gpa+PAGE_SIZE)){
          ghcb = (struct ghcb *)(vm->regions[i]->userspace_addr+(ghcb_gpa-vm->regions[i]->guest_phys_addr));
          found = true;
          break;
        }
      }
      if(found){
        *ghcb_msr |= ghcb_gpa;
      }else{
        *ghcb_msr |=0xfffffffffffff<<12;
      }
      *ghcb_msr |= GHCB_MSR_GPA_RESP;
    */
    default:
      error("vmgexit (msr protocol), ghcb_msr: 0x%llx, invalid request",
                  *ghcb_msr);
      return -1;
      break;
    }
   
}

int handle_io_write(void * data,int size,uint32_t count){
  for(int i=0;i<count;i++){
    for(int j=0;j<size;j++){
      printf("%c",*(char*)(data+i*count+j));
    }
  }
  return 0;

};

uint64_t align_to_page(uint64_t value) {
    return (value + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1);
}

int kvm_handle_vmgexit(VM *vm, __u64 *ghcb_msr, __u64 *psc_ret)
{
    //hwaddr len = sizeof(struct ghcb);
    struct snp_psc_desc *desc;
    uint16_t cur_entry;
    int i;
    uint8_t shared_buf[GHCB_SHARED_BUF_SIZE];
    ghcb = (struct ghcb *)ghcb_msr;
    if (*ghcb_msr & GHCB_MSR_INFO_MASK) {
        return kvm_handle_vmgexit_msr_protocol(vm,ghcb_msr);
    }

    *psc_ret = 0;

    memcpy(shared_buf, ghcb->shared_buffer, GHCB_SHARED_BUF_SIZE);

    desc = (struct snp_psc_desc *)shared_buf;
    cur_entry = desc->hdr.cur_entry;

    for (i = cur_entry; i <= desc->hdr.end_entry; i++) {
        struct psc_entry *entry = &desc->entries[i];
        bool private;
        int ret;

        private = entry->operation == 1;

        ret = kvm_convert_memory(vm->vmfd, entry->gfn * 0x1000, entry->pagesize ? 0x200000 : 0x1000,
                                 private);
        if (ret) {
            *psc_ret = 0x100ULL << 32; /* Indicate interrupted processing */
            error("error doing memory conversion: %d", ret);
            break;
        }
        desc->hdr.cur_entry++;
    }

    /* TODO: what happens if ghcb tries to convert itself? */
    memcpy(ghcb->shared_buffer, shared_buf, GHCB_SHARED_BUF_SIZE);
    return 0;
}

VM *kvm_init(const char * bios_name, const char * kernel_name)
{
  int kvmfd = open("/dev/kvm", O_RDWR | O_CLOEXEC);
  if (kvmfd < 0)
    pexit("open(/dev/kvm)");

  int sevfd = open("/dev/sev", O_RDWR | O_CLOEXEC);
  if (sevfd < 0)
    pexit("open(/dev/sev)");

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

  // Create VM
  int vmfd = ioctl(kvmfd, KVM_CREATE_VM, 3);
  if (vmfd < 0)
    pexit("ioctl(KVM_CREATE_VM)");

  if(kvm_vm_enable_cap(vmfd,KVM_CAP_SPLIT_IRQCHIP,24) < 0){
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
  
  uint64_t data = 0;
  int error = 0;
  if(sev_ioctl(sevfd,vmfd,KVM_SEV_SNP_INIT,(void*)&data,&error)<0){
    pexit("KVM_SEV_SNP_INIT failed");
  };

  struct kvm_sev_snp_launch_start *snp_start = (struct kvm_sev_snp_launch_start *)malloc(sizeof(struct kvm_sev_snp_launch_start));
  memset(snp_start,0x0,sizeof(struct kvm_sev_snp_launch_start));
  snp_start->policy = 0x30133;

  if(sev_ioctl(sevfd,vmfd,KVM_SEV_SNP_LAUNCH_START,(void*)snp_start,&error)<0){
    pexit("KVM_SEV_SNP_LAUNCH_START failed");
  };
  free(snp_start);

  void *bios_ptr = ram_mmap(-1,BIOS_SIZE,0X1000,0,0);
  size_t bios_size = 0;
  read_file(bios_name,bios_ptr,&bios_size);
  Elf64_Ehdr *ehdr = (Elf64_Ehdr *)bios_ptr;
  uint16_t phnum = ehdr->e_phnum;

  int slot_num = 0;
  struct kvm_userspace_memory_region2 **regions = malloc(phnum*sizeof(uint64_t));
  struct kvm_cpuid2 *supported_cpuid;
  for(int i=0;i<phnum;i++){
    Elf64_Phdr *phdr = (Elf64_Phdr *)(bios_ptr+ehdr->e_phoff+i*sizeof(Elf64_Phdr));
    if(phdr->p_type==PT_LOAD){
      //register cpuid page
      if(phdr->p_flags&(1 << 23)){
        struct kvm_create_guest_memfd gmem;
        gmem.size = PAGE_SIZE;
        gmem.flags = 0;
        int gmemfd = ioctl(vmfd,KVM_CREATE_GUEST_MEMFD,&gmem);
        void *cpuid_page = ram_mmap(-1,PAGE_SIZE,0x1000,0,0);
        struct kvm_userspace_memory_region2 * mem_region_cpuid = malloc(sizeof(struct kvm_userspace_memory_region2));
        memset(mem_region_cpuid,0x0,sizeof(struct kvm_userspace_memory_region2));
        mem_region_cpuid->slot = slot_num;
        mem_region_cpuid->flags = KVM_MEM_PRIVATE;
        mem_region_cpuid->memory_size = PAGE_SIZE;
        mem_region_cpuid->guest_phys_addr = phdr->p_paddr;
        mem_region_cpuid->userspace_addr = (__u64)cpuid_page;
        mem_region_cpuid->gmem_fd = gmemfd;
        mem_region_cpuid->gmem_offset = 0;
        if(ioctl(vmfd,KVM_SET_USER_MEMORY_REGION2,mem_region_cpuid)<0){
          pexit("KVM_SET_USER_MEMORY_REGION2 cpuid page failed");
        };
        if(get_supported_cpuid(kvmfd,&supported_cpuid)<0){
          pexit("Get supported cpuid failed");
        };

        fill_cpuid_page(supported_cpuid,cpuid_page);

         //retry once if failed
        if(snp_update_memory(sevfd,vmfd,mem_region_cpuid,0x6)<0){
          if(snp_update_memory(sevfd,vmfd,mem_region_cpuid,0x6)<0){
            pexit("KVM_SEV_SNP_LAUNCH_UPDATE cpuid page failed");
          };
        };
        regions[slot_num++] = mem_region_cpuid;

      }else if(phdr->p_flags&(1 << 24)){
        struct kvm_create_guest_memfd gmem;
        gmem.size = PAGE_SIZE;
        gmem.flags = 0;
        int gmemfd = ioctl(vmfd,KVM_CREATE_GUEST_MEMFD,&gmem);
      //register secret page
        void *secret_page = ram_mmap(-1,PAGE_SIZE,0x1000,0,0);
        struct kvm_userspace_memory_region2 * mem_region_secret = malloc(sizeof(struct kvm_userspace_memory_region2));
        memset(mem_region_secret,0x0,sizeof(struct kvm_userspace_memory_region2));
        mem_region_secret->slot = slot_num;
        mem_region_secret->flags = KVM_MEM_PRIVATE;
        mem_region_secret->memory_size = PAGE_SIZE;
        mem_region_secret->guest_phys_addr = phdr->p_paddr;
        mem_region_secret->userspace_addr = (__u64)secret_page;
        mem_region_secret->gmem_fd = gmemfd;
        mem_region_secret->gmem_offset = 0;
        if(ioctl(vmfd,KVM_SET_USER_MEMORY_REGION2,mem_region_secret)<0){
          pexit("KVM_SET_USER_MEMORY_REGION2 secret page failed");
        };

        if(snp_update_memory(sevfd,vmfd,mem_region_secret,0x5)<0){
            pexit("KVM_SEV_SNP_LAUNCH_UPDATE secret page failed");
        };
        regions[slot_num++] = mem_region_secret;

      }else{
        //register other sections
        struct kvm_create_guest_memfd gmem;
        gmem.size = align_to_page(phdr->p_memsz);
        gmem.flags = 0;
        int gmemfd = ioctl(vmfd,KVM_CREATE_GUEST_MEMFD,&gmem);
        void *mem_region = ram_mmap(-1,phdr->p_memsz,0x1000,0,0);
        memcpy(mem_region,bios_ptr+phdr->p_offset,phdr->p_filesz);
        struct kvm_userspace_memory_region2 * mem_region_normal = malloc(sizeof(struct kvm_userspace_memory_region2));
        memset(mem_region_normal,0x0,sizeof(struct kvm_userspace_memory_region2));
        mem_region_normal->slot = slot_num;
        mem_region_normal->flags = KVM_MEM_PRIVATE;
        mem_region_normal->memory_size = align_to_page(phdr->p_memsz);
        mem_region_normal->guest_phys_addr = phdr->p_paddr;
        mem_region_normal->userspace_addr = (__u64)mem_region;
        mem_region_normal->gmem_fd = gmemfd;
        mem_region_normal->gmem_offset = 0;
        if(ioctl(vmfd,KVM_SET_USER_MEMORY_REGION2,mem_region_normal)<0){
        pexit("KVM_SET_USER_MEMORY_REGION2 normal failed");
        };
        if(snp_update_memory(sevfd,vmfd,mem_region_normal,0x1)<0){
            pexit("KVM_SEV_SNP_LAUNCH_UPDATE normal failed");
        };
        regions[slot_num++] = mem_region_normal;

      }
      
    }

  }

  //register ram
  void *ram_ptr = ram_mmap(-1,RAM_SIZE,0X1000,0,0);

  //read kernel
  void *kernel_ptr = (void *)(ram_ptr+KERNEL_ADDRESS);
  size_t kernel_size = 0;
  read_file(kernel_name,kernel_ptr,&kernel_size);

  struct kvm_create_guest_memfd ram_gmem;
  ram_gmem.size = RAM_SIZE;
  ram_gmem.flags = 0;
  int ram_gmemfd = ioctl(vmfd,KVM_CREATE_GUEST_MEMFD,&ram_gmem);
  struct kvm_userspace_memory_region2 * mem_region_ram = malloc(sizeof(struct kvm_userspace_memory_region2));
  memset(mem_region_ram,0x0,sizeof(struct kvm_userspace_memory_region2));
  mem_region_ram->slot = slot_num;
  mem_region_ram->flags = KVM_MEM_PRIVATE;
  mem_region_ram->memory_size = RAM_SIZE;
  mem_region_ram->guest_phys_addr = 0x0;
  mem_region_ram->userspace_addr = (__u64)ram_ptr;
  mem_region_ram->gmem_fd = ram_gmemfd;
  mem_region_ram->gmem_offset = 0;
  if(ioctl(vmfd,KVM_SET_USER_MEMORY_REGION2,mem_region_ram)<0){
    pexit("KVM_SET_USER_MEMORY_REGION2 ram failed");
  };
  regions[slot_num++] = mem_region_ram;
  
  //update kernel
  if(snp_update_kernel(sevfd,vmfd,mem_region_ram,0x1)<0){
      pexit("KVM_SEV_SNP_LAUNCH_UPDATE kernel failed");
  };

  // Create vcpu
  // Assume there is only one vcpu
  int vcpufd = ioctl(vmfd, KVM_CREATE_VCPU, 0);
  if (vcpufd < 0)
    pexit("ioctl(KVM_CREATE_VCPU)");

  if(ioctl(vcpufd,KVM_SET_CPUID2,supported_cpuid)<0){
    pexit("KVM_SET_CPUID2 failed");
  };

  struct kvm_sev_snp_launch_finish * snp_finish= (struct kvm_sev_snp_launch_finish *)malloc(sizeof(struct kvm_sev_snp_launch_finish));
  memset(snp_finish,0x0,sizeof(struct kvm_sev_snp_launch_finish));
  if(sev_ioctl(sevfd,vmfd,KVM_SEV_SNP_LAUNCH_FINISH,(void*)snp_finish,&error)<0){
    pexit("KVM_SEV_SNP_LAUNCH_FINISH failed");
  }

  size_t vcpu_mmap_size = ioctl(kvmfd, KVM_GET_VCPU_MMAP_SIZE, NULL);
  struct kvm_run *run = (struct kvm_run *)mmap(0,
                                               vcpu_mmap_size,
                                               PROT_READ | PROT_WRITE,
                                               MAP_SHARED,
                                               vcpufd, 0);

  VM *vm = (VM *)malloc(sizeof(VM));
  *vm = (struct VM){
      .mem = ram_ptr,
      .mem_size = RAM_SIZE,
      .vcpufd = vcpufd,
      .vmfd = vmfd,
      .region_num = slot_num,
      .run = run
      };
  vm->regions = regions;

  return vm;
}

void execute(VM *vm)
{
  int ret, run_ret;
  do{
    ret = -1;
    vm->run->exit_reason=0;
    run_ret=ioctl(vm->vcpufd, KVM_RUN, NULL);


    if (run_ret < 0) {
      fprintf(stderr, "error: kvm run failed %s\n", strerror(-run_ret));
      break;
    }

    switch (vm->run->exit_reason)
    {
    case KVM_EXIT_HLT:
      fprintf(stderr, "KVM_EXIT_HLT\n");
      break;
    case KVM_EXIT_IO:
      switch (vm->run->io.port)
      {
      case 0x3f8:
        if(vm->run->io.direction){
          ret = handle_io_write((uint8_t *)vm->run + vm->run->io.data_offset,
                              vm->run->io.size,
                              vm->run->io.count);
        }
        if(ret<0){
          pexit("IO write failed.\n");
        }
        break;
      default:
        if(vm->run->io.port & HP_NR_MARK) {
          if(hp_handler(vm->run->io.port, vm) < 0){
            error("Hypercall failed\n");
          }
          ret = 0; 
        }else {
          error("Unhandled I/O port: 0x%x\n", vm->run->io.port);
        }
        break;
      }
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
    // handle eev specific exit
    case KVM_EXIT_VMGEXIT:
      ret = kvm_handle_vmgexit(vm,&vm->run->vmgexit.ghcb_msr, &vm->run->vmgexit.ret);
      break;
    case KVM_EXIT_MEMORY_FAULT:{
      hwaddr start = vm->run->memory.gpa;
      hwaddr size = vm->run->memory.size;
      bool private = vm->run->memory.flags & KVM_MEMORY_EXIT_FLAG_PRIVATE;
      ret = kvm_convert_memory(vm->vmfd,start,size,private);
      break;
    }
    default:
      error("Unhandled reason: %d\n", vm->run->exit_reason);
      break;
    }
  }while (ret == 0);

  
}



int main(int argc, char *argv[])
{

  if (argc < 3)
  {
    printf("Usage: %s bios.bin kernel.bin\n", argv[0]);
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