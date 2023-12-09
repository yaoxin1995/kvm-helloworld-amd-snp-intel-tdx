#include <mm/kmalloc.h>
#include <mm/translate.h>
#include <utils/panic.h>
#include <mm/kframe.h>
#include <utils/string.h>
#include <utils/tdx.h>
/* Maps
 *  0 ~ 0x800000 -> 0 ~ 0x800000 with kernel privilege
 *  0x7DDDE000 ~ 0x80000000 -> 0x7DDDE000 ~ 0x80000000 bios related stack etc. 
 *  0xff000000 ~ 0xffffffff -> 0xff000000 ~ 0xffffffff bios
 *  0x8000000000 ~ 0x8080000000 -> 0 ~ 0x80000000 ram
 */
void init_pagetable() {
  uint64_t* pml4 = (uint64_t*)kframe_allocate_range_pt(1);
  uint64_t* pdp0 = (uint64_t*)kframe_allocate_range_pt(1);
  uint64_t* pdp1 = (uint64_t*)kframe_allocate_range_pt(1);
  uint64_t* pd0_0 = (uint64_t*)kframe_allocate_range_pt(1);
  uint64_t* pd0_1 = (uint64_t*)kframe_allocate_range_pt(1);
  uint64_t* pd0_3 = (uint64_t*)kframe_allocate_range_pt(1);
  uint64_t* pd1_0 = (uint64_t*)kframe_allocate_range_pt(1);
  uint64_t* pd1_1 = (uint64_t*)kframe_allocate_range_pt(1);
  unsigned char buffer[20] = {0};

  uint64_t cr4;
  asm volatile ("mov %[cr4], cr4 ":[cr4]"=r"(cr4));
  uint64_to_string(cr4,buffer);
  write_in_console("cr4: 0x");
  write_in_console((char*)buffer);
  write_in_console("\n");
  
  uint64_t efer_msr;
  efer_msr = tdvmcall_rdmsr(IA32_EFER);
  uint64_to_string(efer_msr,buffer);
  write_in_console("efer_msr: 0x");
  write_in_console((char*)buffer);
  write_in_console("\n");

  //0 ~ 0x800000 -> 0 ~ 0x800000 with kernel privilege for page table
  pml4[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER |(uint64_t) pdp0;
  pdp0[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER |(uint64_t) pd0_0;
  for(uint64_t i = 0; i < 4; i++){
    uint64_t* pt = (uint64_t*)kframe_allocate_range_pt(1);
    pd0_0[i] = PDE64_PRESENT | PDE64_RW |(uint64_t) pt;
    for(uint64_t j = 0; j < 0x200; j++){
      pt[j] = PDE64_PRESENT | PDE64_RW | (i * PT_MAPPING_SIZE + j * PAGE_SIZE);
    }
  }
  //0x7DDDE000~0x80000000 ->0x7DDDE000~0x80000000 bios related stack etc. 
  uint64_t* pt_temp = (uint64_t*)kframe_allocate_range_pt(1);
  pdp0[1] = PDE64_PRESENT | PDE64_RW | PDE64_USER |(uint64_t) pd0_1;
  pd0_1[0x1ee] = PDE64_PRESENT | PDE64_RW |(uint64_t) pt_temp;
  for(int i=0x1de;i<0x200;i++){
    pt_temp[i] = PDE64_PRESENT | PDE64_RW | (0x1ee * PT_MAPPING_SIZE+0x40000000 + i * PAGE_SIZE);
  }
  for(uint64_t i= 0x1ef;i<0x200;i++){
    uint64_t* pt = (uint64_t*)kframe_allocate_range_pt(1);
    pd0_1[i] = PDE64_PRESENT | PDE64_RW |(uint64_t) pt;
    for(uint64_t j = 0; j < 0x200; j++){
      pt[j] = PDE64_PRESENT | PDE64_RW | (i * PT_MAPPING_SIZE+0x40000000 + j * PAGE_SIZE);
    }
  }
 
  //0xff000000 ~ 0xffffffff -> 0xff000000 ~ 0xffffffff bios
  pdp0[3] = PDE64_PRESENT | PDE64_RW | (uint64_t) pd0_3;
  for(uint64_t i = 0x1f8; i < 0x200; i++){
    uint64_t* pt = (uint64_t*)kframe_allocate_range_pt(1);
    pd0_3[i] = PDE64_PRESENT | PDE64_RW | (uint64_t) pt;
    for(uint64_t j = 0; j < 0x200; j++){
      pt[j] = PDE64_PRESENT | PDE64_RW | ((i + 0x600) * PT_MAPPING_SIZE + j * PAGE_SIZE);
    }
  }

  //0x8000000000 ~ 0x8080000000 -> 0 ~ 0x80000000 ram
  pml4[1] = PDE64_PRESENT | PDE64_RW | (uint64_t) pdp1;
  pdp1[0] = PDE64_PRESENT | PDE64_RW | (uint64_t) pd1_0;
  pdp1[1] = PDE64_PRESENT | PDE64_RW | (uint64_t) pd1_1;

  for(uint64_t i = 0; i < 0x200; i++){
    uint64_t* pt = (uint64_t*)kframe_allocate_range_pt(1);
    pd1_0[i] = PDE64_PRESENT | PDE64_RW | (uint64_t) pt;
    for(uint64_t j = 0; j < 0x200; j++){
      pt[j] = PDE64_PRESENT | PDE64_RW | (i * PT_MAPPING_SIZE + j * PAGE_SIZE);
    }
  }
  
  for(uint64_t i = 0; i < 0x200; i++){
    uint64_t* pt = (uint64_t*)kframe_allocate_range_pt(1);
    pd1_1[i] = PDE64_PRESENT | PDE64_RW | (uint64_t) pt;
    for(uint64_t j = 0; j < 0x200; j++){
      pt[j] = PDE64_PRESENT | PDE64_RW | ((i + 0x200) * PT_MAPPING_SIZE + j * PAGE_SIZE);
    }
  }
  
  //EFER_LME | EFER_LMA| EFER_SCE have been set, just set new cr3

  
  uint64_to_string((uint64_t)pml4,buffer);
  write_in_console("pml4 address: 0x");
  write_in_console((char*)buffer);
  write_in_console("\n");
  
  asm volatile ("mov cr3, %[pml4]": : [pml4]"r"(pml4));
  
  
}
 
  

static inline uint64_t* get_pml4_addr() {
  uint64_t pml4;
  asm("mov %[pml4], cr3" : [pml4]"=r"(pml4));
  return (uint64_t*) (pml4 | KERNEL_BASE_OFFSET);
}

#define _OFFSET(v, bits) (((uint64_t)(v) >> (bits)) & 0x1ff)

#define PML4OFF(v) _OFFSET(v, 39)
#define PDPOFF(v) _OFFSET(v, 30)
#define PDOFF(v) _OFFSET(v, 21)
#define PTOFF(v) _OFFSET(v, 12)

/* if vaddr is already mapping to some address, overwrite it. */
void add_trans_user(void* vaddr_, void* paddr_, int prot) {
  uint64_t vaddr = (uint64_t) vaddr_;
  /* validation of vaddr should be done in sys_mmap, so we can simply panic here */
  if(!USER_MEM_RANGE_OK(vaddr)) panic("translate.c#add_trans_user: not allowed");
  uint64_t paddr = (uint64_t) paddr_ & ~KERNEL_BASE_OFFSET;
  uint64_t* pml4 = get_pml4_addr(), *pdp, *pd, *pt;
#define PAGING(p, c) do { \
    if(!(*p & PDE64_PRESENT)) { \
      c = (uint64_t*) kframe_allocate_range_pt(1); \
      *p = PDE64_PRESENT | PDE64_RW | PDE64_USER |(uint64_t) c; \
    } else { \
      if(!(*p & PDE64_USER)) panic("translate.c#add_trans_user: invalid address"); \
      c = (uint64_t*) ((*p & -0x1000) | KERNEL_BASE_OFFSET); \
    } \
  } while(0);
  PAGING(&pml4[PML4OFF(vaddr)], pdp);
  PAGING(&pdp[PDPOFF(vaddr)], pd);
  PAGING(&pd[PDOFF(vaddr)], pt);
#undef PAGING
  pt[PTOFF(vaddr)] = PDE64_PRESENT | paddr;
  if(prot & PROT_R) pt[PTOFF(vaddr)] |= PDE64_USER;
  if(prot & PROT_W) pt[PTOFF(vaddr)] |= PDE64_RW;
}

int modify_permission(void *vaddr, int prot) {
  uint64_t *pml4 = get_pml4_addr(), *pdp, *pd, *pt;
#define PAGING(p, c) do { \
    if(!(*p & PDE64_PRESENT)) return -1; \
    c = (uint64_t*) ((*p & -0x1000) | KERNEL_BASE_OFFSET);\
  } while(0);
  PAGING(&pml4[PML4OFF(vaddr)], pdp);
  PAGING(&pdp[PDPOFF(vaddr)], pd);
  PAGING(&pd[PDOFF(vaddr)], pt);
#undef PAGING
  uint64_t* e = &pt[PTOFF(vaddr)];
  if(!(*e & PDE64_PRESENT)) return -1;
  *e &= ~(PDE64_USER | PDE64_RW);
  if(prot & PROT_R) *e |= PDE64_USER;
  if(prot & PROT_W) *e |= PDE64_RW;
  return 0;
}

/* translate the virtual address to physical address.
 * returns -1 if page not presented or permission not matched
 */
uint64_t translate(void *vaddr, int usermode, int writable) {
  uint64_t *pml4 = get_pml4_addr(), *pdp, *pd, *pt, *ret;
#define PAGING(p, c) do { \
    if(!(*p & PDE64_PRESENT)) return -1; \
    if(usermode && !(*p & PDE64_USER)) return -1; \
    if(writable && !(*p & PDE64_RW)) return -1; \
    c = (uint64_t*) ((*p & -0x1000) | KERNEL_BASE_OFFSET);\
  } while(0);
  PAGING(&pml4[PML4OFF(vaddr)], pdp);
  PAGING(&pdp[PDPOFF(vaddr)], pd);
  PAGING(&pd[PDOFF(vaddr)], pt);
  /* special handles 2MB paging */
  if(pd[PDOFF(vaddr)] & PDE64_PS)
    return (pd[PDOFF(vaddr)] & -0x200000) + ((uint64_t) vaddr & 0x1fffff);
  PAGING(&pt[PTOFF(vaddr)], ret);
#undef PAGING
  return physical(ret) + ((uint64_t) vaddr & 0xfff);
}

/* vaddr should always an address of kernel-space */
uint64_t physical(void *vaddr_) {
  uint64_t vaddr = (uint64_t) vaddr_;
  if(vaddr & KERNEL_BASE_OFFSET) return vaddr ^ KERNEL_BASE_OFFSET;
  panic("translate.c#physical: don't pass non-kernel based address");
  return -1;
}

int pf_to_prot(Elf64_Word pf) {
  int ret = 0;
  if(pf & PF_R) ret |= PROT_R;
  if(pf & PF_W) ret |= PROT_W;
  if(pf & PF_X) ret |= PROT_X;
  return ret;
}

int set_shared_bit(uint64_t *vaddr, uint64_t len){
  if((uint64_t)vaddr & 0xfff) panic("vaddr should aligned with page size 4KB");
  uint64_t *pml4 = get_pml4_addr(), *pdp, *pd, *pt;
  uint64_t vaddr_end = (uint64_t)vaddr+len;
  while((uint64_t)vaddr < vaddr_end){
    #define PAGING(p, c) do { \
        if(!(*p & PDE64_PRESENT)) return -1; \
        c = (uint64_t*) ((*p & -0x1000) | KERNEL_BASE_OFFSET);\
        } while(0);
      PAGING(&pml4[PML4OFF(vaddr)], pdp);
      PAGING(&pdp[PDPOFF(vaddr)], pd);
      PAGING(&pd[PDOFF(vaddr)], pt);
    #undef PAGING
    pt[PTOFF(vaddr)]|=SHARED_BIT;
    vaddr+=PAGE_SIZE;
  }
  return 0;
}

int clear_shared_bit(uint64_t *vaddr, uint64_t len){
  if((uint64_t)vaddr & 0xfff) panic("vaddr should aligned with page size 4KB");
  uint64_t *pml4 = get_pml4_addr(), *pdp, *pd, *pt;
  uint64_t vaddr_end = (uint64_t)vaddr+len;
  while((uint64_t)vaddr < vaddr_end){
    #define PAGING(p, c) do { \
        if(!(*p & PDE64_PRESENT)) return -1; \
        c = (uint64_t*) ((*p & -0x1000) | KERNEL_BASE_OFFSET);\
        } while(0);
      PAGING(&pml4[PML4OFF(vaddr)], pdp);
      PAGING(&pdp[PDPOFF(vaddr)], pd);
      PAGING(&pd[PDOFF(vaddr)], pt);
    #undef PAGING
    pt[PTOFF(vaddr)] &= (SHARED_BIT-1);
    vaddr+=PAGE_SIZE;
  }
  return 0;
}