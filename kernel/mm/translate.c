#include <mm/kmalloc.h>
#include <mm/translate.h>
#include <utils/panic.h>
#include <mm/kframe.h>
#include <utils/string.h>
#include <utils/tdx.h>
#include <utils/sev_snp.h>


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
      c = (uint64_t*) (kframe_allocate_range_pt(1)| KERNEL_BASE_OFFSET); \
      *p = PDE64_PRESENT | PDE64_RW | PDE64_USER |(uint64_t) physical(c); \
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

  asm  volatile(
    "mov rax, QWORD PTR [rip + pml4]\n"  
    "mov cr3, rax\n"                   
    :
    : 
    : "rax"
 );
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
  return (physical(ret) + ((uint64_t) vaddr & 0xfff));
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

int set_c_bit(uint64_t *vaddr, uint64_t len){
  if((uint64_t)vaddr & 0xfff) panic("set_c_bit:vaddr should aligned with page size 4KB");
  if((uint64_t)len & 0xfff) panic("set_c_bit:len should aligned with page size 4KB");
  uint64_t *pml4 = get_pml4_addr(), *pdp, *pd, *pt;
  uint64_t vaddr_end = (uint64_t)vaddr+len;
  for(uint64_t i=(uint64_t)vaddr;i<vaddr_end;i+=PAGE_SIZE){
    #define PAGING(p, c) do { \
        if(!(*p & PDE64_PRESENT)) return -1; \
        c = (uint64_t*) ((*p & -0x1000) | KERNEL_BASE_OFFSET);\
        } while(0);
      PAGING(&pml4[PML4OFF((uint64_t*)i)], pdp);
      PAGING(&pdp[PDPOFF((uint64_t*)i)], pd);
      PAGING(&pd[PDOFF((uint64_t*)i)], pt);
    #undef PAGING
    int c_bit = get_cbit();
    if(c_bit ==0){
      panic("invalid c_bit!\n");
    }
    uint64_t c_bit_mask = 1<<c_bit;
    pt[PTOFF((uint64_t*)i)]|=c_bit_mask;
  }
  return 0;
}

int clear_c_bit(uint64_t *vaddr, uint64_t len){
  if((uint64_t)vaddr & 0xfff) panic("vaddr should aligned with page size 4KB");
  uint64_t *pml4 = get_pml4_addr(), *pdp, *pd, *pt;
  uint64_t vaddr_end = (uint64_t)vaddr+len;
  for(uint64_t i=(uint64_t)vaddr;i<vaddr_end;i+=PAGE_SIZE){
    #define PAGING(p, c) do { \
        if(!(*p & PDE64_PRESENT)) return -1; \
        c = (uint64_t*) ((*p & -0x1000) | KERNEL_BASE_OFFSET);\
        } while(0);
      PAGING(&pml4[PML4OFF((uint64_t*)i)], pdp);
      PAGING(&pdp[PDPOFF((uint64_t*)i)], pd);
      PAGING(&pd[PDOFF((uint64_t*)i)], pt);
    #undef PAGING
    int c_bit = get_cbit();
    if(c_bit ==0){
      panic("invalid c_bit!\n");
    }
    uint64_t c_bit_mask = 1<<c_bit;
    pt[PTOFF((uint64_t*)i)] &= (c_bit_mask-1);
  }
  return 0;
}