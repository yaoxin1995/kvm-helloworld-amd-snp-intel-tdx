#ifndef __GDT_H 
#define __GDT_H 

#include <stdint.h>
static struct gdt_entry *gdt;
static struct tss *tss;

struct gdt_entry {
    uint16_t limit_low;       
    uint16_t base_low;
    uint8_t base_middle;
    uint8_t access;
    unsigned limit_high: 4;
    unsigned flags: 4;
    uint8_t base_high;
} __attribute__((packed));

struct gdt_ptr {
    uint16_t limit;
    uint64_t base;
} __attribute__((packed));

struct tss{
    uint32_t reserved_1;
    /// The full 64-bit canonical forms of the stack pointers (RSP) for privilege levels 0-2.
    uint64_t privilege_stack_table[3];
    uint64_t reserved_2;
    /// The full 64-bit canonical forms of the interrupt stack table (IST) pointers.
    uint64_t interrupt_stack_table[7];
    uint64_t reserved_3;
    uint16_t reserved_4;
    /// The 16-bit offset to the I/O permission bit map from the 64-bit TSS base.
    uint16_t iomap_base;
}__attribute__((packed));

#define NGDT 8        //  Global Descriptor Table

#define AC_AC 0x1       //  access
#define AC_RW 0x2       //  readable for code selector & writeable for data selector
#define AC_DC 0x4       //  direction
#define AC_EX 0x8       //  executable, code segment
#define AC_US 0x10      //  user segment if set
#define AC_PR 0x80      //  persent in memory

// DPL
#define AC_DPL_KERN 0x00 // RING 0 kernel level
#define AC_DPL_SYST 0x20 // RING 1 systask level
#define AC_DPL_USER 0x60 // RING 3 user level

#define GDT_GR  0x8     //  page granularity, limit in 4k blocks
#define GDT_SZ  0x4     //  size bt, 32 bit protect mode
#define GDT_LM  0x2     //long mode

// gdt selector 
#define SEL_KCODE   0x1  
#define SEL_KDATA   0x2  
#define SEL_UCODE   0x3  
#define SEL_UDATA   0x4 
#define SEL_SCODE   0x5 
#define SEL_SDATA   0x6 
#define SEL_TSS     0x7 

// RPL  request privilege level
#define RPL_KERN    0x0
#define RPL_SYST    0x1
#define RPL_USER    0x3

// CPL  current privilege level
#define CPL_KERN    0x0
#define CPL_SYST    0x1
#define CPL_USER    0x3

#define COMMON_ACCESS (AC_AC|AC_RW|AC_US|AC_PR)
#define COMMON_FLAGS (GDT_GR)

#define KERNEL_CODE32_ACCESS (COMMON_ACCESS|AC_EX)
#define KERNEL_CODE32_FLAGS (COMMON_FLAGS|GDT_SZ)

#define KERNEL_DATA_ACCESS (COMMON_ACCESS)
#define KERNEL_DATA_FLAGS (COMMON_FLAGS|GDT_SZ)

#define KERNEL_CODE64_ACCESS (COMMON_ACCESS|AC_EX)
#define KERNEL_CODE64_FLAGS (COMMON_FLAGS|GDT_LM)


#endif

void init_gdt(struct gdt_entry * allocated_gdt, struct tss * allocated_tss);
