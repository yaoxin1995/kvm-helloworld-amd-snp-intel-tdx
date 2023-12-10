#ifndef __IDT_H
#define __IDT_H
#include <stdint.h>
#include <utils/panic.h>
#include <utils/tdx.h>
#include <utils/string.h>
#include <utils/sev_snp.h>

#define EXIT_REASON_CPUID 10
#define EXIT_REASON_HLT 12
#define EXIT_REASON_RDPMC 15
#define EXIT_REASON_VMCALL 18
#define EXIT_REASON_IO_INSTRUCTION 30
#define EXIT_REASON_MSR_READ 31
#define EXIT_REASON_MSR_WRITE 32
#define EXIT_REASON_MWAIT_INSTRUCTION 36
#define EXIT_REASON_MONITOR_INSTRUCTION 39
#define EXIT_REASON_WBINVD 54


#define IDT_ENTRY_COUNT 0x100

 struct idt_entry {
    uint16_t offsetl;
    uint16_t selector;
    uint8_t zero;
    uint8_t attribute;
    uint16_t offsetm;
    uint32_t offseth;
    uint32_t zero2;
}__attribute__((packed)); //size = 0x10

struct IretRegisters {
    uint64_t rip;
    uint64_t cs;
    uint64_t rflags;
}__attribute__((packed));

struct PreservedRegisters{
    uint64_t r15;
    uint64_t r14;
    uint64_t r13;
    uint64_t r12;
    uint64_t rbp;
    uint64_t rbx;
}__attribute__((packed));

struct ScratchRegisters
{
    uint64_t r11;
    uint64_t r10;
    uint64_t r9;
    uint64_t r8;
    uint64_t rsi;
    uint64_t rdi;
    uint64_t rdx;
    uint64_t rcx;
    uint64_t rax;
}__attribute__((packed));

struct InterruptNoErrorStack
{
    struct PreservedRegisters preserved;
    struct ScratchRegisters scratch;
    struct IretRegisters iret;
}__attribute__((packed));

struct InterruptErrorStack
{
    struct PreservedRegisters preserved;
    struct ScratchRegisters scratch;
    uint64_t code;
    struct IretRegisters iret;
}__attribute__((packed));


struct DescriptorTablePointer {
    /// Size of the DT.
    uint16_t limit;
    /// Pointer to the memory region containing the DT.
    uint64_t base;
}__attribute__((packed));

#define SCRATCH_PUSH() \
    "push rax;"  \
    "push rcx;"  \
    "push rdx;"  \
    "push rdi;"  \
    "push rsi;"  \
    "push r8;"   \
    "push r9;"   \
    "push r10;"  \
    "push r11;"

#define PRESERVED_PUSH() \
    "push rbx;"  \
    "push rbp;"  \
    "push r12;"  \
    "push r13;"  \
    "push r14;"  \
    "push r15;"   

#define SCRATCH_POP() \
    "pop r11;"  \
    "pop r10;" \
    "pop r9;"  \
    "pop r8;"  \
    "pop rsi;"  \
    "pop rdi;"   \
    "pop rdx;"  \
    "pop rcx;"  \
    "pop rax;"

#define PRESERVED_POP() \
    "pop r15;"  \
    "pop r14;" \
    "pop r13;" \
    "pop r12;" \
    "pop rbp;"  \
    "pop rbx;"  

#define INTERRUPT_COMMON(name, func, asm_epilogue) \
    __attribute__((naked))void name() { \
        asm(\
            SCRATCH_PUSH() \
            PRESERVED_PUSH() \
            "mov rcx, rsp;" \
            "mov rbx, rsp;"\
            "and rsp,(~(0x40-1));"\
            "lea rax, %a0;" \
            "call rax;" \
            "mov rsp, rbx;"\
            PRESERVED_POP() \
            SCRATCH_POP() \
            asm_epilogue \
            :: "p" (func) \
            ); \
    };

#define INTERRUPT_NO_ERROR(name,  func) \
    INTERRUPT_COMMON(name, func,"iretq")

#define INTERRUPT_ERROR(name,  func) \
    INTERRUPT_COMMON(name, func,"add rsp, 8;\n\t iretq;")



#define PRESENT  1 << 7
#define RING_0   0 << 5
#define RING_1   1 << 5
#define RING_2   2 << 5
#define RING_3   3 << 5
#define SS       1 << 4
#define INTERRUPT  0xE
#define TRAP       0xF

static struct idt_entry* idt;
void idt_init(struct idt_entry* allocated_idt);
#endif

