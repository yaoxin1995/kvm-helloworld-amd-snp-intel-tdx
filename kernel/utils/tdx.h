#include <stdint.h>
#include <stdbool.h>
#ifndef TDX_H
#define TDX_H

#define TDVMCALL_CPUID  0x0000a
#define TDVMCALL_HALT   0x0000c
#define TDVMCALL_IO     0x0001e
#define TDVMCALL_RDMSR  0x0001f
#define TDVMCALL_WRMSR  0x00020
#define TDVMCALL_MAPGPA 0x10001
#define IO_READ 0x0
#define IO_WRITE 0x1

#define TDCALL_TDINFO 0x1
#define TDCALL_TDGETVEINFO 0x3
#define TDVMCALL_STATUS_SUCCESS 0
#define VmcallRetry 0x1
#define VmcallOperandInvalid 0x8000000000000000
#define VmcallGpaInuse 0x8000000000000001
#define VmcallAlignError 0x8000000000000002
#define TDCALL_STATUS_SUCCESS 0
#define INTERRUPT_FLAG  1UL << 9


struct CpuIdInfo {
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
};

struct TdVeInfo {
    uint32_t exit_reason;
    uint32_t rsvd;
    uint64_t exit_qualification;
    uint64_t guest_la;
    uint64_t guest_pa;
    uint32_t exit_instruction_length;
    uint32_t exit_instruction_info;
    uint64_t rsvd1;
};

struct TdInfo{
    uint64_t gpaw;
    uint64_t attributes;
    uint32_t max_vcpus;
    uint32_t num_vcpus;
    uint64_t rsvd[3];
};

struct TdVmcallArgs{
    uint64_t r10;
    uint64_t r11;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
};

struct TdcallArgs{
    uint64_t rax;
    uint64_t rcx;
    uint64_t rdx;
    uint64_t r8;
    uint64_t r9;
    uint64_t r10;
    uint64_t r11;
    uint64_t r12;
    uint64_t r13;
};



struct TdInfo tdcall_get_td_info();
struct TdVeInfo tdcall_get_ve_info();

struct CpuIdInfo tdvmcall_cpuid(uint32_t eax, uint32_t ecx);
void tdvmcall_halt();
void tdvmcall_sti_halt();
uint8_t tdvmcall_io_read_8(uint16_t port);
uint16_t tdvmcall_io_read_16(uint16_t port);
uint32_t tdvmcall_io_read_32(uint16_t port);
void tdvmcall_io_write_8(uint16_t port, uint8_t byte);
void tdvmcall_io_write_16(uint16_t port, uint16_t byte);
void tdvmcall_io_write_32(uint16_t port, uint32_t byte);
uint64_t tdvmcall_rdmsr(uint32_t index);
void tdvmcall_wrmsr(uint32_t index, uint64_t value);
int tdvmcall_mapgpa(bool shared,uint64_t paddr,uint64_t length);

#endif