#include "tdx.h"
#include <utils/panic.h>
#include <utils/string.h>
uint64_t extern __attribute__((ms_abi))asm_td_vmcall(void *args, uint64_t do_sti);
uint64_t extern __attribute__((ms_abi))asm_td_call(void *args);
static uint64_t SHARED_MASK;
struct TdInfo tdcall_get_td_info() {
    struct TdcallArgs args = {
        .rax = (uint64_t)TDCALL_TDINFO
    };
    
    int ret = asm_td_call((void *)&args);

    if (ret != TDCALL_STATUS_SUCCESS) {
        tdvmcall_halt();
    }

    struct TdInfo td_info ={
        .gpaw = args.rcx & 0x3f,
        .attributes =  args.rdx,
        .max_vcpus = (uint32_t)(args.r8 >> 32),
        .num_vcpus = (uint32_t)args.r8
    };

    return td_info;
}

struct TdVeInfo tdcall_get_ve_info(){
    struct TdcallArgs args = {
        .rax = (uint64_t)TDCALL_TDGETVEINFO
    };

    int ret = asm_td_call((void *)&args);

    if (ret != TDCALL_STATUS_SUCCESS) {
        tdvmcall_halt();
    }

    struct TdVeInfo ve_info = {
        .exit_reason =  (uint32_t)args.rcx,
        .exit_qualification =  args.rdx,
        .guest_la = args.r8,
        .guest_pa = args.r9,
        .exit_instruction_length = (uint32_t) args.r10,
        .exit_instruction_info = (uint32_t) (args.r10 >> 32)
    };

    return ve_info;
}

struct CpuIdInfo tdvmcall_cpuid(uint32_t eax, uint32_t ecx){
    struct TdVmcallArgs args = {
        .r11 = (uint64_t)TDVMCALL_CPUID,
        .r12 = (uint64_t)eax,
        .r13 = (uint64_t)ecx
    };

    uint64_t ret =  asm_td_vmcall((void *)&args,false);

    if (ret != TDVMCALL_STATUS_SUCCESS) {
        tdvmcall_halt();
    }

    struct CpuIdInfo cpuid = {
        .eax = (uint32_t)(args.r12 &0xffffffff),
        .ebx = (uint32_t)(args.r13 &0xffffffff),
        .ecx = (uint32_t)(args.r14 &0xffffffff),
        .edx = (uint32_t)(args.r15 &0xffffffff)
    };
    return cpuid;
}

void tdvmcall_halt(){
    uint64_t flags;
    asm volatile (
        "pushfq;"        
        "pop %0;"     
        : "=g" (flags)    
    );
    
    bool interrupt_enabled = flags&INTERRUPT_FLAG;
    struct TdVmcallArgs args = {
        .r11 = (uint64_t)TDVMCALL_HALT,
        .r12 = !interrupt_enabled
    };
    asm_td_vmcall((void *)&args,false);
}

void tdvmcall_sti_halt(){
    struct TdVmcallArgs args = {
        .r11 = (uint64_t)TDVMCALL_HALT
    };
    asm_td_vmcall((void *)&args,true);
}

uint8_t tdvmcall_io_read_8(uint16_t port) {
    struct TdVmcallArgs args = {
        .r11 = (uint64_t)TDVMCALL_IO,
        .r12 = (uint64_t)sizeof(uint8_t),
        .r13 = (uint64_t)IO_READ,
        .r14 = (uint64_t)port
    };

    uint64_t ret = asm_td_vmcall((void *)&args,false);

    if (ret != TDVMCALL_STATUS_SUCCESS) {
        tdvmcall_halt();
    }

    return (uint8_t)(args.r11 & 0xff);
}

uint16_t tdvmcall_io_read_16(uint16_t port) {
    struct TdVmcallArgs args = {
        .r11 = (uint64_t)TDVMCALL_IO,
        .r12 = (uint64_t)sizeof(uint16_t),
        .r13 = (uint64_t)IO_READ,
        .r14 = (uint64_t)port
    };

    uint64_t ret = asm_td_vmcall((void *)&args,false);

    if (ret != TDVMCALL_STATUS_SUCCESS) {
        tdvmcall_halt();
    }

    return (uint16_t)(args.r11 & 0xffff);
}

uint32_t tdvmcall_io_read_32(uint16_t port) {
    struct TdVmcallArgs args = {
        .r11 = (uint64_t)TDVMCALL_IO,
        .r12 = (uint64_t)sizeof(uint32_t),
        .r13 = (uint64_t)IO_READ,
        .r14 = (uint64_t)port
    };

    uint64_t ret = asm_td_vmcall((void *)&args,false);

    if (ret != TDVMCALL_STATUS_SUCCESS) {
        tdvmcall_halt();
    }

    return (uint32_t)(args.r11 & 0xffffffff);
}

void tdvmcall_io_write_8(uint16_t port, uint8_t byte) {
    struct TdVmcallArgs args = {
        .r11 = (uint64_t)TDVMCALL_IO,
        .r12 = (uint64_t)sizeof(uint8_t),
        .r13 = (uint64_t)IO_WRITE,
        .r14 = (uint64_t)port ,
        .r15 = (uint64_t)byte
    };
    uint64_t ret = asm_td_vmcall((void *)&args,false);

    if (ret != TDVMCALL_STATUS_SUCCESS) {
        tdvmcall_halt();
    }
}

void tdvmcall_io_write_16(uint16_t port, uint16_t byte) {
    struct TdVmcallArgs args = {
        .r11 = (uint64_t)TDVMCALL_IO,
        .r12 = (uint64_t)sizeof(uint16_t),
        .r13 = (uint64_t)IO_WRITE,
        .r14 = (uint64_t)port ,
        .r15 = (uint64_t)byte
    };

    uint64_t ret = asm_td_vmcall((void *)&args,false);

    if (ret != TDVMCALL_STATUS_SUCCESS) {
        tdvmcall_halt();
    }
}

void tdvmcall_io_write_32(uint16_t port, uint32_t byte) {
    struct TdVmcallArgs args = {
        .r11 = (uint64_t)TDVMCALL_IO,
        .r12 = (uint64_t)sizeof(uint32_t),
        .r13 = (uint64_t)IO_WRITE,
        .r14 = (uint64_t)port ,
        .r15 = (uint64_t)byte
    };

    uint64_t ret = asm_td_vmcall((void *)&args,false);

    if (ret != TDVMCALL_STATUS_SUCCESS) {
        tdvmcall_halt();
    }
}

uint64_t tdvmcall_rdmsr(uint32_t index){
    struct TdVmcallArgs args = {
        .r11 = (uint64_t)TDVMCALL_RDMSR,
        .r12 = (uint64_t)index
    };

    uint64_t ret = asm_td_vmcall((void *)&args,false);

    if (ret != TDVMCALL_STATUS_SUCCESS) {
        write_in_console("rdmsr error!\nreturn value:0x");
        unsigned char buffer[20] = {0};
        uint64_to_string((uint64_t)ret,buffer);
        write_in_console((char*)buffer);
        write_in_console("\n");
        tdvmcall_halt();
    }
    return args.r11;
}

void tdvmcall_wrmsr(uint32_t index, uint64_t value) {
    struct TdVmcallArgs args = {
        .r11 = (uint64_t)TDVMCALL_WRMSR,
        .r12 = (uint64_t)index,
        .r13 = value
    };
    write_in_console("wrmsr triggered, index:0x");
    unsigned char buffer[20] = {0};
    uint64_to_string((uint64_t)index,buffer);
    write_in_console((char*)buffer);
    write_in_console(" value:0x");
    uint64_to_string(value,buffer);
    write_in_console((char*)buffer);
    write_in_console("\n");


    uint64_t ret = asm_td_vmcall((void *)&args,false);

    if (ret != TDVMCALL_STATUS_SUCCESS) {
        tdvmcall_halt();
    }
}

int tdvmcall_mapgpa(bool shared,uint64_t paddr,uint64_t length) {
    if (SHARED_MASK == 0){
        uint8_t gpaw =(uint8_t)  tdcall_get_td_info().gpaw& 0x3f;
        if(gpaw == 48||gpaw == 52){
            SHARED_MASK = 1UL<<(gpaw-1);
        }else{
            return -1;
        }
    }
    if(shared){
        paddr |= SHARED_MASK;
    }else{
         paddr &= (~SHARED_MASK);
    }

    struct TdVmcallArgs args = {
        .r11 = (uint64_t)TDVMCALL_MAPGPA,
        .r12 = paddr,
        .r13 = (uint64_t)length
    };

    int ret = asm_td_vmcall((void *)&args,false);

    if (ret != TDVMCALL_STATUS_SUCCESS) {
        return -1;
    }
    return 0;
}
