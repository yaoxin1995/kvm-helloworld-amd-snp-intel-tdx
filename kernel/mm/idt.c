#include <mm/idt.h>
static unsigned char uint64_buffer[20] = {0};

void dump_register(char * name, uint64_t value, unsigned char* string){
    write_in_console(name);
    write_in_console(": 0x");
    uint64_to_string(value,string);
    write_in_console((char*)string);
    write_in_console("\n");
}



void dump_no_error(struct InterruptNoErrorStack * stack){
    write_in_console("Iret Registers: \n");
    dump_register("rip",stack->iret.rip,uint64_buffer);
    dump_register("cs",stack->iret.cs,uint64_buffer);
    dump_register("rflags",stack->iret.rflags,uint64_buffer);

    write_in_console("Scratch Registers: \n");
    dump_register("r8",stack->scratch.r8,uint64_buffer);
    dump_register("r9",stack->scratch.r9,uint64_buffer);
    dump_register("r10",stack->scratch.r10,uint64_buffer);
    dump_register("r11",stack->scratch.r11,uint64_buffer);
    dump_register("rax",stack->scratch.rax,uint64_buffer);
    dump_register("rcx",stack->scratch.rcx,uint64_buffer);
    dump_register("rdx",stack->scratch.rdx,uint64_buffer);
    dump_register("rdi",stack->scratch.rdi,uint64_buffer);
    dump_register("rsi",stack->scratch.rsi,uint64_buffer);
    
    write_in_console("Preserved Registers: \n");
    dump_register("r12",stack->preserved.r12,uint64_buffer);
    dump_register("r13",stack->preserved.r13,uint64_buffer);
    dump_register("r14",stack->preserved.r14,uint64_buffer);
    dump_register("r15",stack->preserved.r15,uint64_buffer);
    dump_register("rbp",stack->preserved.rbp,uint64_buffer);
    dump_register("rbx",stack->preserved.rbx,uint64_buffer);
    
}

void dump_error(struct InterruptErrorStack * stack){
    
    write_in_console("Iret Registers: \n");
    dump_register("rip",stack->iret.rip,uint64_buffer);
    dump_register("cs",stack->iret.cs,uint64_buffer);
    dump_register("rflags",stack->iret.rflags,uint64_buffer);

    write_in_console("Scratch Registers: \n");
    dump_register("r8",stack->scratch.r8,uint64_buffer);
    dump_register("r9",stack->scratch.r9,uint64_buffer);
    dump_register("r10",stack->scratch.r10,uint64_buffer);
    dump_register("r11",stack->scratch.r11,uint64_buffer);
    dump_register("rax",stack->scratch.rax,uint64_buffer);
    dump_register("rcx",stack->scratch.rcx,uint64_buffer);
    dump_register("rdx",stack->scratch.rdx,uint64_buffer);
    dump_register("rdi",stack->scratch.rdi,uint64_buffer);
    dump_register("rsi",stack->scratch.rsi,uint64_buffer);
    
    write_in_console("Preserved Registers: \n");
    dump_register("r12",stack->preserved.r12,uint64_buffer);
    dump_register("r13",stack->preserved.r13,uint64_buffer);
    dump_register("r14",stack->preserved.r14,uint64_buffer);
    dump_register("r15",stack->preserved.r15,uint64_buffer);
    dump_register("rbp",stack->preserved.rbp,uint64_buffer);
    dump_register("rbx",stack->preserved.rbx,uint64_buffer);
    
    write_in_console("Error code: \n");
    dump_register("error code", stack->code,uint64_buffer);

}

void __attribute__((ms_abi))default_exception_inner(struct InterruptNoErrorStack * stack){
    dump_no_error(stack);
    panic("Default exception");

}
void __attribute__((ms_abi))default_interrupt_inner(struct InterruptNoErrorStack * stack){
    dump_no_error(stack);
    panic("Default interrupt");
}

void __attribute__((ms_abi))divide_by_zero_inner(struct InterruptNoErrorStack * stack){
    dump_no_error(stack);
    panic("Divide_by_zero");
}

void __attribute__((ms_abi))debug_inner(struct InterruptNoErrorStack * stack){
    dump_no_error(stack);
    panic("Debug trap");
}

void __attribute__((ms_abi))non_maskable_inner(struct InterruptNoErrorStack * stack){
    dump_no_error(stack);
    panic("Non-maskable interrupt");
}

void __attribute__((ms_abi))breakpoint_inner(struct InterruptNoErrorStack * stack){
    dump_no_error(stack);
    panic("Breakpoint interrupt");
}

void __attribute__((ms_abi))overflow_inner(struct InterruptNoErrorStack * stack){
    dump_no_error(stack);
    panic("Overflow trap");
}

void __attribute__((ms_abi))bound_range_inner(struct InterruptNoErrorStack * stack){
    dump_no_error(stack);
    panic("Bound range exceeded fault");
}

void __attribute__((ms_abi))invalid_opcode_inner(struct InterruptNoErrorStack * stack){
    dump_no_error(stack);
    panic("Invalid opcode fault");
}

void __attribute__((ms_abi))device_not_available_inner(struct InterruptNoErrorStack * stack){
    dump_no_error(stack);
    panic("Device not available fault");
}

void __attribute__((ms_abi))double_fault_inner(struct InterruptErrorStack * stack){
    dump_error(stack);
    panic("Double fault");
}

void __attribute__((ms_abi))invalid_tss_inner(struct InterruptErrorStack * stack){
    dump_error(stack);
    panic("Invalid TSS fault");
}

void __attribute__((ms_abi))segment_not_present_inner(struct InterruptErrorStack * stack){
    dump_error(stack);
    panic("Segment not present fault");
}

void __attribute__((ms_abi))stack_segment_inner(struct InterruptErrorStack * stack){
    dump_error(stack);
    panic("Stack segment fault");
}

void __attribute__((ms_abi))protection_inner(struct InterruptErrorStack * stack){
    dump_error(stack);
    panic("Protection fault");
}

void __attribute__((ms_abi))page_inner(struct InterruptErrorStack * stack){
    uint64_t cr2;
    asm volatile("mov %0, cr2;" : "=r"(cr2) );
    dump_register("Page fault cr2",cr2,uint64_buffer);
    dump_error(stack);
    panic("Page fault");
}

void __attribute__((ms_abi))fpu_inner(struct InterruptErrorStack * stack){
    dump_error(stack);
    panic("FPU floating point fault");
}

void __attribute__((ms_abi))alignment_check_inner(struct InterruptErrorStack * stack){
    dump_error(stack);
    panic("Alignment check fault");
}

void __attribute__((ms_abi))machine_check_inner(struct InterruptErrorStack * stack){
    dump_error(stack);
    panic("Machine check fault");
}

void __attribute__((ms_abi))simd_inner(struct InterruptErrorStack * stack){
    dump_error(stack);
    panic("SIMD floating point fault");
}

void __attribute__((ms_abi))control_flow_inner(struct InterruptErrorStack * stack){
    dump_error(stack);
    panic("Control Flow Exception");
}


uint64_t uint64_t_pow(uint64_t base, uint64_t exponent) {
    if (exponent < 0) {
        return 0;
    }
    uint64_t result = 1;
    
    for (uint64_t i = 0; i < exponent; i++) {
        result *= base;
    }
    
    return result;
}
bool handle_tdx_ioexit(struct TdVeInfo* ve_info,struct InterruptNoErrorStack * stack){
    uint64_t size = (uint64_t)((ve_info->exit_qualification&0x7)+1);// 0 - 1bytes, 1 - 2bytes, 3 - 4bytes
    bool read = ((ve_info->exit_qualification>>3)&0x1) == 1;
    bool string = ((ve_info->exit_qualification>>4)&0x1) == 1;
    //bool _operand = ((ve_info->exit_qualification>>6)&0x1) == 0; // 0 = DX, 1 = immediate
    uint16_t port = (uint16_t)(ve_info->exit_qualification>>16);
    uint64_t repeat;
    if(((ve_info->exit_qualification >> 5) & 0x1) == 1){
        repeat = stack->scratch.rcx;
    }else{
        repeat = 0;
    }

    if(size != 1 && size != 2 && size != 4){
        return false;
    }
    unsigned char buffer[20] = {0};
    uint64_to_string(size,buffer); 
    write_in_console("size: 0x");
    write_in_console((char*)buffer);
    write_in_console("\n");

    uint64_to_string((uint64_t)read,buffer); 
    write_in_console("read: 0x");
    write_in_console((char*)buffer);
    write_in_console("\n");

    uint64_to_string((uint64_t)string,buffer); 
    write_in_console("string: 0x");
    write_in_console((char*)buffer);
    write_in_console("\n");

    uint64_to_string((uint64_t)port,buffer); 
    write_in_console("port: 0x");
    write_in_console((char*)buffer);
    write_in_console("\n");

    uint64_to_string((uint64_t)repeat,buffer); 
    write_in_console("repeat: 0x");
    write_in_console((char*)buffer);
    write_in_console("\n");
    dump_register("r8",stack->scratch.r8,uint64_buffer);
    dump_register("r9",stack->scratch.r9,uint64_buffer);
    dump_register("r10",stack->scratch.r10,uint64_buffer);
    dump_register("r11",stack->scratch.r11,uint64_buffer);
    dump_register("rax",stack->scratch.rax,uint64_buffer);
    dump_register("rcx",stack->scratch.rcx,uint64_buffer);
    dump_register("rdx",stack->scratch.rdx,uint64_buffer);
    dump_register("rdi",stack->scratch.rdi,uint64_buffer);
    dump_register("rsi",stack->scratch.rsi,uint64_buffer);

    typedef uint32_t (*IOReadFunction)(uint16_t);
    IOReadFunction read_func = 0;
    switch (size) {
        case 1:
            read_func = (IOReadFunction)tdvmcall_io_read_8;
            break;
        case 2:
            read_func = (IOReadFunction)tdvmcall_io_read_16;
            break;
        case 4:
            read_func = (IOReadFunction)tdvmcall_io_read_32;
            break;
        default:
            break;
    }

    typedef uint32_t (*IOWriteFunction)(uint16_t,uint32_t);
    IOWriteFunction write_func = 0;
    switch (size) {
        case 1:
            write_func = (IOWriteFunction)tdvmcall_io_write_8;
            break;
        case 2:
            write_func = (IOWriteFunction)tdvmcall_io_write_16;
            break;
        case 4:
            write_func = (IOWriteFunction)tdvmcall_io_write_32;
            break;
        default:
            break;
    }

    if(string){
        for(int i=0;i<repeat;i++){
            if(read){
                uint32_t val = read_func(port);
                unsigned char * rsi = (unsigned char *)stack->scratch.rdi;
                for(int i=0;i<size;i++){
                    rsi[i] = ((unsigned char *)&val)[i];
                }
                stack->scratch.rdi += size;
            }else{
                uint32_t val = 0;
                unsigned char * rsi = (unsigned char *)stack->scratch.rsi;
                for(int i=0;i<size;i++){
                    val |= ((uint32_t)rsi[i])<<(i*8);
                }
                write_func(port,val);
                stack->scratch.rsi += size;
            }
            stack->scratch.rcx -= 1;
        }
    }else{
        if(read){
            uint32_t result = read_func(port);
            uint64_to_string(result,buffer); 
            write_in_console("read result: 0x");
            write_in_console((char*)buffer);
            write_in_console("\n");
            // Write the IO read result to the low $size-bytes of rax
            stack->scratch.rax = (stack->scratch.rax & !(uint64_t_pow(2,((uint32_t)size * 8)) - 1))
                | ((uint64_t) result& (uint64_t_pow(2,((uint32_t)size * 8)) - 1));

            uint64_to_string(stack->scratch.rax,buffer); 
            write_in_console("stack->scratch.rax: 0x");
            write_in_console((char*)buffer);
            write_in_console("\n");
        }else{
            write_func(port,(uint32_t)stack->scratch.rax);
        }

    }
    return true;
}

void __attribute__((ms_abi))virtualization_inner(struct InterruptNoErrorStack * stack){
    struct TdVeInfo ve_info = tdcall_get_ve_info();
    switch (ve_info.exit_reason)
    {
    case EXIT_REASON_HLT:
        tdvmcall_halt();
        break;
    
    case EXIT_REASON_IO_INSTRUCTION:
        write_in_console("ve for io triggered\n");
        if(!handle_tdx_ioexit(&ve_info,stack)){
            tdvmcall_halt();
        }
        break;
    case EXIT_REASON_MSR_READ: {
        uint64_t msr = tdvmcall_rdmsr((uint32_t)stack->scratch.rcx);
        stack->scratch.rax = (uint64_t)(((uint32_t)msr)&0xffffffff);
        stack->scratch.rdx = (uint64_t)(((uint32_t)(msr>>32))&0xffffffff);
	}
        break;
    case EXIT_REASON_MSR_WRITE: {
        uint64_t data = (uint64_t)stack->scratch.rax  | (((uint64_t)stack->scratch.rdx) << 32);
        tdvmcall_wrmsr((uint32_t)stack->scratch.rcx,data);
	}
        break;
    case EXIT_REASON_CPUID: {
        struct CpuIdInfo cpuid = tdvmcall_cpuid((uint32_t)stack->scratch.rax, (uint32_t)stack->scratch.rcx);
        uint64_t mask = 0xffffffff00000000;
        stack->scratch.rax = (stack->scratch.rax & mask) | (uint64_t)cpuid.eax;
        stack->preserved.rbx = (stack->preserved.rbx & mask) | (uint64_t)cpuid.ebx;
        stack->scratch.rcx = (stack->scratch.rcx & mask) | (uint64_t)cpuid.ecx;
        stack->scratch.rdx = (stack->scratch.rdx & mask) | (uint64_t)cpuid.edx;
	}
	break;
    case EXIT_REASON_VMCALL:
    case EXIT_REASON_MWAIT_INSTRUCTION:
    case EXIT_REASON_MONITOR_INSTRUCTION:
    case EXIT_REASON_WBINVD:
    case EXIT_REASON_RDPMC:
        dump_no_error(stack);
        write_in_console("Unsupported #VE exit reason\n");
        panic("Virtualization fault");
    default:
        break;
    }

    stack->iret.rip += (uint64_t)ve_info.exit_instruction_length;

}


INTERRUPT_NO_ERROR(default_exception,default_exception_inner)
INTERRUPT_NO_ERROR(default_interrupt,default_interrupt_inner)
INTERRUPT_NO_ERROR(divide_by_zero,divide_by_zero_inner)
INTERRUPT_NO_ERROR(debug,debug_inner)
INTERRUPT_NO_ERROR(non_maskable,non_maskable_inner)
INTERRUPT_NO_ERROR(breakpoint,breakpoint_inner)
INTERRUPT_NO_ERROR(overflow,overflow_inner)
INTERRUPT_NO_ERROR(bound_range,bound_range_inner)
INTERRUPT_NO_ERROR(invalid_opcode,invalid_opcode_inner)
INTERRUPT_NO_ERROR(device_not_available,device_not_available_inner)
INTERRUPT_ERROR(double_fault,double_fault_inner)
INTERRUPT_ERROR(invalid_tss,invalid_tss_inner)
INTERRUPT_ERROR(segment_not_present,segment_not_present_inner)
INTERRUPT_ERROR(stack_segment,stack_segment_inner)
INTERRUPT_ERROR(protection,protection_inner)
INTERRUPT_ERROR(page,page_inner)
INTERRUPT_ERROR(fpu,fpu_inner)
INTERRUPT_ERROR(alignment_check,alignment_check_inner)
INTERRUPT_ERROR(machine_check,machine_check_inner)
INTERRUPT_ERROR(simd,simd_inner)
INTERRUPT_ERROR(control_flow,control_flow_inner)
INTERRUPT_NO_ERROR(virtualization,virtualization_inner)

void set_flags(struct idt_entry * entry, uint8_t flags){
    entry->attribute = flags;
}

uint16_t get_cs(){
    uint16_t sel;
    asm volatile (
        "mov %[sel],cs ;"
        :[sel] "=r" (sel)
        :
        :"memory"
    );
    return sel;
}

void set_offset(struct idt_entry * entry,uint16_t selector,uint64_t base) {
        entry->selector = selector;
        entry->offsetl = (uint16_t)base;
        entry->offsetm = (uint16_t)(base >> 16);
        entry->offseth = (uint32_t)(base >> 32);
}

void set_func(struct idt_entry * entry, void * func){
    uint64_t func_addr = (uint64_t)func;
    set_flags(entry,PRESENT|RING_0|INTERRUPT);
    set_offset(entry,get_cs(),func_addr);
}


void load_idtr(){
    struct DescriptorTablePointer idtr = {
        .limit = (uint16_t)(IDT_ENTRY_COUNT *sizeof(struct idt_entry)-1),
        .base = (uint64_t) idt
    };

    asm volatile (
        "lidt %0;"  
        :
        : "m" (idtr)
    );
}

void idt_init(struct idt_entry* allocated_idt){
    idt =allocated_idt;
    set_func(&idt[0],divide_by_zero);
    set_func(&idt[1],debug);
    set_func(&idt[2],non_maskable);
    set_func(&idt[3],breakpoint);
    set_func(&idt[4],overflow);
    set_func(&idt[5],bound_range);
    set_func(&idt[6],invalid_opcode);
    set_func(&idt[7],device_not_available);
    set_func(&idt[8],double_fault);
    set_func(&idt[9],default_exception);
    set_func(&idt[10],invalid_tss);
    set_func(&idt[11],segment_not_present);
    set_func(&idt[12],stack_segment);
    set_func(&idt[13],protection);
    set_func(&idt[14],page);
    set_func(&idt[15],default_exception);
    set_func(&idt[16],fpu);
    set_func(&idt[17],alignment_check);
    set_func(&idt[18],machine_check);
    set_func(&idt[19],simd);
    set_func(&idt[20],virtualization);
    set_func(&idt[21],control_flow);

    for(int i=22;i<32;i++){
        set_func(&idt[i],default_exception);
    }

    for(int i=32;i<IDT_ENTRY_COUNT;i++){
        set_func(&idt[i],default_interrupt);
    }
    load_idtr();
}

