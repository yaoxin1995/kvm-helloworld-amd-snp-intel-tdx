#include <mm/gdt.h>
#include <utils/panic.h>
#include <utils/string.h>
static uint16_t gdt_size =1;

uint16_t gdt_install_user_segment_descriptor(uint8_t num, uint8_t access, uint8_t flags){
    gdt[num].access = access;
    gdt[num].flags = flags;
    gdt[num].limit_low = 0xffff;
    gdt[num].limit_high = 0x0f;
    gdt_size+=1;
    if(access&AC_DPL_USER){
        return (num<<3|CPL_USER);
    }else{
        return (num<<3);
    }
}

uint16_t gdt_install_system_segment_descriptor_tss(uint8_t num){
    gdt[num].access = AC_PR|AC_AC|AC_EX;
    gdt[num].base_low = (uint16_t)(uint64_t)tss;
    gdt[num].base_middle = (uint8_t)((uint64_t)tss >>16);
    gdt[num].base_high = (uint8_t)((uint64_t)tss >>24);
    gdt[num].limit_low = sizeof(struct tss)-1;
    gdt[num].limit_high = 0x0f;
    
    gdt[num+1].limit_low = (uint16_t)((uint64_t)tss >>32);
    gdt[num+1].base_low =  (uint16_t)((uint64_t)tss >>48);
    gdt_size+=2;
    return (num<<3);
}

void load_gdtr(){
    struct gdt_ptr gdt_ptr = {
        .base = (uint64_t)gdt,
        .limit = gdt_size*sizeof(uint64_t)-1
    };

    unsigned char buffer[20] = {0};
    uint64_to_string(gdt_ptr.base,buffer);
    write_in_console("Loading gdtr: base:0x");
    write_in_console((char*)buffer);
    uint64_to_string((uint64_t)gdt_ptr.limit,buffer);
    write_in_console(", limit:0x");
    write_in_console((char*)buffer);
    write_in_console("\n");
    asm volatile (
        "lgdt %0;"  
        :
        : "m" (gdt_ptr)
    );
}

void load_cs(uint16_t sel){
    uint64_t tmp = 0;
    asm volatile (
        "push %[sel];"
        "lea %[tmp], [1f + rip];"
        "push %[tmp];"
        "retfq;"
        "1:"
        : [tmp] "+r" (tmp)
        : [sel] "r" ((uint64_t)sel)
    );
}

void load_ds(uint16_t sel){
    asm volatile (
        "mov ds, %[sel];"
        :
        :[sel] "r" (sel)
    );
}

void load_es(uint16_t sel){
    asm volatile (
        "mov es, %[sel];"
        :
        :[sel] "r" (sel)
    );
}

void load_ss(uint16_t sel){
    asm volatile (
        "mov ss, %[sel];"
        :
        :[sel] "r" (sel)
    );
}

void load_fs(uint16_t sel){
    asm volatile (
        "mov fs, %[sel];"
        :
        :[sel] "r" (sel)
    );
}

void load_gs(uint16_t sel){
    asm volatile (
        "mov gs, %[sel];"
        :
        :[sel] "r" (sel)
    );
}

void load_tss(uint16_t sel){
    asm volatile (
        "ltr %[sel];"
        :
        :[sel] "r" (sel)
    );
}

void init_tss(){
    uint16_t tss_sel = gdt_install_system_segment_descriptor_tss(gdt_size);
    load_gdtr();
    load_tss(tss_sel);
}

void init_gdt(struct gdt_entry * allocated_gdt, struct tss * allocated_tss){
    gdt = allocated_gdt;
    tss = allocated_tss;
    unsigned char buffer[20] = {0};
    uint64_to_string((uint64_t)gdt,buffer);
    write_in_console("gdt address: 0x");
    write_in_console((char*)buffer);
    write_in_console("\n");
    //uint16_t _code32 =  gdt_install_user_segment_descriptor(gdt_size,KERNEL_CODE32_ACCESS,KERNEL_CODE32_FLAGS);
    uint16_t code = gdt_install_user_segment_descriptor(gdt_size,KERNEL_CODE64_ACCESS,KERNEL_CODE64_FLAGS);
    //uint16_t _code_exception = gdt_install_user_segment_descriptor(gdt_size,KERNEL_CODE64_ACCESS,KERNEL_CODE64_FLAGS);
    uint16_t data = gdt_install_user_segment_descriptor(gdt_size,KERNEL_DATA_ACCESS,KERNEL_DATA_FLAGS);
    load_gdtr();
    
    struct gdt_ptr gdtr_value;
    asm("sgdt %0":"=m"(gdtr_value));
    uint64_to_string((uint64_t)gdtr_value.limit,buffer);
    write_in_console("gdtr limit: 0x");
    write_in_console((char*)buffer);
    write_in_console("\n");
    
    uint64_to_string(gdtr_value.base,buffer);
    write_in_console("gdtr base: 0x");
    write_in_console((char*)buffer);
    write_in_console("\n");

    load_cs(code);
    load_ds(data);
    load_es(data);
    load_ss(data);
    load_fs(data);
    load_gs(data);
    init_tss();
}

