#include <utils/sev_snp.h>
#include <utils/panic.h>
#include <mm/translate.h>

struct ghcb *ghcb = 0;
void pvalidate(uint64_t vaddr, int size,  bool validated){
    uint32_t rmp_changed;
    uint64_t ret;
    uint32_t flag = (uint32_t)validated;
    vaddr &= (!0xFFF); 
    // pvalidate and output the carry bit in edx
    // return value in rax
   asm volatile(
        ".byte 0xF2, 0x0F, 0x01, 0xFF\n\t"
        "setc    dl"
        : "=a"(ret), "=d"(rmp_changed)
        : "a"(vaddr), "c"((uint64_t)size), "d"(flag)  
        : "cc"
    );
    switch (ret)
    {
    case 0:
        if((uint8_t)rmp_changed != 0){
            write_in_console("rmp not changed!\n");
        };
        break;
    case 1:
        panic("Pvalidate error fail input");
        break;
    case 6:
        panic("Pvalidate error fail size mismatch"); 
        break;
    default:
        panic("Pvalidate error fail unknown return"); 
        break;
    }
}

void set_offset_valid(uint64_t *offset_address) {
        uint64_t offset = (uint64_t)offset_address;
        offset -= (uint64_t)ghcb;
        offset /=8;
        ghcb->save.valid_bitmap[offset/8]|= 1<<(offset&0x7);
}

bool test_offset_valid(uint64_t *offset_address) {
        uint64_t offset = (uint64_t)offset_address;
        offset -= (uint64_t)ghcb;
        offset /=8;
        return ghcb->save.valid_bitmap[offset/8]&(1<<(offset&0x7));
}


void write_msr(uint64_t val, uint32_t msr){
    uint32_t low = (uint32_t)val;
    uint32_t high = (uint32_t)(val>>32);
    asm volatile(
        "wrmsr"
        :: "c"(msr),"a"(low),"d"(high)
    );
}


uint64_t read_msr(uint32_t msr_id) {
    uint32_t low, high;
    uint64_t result;

    asm volatile (
        "rdmsr"
        : "=a" (low), "=d" (high)
        : "c" (msr_id)
    );

    result = ((uint64_t)high << 32) | low;
    return result;
}


uint64_t vmgexit_msr(uint64_t request_code, uint64_t value, uint64_t expected_response) {
    uint64_t val = request_code | value;
   
    write_msr(val,MSR_GHCB);
    asm(
        ".byte 0xf3,0x0f,0x01,0xd9;"
    );
    uint64_t retcode = read_msr(MSR_GHCB);

    if (expected_response != (retcode & 0xFFF)) {
         panic("vmgexit error"); 
    }

    return retcode & (!0xFFF);
}

int vmgexit(uint64_t exit_code, uint64_t exit_info_1,uint64_t exit_info_2){
    ghcb->save.sw_exit_code = exit_code;
    set_offset_valid(&ghcb->save.sw_exit_code);
    ghcb->save.sw_exit_info1 = exit_info_1;
    set_offset_valid(&ghcb->save.sw_exit_info1);
    ghcb->save.sw_exit_info2 = exit_info_2;
    set_offset_valid(&ghcb->save.sw_exit_info2);
    ghcb->ghcb_usage =  GHCB_DEFAULT_USAGE;
    ghcb->protocol_version = GHCB_PROTOCOL_MAX;
    uint64_t gpa = physical(ghcb);
    write_msr(gpa,MSR_GHCB);
    asm(
        ".byte 0xf3,0x0f,0x01,0xd9;"
    );
    if ((ghcb->save.sw_exit_info1 & 0xffffffff) == 1){
        uint64_t exit_info2 = ghcb->save.sw_exit_info2;
        uint64_t vector = exit_info2 & SVM_EVTINJ_VEC_MASK;
         if (((exit_info2 & SVM_EVTINJ_VALID) != 0)
                && ((exit_info2 & SVM_EVTINJ_TYPE_MASK) == SVM_EVTINJ_TYPE_EXEPT)
                && (vector == GP || vector == UD)){

                    return -1; 
        }else{
            return -2;
        }
    }
    return 0;


}

void ghcb_msr_make_page_shared(uint64_t vaddr) {

    pvalidate(vaddr, Size4K, false);
    clear_c_bit((uint64_t *)vaddr,PAGE_SIZE);
    uint64_t gpa = physical((void *)vaddr);// here used in identity map when running the kernel code

    uint64_t shared_op = SNP_PAGE_STATE_SHARED <<PSC_OP_POS;

    uint64_t val = gpa | shared_op;

    uint64_t ret = vmgexit_msr(PSC_REQ, val,PSC_RESP);

    if ((ret & PSC_ERROR_MASK) != 0) {
        panic("ghcb_msr_make_page_shared error");
    }
}
void set_entry(struct psc_entry* entry, uint64_t cur_page, uint64_t operation, uint64_t pagesize) {
        *(uint64_t *)entry = (cur_page|(operation<<52)|(pagesize<<56));
    }

void invalidate(){
    ghcb->save.sw_exit_code =0;
    for(int i=0;i<16;i++){
        ghcb->save.valid_bitmap[i]=0;
    }
}


void __ghcb_block_make_pages_shared(uint64_t vaddr, uint64_t npages){
    for(int i=0;i<npages;i++){
         pvalidate(vaddr, Size4K, false);
    }
    clear_c_bit((uint64_t *)vaddr,npages*PAGE_SIZE);
    struct snp_psc_desc * snp_psc_desc = (struct snp_psc_desc*)&ghcb->shared_buffer;
    snp_psc_desc->hdr.cur_entry=0;
    snp_psc_desc->hdr.end_entry=npages-1;
    uint64_t gpa = physical((void *)vaddr);
    for(int i=0;i<npages;i++){
        set_entry(&snp_psc_desc->entries[i],gpa,SNP_PAGE_STATE_SHARED,Size4K);
        gpa+=PAGE_SIZE;
    }
    while(0){
        if(snp_psc_desc->hdr.cur_entry>snp_psc_desc->hdr.end_entry)
            break;
        invalidate();
        ghcb->save.sw_scratch = (uint64_t)physical(ghcb->shared_buffer);
        set_offset_valid(&ghcb->save.sw_scratch);
        if(vmgexit(SVM_VMGEXIT_PSC,0,0)<0){
            panic("vmgexit psc error!");
        }
        if(ghcb->save.sw_exit_info2!=0){
            panic("vmgexit psc sw_exit_info2 should be zero!");
        }
        if(snp_psc_desc->hdr.reserved!=0){
            panic("vmgexit psc snp_psc_desc reserved should be zero!");
        }
           
    }

}

void ghcb_block_make_pages_shared(uint64_t vaddr, uint64_t npages){
    if(npages==0)
        return;
    int count = npages/VMGEXIT_PSC_MAX_ENTRY;
    for(int i=0;i<count;i++){
         __ghcb_block_make_pages_shared(vaddr+VMGEXIT_PSC_MAX_ENTRY*PAGE_SIZE*count,(npages>=VMGEXIT_PSC_MAX_ENTRY ? VMGEXIT_PSC_MAX_ENTRY:npages));
         npages-=VMGEXIT_PSC_MAX_ENTRY;
    }
}

void ghcb_block_io_write_8(uint16_t port, uint8_t byte){
    invalidate();
    ghcb->save.rax = byte;
    set_offset_valid(&ghcb->save.rax);
    vmgexit(SVM_EXIT_IOIO, IOIO_DATA_8|IOIO_TYPE_OUT|(uint64_t)port<<16, 0);
}

void ghcb_termination(){
    vmgexit_msr(EXIT_REQ,0,0);
}

void ghcb_init(uint64_t vaddr ){
    ghcb_msr_make_page_shared(vaddr);
    uint64_t gpa = physical((void *)vaddr);
    uint64_t ret = vmgexit_msr(GPA_REQ,gpa,GPA_RESP);
    if(ret != gpa){
        panic("ghcb_init GPA_REQ error");
    }
    ghcb = (struct ghcb*)(vaddr);
}


int get_cbit(){
    SnpCpuidInfo cpuidInfo = *(SnpCpuidInfo*)CPUID_PAGE;
    uint32_t count =  cpuidInfo.count;
    for(int i =0;i<count;i++){
        if(cpuidInfo.entries[i].eax_in == 0x8000001f){
            return cpuidInfo.entries[i].ebx&CBIT_MASK;
        }
    }
    return 0;
}