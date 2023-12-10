#include "panic.h"
#include "tdx.h"
#include "sev_snp.h"

void write_in_console(const char *s){
    uint64_t index = 0;
    while (s[index] != 0){
        ghcb_block_io_write_8(0x3f8,s[index++]);
        //tdvmcall_io_write_8(0x3f8,s[index++]);
    }
    
}

void panic(const char *s){
    write_in_console(s);
    ghcb_block_io_write_8(0x3f8,'\n');
    //tdvmcall_io_write_8(0x3f8,'\n');
    ghcb_termination(0,0);
}
