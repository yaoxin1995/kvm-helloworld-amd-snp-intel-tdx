#include "panic.h"
#include "tdx.h"

void write_in_console(const char *s){
    uint64_t index = 0;
    while (s[index] != 0){
        tdvmcall_io_write_8(0x3f8,s[index++]);
    }
    
}

void panic(const char *s){
    write_in_console(s);
    tdvmcall_io_write_8(0x3f8,'\n');
    tdvmcall_halt();
}
