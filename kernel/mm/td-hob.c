#include <utils/uefi.h>
#include <mm/td-hob.h>
#include <utils/string.h>
#include <utils/panic.h>


uint64_t parse_hob_get_size(uint64_t ptr){
    EFI_HOB_HANDOFF_INFO_TABLE phit = * (EFI_HOB_HANDOFF_INFO_TABLE *)ptr;
    if((phit.Header.HobType == EFI_HOB_TYPE_HANDOFF)&&phit.Header.HobLength >= sizeof(EFI_HOB_HANDOFF_INFO_TABLE)){
        uint64_t size = phit.EfiEndOfHobList - ptr;
        return size;
    }
    else{
        panic("Parse hob in kernel failed.");
    }
    return 0;

}

uint64_t align_to_next_hob_offset(uint64_t hob_size, uint64_t offset, uint16_t length){
    if(length == 0 || length > ((1UL<<16)-1)){
        panic("align_to_next_hob_offset failed, invalid length.");
    }
    uint64_t new_offset = offset+((uint64_t)length + 7) / 8 * 8;
    if (new_offset >= hob_size){
        panic("align_to_next_hob_offset failed, out of hob range.");
    }  
    return new_offset;
}

struct e820_table parse_guided_hob(uint8_t *hob){
    uint64_t guid_extension_offset = sizeof(EFI_HOB_GUID_TYPE);
    uint64_t hob_end = (*(EFI_HOB_GUID_TYPE *)hob).Header.HobLength;
    if(hob_end < guid_extension_offset)
        panic("Parsing e820 table failed, wrong HOB configuration");
    int num_entries = (hob_end-guid_extension_offset)/sizeof(struct e820_entry);
    uint8_t * extension_hob = hob+guid_extension_offset;

    struct e820_entry *last_entry = (struct e820_entry *)(extension_hob+(num_entries-1)*sizeof(struct e820_entry));
    struct e820_entry padding_entry;
    memset(&padding_entry,0x0,sizeof(struct e820_entry));
    if(memcmp(last_entry,&padding_entry,sizeof(struct e820_entry)) == 0){
        num_entries -=1;
    }

    if(num_entries == 0 || num_entries > 0x80){
        panic("Invalid number of e820 table entries.");
    }

    struct e820_table parsed_e820_table;
    parsed_e820_table.num_entries = num_entries;
    parsed_e820_table.e820_entry = (struct e820_entry *)extension_hob;
    return parsed_e820_table;

}

struct e820_table get_e820_table_from_hob(uint8_t *hob,uint64_t hob_size){
    for(uint64_t offset = 0; offset < hob_size; ){
        EFI_HOB_GENERIC_HEADER header = * (EFI_HOB_GENERIC_HEADER *)(hob+offset);
        if(header.HobType == EFI_HOB_TYPE_GUID_EXTENSION){
            EFI_HOB_GUID_TYPE hob_guid_extension = * (EFI_HOB_GUID_TYPE *)(hob+offset);
            if(memcmp(&hob_guid_extension.Name,&TD_E820_TABLE_HOB_GUID,sizeof(EFI_GUID)) == 0){
                write_in_console("Get e820 table hob, start parsing\n");
                return parse_guided_hob(hob+offset);
            }
        }
        offset = align_to_next_hob_offset(hob_size,offset,header.HobLength);
    }
    panic("Cannot find e820 table in hob");
    struct e820_table null;
    return null;
}





uint64_t get_usable(uint64_t size, struct e820_entry * memory_map, int num_entries){
    for(int i=0;i<num_entries;i++){
        if(memory_map[i].type == E820_RAM && memory_map[i].length >=size){
            memory_map[i].address += size;
            memory_map[i].length -= size;
            return memory_map[i].address-size;
        }
    }
    panic("Out of memory, cannot get usable memory.");
    return -1;
}