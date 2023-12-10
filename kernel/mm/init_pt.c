#include<mm/init_pt.h>
#include<utils/sev_snp.h>
/*use extern to reference all global variables you will use here*/
/*this function should create pagetables for a given size of memory*/
/*it is possible to also parse the hob here and store the information in
 * static structure defined in this file
 * once initialization is done, the enablemennt of cr3 will be done in the 
 * _start routine
 */
 
 /*assume you know the base address of RAM (region you want to use)
  * assume you know the base virtual address you want to use
  * assume you know the size of ram
  * This function can also take arguments from hob and use it to make decision above.
  */

//pml4 address
uint64_t *pml4=0;
static struct e820_entry memory_map[128];
static int memory_map_num_entries;

struct page_table_config{
  uint64_t start;
  uint64_t size;
  uint64_t offset;
  uint64_t prot;
}__attribute__((packed,aligned(0x1000))) pt_config[10] = {
    #include <mm/page_table_config>
  };

#define _OFFSET(v, bits) (((uint64_t)(v) >> (bits)) & 0x1ff)

#define PML4OFF(v) _OFFSET(v, 39)
#define PDPOFF(v) _OFFSET(v, 30)
#define PDOFF(v) _OFFSET(v, 21)
#define PTOFF(v) _OFFSET(v, 12)

void map_one_page(uint64_t base, uint64_t offset,int prot,int c_bit){
  uint64_t vaddr = base +offset;
  uint64_t *pdp, *pd, *pt;
  #define PAGING(p, c) do { \
    if(!(*p & PDE64_PRESENT)) { \
      c = (uint64_t*) kframe_allocate_range_pt(1); \
      *p = PDE64_PRESENT | PDE64_RW | PDE64_USER |(uint64_t) c; \
    } else { \
      c = (uint64_t*) (*p & -0x1000); \
    } \
  } while(0);
  
  PAGING(&pml4[PML4OFF(vaddr)], pdp);
  PAGING(&pdp[PDPOFF(vaddr)], pd);
  PAGING(&pd[PDOFF(vaddr)], pt);
#undef PAGING
  uint64_t c_bit_mask = 1<<c_bit;
  pt[PTOFF(vaddr)] = PDE64_PRESENT | base | c_bit_mask;
  if(prot & PROT_R) pt[PTOFF(vaddr)] |= PDE64_USER;
  if(prot & PROT_W) pt[PTOFF(vaddr)] |= PDE64_RW;
}

//base size and offset should be page size aligned
void map_address(uint64_t base, uint64_t size, uint64_t offset, int prot){
  if(base&0xfff||size&0xfff||offset&0xfff){
    write_in_console("Invalid mapping address! base,size and offset should be page aligned!");
  }
  if(prot&-0x4){
    write_in_console("Invalid mapping prot!");
  }
  int c_bit = get_cbit();
  if(c_bit ==0){
    panic("invalid c_bit!\n");
  }
  for(int i=0;i<size/0x1000;i++){
    map_one_page(base+0x1000*i,offset,prot,c_bit);
  }
  
}
void init_kernel_page_tables()
{
  unsigned char buffer[20] = {0};
  /*
  write_in_console("Strat hob parsing to get e820 table in kernel.\n");
  
  uint64_to_string(hob,buffer);
  write_in_console("Parameters: hob: 0x");
  write_in_console((char*)buffer);
  write_in_console(", _payload: 0x");
  uint64_to_string(_payload,buffer);
  write_in_console((char*)buffer);
  write_in_console("\n");


  uint64_t hob_size =  parse_hob_get_size(hob);
  write_in_console("Get hob size: 0x");
  uint64_to_string(hob_size,buffer);
  write_in_console((char*)buffer);
  write_in_console("\n");

  struct e820_table parsed_e820_table = get_e820_table_from_hob((uint8_t *)hob,hob_size);
  memory_map_num_entries = parsed_e820_table.num_entries;
  write_in_console("Get parsed_e820_table, number of entries: 0x");
  uint64_to_string(parsed_e820_table.num_entries,buffer);
  write_in_console((char*)buffer);
  write_in_console("\n");

  uint64_to_string((uint64_t)&memory_map,buffer);
  write_in_console("Memory map location: 0x");
  write_in_console((char*)buffer);
  write_in_console("\n");
  
  memcpy(memory_map,parsed_e820_table.e820_entry,parsed_e820_table.num_entries * sizeof(struct e820_entry));
  write_in_console("Parsing e820 table finished.Memory map was initialized.\n");
  */
  memory_map[0].address=0x0;
  memory_map[0].type = E820_RAM;
  memory_map[0].length = 0x7ddde000;

 
 
  //write_in_console("Start setting up page table.\n");
  uint64_t page_table = get_usable(KERNEL_PAGING_SIZE);
  //write_in_console("Page table address:0x");
  memset((uint64_t*)page_table,0x0,KERNEL_PAGING_SIZE);
  kframe_allocator_init_pt(page_table,KERNEL_PAGING_SIZE);
  //uint64_to_string((uint64_t)page_table,buffer);
  //write_in_console((char*)buffer);
  //write_in_console("\n");

  pml4 = (uint64_t*)kframe_allocate_range_pt(1);

  for(int i=0;i<10;i++){
    map_address(pt_config[i].start,pt_config[i].size,pt_config[i].offset,pt_config[i].prot);
  }

 //EFER_LME | EFER_LMA| EFER_SCE have been set, just set new cr3
 
  
  
}


uint64_t get_usable(uint64_t size){
    for(int i=0;i<memory_map_num_entries;i++){
        if(memory_map[i].type == E820_RAM && memory_map[i].length >=size){
            memory_map[i].length -= size;
            return memory_map[i].address+memory_map[i].length;
        }
    }
    panic("Out of memory, cannot get usable memory.");
    return -1;
}