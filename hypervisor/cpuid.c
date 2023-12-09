#include <linux/kvm.h>
#include <sys/mman.h>
#include <linux/unistd.h>
#include <assert.h>
#include "cpuid.h"

#define U_CET_MASK BIT(11)
#define S_CET_MASK BIT(12)
#define XSS_LBRS_MASK BIT(15)
#define XSAVE_XSS_MASK U_CET_MASK|XSS_LBRS_MASK
#define KVM_MAX_CPUID_ENTRIES  100
#define CPUID_VENDOR_INTEL_1 0x756e6547 /* "Genu" */
#define CPUID_VENDOR_INTEL_2 0x49656e69 /* "ineI" */
#define CPUID_VENDOR_INTEL_3 0x6c65746e /* "ntel" */
static struct kvm_tdx_capabilities *tdx_caps;
static struct kvm_cpuid2 *cpuid_cache;
static struct kvm_msr_list *kvm_feature_msrs;
static int kvmfd ;
typedef struct CPUX86State{
    bool cache_info_passthrough;
    bool enable_pmu;
    bool enable_cpuid_0xb;
    bool expose_tcg;
    FeatureWordArray features;
    FeatureWordArray filtered_features;
    unsigned nr_dies;
    uint32_t cpuid_level_func7;
    /* Actual level/xlevel/xlevel2 value: */
    uint32_t cpuid_level, cpuid_xlevel, cpuid_xlevel2;
    uint32_t cpuid_vendor1;
    uint32_t cpuid_vendor2;
    uint32_t cpuid_vendor3;
    uint32_t cpuid_version;
    uint32_t apic_id;
    uint32_t cr[5];
    uint64_t xcr0;

    uint32_t phys_bits;
    int nr_cores;
    int nr_threads;
    bool enable_l3_cache;
    CPUCaches cache_info_cpuid2,cache_info_cpuid4,cache_info_amd;
    struct {
        uint32_t eax;
        uint32_t ebx;
        uint32_t ecx;
        uint32_t edx;
    } mwait;
    uint32_t cpuid_model[12];
}CPUX86State;

void set_para_cpuid(struct kvm_tdx_init_vm *para){
  para->cpuid.entries[0].function=0x0;
  para->cpuid.entries[0].index=0x0;
  para->cpuid.entries[0].flags=0x0;
  para->cpuid.entries[0].eax=0x1f;
  para->cpuid.entries[0].ebx=0x756e6547;
  para->cpuid.entries[0].ecx=0x6c65746e;
  para->cpuid.entries[0].edx=0x49656e69;

  para->cpuid.entries[1].function=0x1;
  para->cpuid.entries[1].index=0x0;
  para->cpuid.entries[1].flags=0x0;
  para->cpuid.entries[1].eax=0x806f8;
  para->cpuid.entries[1].ebx=0x800;
  para->cpuid.entries[1].ecx=0xfffaba17;
  para->cpuid.entries[1].edx=0x3fabfbff;
  
  para->cpuid.entries[2].function=0x2;
  para->cpuid.entries[2].index=0x0;
  para->cpuid.entries[2].flags=0x6;
  para->cpuid.entries[2].eax=0x1;
  para->cpuid.entries[2].ebx=0x0;
  para->cpuid.entries[2].ecx=0x4d;
  para->cpuid.entries[2].edx=0x2c307d;
  
  para->cpuid.entries[3].function=0x4;
  para->cpuid.entries[3].index=0x0;
  para->cpuid.entries[3].flags=0x1;
  para->cpuid.entries[3].eax=0x121;
  para->cpuid.entries[3].ebx=0x1c0003f;
  para->cpuid.entries[3].ecx=0x3f;
  para->cpuid.entries[3].edx=0x1;

  para->cpuid.entries[4].function=0x4;
  para->cpuid.entries[4].index=0x1;
  para->cpuid.entries[4].flags=0x1;
  para->cpuid.entries[4].eax=0x122;
  para->cpuid.entries[4].ebx=0x1c0003f;
  para->cpuid.entries[4].ecx=0x3f;
  para->cpuid.entries[4].edx=0x1;

  para->cpuid.entries[5].function=0x4;
  para->cpuid.entries[5].index=0x2;
  para->cpuid.entries[5].flags=0x1;
  para->cpuid.entries[5].eax=0x143;
  para->cpuid.entries[5].ebx=0x3c0003f;
  para->cpuid.entries[5].ecx=0xfff;
  para->cpuid.entries[5].edx=0x1;

  para->cpuid.entries[6].function=0x4;
  para->cpuid.entries[6].index=0x3;
  para->cpuid.entries[6].flags=0x1;
  para->cpuid.entries[6].eax=0x163;
  para->cpuid.entries[6].ebx=0x3c0003f;
  para->cpuid.entries[6].ecx=0x3fff;
  para->cpuid.entries[6].edx=0x6;

  para->cpuid.entries[7].function=0x4;
  para->cpuid.entries[7].index=0x4;
  para->cpuid.entries[7].flags=0x1;
  para->cpuid.entries[7].eax=0x0;
  para->cpuid.entries[7].ebx=0x0;
  para->cpuid.entries[7].ecx=0x0;
  para->cpuid.entries[7].edx=0x0;

  para->cpuid.entries[8].function=0x5;
  para->cpuid.entries[8].index=0x0;
  para->cpuid.entries[8].flags=0x0;
  para->cpuid.entries[8].eax=0x0;
  para->cpuid.entries[8].ebx=0x0;
  para->cpuid.entries[8].ecx=0x3;
  para->cpuid.entries[8].edx=0x0;

  para->cpuid.entries[9].function=0x6;
  para->cpuid.entries[9].index=0x0;
  para->cpuid.entries[9].flags=0x0;
  para->cpuid.entries[9].eax=0x4;
  para->cpuid.entries[9].ebx=0x0;
  para->cpuid.entries[9].ecx=0x0;
  para->cpuid.entries[9].edx=0x0;

  para->cpuid.entries[10].function=0x7;
  para->cpuid.entries[10].index=0x0;
  para->cpuid.entries[10].flags=0x1;
  para->cpuid.entries[10].eax=0x1;
  para->cpuid.entries[10].ebx=0xf1bf2ff9;
  para->cpuid.entries[10].ecx=0x1b415ffe;
  para->cpuid.entries[10].edx=0xffd94412;

  para->cpuid.entries[11].function=0x7;
  para->cpuid.entries[11].index=0x1;
  para->cpuid.entries[11].flags=0x1;
  para->cpuid.entries[11].eax=0x1c30;
  para->cpuid.entries[11].ebx=0x0;
  para->cpuid.entries[11].ecx=0x0;
  para->cpuid.entries[11].edx=0x0;

  para->cpuid.entries[12].function=0x7;
  para->cpuid.entries[12].index=0x2;
  para->cpuid.entries[12].flags=0x1;
  para->cpuid.entries[12].eax=0x0;
  para->cpuid.entries[12].ebx=0x0;
  para->cpuid.entries[12].ecx=0x0;
  para->cpuid.entries[12].edx=0x0;

  para->cpuid.entries[13].function=0xb;
  para->cpuid.entries[13].index=0x0;
  para->cpuid.entries[13].flags=0x1;
  para->cpuid.entries[13].eax=0x0;
  para->cpuid.entries[13].ebx=0x1;
  para->cpuid.entries[13].ecx=0x100;
  para->cpuid.entries[13].edx=0x0;

  para->cpuid.entries[14].function=0xb;
  para->cpuid.entries[14].index=0x1;
  para->cpuid.entries[14].flags=0x1;
  para->cpuid.entries[14].eax=0x0;
  para->cpuid.entries[14].ebx=0x1;
  para->cpuid.entries[14].ecx=0x201;
  para->cpuid.entries[14].edx=0x0;

  para->cpuid.entries[15].function=0xb;
  para->cpuid.entries[15].index=0x2;
  para->cpuid.entries[15].flags=0x1;
  para->cpuid.entries[15].eax=0x0;
  para->cpuid.entries[15].ebx=0x0;
  para->cpuid.entries[15].ecx=0x2;
  para->cpuid.entries[15].edx=0x0;

  para->cpuid.entries[16].function=0xd;
  para->cpuid.entries[16].index=0x0;
  para->cpuid.entries[16].flags=0x1;
  para->cpuid.entries[16].eax=0x602e7;
  para->cpuid.entries[16].ebx=0x2b00;
  para->cpuid.entries[16].ecx=0x2b00;
  para->cpuid.entries[16].edx=0x0;

  para->cpuid.entries[17].function=0xd;
  para->cpuid.entries[17].index=0x1;
  para->cpuid.entries[17].flags=0x1;
  para->cpuid.entries[17].eax=0x1f;
  para->cpuid.entries[17].ebx=0x2d00;
  para->cpuid.entries[17].ecx=0x1800;
  para->cpuid.entries[17].edx=0x0;

  para->cpuid.entries[18].function=0xd;
  para->cpuid.entries[18].index=0x2;
  para->cpuid.entries[18].flags=0x1;
  para->cpuid.entries[18].eax=0x100;
  para->cpuid.entries[18].ebx=0x240;
  para->cpuid.entries[18].ecx=0x0;
  para->cpuid.entries[18].edx=0x0;

  para->cpuid.entries[19].function=0xd;
  para->cpuid.entries[19].index=0x5;
  para->cpuid.entries[19].flags=0x1;
  para->cpuid.entries[19].eax=0x40;
  para->cpuid.entries[19].ebx=0x440;
  para->cpuid.entries[19].ecx=0x0;
  para->cpuid.entries[19].edx=0x0;

  para->cpuid.entries[20].function=0xd;
  para->cpuid.entries[20].index=0x6;
  para->cpuid.entries[20].flags=0x1;
  para->cpuid.entries[20].eax=0x200;
  para->cpuid.entries[20].ebx=0x480;
  para->cpuid.entries[20].ecx=0x0;
  para->cpuid.entries[20].edx=0x0;

  para->cpuid.entries[21].function=0xd;
  para->cpuid.entries[21].index=0x7;
  para->cpuid.entries[21].flags=0x1;
  para->cpuid.entries[21].eax=0x400;
  para->cpuid.entries[21].ebx=0x680;
  para->cpuid.entries[21].ecx=0x0;
  para->cpuid.entries[21].edx=0x0;

  para->cpuid.entries[22].function=0xd;
  para->cpuid.entries[22].index=0x9;
  para->cpuid.entries[22].flags=0x1;
  para->cpuid.entries[22].eax=0x8;
  para->cpuid.entries[22].ebx=0xa80;
  para->cpuid.entries[22].ecx=0x0;
  para->cpuid.entries[22].edx=0x0;

  para->cpuid.entries[23].function=0xd;
  para->cpuid.entries[23].index=0xb;
  para->cpuid.entries[23].flags=0x1;
  para->cpuid.entries[23].eax=0x10;
  para->cpuid.entries[23].ebx=0x0;
  para->cpuid.entries[23].ecx=0x1;
  para->cpuid.entries[23].edx=0x0;

  para->cpuid.entries[24].function=0xd;
  para->cpuid.entries[24].index=0xf;
  para->cpuid.entries[24].flags=0x1;
  para->cpuid.entries[24].eax=0x328;
  para->cpuid.entries[24].ebx=0x0;
  para->cpuid.entries[24].ecx=0x1;
  para->cpuid.entries[24].edx=0x0;

  para->cpuid.entries[25].function=0xd;
  para->cpuid.entries[25].index=0x11;
  para->cpuid.entries[25].flags=0x1;
  para->cpuid.entries[25].eax=0x40;
  para->cpuid.entries[25].ebx=0xac0;
  para->cpuid.entries[25].ecx=0x2;
  para->cpuid.entries[25].edx=0x0;
  
  para->cpuid.entries[26].function=0xd;
  para->cpuid.entries[26].index=0x12;
  para->cpuid.entries[26].flags=0x1;
  para->cpuid.entries[26].eax=0x2000;
  para->cpuid.entries[26].ebx=0xb00;
  para->cpuid.entries[26].ecx=0x6;
  para->cpuid.entries[26].edx=0x0;

  para->cpuid.entries[27].function=0xd;
  para->cpuid.entries[27].index=0x3f;
  para->cpuid.entries[27].flags=0x1;
  para->cpuid.entries[27].eax=0x0;
  para->cpuid.entries[27].ebx=0x0;
  para->cpuid.entries[27].ecx=0x0;
  para->cpuid.entries[27].edx=0x0;

  para->cpuid.entries[28].function=0x12;
  para->cpuid.entries[28].index=0x0;
  para->cpuid.entries[28].flags=0x1;
  para->cpuid.entries[28].eax=0x0;
  para->cpuid.entries[28].ebx=0x0;
  para->cpuid.entries[28].ecx=0x0;
  para->cpuid.entries[28].edx=0x0;

  para->cpuid.entries[29].function=0x12;
  para->cpuid.entries[29].index=0x1;
  para->cpuid.entries[29].flags=0x1;
  para->cpuid.entries[29].eax=0x0;
  para->cpuid.entries[29].ebx=0x0;
  para->cpuid.entries[29].ecx=0x0;
  para->cpuid.entries[29].edx=0x0;

  para->cpuid.entries[30].function=0x12;
  para->cpuid.entries[30].index=0x2;
  para->cpuid.entries[30].flags=0x1;
  para->cpuid.entries[30].eax=0x0;
  para->cpuid.entries[30].ebx=0x0;
  para->cpuid.entries[30].ecx=0x0;
  para->cpuid.entries[30].edx=0x0;

  para->cpuid.entries[31].function=0x14;
  para->cpuid.entries[31].index=0x0;
  para->cpuid.entries[31].flags=0x1;
  para->cpuid.entries[31].eax=0x0;
  para->cpuid.entries[31].ebx=0x0;
  para->cpuid.entries[31].ecx=0x0;
  para->cpuid.entries[31].edx=0x0;

  para->cpuid.entries[32].function=0x1d;
  para->cpuid.entries[32].index=0x0;
  para->cpuid.entries[32].flags=0x1;
  para->cpuid.entries[32].eax=0x1;
  para->cpuid.entries[32].ebx=0x0;
  para->cpuid.entries[32].ecx=0x0;
  para->cpuid.entries[32].edx=0x0;

  para->cpuid.entries[33].function=0x1d;
  para->cpuid.entries[33].index=0x1;
  para->cpuid.entries[33].flags=0x1;
  para->cpuid.entries[33].eax=0x4002000;
  para->cpuid.entries[33].ebx=0x80040;
  para->cpuid.entries[33].ecx=0x10;
  para->cpuid.entries[33].edx=0x0;
  
  para->cpuid.entries[34].function=0x1e;
  para->cpuid.entries[34].index=0x0;
  para->cpuid.entries[34].flags=0x1;
  para->cpuid.entries[34].eax=0x0;
  para->cpuid.entries[34].ebx=0x4010;
  para->cpuid.entries[34].ecx=0x0;
  para->cpuid.entries[34].edx=0x0;

  para->cpuid.entries[35].function=0x80000000;
  para->cpuid.entries[35].index=0x0;
  para->cpuid.entries[35].flags=0x0;
  para->cpuid.entries[35].eax=0x80000008;
  para->cpuid.entries[35].ebx=0x756e6547;
  para->cpuid.entries[35].ecx=0x6c65746e;
  para->cpuid.entries[35].edx=0x49656e69;

  para->cpuid.entries[36].function=0x80000001;
  para->cpuid.entries[36].index=0x0;
  para->cpuid.entries[36].flags=0x0;
  para->cpuid.entries[36].eax=0x806f8;
  para->cpuid.entries[36].ebx=0x0;
  para->cpuid.entries[36].ecx=0x121;
  para->cpuid.entries[36].edx=0x2d93fbff;

  para->cpuid.entries[37].function=0x80000002;
  para->cpuid.entries[37].index=0x0;
  para->cpuid.entries[37].flags=0x0;
  para->cpuid.entries[37].eax=0x65746e49;
  para->cpuid.entries[37].ebx=0x2952286c;
  para->cpuid.entries[37].ecx=0x6f655820;
  para->cpuid.entries[37].edx=0x2952286e;

  para->cpuid.entries[38].function=0x80000003;
  para->cpuid.entries[38].index=0x0;
  para->cpuid.entries[38].flags=0x0;
  para->cpuid.entries[38].eax=0x616c5020;
  para->cpuid.entries[38].ebx=0x756e6974;
  para->cpuid.entries[38].ecx=0x3438206d;
  para->cpuid.entries[38].edx=0x54433038;

  para->cpuid.entries[39].function=0x80000004;
  para->cpuid.entries[39].index=0x0;
  para->cpuid.entries[39].flags=0x0;
  para->cpuid.entries[39].eax=0x5844;
  para->cpuid.entries[39].ebx=0x0;
  para->cpuid.entries[39].ecx=0x0;
  para->cpuid.entries[39].edx=0x0;

  para->cpuid.entries[40].function=0x80000005;
  para->cpuid.entries[40].index=0x0;
  para->cpuid.entries[40].flags=0x0;
  para->cpuid.entries[40].eax=0x1ff01ff;
  para->cpuid.entries[40].ebx=0x1ff01ff;
  para->cpuid.entries[40].ecx=0x40020140;
  para->cpuid.entries[40].edx=0x40020140;
  
  para->cpuid.entries[41].function=0x80000006;
  para->cpuid.entries[41].index=0x0;
  para->cpuid.entries[41].flags=0x0;
  para->cpuid.entries[41].eax=0x0;
  para->cpuid.entries[41].ebx=0x42004200;
  para->cpuid.entries[41].ecx=0x2008140;
  para->cpuid.entries[41].edx=0x0;

  para->cpuid.entries[42].function=0x80000007;
  para->cpuid.entries[42].index=0x0;
  para->cpuid.entries[42].flags=0x0;
  para->cpuid.entries[42].eax=0x0;
  para->cpuid.entries[42].ebx=0x0;
  para->cpuid.entries[42].ecx=0x0;
  para->cpuid.entries[42].edx=0x100;

  para->cpuid.entries[43].function=0x80000008;
  para->cpuid.entries[43].index=0x0;
  para->cpuid.entries[43].flags=0x0;
  para->cpuid.entries[43].eax=0x3934;
  para->cpuid.entries[43].ebx=0x200;
  para->cpuid.entries[43].ecx=0x0;
  para->cpuid.entries[43].edx=0x0;

  para->cpuid.nent=44;

}

void set_para_cpuid_test(struct kvm_tdx_init_vm *para, struct kvm_tdx_capabilities *caps)
{

  
  
  //Set CPUID in capbilities
  para->cpuid.nent = caps->nr_cpuid_configs+2;
  for (int i = 0; i < caps->nr_cpuid_configs; i++)
  {
    para->cpuid.entries[i].function = caps->cpuid_configs[i].leaf;
    para->cpuid.entries[i].index = caps->cpuid_configs[i].sub_leaf;
    __asm__("mov %4, %%eax\n\t"
            "mov %5, %%ecx\n\t"
            "cpuid \n\t "
            "mov %%eax, %0\n\t"
            "mov %%ebx, %1\n\t"
            "mov %%ecx, %2\n\t"
            "mov %%edx, %3\n\t"
            : "=m"(para->cpuid.entries[i].eax), "=m"(para->cpuid.entries[i].ebx),
              "=m"(para->cpuid.entries[i].ecx), "=m"(para->cpuid.entries[i].edx)
            : "m"(caps->cpuid_configs[i].leaf), "m"(caps->cpuid_configs[i].sub_leaf)
            : "%eax", "%ebx", "%ecx", "%edx");
    para->cpuid.entries[i].eax &= caps->cpuid_configs[i].eax;
    para->cpuid.entries[i].ebx &= caps->cpuid_configs[i].ebx;
    para->cpuid.entries[i].ecx &= caps->cpuid_configs[i].ecx;
    para->cpuid.entries[i].edx &= caps->cpuid_configs[i].edx;

    //disable MWAIT/MONIOR which will cause -EINVAL
    if(para->cpuid.entries[i].function==0x1){
      __u64 mask = BIT(3);
      para->cpuid.entries[i].ecx &= ~mask;
    }
  }
  
  para->cpuid.entries[caps->nr_cpuid_configs].function = 0xd;
  para->cpuid.entries[caps->nr_cpuid_configs+1].function = 0xd;
  para->cpuid.entries[caps->nr_cpuid_configs].index = 0x0;
  para->cpuid.entries[caps->nr_cpuid_configs+1].index = 0x1;
  //Set other CPUID needed for implicit XFAM setting
  for(int i = caps->nr_cpuid_configs; i < caps->nr_cpuid_configs+2;i++){
    __asm__("mov %4, %%eax\n\t"
            "mov %5, %%ecx\n\t"
            "cpuid \n\t "
            "mov %%eax, %0\n\t"
            "mov %%ebx, %1\n\t"
            "mov %%ecx, %2\n\t"
            "mov %%edx, %3\n\t"
            : "=m"(para->cpuid.entries[i].eax), "=m"(para->cpuid.entries[i].ebx),
              "=m"(para->cpuid.entries[i].ecx), "=m"(para->cpuid.entries[i].edx)
            : "m"(para->cpuid.entries[i].function), "m"(para->cpuid.entries[i].index)
            : "%eax", "%ebx", "%ecx", "%edx");
  }
  __u32 xfam_fixed0_low = caps->xfam_fixed0 &0xFFFFFFFF;
  __u32 xfam_fixed0_high = caps->xfam_fixed0 >> 32;
  __u32 xfam_fixed1_low = caps->xfam_fixed1 &0xFFFFFFFF;
  __u32 xfam_fixed1_high = caps->xfam_fixed1 >> 32;
  //set xfam restrictions
  para->cpuid.entries[caps->nr_cpuid_configs].eax&=xfam_fixed0_low;
  para->cpuid.entries[caps->nr_cpuid_configs].eax|=xfam_fixed1_low;
  para->cpuid.entries[caps->nr_cpuid_configs].edx&=xfam_fixed0_high;
  para->cpuid.entries[caps->nr_cpuid_configs].edx|=xfam_fixed1_high;
  para->cpuid.entries[caps->nr_cpuid_configs+1].ecx&=xfam_fixed0_low;
  para->cpuid.entries[caps->nr_cpuid_configs+1].ecx|=xfam_fixed1_low;
  para->cpuid.entries[caps->nr_cpuid_configs+1].edx&=xfam_fixed0_high;
  para->cpuid.entries[caps->nr_cpuid_configs+1].edx|=xfam_fixed1_high;

  para->cpuid.entries[caps->nr_cpuid_configs+1].ecx&=XSAVE_XSS_MASK;

  //close XSS_LBRS not support yet
  para->cpuid.entries[caps->nr_cpuid_configs+1].ecx&=~XSS_LBRS_MASK;
  //Set bit S_CET Bit, which should be same as the U_CET BIT
  if(para->cpuid.entries[caps->nr_cpuid_configs+1].ecx&U_CET_MASK){
    para->cpuid.entries[caps->nr_cpuid_configs+1].ecx|=S_CET_MASK;
  }
  for(int i=0;i<para->cpuid.nent;i++){
    if(para->cpuid.entries[i].index!=0xFFFFFFFF){
      para->cpuid.entries[i].flags=KVM_CPUID_FLAG_SIGNIFCANT_INDEX;
    }
  }

  return;
}

struct cpuid_data{
  struct kvm_cpuid2 cpuid;
  struct kvm_cpuid_entry2 entries[100];
};

void initialize_cpuid2(struct cpuid_data *cpuid_data, struct kvm_tdx_init_vm *vm_paras,CPUX86State *env){
  
  cpuid_data->cpuid.nent = 47;
  cpuid_data->cpuid.padding = 0x0;

  for(int i=0;i<44;i++){
    cpuid_data->entries[0]= vm_paras->entries[0];
  }
  uint32_t signature[3];
  int kvm_base = KVM_CPUID_SIGNATURE;
  memcpy(signature, "KVMKVMKVM\0\0\0", 12);

  cpuid_data->entries[44].function=KVM_CPUID_SIGNATURE | kvm_base;;
  cpuid_data->entries[44].index=0x0;
  cpuid_data->entries[44].flags=0x0;
  cpuid_data->entries[44].eax=KVM_CPUID_FEATURES | kvm_base;
  cpuid_data->entries[44].ebx=signature[0];
  cpuid_data->entries[44].ecx=signature[1];
  cpuid_data->entries[44].edx=signature[2];
  
  cpuid_data->entries[45].function=KVM_CPUID_FEATURES | kvm_base;
  cpuid_data->entries[45].index=0x0;
  cpuid_data->entries[45].flags=0x0;
  cpuid_data->entries[45].eax=env->features[FEAT_KVM];
  cpuid_data->entries[45].ebx=0x0;
  cpuid_data->entries[45].ecx=0x0;
  cpuid_data->entries[45].edx=env->features[FEAT_KVM_HINTS];

  cpuid_data->entries[46].function=KVM_CPUID_SIGNATURE | 0x10;
  cpuid_data->entries[46].index=0x0;
  cpuid_data->entries[46].flags=0x0;
  cpuid_data->entries[46].eax=0x1e8480;//tsc_khz
  cpuid_data->entries[46].ebx=0xf4240;//apic_bus_freq khz
  cpuid_data->entries[46].ecx=0x0;
  cpuid_data->entries[46].edx=0x0;

  }

static uint64_t tdx_disallow_minus_bits(FeatureWord w)
{
    FeatureWordInfo *wi = &feature_word_info[w];
    uint64_t ret = 0;
    int i;

    /*
     * TODO:
     * enable MSR feature configuration for TDX, disallow MSR feature
     * manipulation for TDX for now
     */
    if (wi->type == MSR_FEATURE_WORD) {
        return ~0ull;
    }

    /*
     * inducing_ve type is fully configured by VMM, i.e., all are allowed
     * to be removed
     */
    if (tdx_cpuid_lookup[w].inducing_ve) {
        return 0;
    }

    ret = tdx_cpuid_lookup[w].tdx_fixed1;

    for (i = 0; i < 16; i++) {
        FeatureDep *d = &xfam_dependencies[i];
        if (w == d->to.index) {
            ret |= d->to.mask;
        }
    }

    for (i = 0; i < 19; i++) {
        FeatureMask *fm = &tdx_xfam_representative[i];
        if (w == fm->index) {
            ret &= ~fm->mask;
        }
    }

    return ret;
}

static uint64_t tdx_get_xfam_bitmask(FeatureWord w, uint64_t bit_mask)
{
    int i;

    for (i = 0; i < 16; i++) {
        FeatureDep *d = &xfam_dependencies[i];
        if (w == d->to.index && bit_mask & d->to.mask) {
            return d->from.mask;
        }
    }
    return 0;
}

static int is_tdx_xfam_representative(FeatureWord w, uint64_t bit_mask)
{
    int i;

    for (i = 0; i < 19; i++) {
        FeatureMask *fm = &tdx_xfam_representative[i];
        if (w == fm->index && bit_mask & fm->mask) {
            return i;
        }
    }
    return -1;
}



static const char *tdx_xfam_representative_name(uint64_t xfam_mask)
{
    uint32_t delegate_index, delegate_feature;
    int bitnr, delegate_bitnr;
    const char *name;

    bitnr = ctz32(xfam_mask);
    delegate_index = tdx_xfam_representative[bitnr].index;
    delegate_feature = tdx_xfam_representative[bitnr].mask;
    delegate_bitnr = ctz32(delegate_feature);
    /* get XFAM feature delegate feature name */
    name = feature_word_info[delegate_index].feat_names[delegate_bitnr];
    assert(delegate_bitnr < 32 ||
           !(name &&
             feature_word_info[delegate_index].type == CPUID_FEATURE_WORD));
    return name;
}

static const char *get_register_name_32(unsigned int reg)
{
    if (reg >= CPU_NB_REGS32) {
        return NULL;
    }
    return x86_reg_info_32[reg].name;
}

char *feature_word_description(FeatureWordInfo *f, uint32_t bit)
{
    assert(f->type == CPUID_FEATURE_WORD || f->type == MSR_FEATURE_WORD);

    switch (f->type) {
    case CPUID_FEATURE_WORD:
        {
            const char *reg = get_register_name_32(f->cpuid.reg);
            assert(reg);
            return g_strdup_printf("CPUID.%02XH:%s",
                                   f->cpuid.eax, reg);
        }
    case MSR_FEATURE_WORD:
        return g_strdup_printf("MSR(%02XH)",
                               f->msr.index);
    }

    return NULL;
}

void tdx_check_minus_features(CPUX86State *env)
{
    FeatureWordInfo *wi;
    FeatureWord w;
    uint64_t disallow_minus_bits;
    uint64_t bitmask, xfam_controlling_mask;
    int i;

    char *reason;
    char xfam_dependency_str[100];
    char usual[]="TDX limitation";

    for (w = 0; w < FEATURE_WORDS; w++) {
        wi = &feature_word_info[w];

        if (wi->type == MSR_FEATURE_WORD) {
            continue;
        }

        disallow_minus_bits = /*env->user_minus_features[w] & */tdx_disallow_minus_bits(w);

        for (i = 0; i < 64; i++) {
            bitmask = 1ULL << i;
            if (!(bitmask & disallow_minus_bits)) {
                continue;
            }

            xfam_controlling_mask = tdx_get_xfam_bitmask(w, bitmask);
            if (xfam_controlling_mask && is_tdx_xfam_representative(w, bitmask) == -1) {
                /*
                 * cannot fix env->feature[w] here since whether the bit i is
                 * set or cleared depends on the setting of its XFAM
                 * representative feature bit
                 */
                snprintf(xfam_dependency_str, sizeof(xfam_dependency_str),
                         "it depends on XFAM representative feature (%s)",
                 g_strdup(tdx_xfam_representative_name(xfam_controlling_mask)));
                reason = xfam_dependency_str;
            } else {
                /* set bit i since this feature cannot be removed */
                env->features[w] |= bitmask;
                reason = usual;
            }

            g_autofree char *feature_word_str = feature_word_description(wi, i);
            warn_report("This feature cannot be removed becuase %s: %s%s%s [bit %d]",
                         reason, feature_word_str,
                         wi->feat_names[i] ? "." : "",
                         wi->feat_names[i] ?: "", i);
        }
    }
}

static struct kvm_cpuid2 *try_get_cpuid(int kvmfd, int max)
{
    struct kvm_cpuid2 *cpuid;
    int r, size;

    size = sizeof(*cpuid) + max * sizeof(*cpuid->entries);
    cpuid = (struct kvm_cpuid2 *)malloc(size);
    memset(cpuid,0x0,size);
    cpuid->nent = max;
    r = ioctl(kvmfd,KVM_GET_SUPPORTED_CPUID,cpuid);
    if (r == 0 && cpuid->nent >= max) {
        r = -E2BIG;
    }
    if (r < 0) {
        r = -errno;
        if (r == -E2BIG) {
            free(cpuid);
            return NULL;
        } else {
            fprintf(stderr, "KVM_GET_SUPPORTED_CPUID failed: %s\n",
                    strerror(-r));
            exit(1);
        }
    }
    return cpuid;
}

static struct kvm_cpuid2 *get_supported_cpuid(int kvmfd)
{
    struct kvm_cpuid2 *cpuid;
    int max = 1;

    if (cpuid_cache != NULL) {
        return cpuid_cache;
    }
    while ((cpuid = try_get_cpuid(kvmfd, max)) == NULL) {
        max *= 2;
    }
    cpuid_cache = cpuid;
    return cpuid;
}

static struct kvm_cpuid_entry2 *cpuid_find_entry(struct kvm_cpuid2 *cpuid,
                                                 uint32_t function,
                                                 uint32_t index)
{
    int i;
    for (i = 0; i < cpuid->nent; ++i) {
        if (cpuid->entries[i].function == function &&
            cpuid->entries[i].index == index) {
            return &cpuid->entries[i];
        }
    }
    /* not found: */
    return NULL;
}

static uint32_t cpuid_entry_get_reg(struct kvm_cpuid_entry2 *entry, int reg)
{
    uint32_t ret = 0;
    switch (reg) {
    case R_EAX:
        ret = entry->eax;
        break;
    case R_EBX:
        ret = entry->ebx;
        break;
    case R_ECX:
        ret = entry->ecx;
        break;
    case R_EDX:
        ret = entry->edx;
        break;
    }
    return ret;
}

static FeatureWord get_cpuid_featureword_index(uint32_t function,
                                               uint32_t index, int reg)
{
    FeatureWord w;

    for (w = 0; w < FEATURE_WORDS; w++) {
        FeatureWordInfo *f = &feature_word_info[w];

        if (f->type == MSR_FEATURE_WORD || f->cpuid.eax != function ||
            f->cpuid.reg != reg ||
            (f->cpuid.needs_ecx && f->cpuid.ecx != index)) {
            continue;
        }

        return w;
    }

    return w;
}

void host_cpuid(uint32_t function, uint32_t count,
                uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx)
{
    uint32_t vec[4];

    asm volatile("cpuid"
                 : "=a"(vec[0]), "=b"(vec[1]),
                   "=c"(vec[2]), "=d"(vec[3])
                 : "0"(function), "c"(count) : "cc");
    if (eax)
        *eax = vec[0];
    if (ebx)
        *ebx = vec[1];
    if (ecx)
        *ecx = vec[2];
    if (edx)
        *edx = vec[3];
}

static inline uint32_t host_cpuid_reg(uint32_t function,
                                      uint32_t index, int reg)
{
    uint32_t eax, ebx, ecx, edx;
    uint32_t ret = 0;

    host_cpuid(function, index, &eax, &ebx, &ecx, &edx);

    switch (reg) {
    case R_EAX:
        ret |= eax;
        break;
    case R_EBX:
        ret |= ebx;
        break;
    case R_ECX:
        ret |= ecx;
        break;
    case R_EDX:
        ret |= edx;
        break;
    }
    return ret;
}

static inline uint32_t tdx_cap_cpuid_config(uint32_t function,
                                            uint32_t index, int reg)
{
    struct kvm_tdx_cpuid_config *cpuid_c;
    int ret = 0;
    int i;

    if (tdx_caps->nr_cpuid_configs <= 0) {
        return ret;
    }

    for (i = 0; i < tdx_caps->nr_cpuid_configs; i++) {
        cpuid_c = &tdx_caps->cpuid_configs[i];
        /* 0xffffffff in sub_leaf means the leaf doesn't require a sublesf */
        if (cpuid_c->leaf == function &&
            (cpuid_c->sub_leaf == 0xffffffff || cpuid_c->sub_leaf == index)) {
            switch (reg) {
            case R_EAX:
                ret = cpuid_c->eax;
                break;
            case R_EBX:
                ret = cpuid_c->ebx;
                break;
            case R_ECX:
                ret = cpuid_c->ecx;
                break;
            case R_EDX:
                ret = cpuid_c->edx;
                break;
            default:
                return 0;
            }
        }
    }
    return ret;
}
static inline bool kvm_enabled(){
    return true;
}
static inline bool hvf_enabled(){
    return true;
}
static inline bool tcg_enabled(){
    return true;
}
static inline bool accel_uses_host_cpuid(void)
{
    return kvm_enabled() || hvf_enabled();
}
void tdx_get_supported_cpuid(uint32_t function, uint32_t index, int reg,
                             uint32_t *ret)
{
    uint32_t vmm_cap = *ret;
    FeatureWord w;

    /* Only handle features leaves that recognized by feature_word_info[] */
    w = get_cpuid_featureword_index(function, index, reg);
    if (w == FEATURE_WORDS) {
        return;
    }

    if (tdx_cpuid_lookup[w].inducing_ve) {
        *ret &= tdx_cpuid_lookup[w].supported_on_ve;
        return;
    }

    /*
     * Include all the native bits as first step. It covers types
     * - As configured (if native)
     * - Native
     * - XFAM related and Attributes realted
     *
     * It also has side effect to enable unsupported bits, e.g., the
     * bits of "fixed0" type while present natively. It's safe because
     * the unsupported bits will be masked off by .fixed0 later.
     */
    *ret |= host_cpuid_reg(function, index, reg);

    /* Adjust according to "fixed" type in tdx_cpuid_lookup. */
    *ret |= tdx_cpuid_lookup[w].tdx_fixed1;
    *ret &= ~tdx_cpuid_lookup[w].tdx_fixed0;

    /*
     * Configurable cpuids are supported unconditionally. It's mainly to
     * include those configurable regardless of native existence.
     */
    *ret |= tdx_cap_cpuid_config(function, index, reg);

    /*
     * clear the configurable bits that require VMM emulation and VMM doesn't
     * report the support.
     */
    *ret &= ~(~vmm_cap & tdx_cpuid_lookup[w].vmm_fixup);

    /*if (function == 7 && index == 0 && reg == R_EBX && host_tsx_broken())
        *ret &= ~KVM_TSX_CPUID;
    */  
    bool enable_cpu_pm = false;
    if (function == 1 && reg == R_ECX && !enable_cpu_pm)
        *ret &= ~CPUID_EXT_MONITOR;
}

uint32_t kvm_arch_get_supported_cpuid(int kvmfd, uint32_t function,
                                      uint32_t index, int reg)
{
    struct kvm_cpuid2 *cpuid;
    uint32_t ret = 0;
    uint32_t cpuid_1_edx;
    uint64_t bitmask;

    cpuid = get_supported_cpuid(kvmfd);

    struct kvm_cpuid_entry2 *entry = cpuid_find_entry(cpuid, function, index);
    if (entry) {
        ret = cpuid_entry_get_reg(entry, reg);
    }

    /* Fixups for the data returned by KVM, below */

    if (function == 1 && reg == R_EDX) {
        /* KVM before 2.6.30 misreports the following features */
        ret |= CPUID_MTRR | CPUID_PAT | CPUID_MCE | CPUID_MCA;
    } else if (function == 1 && reg == R_ECX) {
        /* We can set the hypervisor flag, even if KVM does not return it on
         * GET_SUPPORTED_CPUID
         */
        ret |= CPUID_EXT_HYPERVISOR;
        /* tsc-deadline flag is not returned by GET_SUPPORTED_CPUID, but it
         * can be enabled if the kernel has KVM_CAP_TSC_DEADLINE_TIMER,
         * and the irqchip is in the kernel.
         */
        ret |= CPUID_EXT_TSC_DEADLINE_TIMER;
        
    } else if (function == 6 && reg == R_EAX) {
        ret |= CPUID_6_EAX_ARAT; /* safe to allow because of emulated APIC */
    } else if (function == 7 && index == 0 && reg == R_EBX) {
        /*if (host_tsx_broken()) {
            ret &= ~(CPUID_7_0_EBX_RTM | CPUID_7_0_EBX_HLE);
        }*/
    } else if (function == 7 && index == 0 && reg == R_EDX) {
        /*
         * Linux v4.17-v4.20 incorrectly return ARCH_CAPABILITIES on SVM hosts.
         * We can detect the bug by checking if MSR_IA32_ARCH_CAPABILITIES is
         * returned by KVM_GET_MSR_INDEX_LIST.
         */
        /*if (!has_msr_arch_capabs) {
            ret &= ~CPUID_7_0_EDX_ARCH_CAPABILITIES;
        }*/
    } else if (function == 0xd && index == 0 &&
               (reg == R_EAX || reg == R_EDX)) {
        /*
         * The value returned by KVM_GET_SUPPORTED_CPUID does not include
         * features that still have to be enabled with the arch_prctl
         * system call.  QEMU needs the full value, which is retrieved
         * with KVM_GET_DEVICE_ATTR.
         */
        struct kvm_device_attr attr = {
            .group = 0,
            .attr = KVM_X86_XCOMP_GUEST_SUPP,
            .addr = (unsigned long) &bitmask
        };

        bool sys_attr = ioctl(kvmfd, KVM_CHECK_EXTENSION, KVM_CAP_SYS_ATTRIBUTES);
        if (!sys_attr) {
            return ret;
        }

        int rc = ioctl(kvmfd, KVM_GET_DEVICE_ATTR, &attr);
        if (rc < 0) {
            if (rc != -ENXIO) {
                warn_report("KVM_GET_DEVICE_ATTR(0, KVM_X86_XCOMP_GUEST_SUPP) "
                            "error: %d", rc);
            }
            return ret;
        }
        ret = (reg == R_EAX) ? bitmask : bitmask >> 32;
    } else if (function == 0x80000001 && reg == R_ECX) {
        /*
         * It's safe to enable TOPOEXT even if it's not returned by
         * GET_SUPPORTED_CPUID.  Unconditionally enabling TOPOEXT here allows
         * us to keep CPU models including TOPOEXT runnable on older kernels.
         */
        ret |= CPUID_EXT3_TOPOEXT;
    } else if (function == 0x80000001 && reg == R_EDX) {
        /* On Intel, kvm returns cpuid according to the Intel spec,
         * so add missing bits according to the AMD spec:
         */
        cpuid_1_edx = kvm_arch_get_supported_cpuid(kvmfd, 1, 0, R_EDX);
        ret |= cpuid_1_edx & CPUID_EXT2_AMD_ALIASES;
    } else if (function == KVM_CPUID_FEATURES && reg == R_EAX) {
        /* kvm_pv_unhalt is reported by GET_SUPPORTED_CPUID, but it can't
         * be enabled without the in-kernel irqchip
         */
            ret |= 1U << KVM_FEATURE_MSI_EXT_DEST_ID;
    } else if (function == KVM_CPUID_FEATURES && reg == R_EDX) {
        #define KVM_HINTS_REALTIME      0
        ret |= 1U << KVM_HINTS_REALTIME;
    }

    tdx_get_supported_cpuid(function, index, reg, &ret);
    

    return ret;
}

uint64_t kvm_arch_get_supported_msr_feature(int kvmfd, uint32_t index)
{
    struct {
        struct kvm_msrs info;
        struct kvm_msr_entry entries[1];
    } msr_data = {};
    uint64_t value;
    uint32_t ret, can_be_one, must_be_one;

    if (kvm_feature_msrs == NULL) { /* Host doesn't support feature MSRs */
        return 0;
    }

    /* Check if requested MSR is supported feature MSR */
    int i;
    for (i = 0; i < kvm_feature_msrs->nmsrs; i++)
        if (kvm_feature_msrs->indices[i] == index) {
            break;
        }
    if (i == kvm_feature_msrs->nmsrs) {
        return 0; /* if the feature MSR is not supported, simply return 0 */
    }

    msr_data.info.nmsrs = 1;
    msr_data.entries[0].index = index;
    
    ret = ioctl(kvmfd, KVM_GET_MSRS, &msr_data);
    if (ret != 1) {
        error_report("KVM get MSR (index=0x%x) feature failed, %s",
            index, strerror(-ret));
        exit(1);
    }

    value = msr_data.entries[0].data;
    switch (index) {
    case MSR_IA32_VMX_PROCBASED_CTLS2:
    
        //if (!has_msr_vmx_procbased_ctls2) {
            /* KVM forgot to add these bits for some time, do this ourselves. *//*
            if (kvm_arch_get_supported_cpuid(s, 0xD, 1, R_ECX) &
                CPUID_XSAVE_XSAVES) {
                value |= (uint64_t)VMX_SECONDARY_EXEC_XSAVES << 32;
            }
            if (kvm_arch_get_supported_cpuid(s, 1, 0, R_ECX) &
                CPUID_EXT_RDRAND) {
                value |= (uint64_t)VMX_SECONDARY_EXEC_RDRAND_EXITING << 32;
            }
            if (kvm_arch_get_supported_cpuid(s, 7, 0, R_EBX) &
                CPUID_7_0_EBX_INVPCID) {
                value |= (uint64_t)VMX_SECONDARY_EXEC_ENABLE_INVPCID << 32;
            }
            if (kvm_arch_get_supported_cpuid(s, 7, 0, R_EBX) &
                CPUID_7_0_EBX_RDSEED) {
                value |= (uint64_t)VMX_SECONDARY_EXEC_RDSEED_EXITING << 32;
            }
            if (kvm_arch_get_supported_cpuid(s, 0x80000001, 0, R_EDX) &
                CPUID_EXT2_RDTSCP) {
                value |= (uint64_t)VMX_SECONDARY_EXEC_RDTSCP << 32;
            }
        }*/
        /* fall through */
    case MSR_IA32_VMX_TRUE_PINBASED_CTLS:
    case MSR_IA32_VMX_TRUE_PROCBASED_CTLS:
    case MSR_IA32_VMX_TRUE_ENTRY_CTLS:
    case MSR_IA32_VMX_TRUE_EXIT_CTLS:
        /*
         * Return true for bits that can be one, but do not have to be one.
         * The SDM tells us which bits could have a "must be one" setting,
         * so we can do the opposite transformation in make_vmx_msr_value.
         */
        must_be_one = (uint32_t)value;
        can_be_one = (uint32_t)(value >> 32);
        return can_be_one & ~must_be_one;

    default:
        return value;
    }
}
static uint64_t x86_cpu_get_migratable_flags(FeatureWord w)
{
    FeatureWordInfo *wi = &feature_word_info[w];
    uint64_t r = 0;
    int i;

    for (i = 0; i < 64; i++) {
        uint64_t f = 1ULL << i;

        /* If the feature name is known, it is implicitly considered migratable,
         * unless it is explicitly set in unmigratable_flags */
        if ((wi->migratable_flags & f) ||
            (wi->feat_names[i] && !(wi->unmigratable_flags & f))) {
            r |= f;
        }
    }
    return r;
}

uint64_t x86_cpu_get_supported_feature_word(FeatureWord w,
                                            bool migratable_only)
{
    FeatureWordInfo *wi = &feature_word_info[w];
    uint64_t r = 0;
    switch (wi->type) {
        case CPUID_FEATURE_WORD:
            r = kvm_arch_get_supported_cpuid(kvmfd, wi->cpuid.eax,
                                                        wi->cpuid.ecx,
                                                        wi->cpuid.reg);
            break;
        case MSR_FEATURE_WORD:
            r = kvm_arch_get_supported_msr_feature(kvmfd,
                        wi->msr.index);
            break;
        }
    if (wi->type == CPUID_FEATURE_WORD) {
        return r;
    }
    if (migratable_only) {
        r &= x86_cpu_get_migratable_flags(w);
    }
    return r;
    

}

void mark_unavailable_features(CPUX86State *env, FeatureWord w, uint64_t mask,
                               const char *verbose_prefix)
{
    FeatureWordInfo *f = &feature_word_info[w];
    int i;

    env->features[w] &= ~mask;
    
    env->filtered_features[w] |= mask;

    if (!verbose_prefix) {
        return;
    }

    for (i = 0; i < 64; ++i) {
        if ((1ULL << i) & mask) {
            g_autofree char *feat_word_str = feature_word_description(f, i);
            warn_report("%s: %s%s%s [bit %d]\n",
                        verbose_prefix,
                        feat_word_str,
                        f->feat_names[i] ? "." : "",
                        f->feat_names[i] ? f->feat_names[i] : "", i);
        }
    }
}

#define ARCH_REQ_XCOMP_GUEST_PERM       0x1025

void kvm_request_xsave_components(uint64_t mask)
{
    uint64_t supported;

    mask &= XSTATE_DYNAMIC_MASK;
    if (!mask) {
        return;
    }
    /*
     * Just ignore bits that are not in CPUID[EAX=0xD,ECX=0].
     * ARCH_REQ_XCOMP_GUEST_PERM would fail, and QEMU has warned
     * about them already because they are not supported features.
     */
    supported = kvm_arch_get_supported_cpuid(kvmfd, 0xd, 0, R_EAX);
    supported |= (uint64_t)kvm_arch_get_supported_cpuid(kvmfd, 0xd, 0, R_EDX) << 32;
    mask &= supported;

    while (mask) {
        int bit = ctz64(mask);
        int rc = syscall(__NR_arch_prctl, ARCH_REQ_XCOMP_GUEST_PERM, bit);
        if (rc) {
            /*
             * Older kernel version (<5.17) do not support
             * ARCH_REQ_XCOMP_GUEST_PERM, but also do not return
             * any dynamic feature from kvm_arch_get_supported_cpuid.
             */
            warn_report("prctl(ARCH_REQ_XCOMP_GUEST_PERM) failure "
                        "for feature bit %d", bit);
        }
        mask &= ~BIT_ULL(bit);
    }
}

static void x86_cpu_enable_xsave_components(CPUX86State *env)
{
    int i;
    uint64_t mask;
    static bool request_perm;

    if (!(env->features[FEAT_1_ECX] & CPUID_EXT_XSAVE)) {
        env->features[FEAT_XSAVE_XCR0_LO] = 0;
        env->features[FEAT_XSAVE_XCR0_HI] = 0;
        return;
    }

    mask = 0;
    for (i = 0; i < 19; i++) {
        const ExtSaveArea *esa = &x86_ext_save_areas[i];
        if (env->features[esa->feature] & esa->bits) {
            mask |= (1ULL << i);
        }

        /*
         * Both CET SHSTK and IBT feature requires XSAVES support, but two
         * features can be controlled independently by kernel, and we only
         * have one correlated bit set in x86_ext_save_areas, so if either
         * of two features is enabled, we set the XSAVES support bit to make
         * the enabled feature work.
         */
        if (i == XSTATE_CET_U_BIT) {
            uint64_t ecx = env->features[FEAT_7_0_ECX];
            uint64_t edx = env->features[FEAT_7_0_EDX];

            if ((ecx & CPUID_7_0_ECX_CET_SHSTK) ||
                (edx & CPUID_7_0_EDX_CET_IBT)) {
                mask |= (1ULL << i);
            }
        }
    }

    /* Only request permission from first vcpu. */
    if (!request_perm) {
        kvm_request_xsave_components(mask);
        request_perm = true;
    }

    env->features[FEAT_XSAVE_XCR0_LO] = mask & CPUID_XSTATE_XCR0_MASK;
    env->features[FEAT_XSAVE_XCR0_HI] = mask >> 32;
    env->features[FEAT_XSAVE_XSS_LO] = mask & CPUID_XSTATE_XSS_MASK;
    env->features[FEAT_XSAVE_XSS_HI] = mask >> 32;
}

void tdx_apply_xfam_dependencies(CPUX86State *env)
{
    int i;

    for (i = 0; i < 16; i++) {
        FeatureDep *d = &xfam_dependencies[i];
        if (!(env->features[d->from.index] & d->from.mask)) {
            uint64_t unavailable_features = env->features[d->to.index] & d->to.mask;

            /* Not an error unless the dependent feature was added explicitly */
            mark_unavailable_features(env, d->to.index,
                                     unavailable_features,
                                     "This feature cannot be enabled because its XFAM controlling bit is not enabled");
            env->features[d->to.index] &= ~unavailable_features;
        }
    }
}

void initialize_CPUX86State(CPUX86State *env){
    FeatureWord w;
    int i;
    //tdx_check_minus_features(env);
    for (w = 0; w < FEATURE_WORDS; w++) {
            /* Override only features that weren't set explicitly
             * by the user.
             */
            env->features[w] |=
                x86_cpu_get_supported_feature_word(w, true) &
                //~env->user_minus_features[w] &
                ~feature_word_info[w].no_autoenable_flags;
        }

    for (i = 0; i < 24; i++) {
        FeatureDep *d = &feature_dependencies[i];
        if (!(env->features[d->from.index] & d->from.mask)) {
            uint64_t unavailable_features = env->features[d->to.index] & d->to.mask;

            /* Not an error unless the dependent feature was added explicitly.  */
            mark_unavailable_features(env, d->to.index,
                                      unavailable_features,
                                      "This feature depends on other features that were not requested");

            env->features[d->to.index] &= ~unavailable_features;
        }
    }
    x86_cpu_enable_xsave_components(env);
    tdx_apply_xfam_dependencies(env);
    env->phys_bits = 0x34;
    env->nr_dies = 1;
    env->cpuid_level_func7 = 1;
    env->cpuid_level = 0x1f;
    env->cpuid_xlevel = 0x80000008;
    env->cpuid_xlevel2 = 0;
    env->cache_info_passthrough = false;
    env->enable_pmu = false;
    env->enable_cpuid_0xb = true;
    env->expose_tcg = true;
    env->cpuid_vendor1=CPUID_VENDOR_INTEL_1;
    env->cpuid_vendor2=CPUID_VENDOR_INTEL_2;
    env->cpuid_vendor3=CPUID_VENDOR_INTEL_3;

    env->cpuid_version = 0x806f8;
    env->apic_id = 0;
    env->nr_cores = 1;
    env->nr_threads = 1;

    env->enable_l3_cache = true;
    env->cache_info_cpuid2.l3_cache = (CPUCacheInfo *)malloc(sizeof(CPUCacheInfo));
    env->cache_info_cpuid2.l3_cache->type = 0x2;
    env->cache_info_cpuid2.l3_cache->level = 0x3;
    env->cache_info_cpuid2.l3_cache->size = 0x1000000;
    env->cache_info_cpuid2.l3_cache->line_size = 0x40;
    env->cache_info_cpuid2.l3_cache->associativity = 0x10;
    env->cache_info_cpuid2.l3_cache->partitions = 0x1;
    env->cache_info_cpuid2.l3_cache->sets = 0x4000;
    env->cache_info_cpuid2.l3_cache->lines_per_tag = 0x1;
    env->cache_info_cpuid2.l3_cache->self_init = 0x1;
    env->cache_info_cpuid2.l3_cache->no_invd_sharing = 0x0;
    env->cache_info_cpuid2.l3_cache->inclusive = 0x1;
    env->cache_info_cpuid2.l3_cache->complex_indexing = 0x1;

    env->cache_info_cpuid2.l2_cache = (CPUCacheInfo *)malloc(sizeof(CPUCacheInfo));
    env->cache_info_cpuid2.l2_cache->type = 0x2;
    env->cache_info_cpuid2.l2_cache->level = 0x2;
    env->cache_info_cpuid2.l2_cache->size = 0x200000;
    env->cache_info_cpuid2.l2_cache->line_size = 0x40;
    env->cache_info_cpuid2.l2_cache->associativity = 0x8;
    env->cache_info_cpuid2.l2_cache->partitions = 0x0;
    env->cache_info_cpuid2.l2_cache->sets = 0x0;
    env->cache_info_cpuid2.l2_cache->lines_per_tag = 0x0;
    env->cache_info_cpuid2.l2_cache->self_init = 0x0;
    env->cache_info_cpuid2.l2_cache->no_invd_sharing = 0x0;
    env->cache_info_cpuid2.l2_cache->inclusive = 0x0;
    env->cache_info_cpuid2.l2_cache->complex_indexing = 0x0;

    env->cache_info_cpuid2.l1d_cache = (CPUCacheInfo *)malloc(sizeof(CPUCacheInfo));
    env->cache_info_cpuid2.l1d_cache->type = 0x0;
    env->cache_info_cpuid2.l1d_cache->level = 0x1;
    env->cache_info_cpuid2.l1d_cache->size = 0x8000;
    env->cache_info_cpuid2.l1d_cache->line_size = 0x40;
    env->cache_info_cpuid2.l1d_cache->associativity = 0x8;
    env->cache_info_cpuid2.l1d_cache->partitions = 0x1;
    env->cache_info_cpuid2.l1d_cache->sets = 0x40;
    env->cache_info_cpuid2.l1d_cache->lines_per_tag = 0x0;
    env->cache_info_cpuid2.l1d_cache->self_init = 0x1;
    env->cache_info_cpuid2.l1d_cache->no_invd_sharing = 0x1;
    env->cache_info_cpuid2.l1d_cache->inclusive = 0x0;
    env->cache_info_cpuid2.l1d_cache->complex_indexing = 0x0;

    env->cache_info_cpuid2.l1i_cache = (CPUCacheInfo *)malloc(sizeof(CPUCacheInfo));
    env->cache_info_cpuid2.l1i_cache->type = 0x1;
    env->cache_info_cpuid2.l1i_cache->level = 0x1;
    env->cache_info_cpuid2.l1i_cache->size = 0x8000;
    env->cache_info_cpuid2.l1i_cache->line_size = 0x40;
    env->cache_info_cpuid2.l1i_cache->associativity = 0x8;
    env->cache_info_cpuid2.l1i_cache->partitions = 0x1;
    env->cache_info_cpuid2.l1i_cache->sets = 0x40;
    env->cache_info_cpuid2.l1i_cache->lines_per_tag = 0x0;
    env->cache_info_cpuid2.l1i_cache->self_init = 0x1;
    env->cache_info_cpuid2.l1i_cache->no_invd_sharing = 0x1;
    env->cache_info_cpuid2.l1i_cache->inclusive = 0x0;
    env->cache_info_cpuid2.l1i_cache->complex_indexing = 0x0;

    env->cache_info_cpuid4.l3_cache = (CPUCacheInfo *)malloc(sizeof(CPUCacheInfo));
    env->cache_info_cpuid4.l3_cache->type = 0x2;
    env->cache_info_cpuid4.l3_cache->level = 0x3;
    env->cache_info_cpuid4.l3_cache->size = 0x1000000;
    env->cache_info_cpuid4.l3_cache->line_size = 0x40;
    env->cache_info_cpuid4.l3_cache->associativity = 0x10;
    env->cache_info_cpuid4.l3_cache->partitions = 0x1;
    env->cache_info_cpuid4.l3_cache->sets = 0x4000;
    env->cache_info_cpuid4.l3_cache->lines_per_tag = 0x1;
    env->cache_info_cpuid4.l3_cache->self_init = 0x1;
    env->cache_info_cpuid4.l3_cache->no_invd_sharing = 0x0;
    env->cache_info_cpuid4.l3_cache->inclusive = 0x1;
    env->cache_info_cpuid4.l3_cache->complex_indexing = 0x1;

    env->cache_info_cpuid4.l2_cache = (CPUCacheInfo *)malloc(sizeof(CPUCacheInfo));
    env->cache_info_cpuid4.l2_cache->type = 0x2;
    env->cache_info_cpuid4.l2_cache->level = 0x2;
    env->cache_info_cpuid4.l2_cache->size = 0x400000;
    env->cache_info_cpuid4.l2_cache->line_size = 0x40;
    env->cache_info_cpuid4.l2_cache->associativity = 0x10;
    env->cache_info_cpuid4.l2_cache->partitions = 0x1;
    env->cache_info_cpuid4.l2_cache->sets = 0x1000;
    env->cache_info_cpuid4.l2_cache->lines_per_tag = 0x0;
    env->cache_info_cpuid4.l2_cache->self_init = 0x1;
    env->cache_info_cpuid4.l2_cache->no_invd_sharing = 0x1;
    env->cache_info_cpuid4.l2_cache->inclusive = 0x0;
    env->cache_info_cpuid4.l2_cache->complex_indexing = 0x0;

    env->cache_info_cpuid4.l1d_cache = (CPUCacheInfo *)malloc(sizeof(CPUCacheInfo));
    env->cache_info_cpuid4.l1d_cache->type = 0x0;
    env->cache_info_cpuid4.l1d_cache->level = 0x1;
    env->cache_info_cpuid4.l1d_cache->size = 0x8000;
    env->cache_info_cpuid4.l1d_cache->line_size = 0x40;
    env->cache_info_cpuid4.l1d_cache->associativity = 0x8;
    env->cache_info_cpuid4.l1d_cache->partitions = 0x1;
    env->cache_info_cpuid4.l1d_cache->sets = 0x40;
    env->cache_info_cpuid4.l1d_cache->lines_per_tag = 0x0;
    env->cache_info_cpuid4.l1d_cache->self_init = 0x1;
    env->cache_info_cpuid4.l1d_cache->no_invd_sharing = 0x1;
    env->cache_info_cpuid4.l1d_cache->inclusive = 0x0;
    env->cache_info_cpuid4.l1d_cache->complex_indexing = 0x0;

    env->cache_info_cpuid4.l1i_cache = (CPUCacheInfo *)malloc(sizeof(CPUCacheInfo));
    env->cache_info_cpuid4.l1i_cache->type = 0x1;
    env->cache_info_cpuid4.l1i_cache->level = 0x1;
    env->cache_info_cpuid4.l1i_cache->size = 0x8000;
    env->cache_info_cpuid4.l1i_cache->line_size = 0x40;
    env->cache_info_cpuid4.l1i_cache->associativity = 0x8;
    env->cache_info_cpuid4.l1i_cache->partitions = 0x1;
    env->cache_info_cpuid4.l1i_cache->sets = 0x40;
    env->cache_info_cpuid4.l1i_cache->lines_per_tag = 0x0;
    env->cache_info_cpuid4.l1i_cache->self_init = 0x1;
    env->cache_info_cpuid4.l1i_cache->no_invd_sharing = 0x1;
    env->cache_info_cpuid4.l1i_cache->inclusive = 0x0;
    env->cache_info_cpuid4.l1i_cache->complex_indexing = 0x0;

    env->cache_info_amd.l3_cache = (CPUCacheInfo *)malloc(sizeof(CPUCacheInfo));
    env->cache_info_amd.l3_cache->type = 0x2;
    env->cache_info_amd.l3_cache->level = 0x3;
    env->cache_info_amd.l3_cache->size = 0x1000000;
    env->cache_info_amd.l3_cache->line_size = 0x40;
    env->cache_info_amd.l3_cache->associativity = 0x10;
    env->cache_info_amd.l3_cache->partitions = 0x1;
    env->cache_info_amd.l3_cache->sets = 0x4000;
    env->cache_info_amd.l3_cache->lines_per_tag = 0x1;
    env->cache_info_amd.l3_cache->self_init = 0x1;
    env->cache_info_amd.l3_cache->no_invd_sharing = 0x0;
    env->cache_info_amd.l3_cache->inclusive = 0x1;
    env->cache_info_amd.l3_cache->complex_indexing = 0x1;

    env->cache_info_amd.l2_cache = (CPUCacheInfo *)malloc(sizeof(CPUCacheInfo));
    env->cache_info_amd.l2_cache->type = 0x2;
    env->cache_info_amd.l2_cache->level = 0x2;
    env->cache_info_amd.l2_cache->size = 0x80000;
    env->cache_info_amd.l2_cache->line_size = 0x40;
    env->cache_info_amd.l2_cache->associativity = 0x10;
    env->cache_info_amd.l2_cache->partitions = 0x1;
    env->cache_info_amd.l2_cache->sets = 0x200;
    env->cache_info_amd.l2_cache->lines_per_tag = 0x1;
    env->cache_info_amd.l2_cache->self_init = 0x0;
    env->cache_info_amd.l2_cache->no_invd_sharing = 0x0;
    env->cache_info_amd.l2_cache->inclusive = 0x0;
    env->cache_info_amd.l2_cache->complex_indexing = 0x0;

    env->cache_info_amd.l1d_cache = (CPUCacheInfo *)malloc(sizeof(CPUCacheInfo));
    env->cache_info_amd.l1d_cache->type = 0x0;
    env->cache_info_amd.l1d_cache->level = 0x1;
    env->cache_info_amd.l1d_cache->size = 0x10000;
    env->cache_info_amd.l1d_cache->line_size = 0x40;
    env->cache_info_amd.l1d_cache->associativity = 0x2;
    env->cache_info_amd.l1d_cache->partitions = 0x1;
    env->cache_info_amd.l1d_cache->sets = 0x200;
    env->cache_info_amd.l1d_cache->lines_per_tag = 0x1;
    env->cache_info_amd.l1d_cache->self_init = 0x1;
    env->cache_info_amd.l1d_cache->no_invd_sharing = 0x1;
    env->cache_info_amd.l1d_cache->inclusive = 0x0;
    env->cache_info_amd.l1d_cache->complex_indexing = 0x0;

    env->cache_info_amd.l1i_cache = (CPUCacheInfo *)malloc(sizeof(CPUCacheInfo));
    env->cache_info_amd.l1i_cache->type = 0x1;
    env->cache_info_amd.l1i_cache->level = 0x1;
    env->cache_info_amd.l1i_cache->size = 0x10000;
    env->cache_info_amd.l1i_cache->line_size = 0x40;
    env->cache_info_amd.l1i_cache->associativity = 0x2;
    env->cache_info_amd.l1i_cache->partitions = 0x1;
    env->cache_info_amd.l1i_cache->sets = 0x200;
    env->cache_info_amd.l1i_cache->lines_per_tag = 0x1;
    env->cache_info_amd.l1i_cache->self_init = 0x1;
    env->cache_info_amd.l1i_cache->no_invd_sharing = 0x1;
    env->cache_info_amd.l1i_cache->inclusive = 0x0;
    env->cache_info_amd.l1i_cache->complex_indexing = 0x0;


    env->mwait.ecx|= CPUID_MWAIT_EMX | CPUID_MWAIT_IBE;
    uint32_t cpuid_model[12] = {0x65746e49, 0x2952286c, 0x6f655820, 0x2952286e, 0x616c5020, 0x756e6974, 0x3438206d, 0x54433038, 0x5844, 0x0, 0x0, 0x0};
    memcpy(env->cpuid_model,cpuid_model,48);

}

#define CACHE_DESCRIPTOR_UNAVAILABLE 0xFF

/*
 * Return a CPUID 2 cache descriptor for a given cache.
 * If no known descriptor is found, return CACHE_DESCRIPTOR_UNAVAILABLE
 */
static uint8_t cpuid2_cache_descriptor(CPUCacheInfo *cache)
{
    int i;

    assert(cache->size > 0);
    assert(cache->level > 0);
    assert(cache->line_size > 0);
    assert(cache->associativity > 0);
    for (i = 0; i < 237; i++) {
        struct CPUID2CacheDescriptorInfo *d = &cpuid2_cache_descriptors[i];
        if (d->level == cache->level && d->type == cache->type &&
            d->size == cache->size && d->line_size == cache->line_size &&
            d->associativity == cache->associativity) {
                return i;
            }
    }

    return CACHE_DESCRIPTOR_UNAVAILABLE;
}


/* Encode cache info for CPUID[4] */
static void encode_cache_cpuid4(CPUCacheInfo *cache,
                                int num_apic_ids, int num_cores,
                                uint32_t *eax, uint32_t *ebx,
                                uint32_t *ecx, uint32_t *edx)
{
    assert(cache->size == cache->line_size * cache->associativity *
                          cache->partitions * cache->sets);

    assert(num_apic_ids > 0);
    *eax = CACHE_TYPE(cache->type) |
           CACHE_LEVEL(cache->level) |
           (cache->self_init ? CACHE_SELF_INIT_LEVEL : 0) |
           ((num_cores - 1) << 26) |
           ((num_apic_ids - 1) << 14);

    assert(cache->line_size > 0);
    assert(cache->partitions > 0);
    assert(cache->associativity > 0);
    /* We don't implement fully-associative caches */
    assert(cache->associativity < cache->sets);
    *ebx = (cache->line_size - 1) |
           ((cache->partitions - 1) << 12) |
           ((cache->associativity - 1) << 22);

    assert(cache->sets > 0);
    *ecx = cache->sets - 1;

    *edx = (cache->no_invd_sharing ? CACHE_NO_INVD_SHARING : 0) |
           (cache->inclusive ? CACHE_INCLUSIVE : 0) |
           (cache->complex_indexing ? CACHE_COMPLEX_IDX : 0);
}

static inline unsigned int apicid_core_offset(CPUX86State *env){
    int count = env->nr_threads;
    g_assert(count >= 1);
    count -= 1;
    return count ? 32 - clz32(count) : 0;
}

static inline unsigned int apicid_core_width(CPUX86State *env){
    int count = env->nr_cores;
    g_assert(count >= 1);
    count -= 1;
    return count ? 32 - clz32(count) : 0;
}

static inline unsigned int apicid_die_width(CPUX86State *env){
    int count = env->nr_dies;
    g_assert(count >= 1);
    count -= 1;
    return count ? 32 - clz32(count) : 0;
}

static inline unsigned apicid_die_offset(CPUX86State *env)
{
    return apicid_core_offset(env) + apicid_core_width(env);
}

static inline unsigned apicid_pkg_offset(CPUX86State *env)
{
    return apicid_die_offset(env) + apicid_die_width(env);
}

static void x86_cpu_get_supported_cpuid(uint32_t func, uint32_t index,
                                        uint32_t *eax, uint32_t *ebx,
                                        uint32_t *ecx, uint32_t *edx)
{
    *eax = kvm_arch_get_supported_cpuid(kvmfd, func, index, R_EAX);
    *ebx = kvm_arch_get_supported_cpuid(kvmfd, func, index, R_EBX);
    *ecx = kvm_arch_get_supported_cpuid(kvmfd, func, index, R_ECX);
    *edx = kvm_arch_get_supported_cpuid(kvmfd, func, index, R_EDX);
    
}
static void x86_cpu_get_cache_cpuid(uint32_t func, uint32_t index,
                                    uint32_t *eax, uint32_t *ebx,
                                    uint32_t *ecx, uint32_t *edx)
{
    uint32_t level, unused;

    /* Only return valid host leaves.  */
    switch (func) {
    case 2:
    case 4:
        host_cpuid(0, 0, &level, &unused, &unused, &unused);
        break;
    case 0x80000005:
    case 0x80000006:
    case 0x8000001d:
        host_cpuid(0x80000000, 0, &level, &unused, &unused, &unused);
        break;
    default:
        return;
    }

    if (func > level) {
        *eax = 0;
        *ebx = 0;
        *ecx = 0;
        *edx = 0;
    } else {
        host_cpuid(func, index, eax, ebx, ecx, edx);
    }
}

static inline uint64_t x86_cpu_xsave_xcr0_components(CPUX86State *env)
{
    return ((uint64_t)env->features[FEAT_XSAVE_XCR0_HI]) << 32 |
           env->features[FEAT_XSAVE_XCR0_LO];
}

static inline uint64_t x86_cpu_xsave_xss_components(CPUX86State *env)
{
    return ((uint64_t)env->features[FEAT_XSAVE_XSS_HI]) << 32 |
           env->features[FEAT_XSAVE_XSS_LO];
}

uint32_t xsave_area_size(uint64_t mask, bool compacted)
{
    uint64_t ret = x86_ext_save_areas[0].size;
    const ExtSaveArea *esa;
    uint32_t offset = 0;
    int i;

    for (i = 2; i < 19; i++) {
        esa = &x86_ext_save_areas[i];
        if ((mask >> i) & 1) {
            offset = compacted ? ret : esa->offset;
            ret = MAX(ret, offset + esa->size);
        }
    }
    return ret;
}

static uint32_t encode_cache_cpuid80000005(CPUCacheInfo *cache)
{
    assert(cache->size % 1024 == 0);
    assert(cache->lines_per_tag > 0);
    assert(cache->associativity > 0);
    assert(cache->line_size > 0);
    return ((cache->size / 1024) << 24) | (cache->associativity << 16) |
           (cache->lines_per_tag << 8) | (cache->line_size);
}

#define ASSOC_FULL 0xFF

#define AMD_ENC_ASSOC(a) (a <=   1 ? a   : \
                          a ==   2 ? 0x2 : \
                          a ==   4 ? 0x4 : \
                          a ==   8 ? 0x6 : \
                          a ==  16 ? 0x8 : \
                          a ==  32 ? 0xA : \
                          a ==  48 ? 0xB : \
                          a ==  64 ? 0xC : \
                          a ==  96 ? 0xD : \
                          a == 128 ? 0xE : \
                          a == ASSOC_FULL ? 0xF : \
                          0 /* invalid value */)


static void encode_cache_cpuid80000006(CPUCacheInfo *l2,
                                       CPUCacheInfo *l3,
                                       uint32_t *ecx, uint32_t *edx)
{
    assert(l2->size % 1024 == 0);
    assert(l2->associativity > 0);
    assert(l2->lines_per_tag > 0);
    assert(l2->line_size > 0);
    *ecx = ((l2->size / 1024) << 16) |
           (AMD_ENC_ASSOC(l2->associativity) << 12) |
           (l2->lines_per_tag << 8) | (l2->line_size);

    if (l3) {
        assert(l3->size % (512 * 1024) == 0);
        assert(l3->associativity > 0);
        assert(l3->lines_per_tag > 0);
        assert(l3->line_size > 0);
        *edx = ((l3->size / (512 * 1024)) << 18) |
               (AMD_ENC_ASSOC(l3->associativity) << 12) |
               (l3->lines_per_tag << 8) | (l3->line_size);
    } else {
        *edx = 0;
    }
}

static void encode_cache_cpuid8000001d(CPUCacheInfo *cache,
                                       CPUX86State *env,
                                       uint32_t *eax, uint32_t *ebx,
                                       uint32_t *ecx, uint32_t *edx)
{
    uint32_t l3_threads;
    assert(cache->size == cache->line_size * cache->associativity *
                          cache->partitions * cache->sets);

    *eax = CACHE_TYPE(cache->type) | CACHE_LEVEL(cache->level) |
               (cache->self_init ? CACHE_SELF_INIT_LEVEL : 0);

    /* L3 is shared among multiple cores */
    if (cache->level == 3) {
        l3_threads = env->nr_cores * env->nr_threads;
        *eax |= (l3_threads - 1) << 14;
    } else {
        *eax |= ((env->nr_threads - 1) << 14);
    }

    assert(cache->line_size > 0);
    assert(cache->partitions > 0);
    assert(cache->associativity > 0);
    /* We don't implement fully-associative caches */
    assert(cache->associativity < cache->sets);
    *ebx = (cache->line_size - 1) |
           ((cache->partitions - 1) << 12) |
           ((cache->associativity - 1) << 22);

    assert(cache->sets > 0);
    *ecx = cache->sets - 1;

    *edx = (cache->no_invd_sharing ? CACHE_NO_INVD_SHARING : 0) |
           (cache->inclusive ? CACHE_INCLUSIVE : 0) |
           (cache->complex_indexing ? CACHE_COMPLEX_IDX : 0);
}

uint32_t cpu_x86_virtual_addr_width(CPUX86State *env)
{
    if  (env->features[FEAT_7_0_ECX] & CPUID_7_0_ECX_LA57) {
        return 57; /* 57 bits virtual */
    } else {
        return 48; /* 48 bits virtual */
    }
}


void cpu_x86_cpuid(CPUX86State *env, uint32_t index, uint32_t count,
                   uint32_t *eax, uint32_t *ebx,
                   uint32_t *ecx, uint32_t *edx)
{
    uint32_t die_offset;
    uint32_t limit;
    uint32_t signature[3];

    /* Calculate & apply limits for different index ranges */
    if (index >= 0xC0000000) {
        limit = env->cpuid_xlevel2;
    } else if (index >= 0x80000000) {
        limit = env->cpuid_xlevel;
    } else if (index >= 0x40000000) {
        limit = 0x40000001;
    } else {
        limit = env->cpuid_level;
    }

    if (index > limit) {
        /* Intel documentation states that invalid EAX input will
         * return the same information as EAX=cpuid_level
         * (Intel SDM Vol. 2A - Instruction Set Reference - CPUID)
         */
        index = env->cpuid_level;
    }

    switch(index) {
    case 0:
        *eax = env->cpuid_level;
        *ebx = env->cpuid_vendor1;
        *edx = env->cpuid_vendor2;
        *ecx = env->cpuid_vendor3;
        break;
    case 1:
        *eax = env->cpuid_version;
        *ebx = (env->apic_id << 24) |
               8 << 8; /* CLFLUSH size in quad words, Linux wants it. */
        *ecx = env->features[FEAT_1_ECX];
        if ((*ecx & CPUID_EXT_XSAVE) && (env->cr[4] & CR4_OSXSAVE_MASK)) {
            *ecx |= CPUID_EXT_OSXSAVE;
        }
        *edx = env->features[FEAT_1_EDX];
        if (env->nr_cores * env->nr_threads > 1) {
            *ebx |= (env->nr_cores * env->nr_threads) << 16;
            *edx |= CPUID_HT;
        }
        /*
         * tdx_fixed0/1 are only reflected in env->features[].
         * Avoid breaking the tdx_fixed when pmu is disabled and TDX is enabled
         */      
        break;
    case 2:
        /* cache info: needed for Pentium Pro compatibility*/ 
        if (env->cache_info_passthrough) {
            x86_cpu_get_cache_cpuid(index, 0, eax, ebx, ecx, edx);
            break;
        } /*else if (cpu->vendor_cpuid_only && IS_AMD_CPU(env)) {
            *eax = *ebx = *ecx = *edx = 0;
            break;
        }*/
        *eax = 1; /* Number of CPUID[EAX=2] calls required*/ 
        *ebx = 0;
        if (!env->enable_l3_cache) {
            *ecx = 0;
        } else {
            *ecx = cpuid2_cache_descriptor(env->cache_info_cpuid2.l3_cache);
        }
        *edx = (cpuid2_cache_descriptor(env->cache_info_cpuid2.l1d_cache) << 16) |
               (cpuid2_cache_descriptor(env->cache_info_cpuid2.l1i_cache) <<  8) |
               (cpuid2_cache_descriptor(env->cache_info_cpuid2.l2_cache));
        break;
    //case 4:
        /* cache info: needed for Core compatibility */
        if (env->cache_info_passthrough) {
            x86_cpu_get_cache_cpuid(index, count, eax, ebx, ecx, edx);
            /*
             * QEMU has its own number of cores/logical cpus,
             * set 24..14, 31..26 bit to configured values
             */
            if (*eax & 31) {
                int host_vcpus_per_cache = 1 + ((*eax & 0x3FFC000) >> 14);
                int vcpus_per_socket = env->nr_dies * env->nr_cores *
                                       env->nr_threads;
                if (env->nr_cores > 1) {
                    *eax &= ~0xFC000000;
                    *eax |= (pow2ceil(env->nr_cores) - 1) << 26;
                }
                if (host_vcpus_per_cache > vcpus_per_socket) {
                    *eax &= ~0x3FFC000;
                    *eax |= (pow2ceil(vcpus_per_socket) - 1) << 14;
                }
            }
        } /*else if (cpu->vendor_cpuid_only && IS_AMD_CPU(env)) {
            *eax = *ebx = *ecx = *edx = 0;
        } */else {

            *eax = 0;
            switch (count) {
            case 0: /* L1 dcache info */
                encode_cache_cpuid4(env->cache_info_cpuid4.l1d_cache,
                                    1, env->nr_cores,
                                    eax, ebx, ecx, edx);
                break;
            case 1: /* L1 icache info */
                encode_cache_cpuid4(env->cache_info_cpuid4.l1i_cache,
                                    1, env->nr_cores,
                                    eax, ebx, ecx, edx);
                break;
            case 2: /* L2 cache info */
                encode_cache_cpuid4(env->cache_info_cpuid4.l2_cache,
                                    env->nr_threads, env->nr_cores,
                                    eax, ebx, ecx, edx);
                break;
            case 3: /* L3 cache info */
                die_offset = 0;
                if (env->enable_l3_cache) {
                    encode_cache_cpuid4(env->cache_info_cpuid4.l3_cache,
                                        (1 << die_offset), env->nr_cores,
                                        eax, ebx, ecx, edx);
                    break;
                }
                /* fall through */
            default: /* end of info */
                *eax = *ebx = *ecx = *edx = 0;
                break;
            }
        }
        break;
    case 5:
        /* MONITOR/MWAIT Leaf */
        *eax = env->mwait.eax; /* Smallest monitor-line size in bytes */
        *ebx = env->mwait.ebx; /* Largest monitor-line size in bytes */
        *ecx = env->mwait.ecx; /* flags */
        *edx = env->mwait.edx; /* mwait substates */
        break;
    case 6:
        /* Thermal and Power Leaf */
        *eax = env->features[FEAT_6_EAX];
        *ebx = 0;
        *ecx = 0;
        *edx = 0;
        break;
    case 7:
        /* Structured Extended Feature Flags Enumeration Leaf */
        if (count == 0) {
            /* Maximum ECX value for sub-leaves */
            *eax = env->cpuid_level_func7;
            *ebx = env->features[FEAT_7_0_EBX]; /* Feature flags */
            *ecx = env->features[FEAT_7_0_ECX]; /* Feature flags */
            if ((*ecx & CPUID_7_0_ECX_PKU) && env->cr[4] & CR4_PKE_MASK) {
                *ecx |= CPUID_7_0_ECX_OSPKE;
            }
            *edx = env->features[FEAT_7_0_EDX]; /* Feature flags */

            /*
             * SGX cannot be emulated in software.  If hardware does not
             * support enabling SGX and/or SGX flexible launch control,
             * then we need to update the VM's CPUID values accordingly.
             */
            if ((*ebx & CPUID_7_0_EBX_SGX) &&
                (!kvm_enabled() ||
                 !(kvm_arch_get_supported_cpuid(kvmfd, 0x7, 0, R_EBX) &
                    CPUID_7_0_EBX_SGX))) {
                *ebx &= ~CPUID_7_0_EBX_SGX;
            }

            if ((*ecx & CPUID_7_0_ECX_SGX_LC) &&
                (!(*ebx & CPUID_7_0_EBX_SGX) || !kvm_enabled() ||
                 !(kvm_arch_get_supported_cpuid(kvmfd, 0x7, 0, R_ECX) &
                    CPUID_7_0_ECX_SGX_LC))) {
                *ecx &= ~CPUID_7_0_ECX_SGX_LC;
            }
        } else if (count == 1) {
            *eax = env->features[FEAT_7_1_EAX];
            *ebx = 0;
            *ecx = 0;
            *edx = 0;
        } else {
            *eax = 0;
            *ebx = 0;
            *ecx = 0;
            *edx = 0;
        }
        break;
    case 9:
        /* Direct Cache Access Information Leaf */
        *eax = 0; /* Bits 0-31 in DCA_CAP MSR */
        *ebx = 0;
        *ecx = 0;
        *edx = 0;
        break;
    case 0xA:
        /* Architectural Performance Monitoring Leaf */
        if (accel_uses_host_cpuid() && env->enable_pmu) {
            x86_cpu_get_supported_cpuid(0xA, count, eax, ebx, ecx, edx);
        } else {
            *eax = 0;
            *ebx = 0;
            *ecx = 0;
            *edx = 0;
        }
        break;
    case 0xB:
        /* Extended Topology Enumeration Leaf */
        if (!env->enable_cpuid_0xb) {
                *eax = *ebx = *ecx = *edx = 0;
                break;
        }

        *ecx = count & 0xff;
        *edx = env->apic_id;

        switch (count) {
        case 0:
            *eax = apicid_core_offset(env);
            *ebx = env->nr_threads;
            *ecx |= CPUID_TOPOLOGY_LEVEL_SMT;
            break;
        case 1:
            *eax = apicid_pkg_offset(env);
            *ebx = env->nr_cores * env->nr_threads;
            *ecx |= CPUID_TOPOLOGY_LEVEL_CORE;
            break;
        default:
            *eax = 0;
            *ebx = 0;
            *ecx |= CPUID_TOPOLOGY_LEVEL_INVALID;
        }

        assert(!(*eax & ~0x1f));
        *ebx &= 0xffff; /* The count doesn't need to be reliable. */
        break;
    case 0x1C:
        if (accel_uses_host_cpuid() && env->enable_pmu &&
            (env->features[FEAT_7_0_EDX] & CPUID_7_0_EDX_ARCH_LBR)) {
            x86_cpu_get_supported_cpuid(0x1C, 0, eax, ebx, ecx, edx);
            *edx = 0;
        }
        break;
    case 0x1F:
        /* V2 Extended Topology Enumeration Leaf */
        if (env->nr_dies < 2) {
            *eax = *ebx = *ecx = *edx = 0;
            break;
        }

        *ecx = count & 0xff;
        *edx = env->apic_id;
        switch (count) {
        case 0:
            *eax = apicid_core_offset(env);
            *ebx = env->nr_threads;
            *ecx |= CPUID_TOPOLOGY_LEVEL_SMT;
            break;
        case 1:
            *eax = apicid_die_offset(env);
            *ebx = env->nr_cores * env->nr_threads;
            *ecx |= CPUID_TOPOLOGY_LEVEL_CORE;
            break;
        case 2:
            *eax = apicid_pkg_offset(env);
            *ebx = env->nr_dies * env->nr_cores * env->nr_threads;
            *ecx |= CPUID_TOPOLOGY_LEVEL_DIE;
            break;
        default:
            *eax = 0;
            *ebx = 0;
            *ecx |= CPUID_TOPOLOGY_LEVEL_INVALID;
        }
        assert(!(*eax & ~0x1f));
        *ebx &= 0xffff; /* The count doesn't need to be reliable. */
        break;
    case 0xD: {
        /* Processor Extended State */
        *eax = 0;
        *ebx = 0;
        *ecx = 0;
        *edx = 0;
        if (!(env->features[FEAT_1_ECX] & CPUID_EXT_XSAVE)) {
            break;
        }

        if (count == 0) {
            *ecx = xsave_area_size(x86_cpu_xsave_xcr0_components(env), false);
            *eax = env->features[FEAT_XSAVE_XCR0_LO];
            *edx = env->features[FEAT_XSAVE_XCR0_HI];
            /*
             * The initial value of xcr0 and ebx == 0, On host without kvm
             * commit 412a3c41(e.g., CentOS 6), the ebx's value always == 0
             * even through guest update xcr0, this will crash some legacy guest
             * (e.g., CentOS 6), So set ebx == ecx to workaroud it.
             */
            *ebx = kvm_enabled() ? *ecx : xsave_area_size(env->xcr0, false);
        } else if (count == 1) {
            uint64_t xstate = x86_cpu_xsave_xcr0_components(env) |
                              x86_cpu_xsave_xss_components(env);

            *eax = env->features[FEAT_XSAVE];
            *ebx = xsave_area_size(xstate, true);
            *ecx = env->features[FEAT_XSAVE_XSS_LO];
            *edx = env->features[FEAT_XSAVE_XSS_HI];
            if (kvm_enabled() && env->enable_pmu &&
                (env->features[FEAT_7_0_EDX] & CPUID_7_0_EDX_ARCH_LBR) &&
                (*eax & CPUID_XSAVE_XSAVES)) {
                *ecx |= XSTATE_ARCH_LBR_MASK;
            } else {
                *ecx &= ~XSTATE_ARCH_LBR_MASK;
            }
            if (*ecx & XSTATE_CET_MASK) {
                *ecx |= XSTATE_CET_MASK;
            }
        } else if (count == 0xf &&
                   accel_uses_host_cpuid() && env->enable_pmu &&
                   (env->features[FEAT_7_0_EDX] & CPUID_7_0_EDX_ARCH_LBR)) {
            x86_cpu_get_supported_cpuid(0xD, count, eax, ebx, ecx, edx);
        } else if (count < 19) {
            const ExtSaveArea *esa = &x86_ext_save_areas[count];

            if (x86_cpu_xsave_xcr0_components(env) & (1ULL << count)) {
                *eax = esa->size;
                *ebx = esa->offset;
                *ecx = esa->ecx &
                       (ESA_FEATURE_ALIGN64_MASK | ESA_FEATURE_XFD_MASK);
            } else if (x86_cpu_xsave_xss_components(env) & (1ULL << count)) {
                *eax = esa->size;
                *ebx = 0;
                *ecx = 1;
            }
        }
        break;
    }
    case 0x12:
        if (!kvm_enabled() ||
            !(env->features[FEAT_7_0_EBX] & CPUID_7_0_EBX_SGX)) {
            *eax = *ebx = *ecx = *edx = 0;
            break;
        }
        
        /*
         * SGX sub-leafs CPUID.0x12.{0x2..N} enumerate EPC sections.  Retrieve
         * the EPC properties, e.g. confidentiality and integrity, from the
         * host's first EPC section, i.e. assume there is one EPC section or
         * that all EPC sections have the same security properties.
         */
        /*if (count > 1) {
            uint64_t epc_addr, epc_size;

            if (sgx_epc_get_section(count - 2, &epc_addr, &epc_size)) {
                *eax = *ebx = *ecx = *edx = 0;
                break;
            }
            host_cpuid(index, 2, eax, ebx, ecx, edx);
            *eax = (uint32_t)(epc_addr & 0xfffff000) | 0x1;
            *ebx = (uint32_t)(epc_addr >> 32);
            *ecx = (uint32_t)(epc_size & 0xfffff000) | (*ecx & 0xf);
            *edx = (uint32_t)(epc_size >> 32);
            break;
        }
        */
        /*
         * SGX sub-leafs CPUID.0x12.{0x0,0x1} are heavily dependent on hardware
         * and KVM, i.e. QEMU cannot emulate features to override what KVM
         * supports.  Features can be further restricted by userspace, but not
         * made more permissive.
         *//*
        x86_cpu_get_supported_cpuid(0x12, count, eax, ebx, ecx, edx);

        if (count == 0) {
            *eax &= env->features[FEAT_SGX_12_0_EAX];
            *ebx &= env->features[FEAT_SGX_12_0_EBX];
        } else {
            *eax &= env->features[FEAT_SGX_12_1_EAX];
            *ebx &= 0; *//* ebx reserve *//*
            *ecx &= env->features[FEAT_XSAVE_XCR0_LO];
            *edx &= env->features[FEAT_XSAVE_XCR0_HI];

            *//* FP and SSE are always allowed regardless of XSAVE/XCR0. *//*
            *ecx |= XSTATE_FP_MASK | XSTATE_SSE_MASK;

            *//* Access to PROVISIONKEY requires additional credentials. *//*
            if ((*eax & (1U << 4)) &&
                !kvm_enable_sgx_provisioning(cs->kvm_state)) {
                *eax &= ~(1U << 4);
            }
        }*/
        break;
    case 0x14: {
        /* Intel Processor Trace Enumeration */
        *eax = 0;
        *ebx = 0;
        *ecx = 0;
        *edx = 0;
        if (!(env->features[FEAT_7_0_EBX] & CPUID_7_0_EBX_INTEL_PT) ||
            !kvm_enabled()) {
            break;
        }

        if (count == 0) {
            *eax = INTEL_PT_MAX_SUBLEAF;
            *ebx = INTEL_PT_MINIMAL_EBX;
            *ecx = INTEL_PT_MINIMAL_ECX;
            if (env->features[FEAT_14_0_ECX] & CPUID_14_0_ECX_LIP) {
                *ecx |= CPUID_14_0_ECX_LIP;
            }
        } else if (count == 1) {
            *eax = INTEL_PT_MTC_BITMAP | INTEL_PT_ADDR_RANGES_NUM;
            *ebx = INTEL_PT_PSB_BITMAP | INTEL_PT_CYCLE_BITMAP;
        }
        break;
    }
    case 0x1D: {
        /* AMX TILE */
        *eax = 0;
        *ebx = 0;
        *ecx = 0;
        *edx = 0;
        if (!(env->features[FEAT_7_0_EDX] & CPUID_7_0_EDX_AMX_TILE)) {
            break;
        }

        if (count == 0) {
            /* Highest numbered palette subleaf */
            *eax = INTEL_AMX_TILE_MAX_SUBLEAF;
        } else if (count == 1) {
            *eax = INTEL_AMX_TOTAL_TILE_BYTES |
                   (INTEL_AMX_BYTES_PER_TILE << 16);
            *ebx = INTEL_AMX_BYTES_PER_ROW | (INTEL_AMX_TILE_MAX_NAMES << 16);
            *ecx = INTEL_AMX_TILE_MAX_ROWS;
        }
        break;
    }
    case 0x1E: {
        /* AMX TMUL */
        *eax = 0;
        *ebx = 0;
        *ecx = 0;
        *edx = 0;
        if (!(env->features[FEAT_7_0_EDX] & CPUID_7_0_EDX_AMX_TILE)) {
            break;
        }

        if (count == 0) {
            /* Highest numbered palette subleaf */
            *ebx = INTEL_AMX_TMUL_MAX_K | (INTEL_AMX_TMUL_MAX_N << 8);
        }
        break;
    }
    case 0x40000000:
        /*
         * CPUID code in kvm_arch_init_vcpu() ignores stuff
         * set here, but we restrict to TCG none the less.
         */
        if (tcg_enabled() && env->expose_tcg) {
            memcpy(signature, "TCGTCGTCGTCG", 12);
            *eax = 0x40000001;
            *ebx = signature[0];
            *ecx = signature[1];
            *edx = signature[2];
        } else {
            *eax = 0;
            *ebx = 0;
            *ecx = 0;
            *edx = 0;
        }
        break;
    case 0x40000001:
        *eax = 0;
        *ebx = 0;
        *ecx = 0;
        *edx = 0;
        break;
    case 0x80000000:
        *eax = env->cpuid_xlevel;
        *ebx = env->cpuid_vendor1;
        *edx = env->cpuid_vendor2;
        *ecx = env->cpuid_vendor3;
        break;
    case 0x80000001:
        *eax = env->cpuid_version;
        *ebx = 0;
        *ecx = env->features[FEAT_8000_0001_ECX];
        *edx = env->features[FEAT_8000_0001_EDX];

        /* The Linux kernel checks for the CMPLegacy bit and
         * discards multiple thread information if it is set.
         * So don't set it here for Intel to make Linux guests happy.
         */
        if (env->nr_cores * env->nr_threads > 1) {
            if (env->cpuid_vendor1 != CPUID_VENDOR_INTEL_1 ||
                env->cpuid_vendor2 != CPUID_VENDOR_INTEL_2 ||
                env->cpuid_vendor3 != CPUID_VENDOR_INTEL_3) {
                *ecx |= 1 << 1;    /* CmpLegacy bit */
            }
        }
        break;
    case 0x80000002:
    case 0x80000003:
    case 0x80000004:
        *eax = env->cpuid_model[(index - 0x80000002) * 4 + 0];
        *ebx = env->cpuid_model[(index - 0x80000002) * 4 + 1];
        *ecx = env->cpuid_model[(index - 0x80000002) * 4 + 2];
        *edx = env->cpuid_model[(index - 0x80000002) * 4 + 3];
        break;
    case 0x80000005:
        /* cache info (L1 cache) */
        if (env->cache_info_passthrough) {
            x86_cpu_get_cache_cpuid(index, 0, eax, ebx, ecx, edx);
            break;
        }
        *eax = (L1_DTLB_2M_ASSOC << 24) | (L1_DTLB_2M_ENTRIES << 16) |
               (L1_ITLB_2M_ASSOC <<  8) | (L1_ITLB_2M_ENTRIES);
        *ebx = (L1_DTLB_4K_ASSOC << 24) | (L1_DTLB_4K_ENTRIES << 16) |
               (L1_ITLB_4K_ASSOC <<  8) | (L1_ITLB_4K_ENTRIES);
        *ecx = encode_cache_cpuid80000005(env->cache_info_amd.l1d_cache);
        *edx = encode_cache_cpuid80000005(env->cache_info_amd.l1i_cache);
        break;
    case 0x80000006:
        /* cache info (L2 cache) */
        if (env->cache_info_passthrough) {
            x86_cpu_get_cache_cpuid(index, 0, eax, ebx, ecx, edx);
            break;
        }
        *eax = (AMD_ENC_ASSOC(L2_DTLB_2M_ASSOC) << 28) |
               (L2_DTLB_2M_ENTRIES << 16) |
               (AMD_ENC_ASSOC(L2_ITLB_2M_ASSOC) << 12) |
               (L2_ITLB_2M_ENTRIES);
        *ebx = (AMD_ENC_ASSOC(L2_DTLB_4K_ASSOC) << 28) |
               (L2_DTLB_4K_ENTRIES << 16) |
               (AMD_ENC_ASSOC(L2_ITLB_4K_ASSOC) << 12) |
               (L2_ITLB_4K_ENTRIES);
        encode_cache_cpuid80000006(env->cache_info_amd.l2_cache,
                                   env->enable_l3_cache ?
                                   env->cache_info_amd.l3_cache : NULL,
                                   ecx, edx);
        break;
    case 0x80000007:
        *eax = 0;
        *ebx = 0;
        *ecx = 0;
        *edx = env->features[FEAT_8000_0007_EDX];
        break;
    case 0x80000008:
        /* virtual & phys address size in low 2 bytes. */
        *eax = env->phys_bits;
        if (env->features[FEAT_8000_0001_EDX] & CPUID_EXT2_LM) {
            /* 64 bit processor */
             *eax |= (cpu_x86_virtual_addr_width(env) << 8);
        }
        *ebx = env->features[FEAT_8000_0008_EBX];
        if (env->nr_cores * env->nr_threads > 1) {
            /*
             * Bits 15:12 is "The number of bits in the initial
             * Core::X86::Apic::ApicId[ApicId] value that indicate
             * thread ID within a package".
             * Bits 7:0 is "The number of threads in the package is NC+1"
             */
            *ecx = (apicid_pkg_offset(env) << 12) |
                   ((env->nr_cores * env->nr_threads) - 1);
        } else {
            *ecx = 0;
        }
        *edx = 0;
        break;
    case 0x8000000A:
        if (env->features[FEAT_8000_0001_ECX] & CPUID_EXT3_SVM) {
            *eax = 0x00000001; /* SVM Revision */
            *ebx = 0x00000010; /* nr of ASIDs */
            *ecx = 0;
            *edx = env->features[FEAT_SVM]; /* optional features */
        } else {
            *eax = 0;
            *ebx = 0;
            *ecx = 0;
            *edx = 0;
        }
        break;
    case 0x8000001D:
        *eax = 0;
        if (env->cache_info_passthrough) {
            x86_cpu_get_cache_cpuid(index, count, eax, ebx, ecx, edx);
            break;
        }
        switch (count) {
        case 0: /* L1 dcache info */
            encode_cache_cpuid8000001d(env->cache_info_amd.l1d_cache,
                                       env, eax, ebx, ecx, edx);
            break;
        case 1: /* L1 icache info */
            encode_cache_cpuid8000001d(env->cache_info_amd.l1i_cache,
                                       env, eax, ebx, ecx, edx);
            break;
        case 2: /* L2 cache info */
            encode_cache_cpuid8000001d(env->cache_info_amd.l2_cache,
                                       env, eax, ebx, ecx, edx);
            break;
        case 3: /* L3 cache info */
            encode_cache_cpuid8000001d(env->cache_info_amd.l3_cache,
                                       env, eax, ebx, ecx, edx);
            break;
        default: /* end of info */
            *eax = *ebx = *ecx = *edx = 0;
            break;
        }
        break;
    
    default:
        /* reserved values: zero */
        *eax = 0;
        *ebx = 0;
        *ecx = 0;
        *edx = 0;
        break;
    }
}

uint32_t kvm_x86_arch_cpuid(CPUX86State *env, struct kvm_cpuid_entry2 *entries,
                            uint32_t cpuid_i)
{
    uint32_t limit, i, j;
    uint32_t unused;
    struct kvm_cpuid_entry2 *c;

    cpu_x86_cpuid(env, 0, 0, &limit, &unused, &unused, &unused);

    for (i = 0; i <= limit; i++) {
        if (cpuid_i == KVM_MAX_CPUID_ENTRIES) {
            fprintf(stderr, "unsupported level value: 0x%x\n", limit);
            abort();
        }
        c = &entries[cpuid_i++];

        switch (i) {
        case 2: {
            /* Keep reading function 2 till all the input is received */
            int times;

            c->function = i;
            c->flags = KVM_CPUID_FLAG_STATEFUL_FUNC |
                       KVM_CPUID_FLAG_STATE_READ_NEXT;
            cpu_x86_cpuid(env, i, 0, &c->eax, &c->ebx, &c->ecx, &c->edx);
            times = c->eax & 0xff;

            for (j = 1; j < times; ++j) {
                if (cpuid_i == KVM_MAX_CPUID_ENTRIES) {
                    fprintf(stderr, "cpuid_data is full, no space for "
                            "cpuid(eax:2):eax & 0xf = 0x%x\n", times);
                    abort();
                }
                c = &entries[cpuid_i++];
                c->function = i;
                c->flags = KVM_CPUID_FLAG_STATEFUL_FUNC;
                cpu_x86_cpuid(env, i, 0, &c->eax, &c->ebx, &c->ecx, &c->edx);
            }
            break;
        }
        case 0x1f:
            if (env->nr_dies < 2) {
                cpuid_i--;
                break;
            }
            /* fallthrough */
        case 4:
        case 0xb:
        case 0xd:
            for (j = 0; ; j++) {
                if (i == 0xd && j == 64) {
                    break;
                }

                c->function = i;
                c->flags = KVM_CPUID_FLAG_SIGNIFCANT_INDEX;
                c->index = j;
                cpu_x86_cpuid(env, i, j, &c->eax, &c->ebx, &c->ecx, &c->edx);

                if (i == 4 && c->eax == 0) {
                    break;
                }
                if (i == 0xb && !(c->ecx & 0xff00)) {
                    break;
                }
                if (i == 0x1f && !(c->ecx & 0xff00)) {
                    break;
                }
                if (i == 0xd && c->eax == 0) {
                    continue;
                }
                if (cpuid_i == KVM_MAX_CPUID_ENTRIES) {
                    fprintf(stderr, "cpuid_data is full, no space for "
                            "cpuid(eax:0x%x,ecx:0x%x)\n", i, j);
                    abort();
                }
                c = &entries[cpuid_i++];
            }
            break;
        case 0x7:
        case 0x12:
            for (j = 0; ; j++) {
                c->function = i;
                c->flags = KVM_CPUID_FLAG_SIGNIFCANT_INDEX;
                c->index = j;
                cpu_x86_cpuid(env, i, j, &c->eax, &c->ebx, &c->ecx, &c->edx);

                if (j > 1 && (c->eax & 0xf) != 1) {
                    break;
                }

                if (cpuid_i == KVM_MAX_CPUID_ENTRIES) {
                    fprintf(stderr, "cpuid_data is full, no space for "
                                "cpuid(eax:0x12,ecx:0x%x)\n", j);
                    abort();
                }
                c = &entries[cpuid_i++];
            }
            break;
        case 0x14:
        case 0x1d:
        case 0x1e: {
            uint32_t times;

            c->function = i;
            c->index = 0;
            c->flags = KVM_CPUID_FLAG_SIGNIFCANT_INDEX;
            cpu_x86_cpuid(env, i, 0, &c->eax, &c->ebx, &c->ecx, &c->edx);
            times = c->eax;

            for (j = 1; j <= times; ++j) {
                if (cpuid_i == KVM_MAX_CPUID_ENTRIES) {
                    fprintf(stderr, "cpuid_data is full, no space for "
                                "cpuid(eax:0x%x,ecx:0x%x)\n", i, j);
                    abort();
                }
                c = &entries[cpuid_i++];
                c->function = i;
                c->index = j;
                c->flags = KVM_CPUID_FLAG_SIGNIFCANT_INDEX;
                cpu_x86_cpuid(env, i, j, &c->eax, &c->ebx, &c->ecx, &c->edx);
            }
            break;
        }
        default:
            c->function = i;
            c->flags = 0;
            cpu_x86_cpuid(env, i, 0, &c->eax, &c->ebx, &c->ecx, &c->edx);
            if (!c->eax && !c->ebx && !c->ecx && !c->edx) {
                /*
                 * KVM already returns all zeroes if a CPUID entry is missing,
                 * so we can omit it and avoid hitting KVM's 80-entry limit.
                 */
                cpuid_i--;
            }
            break;
        }
    }
    if (limit >= 0x0a) {
        uint32_t eax, edx;

        cpu_x86_cpuid(env, 0x0a, 0, &eax, &unused, &unused, &edx);

        has_architectural_pmu_version = eax & 0xff;
        if (has_architectural_pmu_version > 0) {
            num_architectural_pmu_gp_counters = (eax & 0xff00) >> 8;

            /* Shouldn't be more than 32, since that's the number of bits
             * available in EBX to tell us _which_ counters are available.
             * Play it safe.
             */
            if (num_architectural_pmu_gp_counters > MAX_GP_COUNTERS) {
                num_architectural_pmu_gp_counters = MAX_GP_COUNTERS;
            }

            if (has_architectural_pmu_version > 1) {
                num_architectural_pmu_fixed_counters = edx & 0x1f;

                if (num_architectural_pmu_fixed_counters > MAX_FIXED_COUNTERS) {
                    num_architectural_pmu_fixed_counters = MAX_FIXED_COUNTERS;
                }
            }
        }
    }

    cpu_x86_cpuid(env, 0x80000000, 0, &limit, &unused, &unused, &unused);

    for (i = 0x80000000; i <= limit; i++) {
        if (cpuid_i == KVM_MAX_CPUID_ENTRIES) {
            fprintf(stderr, "unsupported xlevel value: 0x%x\n", limit);
            abort();
        }
        c = &entries[cpuid_i++];

        switch (i) {
        case 0x8000001d:
            /* Query for all AMD cache information leaves */
            for (j = 0; ; j++) {
                c->function = i;
                c->flags = KVM_CPUID_FLAG_SIGNIFCANT_INDEX;
                c->index = j;
                cpu_x86_cpuid(env, i, j, &c->eax, &c->ebx, &c->ecx, &c->edx);

                if (c->eax == 0) {
                    break;
                }
                if (cpuid_i == KVM_MAX_CPUID_ENTRIES) {
                    fprintf(stderr, "cpuid_data is full, no space for "
                            "cpuid(eax:0x%x,ecx:0x%x)\n", i, j);
                    abort();
                }
                c = &entries[cpuid_i++];
            }
            break;
        default:
            c->function = i;
            c->flags = 0;
            cpu_x86_cpuid(env, i, 0, &c->eax, &c->ebx, &c->ecx, &c->edx);
            if (!c->eax && !c->ebx && !c->ecx && !c->edx) {
                /*
                 * KVM already returns all zeroes if a CPUID entry is missing,
                 * so we can omit it and avoid hitting KVM's 80-entry limit.
                 */
                cpuid_i--;
            }
            break;
        }
    }

    /* Call Centaur's CPUID instructions they are supported. */
    if (env->cpuid_xlevel2 > 0) {
        cpu_x86_cpuid(env, 0xC0000000, 0, &limit, &unused, &unused, &unused);

        for (i = 0xC0000000; i <= limit; i++) {
            if (cpuid_i == KVM_MAX_CPUID_ENTRIES) {
                fprintf(stderr, "unsupported xlevel2 value: 0x%x\n", limit);
                abort();
            }
            c = &entries[cpuid_i++];

            c->function = i;
            c->flags = 0;
            cpu_x86_cpuid(env, i, 0, &c->eax, &c->ebx, &c->ecx, &c->edx);
        }
    }

    return cpuid_i;
}
static void update_tdx_cpuid_lookup_by_tdx_caps(void)
{
    KvmTdxCpuidLookup *entry;
    FeatureWordInfo *fi;
    uint32_t config;
    FeatureWord w;
    FeatureMask *fm;
    int i;

    /*
     * Patch tdx_fixed0/1 by tdx_caps that what TDX module reports as
     * configurable is not fixed.
     */
    for (w = 0; w < FEATURE_WORDS; w++) {
        fi = &feature_word_info[w];
        entry = &tdx_cpuid_lookup[w];

        if (fi->type != CPUID_FEATURE_WORD) {
            continue;
        }

        config = tdx_cap_cpuid_config(fi->cpuid.eax,
                                      fi->cpuid.needs_ecx ? fi->cpuid.ecx : ~0u,
                                      fi->cpuid.reg);
        //bits set means configurable
        entry->tdx_fixed0 &= ~config;
        entry->tdx_fixed1 &= ~config;
    }

    //Update attributes related fields
    for (i = 0; i < 64; i++) {
        fm = &tdx_attrs_ctrl_fields[i];

        if (tdx_caps->attrs_fixed0 & (1ULL << i)) {
            tdx_cpuid_lookup[fm->index].tdx_fixed0 |= fm->mask;
        }

        if (tdx_caps->attrs_fixed1 & (1ULL << i)) {
            tdx_cpuid_lookup[fm->index].tdx_fixed1 |= fm->mask;
        }
    }

    /*
     * Because KVM gets XFAM settings via CPUID leaves 0xD,  map
     * tdx_caps->xfam_fixed{0, 1} into tdx_cpuid_lookup[].tdx_fixed{0, 1}.
     *
     * Then the enforment applies in tdx_get_configurable_cpuid() naturally.
     */
    tdx_cpuid_lookup[FEAT_XSAVE_XCR0_LO].tdx_fixed0 =
            (uint32_t)~tdx_caps->xfam_fixed0 & CPUID_XSTATE_XCR0_MASK;
    tdx_cpuid_lookup[FEAT_XSAVE_XCR0_LO].tdx_fixed1 =
            (uint32_t)tdx_caps->xfam_fixed1 & CPUID_XSTATE_XCR0_MASK;
    tdx_cpuid_lookup[FEAT_XSAVE_XCR0_HI].tdx_fixed0 =
            (~tdx_caps->xfam_fixed0 & CPUID_XSTATE_XCR0_MASK) >> 32;
    tdx_cpuid_lookup[FEAT_XSAVE_XCR0_HI].tdx_fixed1 =
            (tdx_caps->xfam_fixed1 & CPUID_XSTATE_XCR0_MASK) >> 32;

    tdx_cpuid_lookup[FEAT_XSAVE_XSS_LO].tdx_fixed0 =
            (uint32_t)~tdx_caps->xfam_fixed0 & CPUID_XSTATE_XSS_MASK;
    tdx_cpuid_lookup[FEAT_XSAVE_XSS_LO].tdx_fixed1 =
            (uint32_t)tdx_caps->xfam_fixed1 & CPUID_XSTATE_XSS_MASK;
    tdx_cpuid_lookup[FEAT_XSAVE_XSS_HI].tdx_fixed0 =
            (~tdx_caps->xfam_fixed0 & CPUID_XSTATE_XSS_MASK) >> 32;
    tdx_cpuid_lookup[FEAT_XSAVE_XSS_HI].tdx_fixed1 =
            (tdx_caps->xfam_fixed1 & CPUID_XSTATE_XSS_MASK) >> 32;
}