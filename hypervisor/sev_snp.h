#include <stdint.h>
#ifndef SNP_SEV
#define SNP_SEV
#define SNP_CPUID_FUNCTION_MAXCOUNT 64
#define SNP_CPUID_FUNCTION_UNKNOWN 0xFFFFFFFF
typedef struct {
    uint32_t eax_in;
    uint32_t ecx_in;
    uint64_t xcr0_in;
    uint64_t xss_in;
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
    uint64_t reserved;
} __attribute__((packed)) SnpCpuidFunc;

typedef struct {
    uint32_t count;
    uint32_t reserved1;
    uint64_t reserved2;
    SnpCpuidFunc entries[SNP_CPUID_FUNCTION_MAXCOUNT];
} __attribute__((packed)) SnpCpuidInfo;


#define GHCB_SHARED_BUF_SIZE    0x7f0

struct ghcb_save_area {
    uint8_t reserved1[203];
    uint8_t cpl;
    uint8_t reserved2[300];
    uint64_t rax;
    uint8_t reserved3[264];
    uint64_t rcx;
    uint64_t rdx;
    uint64_t rbx;
    uint8_t reserved4[112];
    uint64_t sw_exit_code;
    uint64_t sw_exit_info1;
    uint64_t sw_exit_info2;
    uint64_t sw_scratch;
    uint8_t reserved5[56];
    uint64_t xcr0;
    uint8_t valid_bitmap[16];
    uint64_t x87state_gpa;
    uint8_t reserved6[1016];
} __attribute__((__packed__));

struct ghcb {
    struct ghcb_save_area save;
    uint8_t shared_buffer[GHCB_SHARED_BUF_SIZE];

    uint8_t reserved_1[10];
    uint16_t protocol_version;
    uint16_t ghcb_usage;
} __attribute__((__packed__));

struct psc_hdr {
    uint16_t cur_entry;
    uint16_t end_entry;
    uint32_t reserved;
} __attribute__((__packed__));

struct psc_entry {
    uint64_t cur_page    : 12,
             gfn         : 40,
             operation   : 4,
             pagesize    : 1,
             reserved    : 7;
} __attribute__((__packed__));

#define VMGEXIT_PSC_MAX_ENTRY 253

struct snp_psc_desc {
    struct psc_hdr hdr;
    struct psc_entry entries[VMGEXIT_PSC_MAX_ENTRY];
} __attribute__((__packed__));

#endif