#include <stdint.h>
#include <stdbool.h>
#ifndef SNP_SEV
#define SNP_SEV
#define SNP_CPUID_FUNCTION_MAXCOUNT 64
#define CPUID_PAGE 0xffe02000
#define CBIT_MASK 0x3f
#define SNP_CPUID_FUNCTION_UNKNOWN 0xFFFFFFFF
#define SNP_PAGE_STATE_PRIVATE 1
#define SNP_PAGE_STATE_SHARED 2UL
#define GPA_REQ 0x12
#define GPA_RESP 0x13
#define PSC_REQ 0x14
#define PSC_RESP 0x15
#define PSC_OP_POS 52
#define PSC_ERROR_POS 32
#define PSC_ERROR_MASK ((1UL<<(PSC_ERROR_POS))-1)
#define EXIT_REQ  0x100
#define PSC_OP_POS 52
#define MSR_GHCB 0xC0010130
#define GHCB_PROTOCOL_MAX 2
#define GHCB_DEFAULT_USAGE 0

#define IOIO_TYPE_OUT 0
#define IOIO_TYPE_IN 1
#define IOIO_TYPE_STR (1<<2)
#define IOIO_REP      (1<<3)
#define IOIO_DATA_8 (1<<4)
#define IOIO_DATA_16 (1<<5)
#define IOIO_DATA_32 (1<<6)
#define IOIO_ADDR_64 (1<<9)
#define IOIO_ADDR_32 (1<<8)
#define IOIO_ADDR_16 (1<<7)

#define IOIO_TYPE_INS  (IOIO_TYPE_IN | IOIO_TYPE_STR)
#define IOIO_TYPE_OUTS (IOIO_TYPE_OUT | IOIO_TYPE_STR)

#define IOIO_SEG_ES    (0 << 10)
#define IOIO_SEG_DS    (3 << 10)


#define SVM_EVTINJ_VALID  (1 << 31)
#define SVM_EVTINJ_TYPE_SHIFT  8
#define SVM_EVTINJ_TYPE_MASK  (7 << SVM_EVTINJ_TYPE_SHIFT)
#define SVM_EVTINJ_TYPE_EXEPT  (3 << SVM_EVTINJ_TYPE_SHIFT)
#define SVM_EVTINJ_VEC_MASK  0xff
#define UD  6
#define GP  13

#define SVM_EXIT_READ_CR0      0x000
#define SVM_EXIT_READ_CR2      0x002
#define SVM_EXIT_READ_CR3      0x003
#define SVM_EXIT_READ_CR4      0x004
#define SVM_EXIT_READ_CR8      0x008
#define SVM_EXIT_WRITE_CR0     0x010
#define SVM_EXIT_WRITE_CR2     0x012
#define SVM_EXIT_WRITE_CR3     0x013
#define SVM_EXIT_WRITE_CR4     0x014
#define SVM_EXIT_WRITE_CR8     0x018
#define SVM_EXIT_READ_DR0      0x020
#define SVM_EXIT_READ_DR1      0x021
#define SVM_EXIT_READ_DR2      0x022
#define SVM_EXIT_READ_DR3      0x023
#define SVM_EXIT_READ_DR4      0x024
#define SVM_EXIT_READ_DR5      0x025
#define SVM_EXIT_READ_DR6      0x026
#define SVM_EXIT_READ_DR7      0x027
#define SVM_EXIT_WRITE_DR0     0x030
#define SVM_EXIT_WRITE_DR1     0x031
#define SVM_EXIT_WRITE_DR2     0x032
#define SVM_EXIT_WRITE_DR3     0x033
#define SVM_EXIT_WRITE_DR4     0x034
#define SVM_EXIT_WRITE_DR5     0x035
#define SVM_EXIT_WRITE_DR6     0x036
#define SVM_EXIT_WRITE_DR7     0x037
#define SVM_EXIT_EXCP_BASE     0x040
#define SVM_EXIT_LAST_EXCP     0x05f
#define SVM_EXIT_INTR          0x060
#define SVM_EXIT_NMI           0x061
#define SVM_EXIT_SMI           0x062
#define SVM_EXIT_INIT          0x063
#define SVM_EXIT_VINTR         0x064
#define SVM_EXIT_CR0_SEL_WRITE 0x065
#define SVM_EXIT_IDTR_READ     0x066
#define SVM_EXIT_GDTR_READ     0x067
#define SVM_EXIT_LDTR_READ     0x068
#define SVM_EXIT_TR_READ       0x069
#define SVM_EXIT_IDTR_WRITE    0x06a
#define SVM_EXIT_GDTR_WRITE    0x06b
#define SVM_EXIT_LDTR_WRITE    0x06c
#define SVM_EXIT_TR_WRITE      0x06d
#define SVM_EXIT_RDTSC         0x06e
#define SVM_EXIT_RDPMC         0x06f
#define SVM_EXIT_PUSHF         0x070
#define SVM_EXIT_POPF          0x071
#define SVM_EXIT_CPUID         0x072
#define SVM_EXIT_RSM           0x073
#define SVM_EXIT_IRET          0x074
#define SVM_EXIT_SWINT         0x075
#define SVM_EXIT_INVD          0x076
#define SVM_EXIT_PAUSE         0x077
#define SVM_EXIT_HLT           0x078
#define SVM_EXIT_INVLPG        0x079
#define SVM_EXIT_INVLPGA       0x07a
#define SVM_EXIT_IOIO          0x07b
#define SVM_EXIT_MSR           0x07c
#define SVM_EXIT_TASK_SWITCH   0x07d
#define SVM_EXIT_FERR_FREEZE   0x07e
#define SVM_EXIT_SHUTDOWN      0x07f
#define SVM_EXIT_VMRUN         0x080
#define SVM_EXIT_VMMCALL       0x081
#define SVM_EXIT_VMLOAD        0x082
#define SVM_EXIT_VMSAVE        0x083
#define SVM_EXIT_STGI          0x084
#define SVM_EXIT_CLGI          0x085
#define SVM_EXIT_SKINIT        0x086
#define SVM_EXIT_RDTSCP        0x087
#define SVM_EXIT_ICEBP         0x088
#define SVM_EXIT_WBINVD        0x089
#define SVM_EXIT_MONITOR       0x08a
#define SVM_EXIT_MWAIT         0x08b
#define SVM_EXIT_MWAIT_COND    0x08c
#define SVM_EXIT_XSETBV        0x08d
#define SVM_EXIT_RDPRU         0x08e
#define SVM_EXIT_EFER_WRITE_TRAP		0x08f
#define SVM_EXIT_CR0_WRITE_TRAP			0x090
#define SVM_EXIT_CR1_WRITE_TRAP			0x091
#define SVM_EXIT_CR2_WRITE_TRAP			0x092
#define SVM_EXIT_CR3_WRITE_TRAP			0x093
#define SVM_EXIT_CR4_WRITE_TRAP			0x094
#define SVM_EXIT_CR5_WRITE_TRAP			0x095
#define SVM_EXIT_CR6_WRITE_TRAP			0x096
#define SVM_EXIT_CR7_WRITE_TRAP			0x097
#define SVM_EXIT_CR8_WRITE_TRAP			0x098
#define SVM_EXIT_CR9_WRITE_TRAP			0x099
#define SVM_EXIT_CR10_WRITE_TRAP		0x09a
#define SVM_EXIT_CR11_WRITE_TRAP		0x09b
#define SVM_EXIT_CR12_WRITE_TRAP		0x09c
#define SVM_EXIT_CR13_WRITE_TRAP		0x09d
#define SVM_EXIT_CR14_WRITE_TRAP		0x09e
#define SVM_EXIT_CR15_WRITE_TRAP		0x09f
#define SVM_EXIT_INVPCID       0x0a2
#define SVM_EXIT_NPF           0x400
#define SVM_EXIT_AVIC_INCOMPLETE_IPI		0x401
#define SVM_EXIT_AVIC_UNACCELERATED_ACCESS	0x402
#define SVM_EXIT_VMGEXIT       0x403

/* SEV-ES software-defined VMGEXIT events */
#define SVM_VMGEXIT_MMIO_READ			0x80000001
#define SVM_VMGEXIT_MMIO_WRITE			0x80000002
#define SVM_VMGEXIT_NMI_COMPLETE		0x80000003
#define SVM_VMGEXIT_AP_HLT_LOOP			0x80000004
#define SVM_VMGEXIT_AP_JUMP_TABLE		0x80000005
#define SVM_VMGEXIT_SET_AP_JUMP_TABLE		0
#define SVM_VMGEXIT_GET_AP_JUMP_TABLE		1
#define SVM_VMGEXIT_PSC				0x80000010
#define SVM_VMGEXIT_GUEST_REQUEST		0x80000011
#define SVM_VMGEXIT_EXT_GUEST_REQUEST		0x80000012
#define SVM_VMGEXIT_AP_CREATION			0x80000013
#define SVM_VMGEXIT_AP_CREATE_ON_INIT		0
#define SVM_VMGEXIT_AP_CREATE			1
#define SVM_VMGEXIT_AP_DESTROY			2
#define SVM_VMGEXIT_SNP_RUN_VMPL		0x80000018
#define SVM_VMGEXIT_HV_FEATURES			0x8000fffd
#define SVM_VMGEXIT_TERM_REQUEST		0x8000fffe
#define SVM_VMGEXIT_TERM_REASON(reason_set, reason_code)	\
	/* SW_EXITINFO1[3:0] */					\
	(((((u64)reason_set) & 0xf)) |				\
	/* SW_EXITINFO1[11:4] */				\
	((((u64)reason_code) & 0xff) << 4))
#define SVM_VMGEXIT_UNSUPPORTED_EVENT		0x8000ffff
#define X86_EFLAGS_DF (1<<10)


enum PvalidateSize{
    Size4K = 0,
    Size2M = 1
};

extern struct ghcb * ghcb;

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

static inline uint64_t lower_bits(uint64_t val, unsigned int bits)
{
	uint64_t mask = (1ULL << bits) - 1;

	return (val & mask);
}
void pvalidate(uint64_t vaddr, int size,  bool validated);
void ghcb_msr_make_page_shared(uint64_t vaddr);
void invalidate();
uint64_t read_msr(uint32_t msr_id);
void ghcb_termination();
void set_offset_valid(uint64_t *offset_address);
bool test_offset_valid(uint64_t *offset_address);
int vmgexit(uint64_t exit_code, uint64_t exit_info_1,uint64_t exit_info_2);
void ghcb_block_io_write_8(uint16_t port, uint8_t byte);
int get_cbit();
void ghcb_init(uint64_t vaddr);
void ghcb_block_make_pages_shared(uint64_t vaddr, uint64_t npages);
#endif