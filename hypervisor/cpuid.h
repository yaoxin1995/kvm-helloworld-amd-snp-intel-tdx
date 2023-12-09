#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

typedef enum FeatureWordType {
   CPUID_FEATURE_WORD,
   MSR_FEATURE_WORD,
} FeatureWordType;

/* CPUID feature words */
typedef enum FeatureWord {
    FEAT_1_EDX,         /* CPUID[1].EDX */
    FEAT_1_ECX,         /* CPUID[1].ECX */
    FEAT_7_0_EBX,       /* CPUID[EAX=7,ECX=0].EBX */
    FEAT_7_0_ECX,       /* CPUID[EAX=7,ECX=0].ECX */
    FEAT_7_0_EDX,       /* CPUID[EAX=7,ECX=0].EDX */
    FEAT_7_1_EAX,       /* CPUID[EAX=7,ECX=1].EAX */
    FEAT_8000_0001_EDX, /* CPUID[8000_0001].EDX */
    FEAT_8000_0001_ECX, /* CPUID[8000_0001].ECX */
    FEAT_8000_0007_EDX, /* CPUID[8000_0007].EDX */
    FEAT_8000_0008_EBX, /* CPUID[8000_0008].EBX */
    FEAT_C000_0001_EDX, /* CPUID[C000_0001].EDX */
    FEAT_KVM,           /* CPUID[4000_0001].EAX (KVM_CPUID_FEATURES) */
    FEAT_KVM_HINTS,     /* CPUID[4000_0001].EDX */
    FEAT_SVM,           /* CPUID[8000_000A].EDX */
    FEAT_XSAVE,         /* CPUID[EAX=0xd,ECX=1].EAX */
    FEAT_6_EAX,         /* CPUID[6].EAX */
    FEAT_XSAVE_XCR0_LO, /* CPUID[EAX=0xd,ECX=0].EAX */
    FEAT_XSAVE_XCR0_HI, /* CPUID[EAX=0xd,ECX=0].EDX */
    FEAT_ARCH_CAPABILITIES,
    FEAT_CORE_CAPABILITY,
    FEAT_PERF_CAPABILITIES,
    FEAT_VMX_PROCBASED_CTLS,
    FEAT_VMX_SECONDARY_CTLS,
    FEAT_VMX_PINBASED_CTLS,
    FEAT_VMX_EXIT_CTLS,
    FEAT_VMX_ENTRY_CTLS,
    FEAT_VMX_MISC,
    FEAT_VMX_EPT_VPID_CAPS,
    FEAT_VMX_BASIC,
    FEAT_VMX_VMFUNC,
    FEAT_14_0_ECX,
    FEAT_SGX_12_0_EAX,  /* CPUID[EAX=0x12,ECX=0].EAX (SGX) */
    FEAT_SGX_12_0_EBX,  /* CPUID[EAX=0x12,ECX=0].EBX (SGX MISCSELECT[31:0]) */
    FEAT_SGX_12_1_EAX,  /* CPUID[EAX=0x12,ECX=1].EAX (SGX ATTRIBUTES[31:0]) */
    FEAT_XSAVE_XSS_LO,     /* CPUID[EAX=0xd,ECX=1].ECX */
    FEAT_XSAVE_XSS_HI,     /* CPUID[EAX=0xd,ECX=1].EDX */
    FEATURE_WORDS,
} FeatureWord;

enum {
    R_EAX = 0,
    R_ECX = 1,
    R_EDX = 2,
    R_EBX = 3,
    R_ESP = 4,
    R_EBP = 5,
    R_ESI = 6,
    R_EDI = 7,
    R_R8 = 8,
    R_R9 = 9,
    R_R10 = 10,
    R_R11 = 11,
    R_R12 = 12,
    R_R13 = 13,
    R_R14 = 14,
    R_R15 = 15,

    R_AL = 0,
    R_CL = 1,
    R_DL = 2,
    R_BL = 3,
    R_AH = 4,
    R_CH = 5,
    R_DH = 6,
    R_BH = 7,
};

typedef struct FeatureWordInfo {
    FeatureWordType type;
    /* feature flags names are taken from "Intel Processor Identification and
     * the CPUID Instruction" and AMD's "CPUID Specification".
     * In cases of disagreement between feature naming conventions,
     * aliases may be added.
     */
    const char *feat_names[64];
    union {
        /* If type==CPUID_FEATURE_WORD */
        struct {
            uint32_t eax;   /* Input EAX for CPUID */
            bool needs_ecx; /* CPUID instruction uses ECX as input */
            uint32_t ecx;   /* Input ECX value for CPUID */
            int reg;        /* output register (R_* constant) */
        } cpuid;
        /* If type==MSR_FEATURE_WORD */
        struct {
            uint32_t index;
        } msr;
    };
    uint64_t tcg_features; /* Feature flags supported by TCG */
    uint64_t unmigratable_flags; /* Feature flags known to be unmigratable */
    uint64_t migratable_flags; /* Feature flags known to be migratable */
    /* Features that shouldn't be auto-enabled by "-cpu host" */
    uint64_t no_autoenable_flags;
} FeatureWordInfo;

#define CR4_VME_MASK  (1U << 0)
#define CR4_PVI_MASK  (1U << 1)
#define CR4_TSD_MASK  (1U << 2)
#define CR4_DE_MASK   (1U << 3)
#define CR4_PSE_MASK  (1U << 4)
#define CR4_PAE_MASK  (1U << 5)
#define CR4_MCE_MASK  (1U << 6)
#define CR4_PGE_MASK  (1U << 7)
#define CR4_PCE_MASK  (1U << 8)
#define CR4_OSFXSR_SHIFT 9
#define CR4_OSFXSR_MASK (1U << CR4_OSFXSR_SHIFT)
#define CR4_OSXMMEXCPT_MASK  (1U << 10)
#define CR4_UMIP_MASK   (1U << 11)
#define CR4_LA57_MASK   (1U << 12)
#define CR4_VMXE_MASK   (1U << 13)
#define CR4_SMXE_MASK   (1U << 14)
#define CR4_FSGSBASE_MASK (1U << 16)
#define CR4_PCIDE_MASK  (1U << 17)
#define CR4_OSXSAVE_MASK (1U << 18)
#define CR4_SMEP_MASK   (1U << 20)
#define CR4_SMAP_MASK   (1U << 21)
#define CR4_PKE_MASK   (1U << 22)
#define CR4_PKS_MASK   (1U << 24)


/* cpuid_features bits */
#define CPUID_FP87 (1U << 0)
#define CPUID_VME  (1U << 1)
#define CPUID_DE   (1U << 2)
#define CPUID_PSE  (1U << 3)
#define CPUID_TSC  (1U << 4)
#define CPUID_MSR  (1U << 5)
#define CPUID_PAE  (1U << 6)
#define CPUID_MCE  (1U << 7)
#define CPUID_CX8  (1U << 8)
#define CPUID_APIC (1U << 9)
#define CPUID_SEP  (1U << 11) /* sysenter/sysexit */
#define CPUID_MTRR (1U << 12)
#define CPUID_PGE  (1U << 13)
#define CPUID_MCA  (1U << 14)
#define CPUID_CMOV (1U << 15)
#define CPUID_PAT  (1U << 16)
#define CPUID_PSE36   (1U << 17)
#define CPUID_PN   (1U << 18)
#define CPUID_CLFLUSH (1U << 19)
#define CPUID_DTS (1U << 21)
#define CPUID_ACPI (1U << 22)
#define CPUID_MMX  (1U << 23)
#define CPUID_FXSR (1U << 24)
#define CPUID_SSE  (1U << 25)
#define CPUID_SSE2 (1U << 26)
#define CPUID_SS (1U << 27)
#define CPUID_HT (1U << 28)
#define CPUID_TM (1U << 29)
#define CPUID_IA64 (1U << 30)
#define CPUID_PBE (1U << 31)

#define CPUID_EXT_SSE3     (1U << 0)
#define CPUID_EXT_PCLMULQDQ (1U << 1)
#define CPUID_EXT_DTES64   (1U << 2)
#define CPUID_EXT_MONITOR  (1U << 3)
#define CPUID_EXT_DSCPL    (1U << 4)
#define CPUID_EXT_VMX      (1U << 5)
#define CPUID_EXT_SMX      (1U << 6)
#define CPUID_EXT_EST      (1U << 7)
#define CPUID_EXT_TM2      (1U << 8)
#define CPUID_EXT_SSSE3    (1U << 9)
#define CPUID_EXT_CID      (1U << 10)
#define CPUID_EXT_FMA      (1U << 12)
#define CPUID_EXT_CX16     (1U << 13)
#define CPUID_EXT_XTPR     (1U << 14)
#define CPUID_EXT_PDCM     (1U << 15)
#define CPUID_EXT_PCID     (1U << 17)
#define CPUID_EXT_DCA      (1U << 18)
#define CPUID_EXT_SSE41    (1U << 19)
#define CPUID_EXT_SSE42    (1U << 20)
#define CPUID_EXT_X2APIC   (1U << 21)
#define CPUID_EXT_MOVBE    (1U << 22)
#define CPUID_EXT_POPCNT   (1U << 23)
#define CPUID_EXT_TSC_DEADLINE_TIMER (1U << 24)
#define CPUID_EXT_AES      (1U << 25)
#define CPUID_EXT_XSAVE    (1U << 26)
#define CPUID_EXT_OSXSAVE  (1U << 27)
#define CPUID_EXT_AVX      (1U << 28)
#define CPUID_EXT_F16C     (1U << 29)
#define CPUID_EXT_RDRAND   (1U << 30)
#define CPUID_EXT_HYPERVISOR  (1U << 31)

#define CPUID_EXT2_FPU     (1U << 0)
#define CPUID_EXT2_VME     (1U << 1)
#define CPUID_EXT2_DE      (1U << 2)
#define CPUID_EXT2_PSE     (1U << 3)
#define CPUID_EXT2_TSC     (1U << 4)
#define CPUID_EXT2_MSR     (1U << 5)
#define CPUID_EXT2_PAE     (1U << 6)
#define CPUID_EXT2_MCE     (1U << 7)
#define CPUID_EXT2_CX8     (1U << 8)
#define CPUID_EXT2_APIC    (1U << 9)
#define CPUID_EXT2_SYSCALL (1U << 11)
#define CPUID_EXT2_MTRR    (1U << 12)
#define CPUID_EXT2_PGE     (1U << 13)
#define CPUID_EXT2_MCA     (1U << 14)
#define CPUID_EXT2_CMOV    (1U << 15)
#define CPUID_EXT2_PAT     (1U << 16)
#define CPUID_EXT2_PSE36   (1U << 17)
#define CPUID_EXT2_MP      (1U << 19)
#define CPUID_EXT2_NX      (1U << 20)
#define CPUID_EXT2_MMXEXT  (1U << 22)
#define CPUID_EXT2_MMX     (1U << 23)
#define CPUID_EXT2_FXSR    (1U << 24)
#define CPUID_EXT2_FFXSR   (1U << 25)
#define CPUID_EXT2_PDPE1GB (1U << 26)
#define CPUID_EXT2_RDTSCP  (1U << 27)
#define CPUID_EXT2_LM      (1U << 29)
#define CPUID_EXT2_3DNOWEXT (1U << 30)
#define CPUID_EXT2_3DNOW   (1U << 31)

#define CPUID_EXT3_LAHF_LM (1U << 0)
#define CPUID_EXT3_CMP_LEG (1U << 1)
#define CPUID_EXT3_SVM     (1U << 2)
#define CPUID_EXT3_EXTAPIC (1U << 3)
#define CPUID_EXT3_CR8LEG  (1U << 4)
#define CPUID_EXT3_ABM     (1U << 5)
#define CPUID_EXT3_SSE4A   (1U << 6)
#define CPUID_EXT3_MISALIGNSSE (1U << 7)
#define CPUID_EXT3_3DNOWPREFETCH (1U << 8)
#define CPUID_EXT3_OSVW    (1U << 9)
#define CPUID_EXT3_IBS     (1U << 10)
#define CPUID_EXT3_XOP     (1U << 11)
#define CPUID_EXT3_SKINIT  (1U << 12)
#define CPUID_EXT3_WDT     (1U << 13)
#define CPUID_EXT3_LWP     (1U << 15)
#define CPUID_EXT3_FMA4    (1U << 16)
#define CPUID_EXT3_TCE     (1U << 17)
#define CPUID_EXT3_NODEID  (1U << 19)
#define CPUID_EXT3_TBM     (1U << 21)
#define CPUID_EXT3_TOPOEXT (1U << 22)
#define CPUID_EXT3_PERFCORE (1U << 23)
#define CPUID_EXT3_PERFNB  (1U << 24)

#define CPUID_SVM_NPT             (1U << 0)
#define CPUID_SVM_LBRV            (1U << 1)
#define CPUID_SVM_SVMLOCK         (1U << 2)
#define CPUID_SVM_NRIPSAVE        (1U << 3)
#define CPUID_SVM_TSCSCALE        (1U << 4)
#define CPUID_SVM_VMCBCLEAN       (1U << 5)
#define CPUID_SVM_FLUSHASID       (1U << 6)
#define CPUID_SVM_DECODEASSIST    (1U << 7)
#define CPUID_SVM_PAUSEFILTER     (1U << 10)
#define CPUID_SVM_PFTHRESHOLD     (1U << 12)
#define CPUID_SVM_AVIC            (1U << 13)
#define CPUID_SVM_V_VMSAVE_VMLOAD (1U << 15)
#define CPUID_SVM_VGIF            (1U << 16)
#define CPUID_SVM_SVME_ADDR_CHK   (1U << 28)

/* Support RDFSBASE/RDGSBASE/WRFSBASE/WRGSBASE */
#define CPUID_7_0_EBX_FSGSBASE          (1U << 0)
/* Support for TSC adjustment MSR 0x3B */
#define CPUID_7_0_EBX_TSC_ADJUST        (1U << 1)
/* Support SGX */
#define CPUID_7_0_EBX_SGX               (1U << 2)
/* 1st Group of Advanced Bit Manipulation Extensions */
#define CPUID_7_0_EBX_BMI1              (1U << 3)
/* Hardware Lock Elision */
#define CPUID_7_0_EBX_HLE               (1U << 4)
/* Intel Advanced Vector Extensions 2 */
#define CPUID_7_0_EBX_AVX2              (1U << 5)
/* Supervisor-mode Execution Prevention */
#define CPUID_7_0_EBX_SMEP              (1U << 7)
/* 2nd Group of Advanced Bit Manipulation Extensions */
#define CPUID_7_0_EBX_BMI2              (1U << 8)
/* Enhanced REP MOVSB/STOSB */
#define CPUID_7_0_EBX_ERMS              (1U << 9)
/* Invalidate Process-Context Identifier */
#define CPUID_7_0_EBX_INVPCID           (1U << 10)
/* Restricted Transactional Memory */
#define CPUID_7_0_EBX_RTM               (1U << 11)
/* Cache QoS Monitoring */
#define CPUID_7_0_EBX_PQM               (1U << 12)
/* Memory Protection Extension */
#define CPUID_7_0_EBX_MPX               (1U << 14)
/* Resource Director Technology Allocation */
#define CPUID_7_0_EBX_RDT_A             (1U << 15)
/* AVX-512 Foundation */
#define CPUID_7_0_EBX_AVX512F           (1U << 16)
/* AVX-512 Doubleword & Quadword Instruction */
#define CPUID_7_0_EBX_AVX512DQ          (1U << 17)
/* Read Random SEED */
#define CPUID_7_0_EBX_RDSEED            (1U << 18)
/* ADCX and ADOX instructions */
#define CPUID_7_0_EBX_ADX               (1U << 19)
/* Supervisor Mode Access Prevention */
#define CPUID_7_0_EBX_SMAP              (1U << 20)
/* AVX-512 Integer Fused Multiply Add */
#define CPUID_7_0_EBX_AVX512IFMA        (1U << 21)
/* Persistent Commit */
#define CPUID_7_0_EBX_PCOMMIT           (1U << 22)
/* Flush a Cache Line Optimized */
#define CPUID_7_0_EBX_CLFLUSHOPT        (1U << 23)
/* Cache Line Write Back */
#define CPUID_7_0_EBX_CLWB              (1U << 24)
/* Intel Processor Trace */
#define CPUID_7_0_EBX_INTEL_PT          (1U << 25)
/* AVX-512 Prefetch */
#define CPUID_7_0_EBX_AVX512PF          (1U << 26)
/* AVX-512 Exponential and Reciprocal */
#define CPUID_7_0_EBX_AVX512ER          (1U << 27)
/* AVX-512 Conflict Detection */
#define CPUID_7_0_EBX_AVX512CD          (1U << 28)
/* SHA1/SHA256 Instruction Extensions */
#define CPUID_7_0_EBX_SHA_NI            (1U << 29)
/* AVX-512 Byte and Word Instructions */
#define CPUID_7_0_EBX_AVX512BW          (1U << 30)
/* AVX-512 Vector Length Extensions */
#define CPUID_7_0_EBX_AVX512VL          (1U << 31)

/* AVX-512 Vector Byte Manipulation Instruction */
#define CPUID_7_0_ECX_AVX512_VBMI       (1U << 1)
/* User-Mode Instruction Prevention */
#define CPUID_7_0_ECX_UMIP              (1U << 2)
/* Protection Keys for User-mode Pages */
#define CPUID_7_0_ECX_PKU               (1U << 3)
/* OS Enable Protection Keys */
#define CPUID_7_0_ECX_OSPKE             (1U << 4)
/* UMONITOR/UMWAIT/TPAUSE Instructions */
#define CPUID_7_0_ECX_WAITPKG           (1U << 5)
/* Additional AVX-512 Vector Byte Manipulation Instruction */
#define CPUID_7_0_ECX_AVX512_VBMI2      (1U << 6)
/* CET SHSTK feature */
#define CPUID_7_0_ECX_CET_SHSTK         (1U << 7)
/* Galois Field New Instructions */
#define CPUID_7_0_ECX_GFNI              (1U << 8)
/* Vector AES Instructions */
#define CPUID_7_0_ECX_VAES              (1U << 9)
/* Carry-Less Multiplication Quadword */
#define CPUID_7_0_ECX_VPCLMULQDQ        (1U << 10)
/* Vector Neural Network Instructions */
#define CPUID_7_0_ECX_AVX512VNNI        (1U << 11)
/* Support for VPOPCNT[B,W] and VPSHUFBITQMB */
#define CPUID_7_0_ECX_AVX512BITALG      (1U << 12)
/* Intel Total Memory Encryption */
#define CPUID_7_0_ECX_TME               (1U << 13)
/* POPCNT for vectors of DW/QW */
#define CPUID_7_0_ECX_AVX512_VPOPCNTDQ  (1U << 14)
/* Placeholder for bit 15 */
#define CPUID_7_0_ECX_FZM               (1U << 15)
/* 5-level Page Tables */
#define CPUID_7_0_ECX_LA57              (1U << 16)
/* MAWAU for MPX */
#define CPUID_7_0_ECX_MAWAU             (31U << 17)
/* Read Processor ID */
#define CPUID_7_0_ECX_RDPID             (1U << 22)
/* KeyLocker */
#define CPUID_7_0_ECX_KeyLocker         (1U << 23)
/* Bus Lock Debug Exception */
#define CPUID_7_0_ECX_BUS_LOCK_DETECT   (1U << 24)
/* Cache Line Demote Instruction */
#define CPUID_7_0_ECX_CLDEMOTE          (1U << 25)
/* Move Doubleword as Direct Store Instruction */
#define CPUID_7_0_ECX_MOVDIRI           (1U << 27)
/* Move 64 Bytes as Direct Store Instruction */
#define CPUID_7_0_ECX_MOVDIR64B         (1U << 28)
/* ENQCMD and ENQCMDS instructions */
#define CPUID_7_0_ECX_ENQCMD            (1U << 29)
/* Support SGX Launch Control */
#define CPUID_7_0_ECX_SGX_LC            (1U << 30)
/* Protection Keys for Supervisor-mode Pages */
#define CPUID_7_0_ECX_PKS               (1U << 31)

/* AVX512 Neural Network Instructions */
#define CPUID_7_0_EDX_AVX512_4VNNIW     (1U << 2)
/* AVX512 Multiply Accumulation Single Precision */
#define CPUID_7_0_EDX_AVX512_4FMAPS     (1U << 3)
/* Fast Short Rep Mov */
#define CPUID_7_0_EDX_FSRM              (1U << 4)
/* User Interrupt Support*/
#define CPUID_7_0_EDX_UNIT              (1U << 5)
/* AVX512 Vector Pair Intersection to a Pair of Mask Registers */
#define CPUID_7_0_EDX_AVX512_VP2INTERSECT (1U << 8)
/* SERIALIZE instruction */
#define CPUID_7_0_EDX_SERIALIZE         (1U << 14)
/* TSX Suspend Load Address Tracking instruction */
#define CPUID_7_0_EDX_TSX_LDTRK         (1U << 16)
/* PCONFIG instruction */
#define CPUID_7_0_EDX_PCONFIG           (1U << 18)
/* Architectural LBRs */
#define CPUID_7_0_EDX_ARCH_LBR          (1U << 19)
/* CET IBT feature */
#define CPUID_7_0_EDX_CET_IBT           (1U << 20)
/* Intel AMX BF16 Support */
#define CPUID_7_0_EDX_AMX_BF16          (1U << 22)
/* AVX512_FP16 instruction */
#define CPUID_7_0_EDX_AVX512_FP16       (1U << 23)
/* AMX tile (two-dimensional register) */
#define CPUID_7_0_EDX_AMX_TILE          (1U << 24)
/* Intel AMX INT8 Support */
#define CPUID_7_0_EDX_AMX_INT8          (1U << 25)
/* Speculation Control */
#define CPUID_7_0_EDX_SPEC_CTRL         (1U << 26)
/* Single Thread Indirect Branch Predictors */
#define CPUID_7_0_EDX_STIBP             (1U << 27)
/* Arch Capabilities */
#define CPUID_7_0_EDX_ARCH_CAPABILITIES (1U << 29)
/* Core Capability */
#define CPUID_7_0_EDX_CORE_CAPABILITY   (1U << 30)
/* Speculative Store Bypass Disable */
#define CPUID_7_0_EDX_SPEC_CTRL_SSBD    (1U << 31)

/* AVX VNNI Instruction */
#define CPUID_7_1_EAX_AVX_VNNI          (1U << 4)
/* AVX512 BFloat16 Instruction */
#define CPUID_7_1_EAX_AVX512_BF16       (1U << 5)
/* XFD Extend Feature Disabled */
#define CPUID_D_1_EAX_XFD               (1U << 4)

/* Packets which contain IP payload have LIP values */
#define CPUID_14_0_ECX_LIP              (1U << 31)

/* CLZERO instruction */
#define CPUID_8000_0008_EBX_CLZERO      (1U << 0)
/* Always save/restore FP error pointers */
#define CPUID_8000_0008_EBX_XSAVEERPTR  (1U << 2)
/* Write back and do not invalidate cache */
#define CPUID_8000_0008_EBX_WBNOINVD    (1U << 9)
/* Indirect Branch Prediction Barrier */
#define CPUID_8000_0008_EBX_IBPB        (1U << 12)
/* Indirect Branch Restricted Speculation */
#define CPUID_8000_0008_EBX_IBRS        (1U << 14)
/* Single Thread Indirect Branch Predictors */
#define CPUID_8000_0008_EBX_STIBP       (1U << 15)
/* Speculative Store Bypass Disable */
#define CPUID_8000_0008_EBX_AMD_SSBD    (1U << 24)

#define CPUID_XSAVE_XSAVEOPT   (1U << 0)
#define CPUID_XSAVE_XSAVEC     (1U << 1)
#define CPUID_XSAVE_XGETBV1    (1U << 2)
#define CPUID_XSAVE_XSAVES     (1U << 3)

#define CPUID_6_EAX_ARAT       (1U << 2)

/* CPUID[0x80000007].EDX flags: */
#define CPUID_APM_INVTSC       (1U << 8)

#define CPUID_VENDOR_SZ      12

#define CPUID_VENDOR_INTEL_1 0x756e6547 /* "Genu" */
#define CPUID_VENDOR_INTEL_2 0x49656e69 /* "ineI" */
#define CPUID_VENDOR_INTEL_3 0x6c65746e /* "ntel" */
#define CPUID_VENDOR_INTEL "GenuineIntel"

#define TCG_EXT3_FEATURES (CPUID_EXT3_LAHF_LM | CPUID_EXT3_SVM | \
          CPUID_EXT3_CR8LEG | CPUID_EXT3_ABM | CPUID_EXT3_SSE4A)

#define TCG_FEATURES (CPUID_FP87 | CPUID_PSE | CPUID_TSC | CPUID_MSR | \
          CPUID_PAE | CPUID_MCE | CPUID_CX8 | CPUID_APIC | CPUID_SEP | \
          CPUID_MTRR | CPUID_PGE | CPUID_MCA | CPUID_CMOV | CPUID_PAT | \
          CPUID_PSE36 | CPUID_CLFLUSH | CPUID_ACPI | CPUID_MMX | \
          CPUID_FXSR | CPUID_SSE | CPUID_SSE2 | CPUID_SS | CPUID_DE)

#define TCG_EXT_FEATURES (CPUID_EXT_SSE3 | CPUID_EXT_PCLMULQDQ | \
          CPUID_EXT_MONITOR | CPUID_EXT_SSSE3 | CPUID_EXT_CX16 | \
          CPUID_EXT_SSE41 | CPUID_EXT_SSE42 | CPUID_EXT_POPCNT | \
          CPUID_EXT_XSAVE | /* CPUID_EXT_OSXSAVE is dynamic */   \
          CPUID_EXT_MOVBE | CPUID_EXT_AES | CPUID_EXT_HYPERVISOR | \
          CPUID_EXT_RDRAND | CPUID_EXT_AVX | CPUID_EXT_F16C | \
          CPUID_EXT_FMA)

#define CPUID_EXT2_AMD_ALIASES (CPUID_EXT2_FPU | CPUID_EXT2_VME | \
                                CPUID_EXT2_DE | CPUID_EXT2_PSE | \
                                CPUID_EXT2_TSC | CPUID_EXT2_MSR | \
                                CPUID_EXT2_PAE | CPUID_EXT2_MCE | \
                                CPUID_EXT2_CX8 | CPUID_EXT2_APIC | \
                                CPUID_EXT2_MTRR | CPUID_EXT2_PGE | \
                                CPUID_EXT2_MCA | CPUID_EXT2_CMOV | \
                                CPUID_EXT2_PAT | CPUID_EXT2_PSE36 | \
                                CPUID_EXT2_MMX | CPUID_EXT2_FXSR)

#define TCG_EXT2_X86_64_FEATURES (CPUID_EXT2_SYSCALL | CPUID_EXT2_LM)

#define TCG_EXT2_FEATURES ((TCG_FEATURES & CPUID_EXT2_AMD_ALIASES) | \
          CPUID_EXT2_NX | CPUID_EXT2_MMXEXT | CPUID_EXT2_RDTSCP | \
          CPUID_EXT2_3DNOW | CPUID_EXT2_3DNOWEXT | CPUID_EXT2_PDPE1GB | \
          TCG_EXT2_X86_64_FEATURES)
#define TCG_EXT4_FEATURES 0

#define KVM_CPUID_FEATURES	0x40000001
#define KVM_FEATURE_CLOCKSOURCE		0
#define KVM_FEATURE_NOP_IO_DELAY	1
#define KVM_FEATURE_MMU_OP		2
/* This indicates that the new set of kvmclock msrs
 * are available. The use of 0x11 and 0x12 is deprecated
 */
#define KVM_FEATURE_CLOCKSOURCE2        3
#define KVM_FEATURE_ASYNC_PF		4
#define KVM_FEATURE_STEAL_TIME		5
#define KVM_FEATURE_PV_EOI		6
#define KVM_FEATURE_PV_UNHALT		7
#define KVM_FEATURE_PV_TLB_FLUSH	9
#define KVM_FEATURE_ASYNC_PF_VMEXIT	10
#define KVM_FEATURE_PV_SEND_IPI	11
#define KVM_FEATURE_POLL_CONTROL	12
#define KVM_FEATURE_PV_SCHED_YIELD	13
#define KVM_FEATURE_ASYNC_PF_INT	14
#define KVM_FEATURE_MSI_EXT_DEST_ID	15
#define KVM_FEATURE_HC_MAP_GPA_RANGE	16
#define KVM_FEATURE_MIGRATION_CONTROL	17

#define TDX_SUPPORTED_KVM_FEATURES  ((1U << KVM_FEATURE_NOP_IO_DELAY) | \
                                     (1U << KVM_FEATURE_PV_UNHALT) | \
                                     (1U << KVM_FEATURE_PV_TLB_FLUSH) | \
                                     (1U << KVM_FEATURE_PV_SEND_IPI) | \
                                     (1U << KVM_FEATURE_POLL_CONTROL) | \
                                     (1U << KVM_FEATURE_PV_SCHED_YIELD) | \
                                     (1U << KVM_FEATURE_MSI_EXT_DEST_ID))

#define TCG_KVM_FEATURES 0
#define TCG_SVM_FEATURES (CPUID_SVM_NPT | CPUID_SVM_VGIF | \
          CPUID_SVM_SVME_ADDR_CHK)

#define TCG_7_0_EBX_FEATURES (CPUID_7_0_EBX_SMEP | CPUID_7_0_EBX_SMAP | \
          CPUID_7_0_EBX_BMI1 | CPUID_7_0_EBX_BMI2 | CPUID_7_0_EBX_ADX | \
          CPUID_7_0_EBX_PCOMMIT | CPUID_7_0_EBX_CLFLUSHOPT |            \
          CPUID_7_0_EBX_CLWB | CPUID_7_0_EBX_MPX | CPUID_7_0_EBX_FSGSBASE | \
          CPUID_7_0_EBX_ERMS | CPUID_7_0_EBX_AVX2)

#define TCG_7_0_ECX_FEATURES (CPUID_7_0_ECX_UMIP | CPUID_7_0_ECX_PKU | \
          /* CPUID_7_0_ECX_OSPKE is dynamic */ \
          CPUID_7_0_ECX_LA57 | CPUID_7_0_ECX_PKS | CPUID_7_0_ECX_VAES)
#define TCG_7_0_EDX_FEATURES 0
#define TCG_7_1_EAX_FEATURES 0
#define TCG_APM_FEATURES 0
#define TCG_6_EAX_FEATURES CPUID_6_EAX_ARAT
#define TCG_XSAVE_FEATURES (CPUID_XSAVE_XSAVEOPT | CPUID_XSAVE_XGETBV1)
          /* missing:
          CPUID_XSAVE_XSAVEC, CPUID_XSAVE_XSAVES */
#define TCG_14_0_ECX_FEATURES 0
#define TCG_SGX_12_0_EAX_FEATURES 0
#define TCG_SGX_12_0_EBX_FEATURES 0
#define TCG_SGX_12_1_EAX_FEATURES 0

#define XSTATE_FP_BIT                   0
#define XSTATE_SSE_BIT                  1
#define XSTATE_YMM_BIT                  2
#define XSTATE_BNDREGS_BIT              3
#define XSTATE_BNDCSR_BIT               4
#define XSTATE_OPMASK_BIT               5
#define XSTATE_ZMM_Hi256_BIT            6
#define XSTATE_Hi16_ZMM_BIT             7
#define XSTATE_RTIT_BIT                 8
#define XSTATE_PKRU_BIT                 9
#define XSTATE_CET_U_BIT                11
#define XSTATE_CET_S_BIT                12
#define XSTATE_UINTR_BIT                14
#define XSTATE_ARCH_LBR_BIT             15
#define XSTATE_XTILE_CFG_BIT            17
#define XSTATE_XTILE_DATA_BIT           18

#define XSTATE_FP_MASK                  (1ULL << XSTATE_FP_BIT)
#define XSTATE_SSE_MASK                 (1ULL << XSTATE_SSE_BIT)
#define XSTATE_YMM_MASK                 (1ULL << XSTATE_YMM_BIT)
#define XSTATE_BNDREGS_MASK             (1ULL << XSTATE_BNDREGS_BIT)
#define XSTATE_BNDCSR_MASK              (1ULL << XSTATE_BNDCSR_BIT)
#define XSTATE_OPMASK_MASK              (1ULL << XSTATE_OPMASK_BIT)
#define XSTATE_ZMM_Hi256_MASK           (1ULL << XSTATE_ZMM_Hi256_BIT)
#define XSTATE_Hi16_ZMM_MASK            (1ULL << XSTATE_Hi16_ZMM_BIT)
#define XSTATE_RTIT_MASK                (1ULL << XSTATE_RTIT_BIT)
#define XSTATE_PKRU_MASK                (1ULL << XSTATE_PKRU_BIT)
#define XSTATE_CET_U_MASK               (1ULL << XSTATE_CET_U_BIT)
#define XSTATE_CET_S_MASK               (1ULL << XSTATE_CET_S_BIT)
#define XSTATE_UINTR_MASK               (1ULL << XSTATE_UINTR_BIT)
#define XSTATE_ARCH_LBR_MASK            (1ULL << XSTATE_ARCH_LBR_BIT)
#define XSTATE_XTILE_CFG_MASK           (1ULL << XSTATE_XTILE_CFG_BIT)
#define XSTATE_XTILE_DATA_MASK          (1ULL << XSTATE_XTILE_DATA_BIT)

#define XSTATE_DYNAMIC_MASK             (XSTATE_XTILE_DATA_MASK)

#define XSTATE_AVX_512_MASK             (XSTATE_OPMASK_MASK |       \
                                         XSTATE_ZMM_Hi256_MASK |    \
                                         XSTATE_Hi16_ZMM_MASK)
#define XSTATE_CET_MASK                 (XSTATE_CET_U_MASK  |       \
                                         XSTATE_CET_S_MASK)
#define XSTATE_AMX_MASK                 (XSTATE_XTILE_CFG_MASK |    \
                                         XSTATE_XTILE_DATA_MASK)

#define ESA_FEATURE_ALIGN64_BIT         1
#define ESA_FEATURE_XFD_BIT             2

#define ESA_FEATURE_ALIGN64_MASK        (1U << ESA_FEATURE_ALIGN64_BIT)
#define ESA_FEATURE_XFD_MASK            (1U << ESA_FEATURE_XFD_BIT)


/* CPUID feature bits available in XCR0 */
#define CPUID_XSTATE_XCR0_MASK  (XSTATE_FP_MASK | XSTATE_SSE_MASK | \
                                 XSTATE_YMM_MASK | XSTATE_BNDREGS_MASK | \
                                 XSTATE_BNDCSR_MASK | XSTATE_OPMASK_MASK | \
                                 XSTATE_ZMM_Hi256_MASK | \
                                 XSTATE_Hi16_ZMM_MASK | XSTATE_PKRU_MASK | \
                                 XSTATE_XTILE_CFG_MASK | XSTATE_XTILE_DATA_MASK)

/* CPUID feature bits available in XSS */
#define CPUID_XSTATE_XSS_MASK (XSTATE_ARCH_LBR_MASK | XSTATE_CET_U_MASK)
#define MSR_IA32_ARCH_CAPABILITIES      0x10a

#define MSR_IA32_TSC                    0x10
#define MSR_IA32_APICBASE               0x1b
#define MSR_IA32_APICBASE_BSP           (1<<8)
#define MSR_IA32_APICBASE_ENABLE        (1<<11)
#define MSR_IA32_APICBASE_EXTD          (1 << 10)
#define MSR_IA32_APICBASE_BASE          (0xfffffU<<12)
#define MSR_IA32_FEATURE_CONTROL        0x0000003a
#define MSR_TSC_ADJUST                  0x0000003b
#define MSR_IA32_SPEC_CTRL              0x48
#define MSR_VIRT_SSBD                   0xc001011f
#define MSR_IA32_PRED_CMD               0x49
#define MSR_IA32_UCODE_REV              0x8b
#define MSR_IA32_CORE_CAPABILITY        0xcf

#define MSR_IA32_PERF_CAPABILITIES      0x345

#define MSR_IA32_VMX_BASIC              0x00000480
#define MSR_IA32_VMX_PINBASED_CTLS      0x00000481
#define MSR_IA32_VMX_PROCBASED_CTLS     0x00000482
#define MSR_IA32_VMX_EXIT_CTLS          0x00000483
#define MSR_IA32_VMX_ENTRY_CTLS         0x00000484
#define MSR_IA32_VMX_MISC               0x00000485
#define MSR_IA32_VMX_CR0_FIXED0         0x00000486
#define MSR_IA32_VMX_CR0_FIXED1         0x00000487
#define MSR_IA32_VMX_CR4_FIXED0         0x00000488
#define MSR_IA32_VMX_CR4_FIXED1         0x00000489
#define MSR_IA32_VMX_VMCS_ENUM          0x0000048a
#define MSR_IA32_VMX_PROCBASED_CTLS2    0x0000048b
#define MSR_IA32_VMX_EPT_VPID_CAP       0x0000048c
#define MSR_IA32_VMX_TRUE_PINBASED_CTLS  0x0000048d
#define MSR_IA32_VMX_TRUE_PROCBASED_CTLS 0x0000048e
#define MSR_IA32_VMX_TRUE_EXIT_CTLS      0x0000048f
#define MSR_IA32_VMX_TRUE_ENTRY_CTLS     0x00000490
#define MSR_IA32_VMX_VMFUNC             0x00000491


/* VMX controls */
#define VMX_CPU_BASED_VIRTUAL_INTR_PENDING          0x00000004
#define VMX_CPU_BASED_USE_TSC_OFFSETING             0x00000008
#define VMX_CPU_BASED_HLT_EXITING                   0x00000080
#define VMX_CPU_BASED_INVLPG_EXITING                0x00000200
#define VMX_CPU_BASED_MWAIT_EXITING                 0x00000400
#define VMX_CPU_BASED_RDPMC_EXITING                 0x00000800
#define VMX_CPU_BASED_RDTSC_EXITING                 0x00001000
#define VMX_CPU_BASED_CR3_LOAD_EXITING              0x00008000
#define VMX_CPU_BASED_CR3_STORE_EXITING             0x00010000
#define VMX_CPU_BASED_CR8_LOAD_EXITING              0x00080000
#define VMX_CPU_BASED_CR8_STORE_EXITING             0x00100000
#define VMX_CPU_BASED_TPR_SHADOW                    0x00200000
#define VMX_CPU_BASED_VIRTUAL_NMI_PENDING           0x00400000
#define VMX_CPU_BASED_MOV_DR_EXITING                0x00800000
#define VMX_CPU_BASED_UNCOND_IO_EXITING             0x01000000
#define VMX_CPU_BASED_USE_IO_BITMAPS                0x02000000
#define VMX_CPU_BASED_MONITOR_TRAP_FLAG             0x08000000
#define VMX_CPU_BASED_USE_MSR_BITMAPS               0x10000000
#define VMX_CPU_BASED_MONITOR_EXITING               0x20000000
#define VMX_CPU_BASED_PAUSE_EXITING                 0x40000000
#define VMX_CPU_BASED_ACTIVATE_SECONDARY_CONTROLS   0x80000000

#define VMX_SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES 0x00000001
#define VMX_SECONDARY_EXEC_ENABLE_EPT               0x00000002
#define VMX_SECONDARY_EXEC_DESC                     0x00000004
#define VMX_SECONDARY_EXEC_RDTSCP                   0x00000008
#define VMX_SECONDARY_EXEC_VIRTUALIZE_X2APIC_MODE   0x00000010
#define VMX_SECONDARY_EXEC_ENABLE_VPID              0x00000020
#define VMX_SECONDARY_EXEC_WBINVD_EXITING           0x00000040
#define VMX_SECONDARY_EXEC_UNRESTRICTED_GUEST       0x00000080
#define VMX_SECONDARY_EXEC_APIC_REGISTER_VIRT       0x00000100
#define VMX_SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY    0x00000200
#define VMX_SECONDARY_EXEC_PAUSE_LOOP_EXITING       0x00000400
#define VMX_SECONDARY_EXEC_RDRAND_EXITING           0x00000800
#define VMX_SECONDARY_EXEC_ENABLE_INVPCID           0x00001000
#define VMX_SECONDARY_EXEC_ENABLE_VMFUNC            0x00002000
#define VMX_SECONDARY_EXEC_SHADOW_VMCS              0x00004000
#define VMX_SECONDARY_EXEC_ENCLS_EXITING            0x00008000
#define VMX_SECONDARY_EXEC_RDSEED_EXITING           0x00010000
#define VMX_SECONDARY_EXEC_ENABLE_PML               0x00020000
#define VMX_SECONDARY_EXEC_XSAVES                   0x00100000
#define VMX_SECONDARY_EXEC_TSC_SCALING              0x02000000

#define VMX_PIN_BASED_EXT_INTR_MASK                 0x00000001
#define VMX_PIN_BASED_NMI_EXITING                   0x00000008
#define VMX_PIN_BASED_VIRTUAL_NMIS                  0x00000020
#define VMX_PIN_BASED_VMX_PREEMPTION_TIMER          0x00000040
#define VMX_PIN_BASED_POSTED_INTR                   0x00000080

#define VMX_VM_EXIT_SAVE_DEBUG_CONTROLS             0x00000004
#define VMX_VM_EXIT_HOST_ADDR_SPACE_SIZE            0x00000200
#define VMX_VM_EXIT_LOAD_IA32_PERF_GLOBAL_CTRL      0x00001000
#define VMX_VM_EXIT_ACK_INTR_ON_EXIT                0x00008000
#define VMX_VM_EXIT_SAVE_IA32_PAT                   0x00040000
#define VMX_VM_EXIT_LOAD_IA32_PAT                   0x00080000
#define VMX_VM_EXIT_SAVE_IA32_EFER                  0x00100000
#define VMX_VM_EXIT_LOAD_IA32_EFER                  0x00200000
#define VMX_VM_EXIT_SAVE_VMX_PREEMPTION_TIMER       0x00400000
#define VMX_VM_EXIT_CLEAR_BNDCFGS                   0x00800000
#define VMX_VM_EXIT_PT_CONCEAL_PIP                  0x01000000
#define VMX_VM_EXIT_CLEAR_IA32_RTIT_CTL             0x02000000
#define VMX_VM_EXIT_LOAD_IA32_PKRS                  0x20000000

#define VMX_VM_ENTRY_LOAD_DEBUG_CONTROLS            0x00000004
#define VMX_VM_ENTRY_IA32E_MODE                     0x00000200
#define VMX_VM_ENTRY_SMM                            0x00000400
#define VMX_VM_ENTRY_DEACT_DUAL_MONITOR             0x00000800
#define VMX_VM_ENTRY_LOAD_IA32_PERF_GLOBAL_CTRL     0x00002000
#define VMX_VM_ENTRY_LOAD_IA32_PAT                  0x00004000
#define VMX_VM_ENTRY_LOAD_IA32_EFER                 0x00008000
#define VMX_VM_ENTRY_LOAD_BNDCFGS                   0x00010000
#define VMX_VM_ENTRY_PT_CONCEAL_PIP                 0x00020000
#define VMX_VM_ENTRY_LOAD_IA32_RTIT_CTL             0x00040000
#define VMX_VM_ENTRY_LOAD_IA32_PKRS                 0x00400000

#define MSR_VMX_BASIC_DUAL_MONITOR                   (1ULL << 49)

FeatureWordInfo feature_word_info[FEATURE_WORDS] = {
    [FEAT_1_EDX] = {
        .type = CPUID_FEATURE_WORD,
        .feat_names = {
            "fpu", "vme", "de", "pse",
            "tsc", "msr", "pae", "mce",
            "cx8", "apic", NULL, "sep",
            "mtrr", "pge", "mca", "cmov",
            "pat", "pse36", "pn" /* Intel psn */, "clflush" /* Intel clfsh */,
            NULL, "ds" /* Intel dts */, "acpi", "mmx",
            "fxsr", "sse", "sse2", "ss",
            "ht" /* Intel htt */, "tm", "ia64", "pbe",
        },
        .cpuid = {.eax = 1, .reg = R_EDX, },
        .tcg_features = TCG_FEATURES,
    },
    [FEAT_1_ECX] = {
        .type = CPUID_FEATURE_WORD,
        .feat_names = {
            "pni" /* Intel,AMD sse3 */, "pclmulqdq", "dtes64", "monitor",
            "ds-cpl", "vmx", "smx", "est",
            "tm2", "ssse3", "cid", NULL,
            "fma", "cx16", "xtpr", "pdcm",
            NULL, "pcid", "dca", "sse4.1",
            "sse4.2", "x2apic", "movbe", "popcnt",
            "tsc-deadline", "aes", "xsave", NULL /* osxsave */,
            "avx", "f16c", "rdrand", "hypervisor",
        },
        .cpuid = { .eax = 1, .reg = R_ECX, },
        .tcg_features = TCG_EXT_FEATURES,
    },
    /* Feature names that are already defined on feature_name[] but
     * are set on CPUID[8000_0001].EDX on AMD CPUs don't have their
     * names on feat_names below. They are copied automatically
     * to features[FEAT_8000_0001_EDX] if and only if CPU vendor is AMD.
     */
    [FEAT_8000_0001_EDX] = {
        .type = CPUID_FEATURE_WORD,
        .feat_names = {
            NULL /* fpu */, NULL /* vme */, NULL /* de */, NULL /* pse */,
            NULL /* tsc */, NULL /* msr */, NULL /* pae */, NULL /* mce */,
            NULL /* cx8 */, NULL /* apic */, NULL, "syscall",
            NULL /* mtrr */, NULL /* pge */, NULL /* mca */, NULL /* cmov */,
            NULL /* pat */, NULL /* pse36 */, NULL, NULL /* Linux mp */,
            "nx", NULL, "mmxext", NULL /* mmx */,
            NULL /* fxsr */, "fxsr-opt", "pdpe1gb", "rdtscp",
            NULL, "lm", "3dnowext", "3dnow",
        },
        .cpuid = { .eax = 0x80000001, .reg = R_EDX, },
        .tcg_features = TCG_EXT2_FEATURES,
    },
    [FEAT_8000_0001_ECX] = {
        .type = CPUID_FEATURE_WORD,
        .feat_names = {
            "lahf-lm", "cmp-legacy", "svm", "extapic",
            "cr8legacy", "abm", "sse4a", "misalignsse",
            "3dnowprefetch", "osvw", "ibs", "xop",
            "skinit", "wdt", NULL, "lwp",
            "fma4", "tce", NULL, "nodeid-msr",
            NULL, "tbm", "topoext", "perfctr-core",
            "perfctr-nb", NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
        },
        .cpuid = { .eax = 0x80000001, .reg = R_ECX, },
        .tcg_features = TCG_EXT3_FEATURES,
        /*
         * TOPOEXT is always allowed but can't be enabled blindly by
         * "-cpu host", as it requires consistent cache topology info
         * to be provided so it doesn't confuse guests.
         */
        .no_autoenable_flags = CPUID_EXT3_TOPOEXT,
    },
    [FEAT_C000_0001_EDX] = {
        .type = CPUID_FEATURE_WORD,
        .feat_names = {
            NULL, NULL, "xstore", "xstore-en",
            NULL, NULL, "xcrypt", "xcrypt-en",
            "ace2", "ace2-en", "phe", "phe-en",
            "pmm", "pmm-en", NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
        },
        .cpuid = { .eax = 0xC0000001, .reg = R_EDX, },
        .tcg_features = TCG_EXT4_FEATURES,
    },
    [FEAT_KVM] = {
        .type = CPUID_FEATURE_WORD,
        .feat_names = {
            "kvmclock", "kvm-nopiodelay", "kvm-mmu", "kvmclock",
            "kvm-asyncpf", "kvm-steal-time", "kvm-pv-eoi", "kvm-pv-unhalt",
            NULL, "kvm-pv-tlb-flush", NULL, "kvm-pv-ipi",
            "kvm-poll-control", "kvm-pv-sched-yield", "kvm-asyncpf-int", "kvm-msi-ext-dest-id",
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            "kvmclock-stable-bit", NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
        },
        .cpuid = { .eax = KVM_CPUID_FEATURES, .reg = R_EAX, },
        .tcg_features = TCG_KVM_FEATURES,
    },
    [FEAT_KVM_HINTS] = {
        .type = CPUID_FEATURE_WORD,
        .feat_names = {
            "kvm-hint-dedicated", NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
        },
        .cpuid = { .eax = KVM_CPUID_FEATURES, .reg = R_EDX, },
        .tcg_features = TCG_KVM_FEATURES,
        /*
         * KVM hints aren't auto-enabled by -cpu host, they need to be
         * explicitly enabled in the command-line.
         */
        .no_autoenable_flags = ~0U,
    },
    [FEAT_SVM] = {
        .type = CPUID_FEATURE_WORD,
        .feat_names = {
            "npt", "lbrv", "svm-lock", "nrip-save",
            "tsc-scale", "vmcb-clean",  "flushbyasid", "decodeassists",
            NULL, NULL, "pause-filter", NULL,
            "pfthreshold", "avic", NULL, "v-vmsave-vmload",
            "vgif", NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            "svme-addr-chk", NULL, NULL, NULL,
        },
        .cpuid = { .eax = 0x8000000A, .reg = R_EDX, },
        .tcg_features = TCG_SVM_FEATURES,
    },
    [FEAT_7_0_EBX] = {
        .type = CPUID_FEATURE_WORD,
        .feat_names = {
            "fsgsbase", "tsc-adjust", "sgx", "bmi1",
            "hle", "avx2", NULL, "smep",
            "bmi2", "erms", "invpcid", "rtm",
            NULL, NULL, "mpx", NULL,
            "avx512f", "avx512dq", "rdseed", "adx",
            "smap", "avx512ifma", "pcommit", "clflushopt",
            "clwb", "intel-pt", "avx512pf", "avx512er",
            "avx512cd", "sha-ni", "avx512bw", "avx512vl",
        },
        .cpuid = {
            .eax = 7,
            .needs_ecx = true, .ecx = 0,
            .reg = R_EBX,
        },
        .tcg_features = TCG_7_0_EBX_FEATURES,
    },
    [FEAT_7_0_ECX] = {
        .type = CPUID_FEATURE_WORD,
        .feat_names = {
            NULL, "avx512vbmi", "umip", "pku",
            NULL /* ospke */, "waitpkg", "avx512vbmi2", "shstk",
            "gfni", "vaes", "vpclmulqdq", "avx512vnni",
            "avx512bitalg", NULL, "avx512-vpopcntdq", NULL,
            "la57", NULL, NULL, NULL,
            NULL, NULL, "rdpid", NULL,
            "bus-lock-detect", "cldemote", NULL, "movdiri",
            "movdir64b", NULL, "sgxlc", "pks",
        },
        .cpuid = {
            .eax = 7,
            .needs_ecx = true, .ecx = 0,
            .reg = R_ECX,
        },
        .tcg_features = TCG_7_0_ECX_FEATURES,
    },
    [FEAT_7_0_EDX] = {
        .type = CPUID_FEATURE_WORD,
        .feat_names = {
            NULL, NULL, "avx512-4vnniw", "avx512-4fmaps",
            "fsrm", NULL, NULL, NULL,
            "avx512-vp2intersect", NULL, "md-clear", NULL,
            NULL, NULL, "serialize", NULL,
            "tsx-ldtrk", NULL, NULL /* pconfig */, "arch-lbr",
            "ibt", NULL, "amx-bf16", "avx512-fp16",
            "amx-tile", "amx-int8", "spec-ctrl", "stibp",
            NULL, "arch-capabilities", "core-capability", "ssbd",
        },
        .cpuid = {
            .eax = 7,
            .needs_ecx = true, .ecx = 0,
            .reg = R_EDX,
        },
        .tcg_features = TCG_7_0_EDX_FEATURES,
    },
    [FEAT_7_1_EAX] = {
        .type = CPUID_FEATURE_WORD,
        .feat_names = {
            NULL, NULL, NULL, NULL,
            "avx-vnni", "avx512-bf16", NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
        },
        .cpuid = {
            .eax = 7,
            .needs_ecx = true, .ecx = 1,
            .reg = R_EAX,
        },
        .tcg_features = TCG_7_1_EAX_FEATURES,
    },
    [FEAT_8000_0007_EDX] = {
        .type = CPUID_FEATURE_WORD,
        .feat_names = {
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            "invtsc", NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
        },
        .cpuid = { .eax = 0x80000007, .reg = R_EDX, },
        .tcg_features = TCG_APM_FEATURES,
        .unmigratable_flags = CPUID_APM_INVTSC,
    },
    [FEAT_8000_0008_EBX] = {
        .type = CPUID_FEATURE_WORD,
        .feat_names = {
            "clzero", NULL, "xsaveerptr", NULL,
            NULL, NULL, NULL, NULL,
            NULL, "wbnoinvd", NULL, NULL,
            "ibpb", NULL, "ibrs", "amd-stibp",
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            "amd-ssbd", "virt-ssbd", "amd-no-ssb", NULL,
            NULL, NULL, NULL, NULL,
        },
        .cpuid = { .eax = 0x80000008, .reg = R_EBX, },
        .tcg_features = 0,
        .unmigratable_flags = 0,
    },
    [FEAT_XSAVE] = {
        .type = CPUID_FEATURE_WORD,
        .feat_names = {
            "xsaveopt", "xsavec", "xgetbv1", "xsaves",
            "xfd", NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
        },
        .cpuid = {
            .eax = 0xd,
            .needs_ecx = true, .ecx = 1,
            .reg = R_EAX,
        },
        .tcg_features = TCG_XSAVE_FEATURES,
    },
    [FEAT_XSAVE_XSS_LO] = {
        .type = CPUID_FEATURE_WORD,
        .feat_names = {
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, "cet-u",
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
        },
        .cpuid = {
            .eax = 0xD,
            .needs_ecx = true,
            .ecx = 1,
            .reg = R_ECX,
        },
    },
    [FEAT_XSAVE_XSS_HI] = {
        .type = CPUID_FEATURE_WORD,
        .cpuid = {
            .eax = 0xD,
            .needs_ecx = true,
            .ecx = 1,
            .reg = R_EDX
        },
    },
    [FEAT_6_EAX] = {
        .type = CPUID_FEATURE_WORD,
        .feat_names = {
            NULL, NULL, "arat", NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
        },
        .cpuid = { .eax = 6, .reg = R_EAX, },
        .tcg_features = TCG_6_EAX_FEATURES,
    },
    [FEAT_XSAVE_XCR0_LO] = {
        .type = CPUID_FEATURE_WORD,
        .cpuid = {
            .eax = 0xD,
            .needs_ecx = true, .ecx = 0,
            .reg = R_EAX,
        },
        .tcg_features = ~0U,
        .migratable_flags = XSTATE_FP_MASK | XSTATE_SSE_MASK |
            XSTATE_YMM_MASK | XSTATE_BNDREGS_MASK | XSTATE_BNDCSR_MASK |
            XSTATE_OPMASK_MASK | XSTATE_ZMM_Hi256_MASK | XSTATE_Hi16_ZMM_MASK |
            XSTATE_PKRU_MASK,
    },
    [FEAT_XSAVE_XCR0_HI] = {
        .type = CPUID_FEATURE_WORD,
        .cpuid = {
            .eax = 0xD,
            .needs_ecx = true, .ecx = 0,
            .reg = R_EDX,
        },
        .tcg_features = ~0U,
    },
    /*Below are MSR exposed features*/
    [FEAT_ARCH_CAPABILITIES] = {
        .type = MSR_FEATURE_WORD,
        .feat_names = {
            "rdctl-no", "ibrs-all", "rsba", "skip-l1dfl-vmentry",
            "ssb-no", "mds-no", "pschange-mc-no", "tsx-ctrl",
            "taa-no", NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
        },
        .msr = {
            .index = MSR_IA32_ARCH_CAPABILITIES,
        },
    },
    [FEAT_CORE_CAPABILITY] = {
        .type = MSR_FEATURE_WORD,
        .feat_names = {
            NULL, NULL, NULL, NULL,
            NULL, "split-lock-detect", NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
        },
        .msr = {
            .index = MSR_IA32_CORE_CAPABILITY,
        },
    },
    [FEAT_PERF_CAPABILITIES] = {
        .type = MSR_FEATURE_WORD,
        .feat_names = {
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, "full-width-write", NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
        },
        .msr = {
            .index = MSR_IA32_PERF_CAPABILITIES,
        },
    },

    [FEAT_VMX_PROCBASED_CTLS] = {
        .type = MSR_FEATURE_WORD,
        .feat_names = {
            NULL, NULL, "vmx-vintr-pending", "vmx-tsc-offset",
            NULL, NULL, NULL, "vmx-hlt-exit",
            NULL, "vmx-invlpg-exit", "vmx-mwait-exit", "vmx-rdpmc-exit",
            "vmx-rdtsc-exit", NULL, NULL, "vmx-cr3-load-noexit",
            "vmx-cr3-store-noexit", NULL, NULL, "vmx-cr8-load-exit",
            "vmx-cr8-store-exit", "vmx-flexpriority", "vmx-vnmi-pending", "vmx-movdr-exit",
            "vmx-io-exit", "vmx-io-bitmap", NULL, "vmx-mtf",
            "vmx-msr-bitmap", "vmx-monitor-exit", "vmx-pause-exit", "vmx-secondary-ctls",
        },
        .msr = {
            .index = MSR_IA32_VMX_TRUE_PROCBASED_CTLS,
        }
    },

    [FEAT_VMX_SECONDARY_CTLS] = {
        .type = MSR_FEATURE_WORD,
        .feat_names = {
            "vmx-apicv-xapic", "vmx-ept", "vmx-desc-exit", "vmx-rdtscp-exit",
            "vmx-apicv-x2apic", "vmx-vpid", "vmx-wbinvd-exit", "vmx-unrestricted-guest",
            "vmx-apicv-register", "vmx-apicv-vid", "vmx-ple", "vmx-rdrand-exit",
            "vmx-invpcid-exit", "vmx-vmfunc", "vmx-shadow-vmcs", "vmx-encls-exit",
            "vmx-rdseed-exit", "vmx-pml", NULL, NULL,
            "vmx-xsaves", NULL, NULL, NULL,
            NULL, "vmx-tsc-scaling", NULL, NULL,
            NULL, NULL, NULL, NULL,
        },
        .msr = {
            .index = MSR_IA32_VMX_PROCBASED_CTLS2,
        }
    },

    [FEAT_VMX_PINBASED_CTLS] = {
        .type = MSR_FEATURE_WORD,
        .feat_names = {
            "vmx-intr-exit", NULL, NULL, "vmx-nmi-exit",
            NULL, "vmx-vnmi", "vmx-preemption-timer", "vmx-posted-intr",
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
        },
        .msr = {
            .index = MSR_IA32_VMX_TRUE_PINBASED_CTLS,
        }
    },

    [FEAT_VMX_EXIT_CTLS] = {
        .type = MSR_FEATURE_WORD,
        /*
         * VMX_VM_EXIT_HOST_ADDR_SPACE_SIZE is copied from
         * the LM CPUID bit.
         */
        .feat_names = {
            NULL, NULL, "vmx-exit-nosave-debugctl", NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL /* vmx-exit-host-addr-space-size */, NULL, NULL,
            "vmx-exit-load-perf-global-ctrl", NULL, NULL, "vmx-exit-ack-intr",
            NULL, NULL, "vmx-exit-save-pat", "vmx-exit-load-pat",
            "vmx-exit-save-efer", "vmx-exit-load-efer",
                "vmx-exit-save-preemption-timer", "vmx-exit-clear-bndcfgs",
            NULL, "vmx-exit-clear-rtit-ctl", NULL, NULL,
            "vmx-exit-save-cet-ctl", "vmx-exit-load-pkrs", NULL, NULL,
        },
        .msr = {
            .index = MSR_IA32_VMX_TRUE_EXIT_CTLS,
        }
    },

    [FEAT_VMX_ENTRY_CTLS] = {
        .type = MSR_FEATURE_WORD,
        .feat_names = {
            NULL, NULL, "vmx-entry-noload-debugctl", NULL,
            NULL, NULL, NULL, NULL,
            NULL, "vmx-entry-ia32e-mode", NULL, NULL,
            NULL, "vmx-entry-load-perf-global-ctrl", "vmx-entry-load-pat", "vmx-entry-load-efer",
            "vmx-entry-load-bndcfgs", NULL, "vmx-entry-load-rtit-ctl", NULL,
            "vmx-entry-load-cet-ctl", NULL, "vmx-entry-load-pkrs", NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
        },
        .msr = {
            .index = MSR_IA32_VMX_TRUE_ENTRY_CTLS,
        }
    },

    [FEAT_VMX_MISC] = {
        .type = MSR_FEATURE_WORD,
        .feat_names = {
            NULL, NULL, NULL, NULL,
            NULL, "vmx-store-lma", "vmx-activity-hlt", "vmx-activity-shutdown",
            "vmx-activity-wait-sipi", NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, "vmx-vmwrite-vmexit-fields", "vmx-zero-len-inject", NULL,
        },
        .msr = {
            .index = MSR_IA32_VMX_MISC,
        }
    },

    [FEAT_VMX_EPT_VPID_CAPS] = {
        .type = MSR_FEATURE_WORD,
        .feat_names = {
            "vmx-ept-execonly", NULL, NULL, NULL,
            NULL, NULL, "vmx-page-walk-4", "vmx-page-walk-5",
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            "vmx-ept-2mb", "vmx-ept-1gb", NULL, NULL,
            "vmx-invept", "vmx-eptad", "vmx-ept-advanced-exitinfo", NULL,
            NULL, "vmx-invept-single-context", "vmx-invept-all-context", NULL,
            NULL, NULL, NULL, NULL,
            "vmx-invvpid", NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            "vmx-invvpid-single-addr", "vmx-invept-single-context",
                "vmx-invvpid-all-context", "vmx-invept-single-context-noglobals",
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
        },
        .msr = {
            .index = MSR_IA32_VMX_EPT_VPID_CAP,
        }
    },

    [FEAT_VMX_BASIC] = {
        .type = MSR_FEATURE_WORD,
        .feat_names = {
            [54] = "vmx-ins-outs",
            [55] = "vmx-true-ctls",
        },
        .msr = {
            .index = MSR_IA32_VMX_BASIC,
        },
        /* Just to be safe - we don't support setting the MSEG version field.  */
        .no_autoenable_flags = MSR_VMX_BASIC_DUAL_MONITOR,
    },

    [FEAT_VMX_VMFUNC] = {
        .type = MSR_FEATURE_WORD,
        .feat_names = {
            [0] = "vmx-eptp-switching",
        },
        .msr = {
            .index = MSR_IA32_VMX_VMFUNC,
        }
    },

    [FEAT_14_0_ECX] = {
        .type = CPUID_FEATURE_WORD,
        .feat_names = {
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, "intel-pt-lip",
        },
        .cpuid = {
            .eax = 0x14,
            .needs_ecx = true, .ecx = 0,
            .reg = R_ECX,
        },
        .tcg_features = TCG_14_0_ECX_FEATURES,
     },

    [FEAT_SGX_12_0_EAX] = {
        .type = CPUID_FEATURE_WORD,
        .feat_names = {
            "sgx1", "sgx2", NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
        },
        .cpuid = {
            .eax = 0x12,
            .needs_ecx = true, .ecx = 0,
            .reg = R_EAX,
        },
        .tcg_features = TCG_SGX_12_0_EAX_FEATURES,
    },

    [FEAT_SGX_12_0_EBX] = {
        .type = CPUID_FEATURE_WORD,
        .feat_names = {
            "sgx-exinfo" , NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
        },
        .cpuid = {
            .eax = 0x12,
            .needs_ecx = true, .ecx = 0,
            .reg = R_EBX,
        },
        .tcg_features = TCG_SGX_12_0_EBX_FEATURES,
    },

    [FEAT_SGX_12_1_EAX] = {
        .type = CPUID_FEATURE_WORD,
        .feat_names = {
            NULL, "sgx-debug", "sgx-mode64", NULL,
            "sgx-provisionkey", "sgx-tokenkey", NULL, "sgx-kss",
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL,
        },
        .cpuid = {
            .eax = 0x12,
            .needs_ecx = true, .ecx = 1,
            .reg = R_EAX,
        },
        .tcg_features = TCG_SGX_12_1_EAX_FEATURES,
    },
};

typedef struct KvmTdxCpuidLookup {
    uint32_t tdx_fixed0;
    uint32_t tdx_fixed1;

    /*
     * The CPUID bits that are configurable from the view of TDX module
     * but require VMM emulation if configured to enabled by VMM.
     *
     * For those bits, they cannot be enabled actually if VMM (KVM/QEMU) cannot
     * virtualize them.
     */
    uint32_t vmm_fixup;

    bool inducing_ve;
    /*
     * The maximum supported feature set for given inducing-#VE leaf.
     * It's valid only when .inducing_ve is true.
     */
    uint32_t supported_on_ve;
} KvmTdxCpuidLookup;

#define BIT(nr)                 (1UL << (nr))
#define BIT_ULL(nr)             (1ULL << (nr))
static KvmTdxCpuidLookup tdx_cpuid_lookup[FEATURE_WORDS] = {
    [FEAT_1_EDX] = {
        .tdx_fixed0 =
            BIT(10) | BIT(20) | CPUID_IA64,
        .tdx_fixed1 =
            CPUID_MSR | CPUID_PAE | CPUID_MCE | CPUID_APIC |
            CPUID_MTRR | CPUID_MCA | CPUID_CLFLUSH | CPUID_DTS,
        .vmm_fixup =
            CPUID_ACPI | CPUID_PBE,
    },
    [FEAT_1_ECX] = {
        .tdx_fixed0 =
            CPUID_EXT_VMX | CPUID_EXT_SMX |
            BIT(16),
        .tdx_fixed1 =
            CPUID_EXT_CX16 | CPUID_EXT_PDCM | CPUID_EXT_X2APIC |
            CPUID_EXT_AES | CPUID_EXT_XSAVE | CPUID_EXT_RDRAND |
            CPUID_EXT_HYPERVISOR | CPUID_EXT_MONITOR,
        .vmm_fixup =
            CPUID_EXT_EST | CPUID_EXT_TM2 | CPUID_EXT_XTPR | CPUID_EXT_DCA,
    },
    [FEAT_8000_0001_EDX] = {
        .tdx_fixed1 =
            CPUID_EXT2_NX | CPUID_EXT2_PDPE1GB | CPUID_EXT2_RDTSCP |
            CPUID_EXT2_LM,
    },
    [FEAT_7_0_EBX] = {
        .tdx_fixed0 =
            CPUID_7_0_EBX_TSC_ADJUST | CPUID_7_0_EBX_SGX | CPUID_7_0_EBX_MPX,
        .tdx_fixed1 =
            CPUID_7_0_EBX_FSGSBASE | CPUID_7_0_EBX_RTM |
            CPUID_7_0_EBX_RDSEED | CPUID_7_0_EBX_SMAP |
            CPUID_7_0_EBX_CLFLUSHOPT | CPUID_7_0_EBX_CLWB |
            CPUID_7_0_EBX_SHA_NI | CPUID_7_0_EBX_HLE,
        .vmm_fixup =
            CPUID_7_0_EBX_PQM | CPUID_7_0_EBX_RDT_A,
    },
    [FEAT_7_0_ECX] = {
        .tdx_fixed0 =
            CPUID_7_0_ECX_FZM | CPUID_7_0_ECX_MAWAU |
            CPUID_7_0_ECX_ENQCMD | CPUID_7_0_ECX_SGX_LC,
        .tdx_fixed1 =
            CPUID_7_0_ECX_MOVDIR64B | CPUID_7_0_ECX_BUS_LOCK_DETECT,
        .vmm_fixup =
            CPUID_7_0_ECX_TME,
    },
    [FEAT_7_0_EDX] = {
        .tdx_fixed1 =
            CPUID_7_0_EDX_SPEC_CTRL | CPUID_7_0_EDX_ARCH_CAPABILITIES |
            CPUID_7_0_EDX_CORE_CAPABILITY | CPUID_7_0_EDX_SPEC_CTRL_SSBD,
        .vmm_fixup =
            CPUID_7_0_EDX_PCONFIG,
    },
    [FEAT_8000_0008_EBX] = {
        .tdx_fixed0 =
            ~CPUID_8000_0008_EBX_WBNOINVD,
        .tdx_fixed1 =
            CPUID_8000_0008_EBX_WBNOINVD,
    },
    [FEAT_XSAVE] = {
        .tdx_fixed1 =
            CPUID_XSAVE_XSAVEOPT | CPUID_XSAVE_XSAVEC |
            CPUID_XSAVE_XSAVES,
    },
    [FEAT_6_EAX] = {
        .inducing_ve = true,
        .supported_on_ve = -1U,
    },
    [FEAT_8000_0007_EDX] = {
        .inducing_ve = true,
        .supported_on_ve = -1U,
    },
    [FEAT_KVM] = {
        .inducing_ve = true,
        .supported_on_ve = TDX_SUPPORTED_KVM_FEATURES,
    },
};

#define TDX_ATTRIBUTES_MAX_BITS      64

typedef struct FeatureMask {
    FeatureWord index;
    uint64_t mask;
} FeatureMask;

typedef struct FeatureDep {
    FeatureMask from, to;
} FeatureDep;

static FeatureMask tdx_attrs_ctrl_fields[TDX_ATTRIBUTES_MAX_BITS] = {
    [30] = { .index = FEAT_7_0_ECX, .mask = CPUID_7_0_ECX_PKS },
    [31] = { .index = FEAT_7_0_ECX, .mask = CPUID_7_0_ECX_KeyLocker},
};

static FeatureDep xfam_dependencies[] = {
    /* XFAM[7:5] may be set to 111 only when XFAM[2] is set to 1 */
    {
        .from = { FEAT_XSAVE_XCR0_LO, XSTATE_YMM_MASK },
        .to = { FEAT_XSAVE_XCR0_LO, XSTATE_AVX_512_MASK },
    },
    {
        .from = { FEAT_XSAVE_XCR0_LO, XSTATE_YMM_MASK },
        .to = { FEAT_1_ECX,
                CPUID_EXT_FMA | CPUID_EXT_AVX | CPUID_EXT_F16C },
    },
    {
        .from = { FEAT_XSAVE_XCR0_LO, XSTATE_YMM_MASK },
        .to = { FEAT_7_0_EBX, CPUID_7_0_EBX_AVX2 },
    },
    {
        .from = { FEAT_XSAVE_XCR0_LO, XSTATE_YMM_MASK },
        .to = { FEAT_7_0_ECX, CPUID_7_0_ECX_VAES | CPUID_7_0_ECX_VPCLMULQDQ},
    },
    {
        .from = { FEAT_XSAVE_XCR0_LO, XSTATE_AVX_512_MASK },
        .to = { FEAT_7_0_EBX,
                CPUID_7_0_EBX_AVX512F | CPUID_7_0_EBX_AVX512DQ |
                CPUID_7_0_EBX_AVX512IFMA | CPUID_7_0_EBX_AVX512PF |
                CPUID_7_0_EBX_AVX512ER | CPUID_7_0_EBX_AVX512CD |
                CPUID_7_0_EBX_AVX512BW | CPUID_7_0_EBX_AVX512VL },
    },
    {
        .from = { FEAT_XSAVE_XCR0_LO, XSTATE_AVX_512_MASK },
        .to = { FEAT_7_0_ECX,
                CPUID_7_0_ECX_AVX512_VBMI | CPUID_7_0_ECX_AVX512_VBMI2 |
                CPUID_7_0_ECX_AVX512VNNI | CPUID_7_0_ECX_AVX512BITALG |
                CPUID_7_0_ECX_AVX512_VPOPCNTDQ },
    },
    {
        .from = { FEAT_XSAVE_XCR0_LO, XSTATE_AVX_512_MASK },
        .to = { FEAT_7_0_EDX,
                CPUID_7_0_EDX_AVX512_4VNNIW | CPUID_7_0_EDX_AVX512_4FMAPS |
                CPUID_7_0_EDX_AVX512_VP2INTERSECT | CPUID_7_0_EDX_AVX512_FP16 },
    },
    {
        .from = { FEAT_XSAVE_XCR0_LO, XSTATE_AVX_512_MASK },
        .to = { FEAT_7_1_EAX, CPUID_7_1_EAX_AVX512_BF16 | CPUID_7_1_EAX_AVX_VNNI },
    },
    {
        .from = { FEAT_XSAVE_XCR0_LO, XSTATE_PKRU_MASK },
        .to = { FEAT_7_0_ECX, CPUID_7_0_ECX_PKU },
    },
    {
        .from = { FEAT_XSAVE_XCR0_LO, XSTATE_AMX_MASK },
        .to = { FEAT_7_0_EDX,
                CPUID_7_0_EDX_AMX_BF16 | CPUID_7_0_EDX_AMX_TILE |
                CPUID_7_0_EDX_AMX_INT8}
    },
    /* XSS features */
    {
        .from = { FEAT_XSAVE_XSS_LO, XSTATE_RTIT_MASK },
        .to = { FEAT_7_0_EBX, CPUID_7_0_EBX_INTEL_PT },
    },
    {
        .from = { FEAT_XSAVE_XSS_LO, XSTATE_RTIT_MASK },
        .to = { FEAT_14_0_ECX, ~0ull },
    },
    {
        .from = { FEAT_XSAVE_XSS_LO, XSTATE_CET_MASK },
        .to = { FEAT_7_0_ECX, CPUID_7_0_ECX_CET_SHSTK },
    },
    {
        .from = { FEAT_XSAVE_XSS_LO, XSTATE_CET_MASK },
        .to = { FEAT_7_0_EDX, CPUID_7_0_EDX_CET_IBT },
    },
    {
        .from = { FEAT_XSAVE_XSS_LO, XSTATE_UINTR_MASK },
        .to = { FEAT_7_0_EDX, CPUID_7_0_EDX_UNIT },
    },
    {
        .from = { FEAT_XSAVE_XSS_LO, XSTATE_ARCH_LBR_MASK },
        .to = { FEAT_7_0_EDX, CPUID_7_0_EDX_ARCH_LBR },
    },
};

FeatureMask tdx_xfam_representative[] = {
    [XSTATE_YMM_BIT] = { .index = FEAT_1_ECX, .mask = CPUID_EXT_AVX },
    [XSTATE_OPMASK_BIT] = { .index = FEAT_7_0_EBX, .mask = CPUID_7_0_EBX_AVX512F },
    [XSTATE_ZMM_Hi256_BIT] = { .index = FEAT_7_0_EBX, .mask = CPUID_7_0_EBX_AVX512F },
    [XSTATE_Hi16_ZMM_BIT] = { .index = FEAT_7_0_EBX, .mask = CPUID_7_0_EBX_AVX512F },
    [XSTATE_RTIT_BIT] = { .index = FEAT_7_0_EBX, .mask = CPUID_7_0_EBX_INTEL_PT },
    [XSTATE_PKRU_BIT] = { .index = FEAT_7_0_ECX, .mask = CPUID_7_0_ECX_PKU },
    [XSTATE_CET_U_BIT] = { .index = FEAT_7_0_ECX, .mask = CPUID_7_0_ECX_CET_SHSTK },
    [XSTATE_CET_S_BIT] = { .index = FEAT_7_0_ECX, .mask = CPUID_7_0_ECX_CET_SHSTK },
    [XSTATE_ARCH_LBR_BIT] = { .index = FEAT_7_0_EDX, .mask = CPUID_7_0_EDX_ARCH_LBR },
    [XSTATE_XTILE_CFG_BIT] = { .index = FEAT_7_0_EDX, .mask = CPUID_7_0_EDX_AMX_TILE },
    [XSTATE_XTILE_DATA_BIT] = { .index = FEAT_7_0_EDX, .mask = CPUID_7_0_EDX_AMX_TILE },
};
typedef uint64_t FeatureWordArray[FEATURE_WORDS];


typedef enum X86CPURegister32 {
    X86_CPU_REGISTER32_EAX,
    X86_CPU_REGISTER32_EBX,
    X86_CPU_REGISTER32_ECX,
    X86_CPU_REGISTER32_EDX,
    X86_CPU_REGISTER32_ESP,
    X86_CPU_REGISTER32_EBP,
    X86_CPU_REGISTER32_ESI,
    X86_CPU_REGISTER32_EDI,
    X86_CPU_REGISTER32__MAX,
} X86CPURegister32;


typedef struct X86RegisterInfo32 {
    /* Name of register */
    const char *name;
    /* QAPI enum value register */
    X86CPURegister32 qapi_enum;
} X86RegisterInfo32;

#define CPU_NB_REGS32 8

#define REGISTER(reg) \
    [R_##reg] = { .name = #reg, .qapi_enum = X86_CPU_REGISTER32_##reg }
static const X86RegisterInfo32 x86_reg_info_32[CPU_NB_REGS32] = {
    REGISTER(EAX),
    REGISTER(ECX),
    REGISTER(EDX),
    REGISTER(EBX),
    REGISTER(ESP),
    REGISTER(EBP),
    REGISTER(ESI),
    REGISTER(EDI),
};
#undef REGISTER

static FeatureDep feature_dependencies[] = {
    {
        .from = { FEAT_7_0_EDX,             CPUID_7_0_EDX_ARCH_CAPABILITIES },
        .to = { FEAT_ARCH_CAPABILITIES,     ~0ull },
    },
    {
        .from = { FEAT_7_0_EDX,             CPUID_7_0_EDX_CORE_CAPABILITY },
        .to = { FEAT_CORE_CAPABILITY,       ~0ull },
    },
    {
        .from = { FEAT_1_ECX,             CPUID_EXT_PDCM },
        .to = { FEAT_PERF_CAPABILITIES,       ~0ull },
    },
    {
        .from = { FEAT_1_ECX,               CPUID_EXT_VMX },
        .to = { FEAT_VMX_PROCBASED_CTLS,    ~0ull },
    },
    {
        .from = { FEAT_1_ECX,               CPUID_EXT_VMX },
        .to = { FEAT_VMX_PINBASED_CTLS,     ~0ull },
    },
    {
        .from = { FEAT_1_ECX,               CPUID_EXT_VMX },
        .to = { FEAT_VMX_EXIT_CTLS,         ~0ull },
    },
    {
        .from = { FEAT_1_ECX,               CPUID_EXT_VMX },
        .to = { FEAT_VMX_ENTRY_CTLS,        ~0ull },
    },
    {
        .from = { FEAT_1_ECX,               CPUID_EXT_VMX },
        .to = { FEAT_VMX_MISC,              ~0ull },
    },
    {
        .from = { FEAT_1_ECX,               CPUID_EXT_VMX },
        .to = { FEAT_VMX_BASIC,             ~0ull },
    },
    {
        .from = { FEAT_8000_0001_EDX,       CPUID_EXT2_LM },
        .to = { FEAT_VMX_ENTRY_CTLS,        VMX_VM_ENTRY_IA32E_MODE },
    },
    {
        .from = { FEAT_VMX_PROCBASED_CTLS,  VMX_CPU_BASED_ACTIVATE_SECONDARY_CONTROLS },
        .to = { FEAT_VMX_SECONDARY_CTLS,    ~0ull },
    },
    {
        .from = { FEAT_XSAVE,               CPUID_XSAVE_XSAVES },
        .to = { FEAT_VMX_SECONDARY_CTLS,    VMX_SECONDARY_EXEC_XSAVES },
    },
    {
        .from = { FEAT_1_ECX,               CPUID_EXT_RDRAND },
        .to = { FEAT_VMX_SECONDARY_CTLS,    VMX_SECONDARY_EXEC_RDRAND_EXITING },
    },
    {
        .from = { FEAT_7_0_EBX,             CPUID_7_0_EBX_INVPCID },
        .to = { FEAT_VMX_SECONDARY_CTLS,    VMX_SECONDARY_EXEC_ENABLE_INVPCID },
    },
    {
        .from = { FEAT_7_0_EBX,             CPUID_7_0_EBX_MPX },
        .to = { FEAT_VMX_EXIT_CTLS,         VMX_VM_EXIT_CLEAR_BNDCFGS },
    },
    {
        .from = { FEAT_7_0_EBX,             CPUID_7_0_EBX_MPX },
        .to = { FEAT_VMX_ENTRY_CTLS,        VMX_VM_ENTRY_LOAD_BNDCFGS },
    },
    {
        .from = { FEAT_7_0_EBX,             CPUID_7_0_EBX_RDSEED },
        .to = { FEAT_VMX_SECONDARY_CTLS,    VMX_SECONDARY_EXEC_RDSEED_EXITING },
    },
    {
        .from = { FEAT_7_0_EBX,             CPUID_7_0_EBX_INTEL_PT },
        .to = { FEAT_14_0_ECX,              ~0ull },
    },
    {
        .from = { FEAT_8000_0001_EDX,       CPUID_EXT2_RDTSCP },
        .to = { FEAT_VMX_SECONDARY_CTLS,    VMX_SECONDARY_EXEC_RDTSCP },
    },
    {
        .from = { FEAT_VMX_SECONDARY_CTLS,  VMX_SECONDARY_EXEC_ENABLE_EPT },
        .to = { FEAT_VMX_EPT_VPID_CAPS,     0xffffffffull },
    },
    {
        .from = { FEAT_VMX_SECONDARY_CTLS,  VMX_SECONDARY_EXEC_ENABLE_EPT },
        .to = { FEAT_VMX_SECONDARY_CTLS,    VMX_SECONDARY_EXEC_UNRESTRICTED_GUEST },
    },
    {
        .from = { FEAT_VMX_SECONDARY_CTLS,  VMX_SECONDARY_EXEC_ENABLE_VPID },
        .to = { FEAT_VMX_EPT_VPID_CAPS,     0xffffffffull << 32 },
    },
    {
        .from = { FEAT_VMX_SECONDARY_CTLS,  VMX_SECONDARY_EXEC_ENABLE_VMFUNC },
        .to = { FEAT_VMX_VMFUNC,            ~0ull },
    },
    {
        .from = { FEAT_8000_0001_ECX,       CPUID_EXT3_SVM },
        .to = { FEAT_SVM,                   ~0ull },
    },
};

typedef struct ExtSaveArea {
    uint32_t feature, bits;
    uint32_t offset, size;
    uint32_t ecx;
} ExtSaveArea;

typedef struct {
    uint64_t low;
    uint16_t high;
} floatx80;

typedef uint16_t float16;
typedef uint32_t float32;
typedef uint64_t float64;

typedef union MMXReg {
    uint8_t  _b_MMXReg[64 / 8];
    uint16_t _w_MMXReg[64 / 16];
    uint32_t _l_MMXReg[64 / 32];
    uint64_t _q_MMXReg[64 / 64];
    float32  _s_MMXReg[64 / 32];
    float64  _d_MMXReg[64 / 64];
} MMXReg;

typedef union {
    floatx80 d __attribute__((aligned(16)));
    MMXReg mmx;
} FPReg;

typedef struct BNDReg {
    uint64_t lb;
    uint64_t ub;
} BNDReg;

typedef struct BNDCSReg {
    uint64_t cfgu;
    uint64_t sts;
} BNDCSReg;

typedef union X86LegacyXSaveArea {
    struct {
        uint16_t fcw;
        uint16_t fsw;
        uint8_t ftw;
        uint8_t reserved;
        uint16_t fpop;
        uint64_t fpip;
        uint64_t fpdp;
        uint32_t mxcsr;
        uint32_t mxcsr_mask;
        FPReg fpregs[8];
        uint8_t xmm_regs[16][16];
    };
    uint8_t data[512];
} X86LegacyXSaveArea;

typedef struct X86XSaveHeader {
    uint64_t xstate_bv;
    uint64_t xcomp_bv;
    uint64_t reserve0;
    uint8_t reserved[40];
} X86XSaveHeader;

/* Ext. save area 2: AVX State */
typedef struct XSaveAVX {
    uint8_t ymmh[16][16];
} XSaveAVX;

/* Ext. save area 3: BNDREG */
typedef struct XSaveBNDREG {
    BNDReg bnd_regs[4];
} XSaveBNDREG;

/* Ext. save area 4: BNDCSR */
typedef union XSaveBNDCSR {
    BNDCSReg bndcsr;
    uint8_t data[64];
} XSaveBNDCSR;

#define NB_OPMASK_REGS 8

/* Ext. save area 5: Opmask */
typedef struct XSaveOpmask {
    uint64_t opmask_regs[NB_OPMASK_REGS];
} XSaveOpmask;

/* Ext. save area 6: ZMM_Hi256 */
typedef struct XSaveZMM_Hi256 {
    uint8_t zmm_hi256[16][32];
} XSaveZMM_Hi256;

/* Ext. save area 7: Hi16_ZMM */
typedef struct XSaveHi16_ZMM {
    uint8_t hi16_zmm[16][64];
} XSaveHi16_ZMM;

/* Ext. save area 9: PKRU state */
typedef struct XSavePKRU {
    uint32_t pkru;
    uint32_t padding;
} XSavePKRU;

/* Ext. save area 11: User mode CET state */
typedef struct XSavesCETU {
    uint64_t u_cet;
    uint64_t user_ssp;
} XSavesCETU;

/* Ext. save area 17: AMX XTILECFG state */
typedef struct XSaveXTILECFG {
    uint8_t xtilecfg[64];
} XSaveXTILECFG;

/* Ext. save area 18: AMX XTILEDATA state */
typedef struct XSaveXTILEDATA {
    uint8_t xtiledata[8][1024];
} XSaveXTILEDATA;

typedef struct {
       uint64_t from;
       uint64_t to;
       uint64_t info;
} LBREntry;

#define ARCH_LBR_NR_ENTRIES            32

/* Ext. save area 19: Supervisor mode Arch LBR state */
typedef struct XSavesArchLBR {
    uint64_t lbr_ctl;
    uint64_t lbr_depth;
    uint64_t ler_from;
    uint64_t ler_to;
    uint64_t ler_info;
    LBREntry lbr_records[ARCH_LBR_NR_ENTRIES];
} XSavesArchLBR;

#define XSAVE_STATE_AREA_COUNT (XSTATE_XTILE_DATA_BIT + 1)
ExtSaveArea x86_ext_save_areas[XSAVE_STATE_AREA_COUNT] = {
    [XSTATE_FP_BIT] = {
        /* x87 FP state component is always enabled if XSAVE is supported */
        .feature = FEAT_1_ECX, .bits = CPUID_EXT_XSAVE,
        .size = sizeof(X86LegacyXSaveArea) + sizeof(X86XSaveHeader),
    },
    [XSTATE_SSE_BIT] = {
        /* SSE state component is always enabled if XSAVE is supported */
        .feature = FEAT_1_ECX, .bits = CPUID_EXT_XSAVE,
        .size = sizeof(X86LegacyXSaveArea) + sizeof(X86XSaveHeader),
    },
    [XSTATE_YMM_BIT] =
          { .feature = FEAT_1_ECX, .bits = CPUID_EXT_AVX,
            .size = sizeof(XSaveAVX) },
    [XSTATE_BNDREGS_BIT] =
          { .feature = FEAT_7_0_EBX, .bits = CPUID_7_0_EBX_MPX,
            .size = sizeof(XSaveBNDREG) },
    [XSTATE_BNDCSR_BIT] =
          { .feature = FEAT_7_0_EBX, .bits = CPUID_7_0_EBX_MPX,
            .size = sizeof(XSaveBNDCSR)  },
    [XSTATE_OPMASK_BIT] =
          { .feature = FEAT_7_0_EBX, .bits = CPUID_7_0_EBX_AVX512F,
            .size = sizeof(XSaveOpmask) },
    [XSTATE_ZMM_Hi256_BIT] =
          { .feature = FEAT_7_0_EBX, .bits = CPUID_7_0_EBX_AVX512F,
            .size = sizeof(XSaveZMM_Hi256) },
    [XSTATE_Hi16_ZMM_BIT] =
          { .feature = FEAT_7_0_EBX, .bits = CPUID_7_0_EBX_AVX512F,
            .size = sizeof(XSaveHi16_ZMM) },
    [XSTATE_PKRU_BIT] =
          { .feature = FEAT_7_0_ECX, .bits = CPUID_7_0_ECX_PKU,
            .size = sizeof(XSavePKRU) },
    [XSTATE_ARCH_LBR_BIT] = {
            .feature = FEAT_7_0_EDX, .bits = CPUID_7_0_EDX_ARCH_LBR,
            .offset = 0 /*supervisor mode component, offset = 0 */,
            .size = sizeof(XSavesArchLBR) },
    [XSTATE_CET_U_BIT] = {
        .feature = FEAT_7_0_ECX, .bits = CPUID_7_0_ECX_CET_SHSTK,
        /*
         * The features enabled in XSS MSR always use compacted format
         * to store the data, in this case .offset == 0.
         */
        .offset = 0,
        .size = sizeof(XSavesCETU) },
    [XSTATE_XTILE_CFG_BIT] = {
        .feature = FEAT_7_0_EDX, .bits = CPUID_7_0_EDX_AMX_TILE,
        .size = sizeof(XSaveXTILECFG) },
    [XSTATE_XTILE_DATA_BIT] = {
        .feature = FEAT_7_0_EDX, .bits = CPUID_7_0_EDX_AMX_TILE,
        .size = sizeof(XSaveXTILEDATA) }
};

/* Helpers for building CPUID[2] descriptors: */

enum CacheType {
    DATA_CACHE,
    INSTRUCTION_CACHE,
    UNIFIED_CACHE
};

typedef struct CPUCacheInfo {
    enum CacheType type;
    uint8_t level;
    /* Size in bytes */
    uint32_t size;
    /* Line size, in bytes */
    uint16_t line_size;
    /*
     * Associativity.
     * Note: representation of fully-associative caches is not implemented
     */
    uint8_t associativity;
    /* Physical line partitions. CPUID[0x8000001D].EBX, CPUID[4].EBX */
    uint8_t partitions;
    /* Number of sets. CPUID[0x8000001D].ECX, CPUID[4].ECX */
    uint32_t sets;
    /*
     * Lines per tag.
     * AMD-specific: CPUID[0x80000005], CPUID[0x80000006].
     * (Is this synonym to @partitions?)
     */
    uint8_t lines_per_tag;

    /* Self-initializing cache */
    bool self_init;
    /*
     * WBINVD/INVD is not guaranteed to act upon lower level caches of
     * non-originating threads sharing this cache.
     * CPUID[4].EDX[bit 0], CPUID[0x8000001D].EDX[bit 0]
     */
    bool no_invd_sharing;
    /*
     * Cache is inclusive of lower cache levels.
     * CPUID[4].EDX[bit 1], CPUID[0x8000001D].EDX[bit 1].
     */
    bool inclusive;
    /*
     * A complex function is used to index the cache, potentially using all
     * address bits.  CPUID[4].EDX[bit 2].
     */
    bool complex_indexing;
} CPUCacheInfo;

typedef struct CPUCaches {
        CPUCacheInfo *l1d_cache;
        CPUCacheInfo *l1i_cache;
        CPUCacheInfo *l2_cache;
        CPUCacheInfo *l3_cache;
} CPUCaches;



struct CPUID2CacheDescriptorInfo {
    enum CacheType type;
    int level;
    int size;
    int line_size;
    int associativity;
};

#define KiB     (INT64_C(1) << 10)
#define MiB     (INT64_C(1) << 20)
#define GiB     (INT64_C(1) << 30)
#define TiB     (INT64_C(1) << 40)
#define PiB     (INT64_C(1) << 50)
#define EiB     (INT64_C(1) << 60)

/*
 * Known CPUID 2 cache descriptors.
 * From Intel SDM Volume 2A, CPUID instruction
 */
struct CPUID2CacheDescriptorInfo cpuid2_cache_descriptors[] = {
    [0x06] = { .level = 1, .type = INSTRUCTION_CACHE, .size =   8 * KiB,
               .associativity = 4,  .line_size = 32, },
    [0x08] = { .level = 1, .type = INSTRUCTION_CACHE, .size =  16 * KiB,
               .associativity = 4,  .line_size = 32, },
    [0x09] = { .level = 1, .type = INSTRUCTION_CACHE, .size =  32 * KiB,
               .associativity = 4,  .line_size = 64, },
    [0x0A] = { .level = 1, .type = DATA_CACHE,        .size =   8 * KiB,
               .associativity = 2,  .line_size = 32, },
    [0x0C] = { .level = 1, .type = DATA_CACHE,        .size =  16 * KiB,
               .associativity = 4,  .line_size = 32, },
    [0x0D] = { .level = 1, .type = DATA_CACHE,        .size =  16 * KiB,
               .associativity = 4,  .line_size = 64, },
    [0x0E] = { .level = 1, .type = DATA_CACHE,        .size =  24 * KiB,
               .associativity = 6,  .line_size = 64, },
    [0x1D] = { .level = 2, .type = UNIFIED_CACHE,     .size = 128 * KiB,
               .associativity = 2,  .line_size = 64, },
    [0x21] = { .level = 2, .type = UNIFIED_CACHE,     .size = 256 * KiB,
               .associativity = 8,  .line_size = 64, },
    /* lines per sector is not supported cpuid2_cache_descriptor(),
    * so descriptors 0x22, 0x23 are not included
    */
    [0x24] = { .level = 2, .type = UNIFIED_CACHE,     .size =   1 * MiB,
               .associativity = 16, .line_size = 64, },
    /* lines per sector is not supported cpuid2_cache_descriptor(),
    * so descriptors 0x25, 0x20 are not included
    */
    [0x2C] = { .level = 1, .type = DATA_CACHE,        .size =  32 * KiB,
               .associativity = 8,  .line_size = 64, },
    [0x30] = { .level = 1, .type = INSTRUCTION_CACHE, .size =  32 * KiB,
               .associativity = 8,  .line_size = 64, },
    [0x41] = { .level = 2, .type = UNIFIED_CACHE,     .size = 128 * KiB,
               .associativity = 4,  .line_size = 32, },
    [0x42] = { .level = 2, .type = UNIFIED_CACHE,     .size = 256 * KiB,
               .associativity = 4,  .line_size = 32, },
    [0x43] = { .level = 2, .type = UNIFIED_CACHE,     .size = 512 * KiB,
               .associativity = 4,  .line_size = 32, },
    [0x44] = { .level = 2, .type = UNIFIED_CACHE,     .size =   1 * MiB,
               .associativity = 4,  .line_size = 32, },
    [0x45] = { .level = 2, .type = UNIFIED_CACHE,     .size =   2 * MiB,
               .associativity = 4,  .line_size = 32, },
    [0x46] = { .level = 3, .type = UNIFIED_CACHE,     .size =   4 * MiB,
               .associativity = 4,  .line_size = 64, },
    [0x47] = { .level = 3, .type = UNIFIED_CACHE,     .size =   8 * MiB,
               .associativity = 8,  .line_size = 64, },
    [0x48] = { .level = 2, .type = UNIFIED_CACHE,     .size =   3 * MiB,
               .associativity = 12, .line_size = 64, },
    /* Descriptor 0x49 depends on CPU family/model, so it is not included */
    [0x4A] = { .level = 3, .type = UNIFIED_CACHE,     .size =   6 * MiB,
               .associativity = 12, .line_size = 64, },
    [0x4B] = { .level = 3, .type = UNIFIED_CACHE,     .size =   8 * MiB,
               .associativity = 16, .line_size = 64, },
    [0x4C] = { .level = 3, .type = UNIFIED_CACHE,     .size =  12 * MiB,
               .associativity = 12, .line_size = 64, },
    [0x4D] = { .level = 3, .type = UNIFIED_CACHE,     .size =  16 * MiB,
               .associativity = 16, .line_size = 64, },
    [0x4E] = { .level = 2, .type = UNIFIED_CACHE,     .size =   6 * MiB,
               .associativity = 24, .line_size = 64, },
    [0x60] = { .level = 1, .type = DATA_CACHE,        .size =  16 * KiB,
               .associativity = 8,  .line_size = 64, },
    [0x66] = { .level = 1, .type = DATA_CACHE,        .size =   8 * KiB,
               .associativity = 4,  .line_size = 64, },
    [0x67] = { .level = 1, .type = DATA_CACHE,        .size =  16 * KiB,
               .associativity = 4,  .line_size = 64, },
    [0x68] = { .level = 1, .type = DATA_CACHE,        .size =  32 * KiB,
               .associativity = 4,  .line_size = 64, },
    [0x78] = { .level = 2, .type = UNIFIED_CACHE,     .size =   1 * MiB,
               .associativity = 4,  .line_size = 64, },
    /* lines per sector is not supported cpuid2_cache_descriptor(),
    * so descriptors 0x79, 0x7A, 0x7B, 0x7C are not included.
    */
    [0x7D] = { .level = 2, .type = UNIFIED_CACHE,     .size =   2 * MiB,
               .associativity = 8,  .line_size = 64, },
    [0x7F] = { .level = 2, .type = UNIFIED_CACHE,     .size = 512 * KiB,
               .associativity = 2,  .line_size = 64, },
    [0x80] = { .level = 2, .type = UNIFIED_CACHE,     .size = 512 * KiB,
               .associativity = 8,  .line_size = 64, },
    [0x82] = { .level = 2, .type = UNIFIED_CACHE,     .size = 256 * KiB,
               .associativity = 8,  .line_size = 32, },
    [0x83] = { .level = 2, .type = UNIFIED_CACHE,     .size = 512 * KiB,
               .associativity = 8,  .line_size = 32, },
    [0x84] = { .level = 2, .type = UNIFIED_CACHE,     .size =   1 * MiB,
               .associativity = 8,  .line_size = 32, },
    [0x85] = { .level = 2, .type = UNIFIED_CACHE,     .size =   2 * MiB,
               .associativity = 8,  .line_size = 32, },
    [0x86] = { .level = 2, .type = UNIFIED_CACHE,     .size = 512 * KiB,
               .associativity = 4,  .line_size = 64, },
    [0x87] = { .level = 2, .type = UNIFIED_CACHE,     .size =   1 * MiB,
               .associativity = 8,  .line_size = 64, },
    [0xD0] = { .level = 3, .type = UNIFIED_CACHE,     .size = 512 * KiB,
               .associativity = 4,  .line_size = 64, },
    [0xD1] = { .level = 3, .type = UNIFIED_CACHE,     .size =   1 * MiB,
               .associativity = 4,  .line_size = 64, },
    [0xD2] = { .level = 3, .type = UNIFIED_CACHE,     .size =   2 * MiB,
               .associativity = 4,  .line_size = 64, },
    [0xD6] = { .level = 3, .type = UNIFIED_CACHE,     .size =   1 * MiB,
               .associativity = 8,  .line_size = 64, },
    [0xD7] = { .level = 3, .type = UNIFIED_CACHE,     .size =   2 * MiB,
               .associativity = 8,  .line_size = 64, },
    [0xD8] = { .level = 3, .type = UNIFIED_CACHE,     .size =   4 * MiB,
               .associativity = 8,  .line_size = 64, },
    [0xDC] = { .level = 3, .type = UNIFIED_CACHE,     .size = 1.5 * MiB,
               .associativity = 12, .line_size = 64, },
    [0xDD] = { .level = 3, .type = UNIFIED_CACHE,     .size =   3 * MiB,
               .associativity = 12, .line_size = 64, },
    [0xDE] = { .level = 3, .type = UNIFIED_CACHE,     .size =   6 * MiB,
               .associativity = 12, .line_size = 64, },
    [0xE2] = { .level = 3, .type = UNIFIED_CACHE,     .size =   2 * MiB,
               .associativity = 16, .line_size = 64, },
    [0xE3] = { .level = 3, .type = UNIFIED_CACHE,     .size =   4 * MiB,
               .associativity = 16, .line_size = 64, },
    [0xE4] = { .level = 3, .type = UNIFIED_CACHE,     .size =   8 * MiB,
               .associativity = 16, .line_size = 64, },
    [0xEA] = { .level = 3, .type = UNIFIED_CACHE,     .size =  12 * MiB,
               .associativity = 24, .line_size = 64, },
    [0xEB] = { .level = 3, .type = UNIFIED_CACHE,     .size =  18 * MiB,
               .associativity = 24, .line_size = 64, },
    [0xEC] = { .level = 3, .type = UNIFIED_CACHE,     .size =  24 * MiB,
               .associativity = 24, .line_size = 64, },
};

/* EAX: */
#define CACHE_TYPE_D    1
#define CACHE_TYPE_I    2
#define CACHE_TYPE_UNIFIED   3

#define CACHE_LEVEL(l)        (l << 5)

#define CACHE_SELF_INIT_LEVEL (1 << 8)

/* EDX: */
#define CACHE_NO_INVD_SHARING   (1 << 0)
#define CACHE_INCLUSIVE       (1 << 1)
#define CACHE_COMPLEX_IDX     (1 << 2)

/* Encode CacheType for CPUID[4].EAX */
#define CACHE_TYPE(t) (((t) == DATA_CACHE) ? CACHE_TYPE_D : \
                       ((t) == INSTRUCTION_CACHE) ? CACHE_TYPE_I : \
                       ((t) == UNIFIED_CACHE) ? CACHE_TYPE_UNIFIED : \
                       0 /* Invalid value */)
#define CPUID_MWAIT_IBE     (1U << 1) /* Interrupts can exit capability */
#define CPUID_MWAIT_EMX     (1U << 0) /* enumeration supported */

static inline int clz32(uint32_t val)
{
    return val ? __builtin_clz(val) : 32;
}

static inline int clz64(uint64_t val)
{
    return val ? __builtin_clzll(val) : 64;
}

static inline int ctz32(uint32_t val)
{
    return val ? __builtin_ctz(val) : 32;
}

static inline int ctz64(uint64_t val)
{
    return val ? __builtin_ctzll(val) : 64;
}

static inline uint64_t pow2ceil(uint64_t value)
{
    int n = clz64(value - 1);

    if (!n) {
        /*
         * @value - 1 has no leading zeroes, thus @value - 1 >= 2^63
         * Therefore, either @value == 0 or @value > 2^63.
         * If it's 0, return 1, else return 0.
         */
        return !value;
    }
    return 0x8000000000000000ull >> (n - 1);
}

/* CPUID[0xB].ECX level types */
#define CPUID_TOPOLOGY_LEVEL_INVALID  (0U << 8)
#define CPUID_TOPOLOGY_LEVEL_SMT      (1U << 8)
#define CPUID_TOPOLOGY_LEVEL_CORE     (2U << 8)
#define CPUID_TOPOLOGY_LEVEL_DIE      (5U << 8)

/* CPUID Leaf 0x14 constants: */
#define INTEL_PT_MAX_SUBLEAF     0x1
/*
 * bit[00]: IA32_RTIT_CTL.CR3 filter can be set to 1 and IA32_RTIT_CR3_MATCH
 *          MSR can be accessed;
 * bit[01]: Support Configurable PSB and Cycle-Accurate Mode;
 * bit[02]: Support IP Filtering, TraceStop filtering, and preservation
 *          of Intel PT MSRs across warm reset;
 * bit[03]: Support MTC timing packet and suppression of COFI-based packets;
 */
#define INTEL_PT_MINIMAL_EBX     0xf
/*
 * bit[00]: Tracing can be enabled with IA32_RTIT_CTL.ToPA = 1 and
 *          IA32_RTIT_OUTPUT_BASE and IA32_RTIT_OUTPUT_MASK_PTRS MSRs can be
 *          accessed;
 * bit[01]: ToPA tables can hold any number of output entries, up to the
 *          maximum allowed by the MaskOrTableOffset field of
 *          IA32_RTIT_OUTPUT_MASK_PTRS;
 * bit[02]: Support Single-Range Output scheme;
 */
#define INTEL_PT_MINIMAL_ECX     0x7
/* generated packets which contain IP payloads have LIP values */
#define INTEL_PT_IP_LIP          (1 << 31)
#define INTEL_PT_ADDR_RANGES_NUM 0x2 /* Number of configurable address ranges */
#define INTEL_PT_ADDR_RANGES_NUM_MASK 0x3
#define INTEL_PT_MTC_BITMAP      (0x0249 << 16) /* Support ART(0,3,6,9) */
#define INTEL_PT_CYCLE_BITMAP    0x1fff         /* Support 0,2^(0~11) */
#define INTEL_PT_PSB_BITMAP      (0x003f << 16) /* Support 2K,4K,8K,16K,32K,64K */

/* CPUID Leaf 0x1D constants: */
#define INTEL_AMX_TILE_MAX_SUBLEAF     0x1
#define INTEL_AMX_TOTAL_TILE_BYTES     0x2000
#define INTEL_AMX_BYTES_PER_TILE       0x400
#define INTEL_AMX_BYTES_PER_ROW        0x40
#define INTEL_AMX_TILE_MAX_NAMES       0x8
#define INTEL_AMX_TILE_MAX_ROWS        0x10

/* CPUID Leaf 0x1E constants: */
#define INTEL_AMX_TMUL_MAX_K           0x10
#define INTEL_AMX_TMUL_MAX_N           0x40

/* TLB definitions: */

#define L1_DTLB_2M_ASSOC       1
#define L1_DTLB_2M_ENTRIES   255
#define L1_DTLB_4K_ASSOC       1
#define L1_DTLB_4K_ENTRIES   255

#define L1_ITLB_2M_ASSOC       1
#define L1_ITLB_2M_ENTRIES   255
#define L1_ITLB_4K_ASSOC       1
#define L1_ITLB_4K_ENTRIES   255

#define L2_DTLB_2M_ASSOC       0 /* disabled */
#define L2_DTLB_2M_ENTRIES     0 /* disabled */
#define L2_DTLB_4K_ASSOC       4
#define L2_DTLB_4K_ENTRIES   512

#define L2_ITLB_2M_ASSOC       0 /* disabled */
#define L2_ITLB_2M_ENTRIES     0 /* disabled */
#define L2_ITLB_4K_ASSOC       4
#define L2_ITLB_4K_ENTRIES   512

#define KVM_CPUID_SIGNATURE	0x40000000
#define KVM_SIGNATURE "KVMKVMKVM\0\0\0"

static uint32_t has_architectural_pmu_version;
static uint32_t num_architectural_pmu_gp_counters;
static uint32_t num_architectural_pmu_fixed_counters;

#define MSR_IA32_PERF_STATUS            0x198
#define MSR_P6_EVNTSEL0                 0x186
#define MAX_GP_COUNTERS    (MSR_IA32_PERF_STATUS - MSR_P6_EVNTSEL0)
#define MAX_FIXED_COUNTERS 3