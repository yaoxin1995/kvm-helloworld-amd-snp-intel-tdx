#include <stdint.h>
#include <asm/byteorder.h>

typedef struct TdxRamEntry
{
  uint64_t address;
  uint64_t length;
  uint32_t type;
} TdxRamEntry;

#ifndef TDVF
#define TDVF
typedef struct TdxFirmwareEntry {
    uint32_t data_offset;
    uint32_t data_len;
    uint64_t address;
    uint64_t size;
    uint32_t type;
    uint32_t attributes;

    void *mem_ptr;
} TdxFirmwareEntry;

typedef struct TdxFirmware {
    void *mem_ptr;

    uint32_t nr_entries;
    TdxFirmwareEntry *entries;

    /* For compatibility */
    bool guid_found;
} TdxFirmware;
#endif

typedef struct TdxGuest
{
  // ConfidentialGuestSupport parent_obj;

  // QemuMutex lock;

  bool initialized;
  uint64_t attributes;       /* TD attributes */
  uint8_t mrconfigid[48];    /* sha348 digest */
  uint8_t mrowner[48];       /* sha348 digest */
  uint8_t mrownerconfig[48]; /* sha348 digest */

  TdxFirmware tdvf;
  // MemoryRegion *tdvf_region;

  uint32_t nr_ram_entries;
  TdxRamEntry *ram_entries;

  /* runtime state */
  int event_notify_interrupt;
  uint32_t apic_id;

  /* GetQuote */
  int quote_generation_num;
  char *quote_generation_str;
  // SocketAddress *quote_generation;
} TdxGuest;



enum TdxRamType
{
  TDX_RAM_UNACCEPTED,
  TDX_RAM_ADDED,
};

#define error_report(fmt, ...) do { \
  fprintf(stderr, fmt, ##__VA_ARGS__); \
} while(0)

#define warn_report(fmt, ...) do { \
  fprintf(stderr, fmt, ##__VA_ARGS__); \
} while(0)
