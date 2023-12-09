#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdbool.h>
#include <linux/byteorder/little_endian.h>
#define cpu_to_le64 __cpu_to_le64
#define le64_to_cpu __le64_to_cpu
#define cpu_to_le32 __cpu_to_le32
#define le32_to_cpu __le32_to_cpu
#define cpu_to_le16 __cpu_to_le16
#define le16_to_cpu __le16_to_cpu
#define cpu_to_be64 __cpu_to_be64
#define be64_to_cpu __be64_to_cpu
#define cpu_to_be32 __cpu_to_be32
#define be32_to_cpu __be32_to_cpu
#define cpu_to_be16 __cpu_to_be16
#define be16_to_cpu __be16_to_cpu


#define error_report(fmt, ...) do { \
  fprintf(stderr, fmt, ##__VA_ARGS__); \
} while(0)

#define TARGET_PAGE_SIZE   (1 << 12)
void pc_system_parse_ovmf_flash(uint8_t *flash_ptr, size_t flash_size);
bool pc_system_ovmf_table_find(const char *entry, uint8_t **data, int *data_len);
