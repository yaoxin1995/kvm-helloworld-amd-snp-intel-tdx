/*
 * Copyright (C) 2020 Intel Corporation
 *
 * Author: Isaku Yamahata <isaku.yamahata at gmail.com>
 *                        <isaku.yamahata at intel.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License along
 * with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 */
#include "stdint.h"
#include "stdbool.h"
#ifndef HW_I386_UEFI_H
#define HW_I386_UEFI_H

/***************************************************************************/
/*
 * basic EFI definitions
 * supplemented with UEFI Specification Version 2.8 (Errata A)
 * released February 2020
 */
/* UEFI integer is little endian */

typedef struct {
    uint32_t Data1;
    uint16_t Data2;
    uint16_t Data3;
    uint8_t Data4[8];
} EFI_GUID;

typedef enum {
    EfiReservedMemoryType,
    EfiLoaderCode,
    EfiLoaderData,
    EfiBootServicesCode,
    EfiBootServicesData,
    EfiRuntimeServicesCode,
    EfiRuntimeServicesData,
    EfiConventionalMemory,
    EfiUnusableMemory,
    EfiACPIReclaimMemory,
    EfiACPIMemoryNVS,
    EfiMemoryMappedIO,
    EfiMemoryMappedIOPortSpace,
    EfiPalCode,
    EfiPersistentMemory,
    EfiUnacceptedMemoryType,
    EfiMaxMemoryType
} EFI_MEMORY_TYPE;

#define EFI_HOB_HANDOFF_TABLE_VERSION 0x0009

#define EFI_HOB_TYPE_HANDOFF              0x0001
#define EFI_HOB_TYPE_MEMORY_ALLOCATION    0x0002
#define EFI_HOB_TYPE_RESOURCE_DESCRIPTOR  0x0003
#define EFI_HOB_TYPE_GUID_EXTENSION       0x0004
#define EFI_HOB_TYPE_FV                   0x0005
#define EFI_HOB_TYPE_CPU                  0x0006
#define EFI_HOB_TYPE_MEMORY_POOL          0x0007
#define EFI_HOB_TYPE_FV2                  0x0009
#define EFI_HOB_TYPE_LOAD_PEIM_UNUSED     0x000A
#define EFI_HOB_TYPE_UEFI_CAPSULE         0x000B
#define EFI_HOB_TYPE_FV3                  0x000C
#define EFI_HOB_TYPE_UNUSED               0xFFFE
#define EFI_HOB_TYPE_END_OF_HOB_LIST      0xFFFF

typedef struct {
    uint16_t HobType;
    uint16_t HobLength;
    uint32_t Reserved;
} EFI_HOB_GENERIC_HEADER;

typedef uint64_t EFI_PHYSICAL_ADDRESS;
typedef uint32_t EFI_BOOT_MODE;

typedef struct {
    EFI_HOB_GENERIC_HEADER Header;
    uint32_t Version;
    EFI_BOOT_MODE BootMode;
    EFI_PHYSICAL_ADDRESS EfiMemoryTop;
    EFI_PHYSICAL_ADDRESS EfiMemoryBottom;
    EFI_PHYSICAL_ADDRESS EfiFreeMemoryTop;
    EFI_PHYSICAL_ADDRESS EfiFreeMemoryBottom;
    EFI_PHYSICAL_ADDRESS EfiEndOfHobList;
} EFI_HOB_HANDOFF_INFO_TABLE;

#define EFI_RESOURCE_SYSTEM_MEMORY          0x00000000
#define EFI_RESOURCE_MEMORY_MAPPED_IO       0x00000001
#define EFI_RESOURCE_IO                     0x00000002
#define EFI_RESOURCE_FIRMWARE_DEVICE        0x00000003
#define EFI_RESOURCE_MEMORY_MAPPED_IO_PORT  0x00000004
#define EFI_RESOURCE_MEMORY_RESERVED        0x00000005
#define EFI_RESOURCE_IO_RESERVED            0x00000006
#define EFI_RESOURCE_MEMORY_UNACCEPTED      0x00000007
#define EFI_RESOURCE_MAX_MEMORY_TYPE        0x00000008

#define EFI_RESOURCE_ATTRIBUTE_PRESENT                  0x00000001
#define EFI_RESOURCE_ATTRIBUTE_INITIALIZED              0x00000002
#define EFI_RESOURCE_ATTRIBUTE_TESTED                   0x00000004
#define EFI_RESOURCE_ATTRIBUTE_SINGLE_BIT_ECC           0x00000008
#define EFI_RESOURCE_ATTRIBUTE_MULTIPLE_BIT_ECC         0x00000010
#define EFI_RESOURCE_ATTRIBUTE_ECC_RESERVED_1           0x00000020
#define EFI_RESOURCE_ATTRIBUTE_ECC_RESERVED_2           0x00000040
#define EFI_RESOURCE_ATTRIBUTE_READ_PROTECTED           0x00000080
#define EFI_RESOURCE_ATTRIBUTE_WRITE_PROTECTED          0x00000100
#define EFI_RESOURCE_ATTRIBUTE_EXECUTION_PROTECTED      0x00000200
#define EFI_RESOURCE_ATTRIBUTE_UNCACHEABLE              0x00000400
#define EFI_RESOURCE_ATTRIBUTE_WRITE_COMBINEABLE        0x00000800
#define EFI_RESOURCE_ATTRIBUTE_WRITE_THROUGH_CACHEABLE  0x00001000
#define EFI_RESOURCE_ATTRIBUTE_WRITE_BACK_CACHEABLE     0x00002000
#define EFI_RESOURCE_ATTRIBUTE_16_BIT_IO                0x00004000
#define EFI_RESOURCE_ATTRIBUTE_32_BIT_IO                0x00008000
#define EFI_RESOURCE_ATTRIBUTE_64_BIT_IO                0x00010000
#define EFI_RESOURCE_ATTRIBUTE_UNCACHED_EXPORTED        0x00020000
#define EFI_RESOURCE_ATTRIBUTE_READ_ONLY_PROTECTED      0x00040000
#define EFI_RESOURCE_ATTRIBUTE_READ_ONLY_PROTECTABLE    0x00080000
#define EFI_RESOURCE_ATTRIBUTE_READ_PROTECTABLE         0x00100000
#define EFI_RESOURCE_ATTRIBUTE_WRITE_PROTECTABLE        0x00200000
#define EFI_RESOURCE_ATTRIBUTE_EXECUTION_PROTECTABLE    0x00400000
#define EFI_RESOURCE_ATTRIBUTE_PERSISTENT               0x00800000
#define EFI_RESOURCE_ATTRIBUTE_PERSISTABLE              0x01000000
#define EFI_RESOURCE_ATTRIBUTE_MORE_RELIABLE            0x02000000

typedef uint32_t EFI_RESOURCE_TYPE;
typedef uint32_t EFI_RESOURCE_ATTRIBUTE_TYPE;

typedef struct {
    EFI_HOB_GENERIC_HEADER Header;
    EFI_GUID Owner;
    EFI_RESOURCE_TYPE ResourceType;
    EFI_RESOURCE_ATTRIBUTE_TYPE ResourceAttribute;
    EFI_PHYSICAL_ADDRESS PhysicalStart;
    uint64_t ResourceLength;
} EFI_HOB_RESOURCE_DESCRIPTOR;

typedef struct {
    EFI_HOB_GENERIC_HEADER Header;
    EFI_GUID Name;

    /* guid specific data follows */
} EFI_HOB_GUID_TYPE;

typedef struct {
    EFI_HOB_GENERIC_HEADER Header;
    EFI_PHYSICAL_ADDRESS BaseAddress;
    uint64_t Length;
} EFI_HOB_FIRMWARE_VOLUME;

typedef struct {
    EFI_HOB_GENERIC_HEADER Header;
    EFI_PHYSICAL_ADDRESS BaseAddress;
    uint64_t Length;
    EFI_GUID FvName;
    EFI_GUID FileName;
} EFI_HOB_FIRMWARE_VOLUME2;

typedef struct {
    EFI_HOB_GENERIC_HEADER Header;
    EFI_PHYSICAL_ADDRESS BaseAddress;
    uint64_t Length;
    uint32_t AuthenticationStatus;
    bool ExtractedFv;
    EFI_GUID FvName;
    EFI_GUID FileName;
} EFI_HOB_FIRMWARE_VOLUME3;

typedef struct {
    EFI_HOB_GENERIC_HEADER Header;
    uint8_t SizeOfMemorySpace;
    uint8_t SizeOfIoSpace;
    uint8_t Reserved[6];
} EFI_HOB_CPU;

typedef struct {
    EFI_HOB_GENERIC_HEADER Header;
} EFI_HOB_MEMORY_POOL;

typedef struct {
    EFI_HOB_GENERIC_HEADER Header;

    EFI_PHYSICAL_ADDRESS BaseAddress;
    uint64_t Length;
} EFI_HOB_UEFI_CAPSULE;


typedef struct {
  EFI_HOB_GENERIC_HEADER Header; // normal GUID HOB header
  EFI_GUID               Name;   // TD_HOB_PAYLOAD_ENTRYPOINT_GUID

  // TD_PAYLOAD_IMAGE_TYPE
  uint32_t                 ImageType;

  // Reserved field
  uint32_t                 Reserved;

  // Guest physical address of the payload entrypoint.
  uint64_t                 Entrypoint;
} HOB_PAYLOAD_INFO_TABLE;

typedef enum {

  // Payload Binary is a PE/COFF or ELF executable image as payload.
  // Entrypoint can be found by parsing the image header.
  // This type image does not follow Linux boot protocol.
  // A payload HOB is used to pass data from TdShim to payload.
  PayloadImageTypeExecutablePayload,

  // Payload Binary is bzImage, follow Linux boot protocol.
  // The first 512 bytes are boot_param. (zero page)
  // The entrypoint is start address of loaded 64bit Linux kernel
  //   plus 0x200
  PayloadImageTypeBzImage,

  // Payload Binary is vmlinux, follow Linux boot protocol.
  // It's an ELF64 binary image.
  PayloadImageTypeVmLinux,

  // Payload Binary is VMM loaded vmLinux, follow Linux boot protocol.
  // The entrypoint is defined at HOB_PAYLOAD_INFO_TABLE.Entrypoint.
  PayloadImageTypeRawVmLinux,

} PAYLOAD_IMAGE_TYPE;

#define HOB_PAYLOAD_INFO_GUID                                   \
    ((EFI_GUID){ 0xb96fa412, 0x461f, 0x4be3,                    \
        { 0x8c, 0xd, 0xad, 0x80, 0x5a, 0x49, 0x7a, 0xc0 }})      

#define EFI_HOB_OWNER_ZERO                                      \
    ((EFI_GUID){ 0x00000000, 0x0000, 0x0000,                    \
        { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } })

#define TD_E820_TABLE_HOB_GUID                                  \
    ((EFI_GUID){ 0x8f8072ea, 0x3486, 0x4b47,                    \
        { 0x86, 0xa7, 0x23, 0x53, 0xb8, 0x8a, 0x87, 0x73 }})

#endif