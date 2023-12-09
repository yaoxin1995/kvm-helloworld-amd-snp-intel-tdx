/*
 * SPDX-License-Identifier: GPL-2.0-or-later

 * Copyright (c) 2020 Intel Corporation
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
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "uefi.h"
#include "tdx.h"
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




typedef uint64_t hwaddr;
#define EFI_RESOURCE_ATTRIBUTE_TDVF_PRIVATE     \
    (EFI_RESOURCE_ATTRIBUTE_PRESENT |           \
     EFI_RESOURCE_ATTRIBUTE_INITIALIZED |       \
     EFI_RESOURCE_ATTRIBUTE_TESTED)

#define EFI_RESOURCE_ATTRIBUTE_TDVF_UNACCEPTED  \
    (EFI_RESOURCE_ATTRIBUTE_PRESENT |           \
     EFI_RESOURCE_ATTRIBUTE_INITIALIZED |       \
     EFI_RESOURCE_ATTRIBUTE_TESTED)

#define EFI_RESOURCE_ATTRIBUTE_TDVF_MMIO        \
    (EFI_RESOURCE_ATTRIBUTE_PRESENT     |       \
     EFI_RESOURCE_ATTRIBUTE_INITIALIZED |       \
     EFI_RESOURCE_ATTRIBUTE_UNCACHEABLE)

#define QEMU_ALIGN_DOWN(n, m) ((n) / (m) * (m))
#define QEMU_ALIGN_UP(n, m) QEMU_ALIGN_DOWN((n) + (m) - 1, (m))
#define QEMU_ALIGN_PTR_UP(p, n) \
    ((typeof(p))QEMU_ALIGN_UP((uintptr_t)(p), (n)))

typedef struct TdvfHob {
    hwaddr hob_addr;
    void *ptr;
    int size;

    /* working area */
    void *current;
    void *end;
} TdvfHob;

static uint64_t tdvf_current_guest_addr(const TdvfHob *hob)
{
    return hob->hob_addr + (hob->current - hob->ptr);
}

static void tdvf_align(TdvfHob *hob, size_t align)
{
    hob->current = QEMU_ALIGN_PTR_UP(hob->current, align);
}

static void *tdvf_get_area(TdvfHob *hob, uint64_t size)
{
    void *ret;
    if (hob->current + size > hob->end) {
        error_report("TD_HOB overrun, size = 0x'%llx'", (unsigned long long)size);
    }

    ret = hob->current;
    hob->current += size;
    tdvf_align(hob, 8);
    return ret;
}

static void tdvf_hob_add_memory_resources(TdxGuest *tdx, TdvfHob *hob)
{
    EFI_HOB_RESOURCE_DESCRIPTOR *region;
    EFI_RESOURCE_ATTRIBUTE_TYPE attr;
    EFI_RESOURCE_TYPE resource_type;

    TdxRamEntry *e;
    int i;

    for (i = 0; i < tdx->nr_ram_entries; i++) {
        e = &tdx->ram_entries[i];

        if (e->type == TDX_RAM_UNACCEPTED) {
            resource_type = EFI_RESOURCE_MEMORY_UNACCEPTED;
            attr = EFI_RESOURCE_ATTRIBUTE_TDVF_UNACCEPTED;
        } else if (e->type == TDX_RAM_ADDED){
            resource_type = EFI_RESOURCE_SYSTEM_MEMORY;
            attr = EFI_RESOURCE_ATTRIBUTE_TDVF_PRIVATE;
        } else {
            error_report("unknown TDX_RAM_ENTRY type %d", e->type);
            exit(1);
        }

        /* REVERTME: workaround for the old version of TDVF expectations. */
        if (!tdx->tdvf.guid_found) {
            switch (e->type) {
            case TDX_RAM_UNACCEPTED:
                resource_type = EFI_RESOURCE_SYSTEM_MEMORY;
                break;
            case TDX_RAM_ADDED:
                resource_type = EFI_RESOURCE_MEMORY_RESERVED;
                break;
            default:
                break;
            }
        }

        region = tdvf_get_area(hob, sizeof(*region));
        *region = (EFI_HOB_RESOURCE_DESCRIPTOR) {
            .Header = {
                .HobType = EFI_HOB_TYPE_RESOURCE_DESCRIPTOR,
                .HobLength = cpu_to_le16(sizeof(*region)),
                .Reserved = cpu_to_le32(0),
            },
            .Owner = EFI_HOB_OWNER_ZERO,
            .ResourceType = cpu_to_le32(resource_type),
            .ResourceAttribute = cpu_to_le32(attr),
            .PhysicalStart = cpu_to_le64(e->address),
            .ResourceLength = cpu_to_le64(e->length),
        };
        printf("-----HOB Start-----\n");
        printf("Header:\n    HobType = %x\n    HobLength = %x\n    Reserved = %x\n",region->Header.HobType,region->Header.HobLength,region->Header.Reserved);
        printf("Owner = %x %x %x %x %x %x %x %x %x %x %x\n",region->Owner.Data1,region->Owner.Data2,region->Owner.Data3,
                                                                region->Owner.Data4[0],region->Owner.Data4[1],region->Owner.Data4[2],region->Owner.Data4[3],
                                                                region->Owner.Data4[4],region->Owner.Data4[5],region->Owner.Data4[6],region->Owner.Data4[7]);
        printf("ResourceType = %x\n",region->ResourceType);
        printf("ResourceAttribute = %x\n",region->ResourceAttribute);
        printf("PhysicalStart = %lx\n",region->PhysicalStart);
        printf("ResourceLength = %lx\n",region->ResourceLength);
        printf("-----HOB ENd-----\n");
    }
}

static void tdvf_hob_add_payload_resources(TdxGuest *tdx, TdvfHob *hob, void * mem_kernel){
    HOB_PAYLOAD_INFO_TABLE *payload_hob;
    payload_hob = tdvf_get_area(hob, sizeof(payload_hob));
    *payload_hob = (HOB_PAYLOAD_INFO_TABLE) {
        .Header = {
            .HobType = EFI_HOB_TYPE_GUID_EXTENSION,
            .HobLength = cpu_to_le16(sizeof(*payload_hob)),
            .Reserved = cpu_to_le32(0),
        },
        .Name = HOB_PAYLOAD_INFO_GUID,
        .ImageType = PayloadImageTypeBzImage,
        .Reserved = cpu_to_le32(0),
        .Entrypoint = cpu_to_le64((__u64)mem_kernel+0x200),
    };
}


void tdvf_hob_create(TdxGuest *tdx, TdxFirmwareEntry *td_hob)
{
    TdvfHob hob = {
        .hob_addr = td_hob->address,
        .size = td_hob->size,
        .ptr = td_hob->mem_ptr,

        .current = td_hob->mem_ptr,
        .end = td_hob->mem_ptr + td_hob->size,
    };

    EFI_HOB_GENERIC_HEADER *last_hob;
    EFI_HOB_HANDOFF_INFO_TABLE *hit;
    

    /* Note, Efi{Free}Memory{Bottom,Top} are ignored, leave 'em zeroed. */
    hit = tdvf_get_area(&hob, sizeof(*hit));
    *hit = (EFI_HOB_HANDOFF_INFO_TABLE) {
        .Header = {
            .HobType = EFI_HOB_TYPE_HANDOFF,
            .HobLength = cpu_to_le16(sizeof(*hit)),
            .Reserved = cpu_to_le32(0),
        },
        .Version = cpu_to_le32(EFI_HOB_HANDOFF_TABLE_VERSION),
        .BootMode = cpu_to_le32(0),
        .EfiMemoryTop = cpu_to_le64(0),
        .EfiMemoryBottom = cpu_to_le64(0),
        .EfiFreeMemoryTop = cpu_to_le64(0),
        .EfiFreeMemoryBottom = cpu_to_le64(0),
        .EfiEndOfHobList = cpu_to_le64(0), /* initialized later */
    };
    printf("-----HOB Start-----\n");
    printf("Header:\n    HobType = %x\n    HobLength = %x\n    Reserved = %x\n",hit->Header.HobType,hit->Header.HobLength,hit->Header.Reserved);
    printf("Version = %x\n",hit->Version);
    printf("BootMode = %x\n",hit->BootMode);
    printf("EfiMemoryTop = %lx\n",hit->EfiMemoryTop);
    printf("EfiMemoryBottom = %lx\n",hit->EfiMemoryBottom);
    printf("EfiFreeMemoryTop = %lx\n",hit->EfiFreeMemoryTop);
    printf("EfiFreeMemoryBottom = %lx\n",hit->EfiFreeMemoryBottom);
    printf("EfiEndOfHobList = %lx\n",hit->EfiEndOfHobList);
    printf("-----HOB ENd-----\n");

    tdvf_hob_add_memory_resources(tdx, &hob);
    //tdvf_hob_add_payload_resources(tdx, &hob,mem_kernel);

    last_hob = tdvf_get_area(&hob, sizeof(*last_hob));
    *last_hob =  (EFI_HOB_GENERIC_HEADER) {
        .HobType = EFI_HOB_TYPE_END_OF_HOB_LIST,
        .HobLength = cpu_to_le16(sizeof(*last_hob)),
        .Reserved = cpu_to_le32(0),
    };
    hit->EfiEndOfHobList = tdvf_current_guest_addr(&hob);
    printf("-----HOB Start-----\n");
    printf("Header:\n    HobType = %x\n    HobLength = %x\n    Reserved = %x\n",hit->Header.HobType,hit->Header.HobLength,hit->Header.Reserved);
    printf("-----HOB ENd-----\n");

}
