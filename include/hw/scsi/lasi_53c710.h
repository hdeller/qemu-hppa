/*
 * QEMU LASI LSI 53c710 device emulation
 *
 * Copyright (c) 2021 Helge Deller <deller@gmx.de>
 *
 */

#ifndef LASI_53c710_H
#define LASI_53c710_H

#include "net/net.h"
#include "hw/scsi/lsi53c710.h"
#include "qom/object.h"

#define TYPE_LASI_53C710 "lasi_53c710"
typedef struct SysBus53C710State SysBus53C710State;
DECLARE_INSTANCE_CHECKER(SysBus53C710State, SYSBUS_53C710,
                         TYPE_LASI_53C710)

struct SysBus53C710State {
    SysBusDevice parent_obj;

    LSI_53C710State state;
};

SysBus53C710State *lasi_53c710_init(MemoryRegion *addr_space,
                                    hwaddr hpa, qemu_irq irq);

#endif
