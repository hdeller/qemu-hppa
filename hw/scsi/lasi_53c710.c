/*
 * QEMU LASI SCSI 53c710 emulation
 *
 * Copyright (c) 2021 Helge Deller <deller@gmx.de>
 * This work is licensed under the GNU GPL license version 2 or later.
 *
 *
 * On PA-RISC, this is the SCSI part of the LASI Multi-I/O chip.
 * See:
 * https://parisc.wiki.kernel.org/images-parisc/7/79/Lasi_ers.pdf
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/timer.h"
#include "hw/sysbus.h"
#include "net/eth.h"
#include "hw/scsi/lasi_53c710.h"
#include "hw/scsi/lsi53c710.h"
#include "trace.h"
#include "sysemu/sysemu.h"
#include "hw/qdev-properties.h"
#include "migration/vmstate.h"

#define PA_53C710_RESET         0       /* Offsets relative to LASI-SCSI-Addr.*/

static void lasi_53c710_mem_write(void *opaque, hwaddr addr,
                            uint64_t val, unsigned size)
{
    // SysBus53C710State *d = opaque;

    // trace_lasi_53c710_mem_writew(addr, val);
    switch (addr) {
    case PA_53C710_RESET:
        // lasi_53c710_h_reset(&d->state);
        fprintf(stderr, "LASI WRITE RESET\n");
        break;
    case 0x100 ... 0x13b:
        addr -= 0x100;
        addr ^= 0x03;
        fprintf(stderr, "LASI WRITE %#02lx %s size=%d  val=%ld\n", addr, lsi_regname(addr), size, val);
        lsi710_mmio_write(opaque, addr, val, size);
        break;
    default:
        break; // XXX
    }
}

static uint64_t lasi_53c710_mem_read(void *opaque, hwaddr addr,
                               unsigned size)
{
    // SysBus53C710State *d = opaque;
    uint32_t val = 0;

    switch (addr) {
    case PA_53C710_RESET:
        fprintf(stderr, "LASI WRITE RESET\n");
        break;
    case 0x100 ... 0x13b:
        addr -= 0x100;
        addr ^= 0x03;
        fprintf(stderr, "LASI READ %#02lx %s size=%d  ", addr, lsi_regname(addr), size);
        val = lsi710_mmio_read(opaque, addr, size);
        break;
    default:
        break; // XXX
    }
    // trace_lasi_53c710_mem_readw(addr, val);
    fprintf(stderr, "  - VAL = %d\n", val);
    return val;

}

static const MemoryRegionOps lasi_53c710_mem_ops = {
    .read = lasi_53c710_mem_read,
    .write = lasi_53c710_mem_write,
    .endianness = DEVICE_BIG_ENDIAN,
    .valid = {
        .min_access_size = 1,
        .max_access_size = 1,
    },
};

static const VMStateDescription vmstate_lasi_53c710 = {
    .name = "53c710",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (VMStateField[]) {
#if 0
        VMSTATE_STRUCT(state, SysBus53C710State, 0, vmstate_53c710,
               LSI_53C710State),
#endif
        VMSTATE_END_OF_LIST()
    }
};

static void lasi_53c710_realize(DeviceState *dev, Error **errp)
{
    SysBus53C710State *d = SYSBUS_53C710(dev);
    LSI_53C710State *s = &d->state;

    memory_region_init_io(&s->mmio, OBJECT(d), &lasi_53c710_mem_ops, d,
                "lasi_53c710-mmio", 0x1000);

    lsi710_common_init(dev, errp);
}

SysBus53C710State *lasi_53c710_init(MemoryRegion *addr_space,
                  hwaddr hpa, qemu_irq scsi_irq)
{
    DeviceState *dev;
    SysBus53C710State *s;

    dev = qdev_new(TYPE_LASI_53C710);
    s = SYSBUS_53C710(dev);
    s->state.irq = scsi_irq;
    sysbus_realize_and_unref(SYS_BUS_DEVICE(dev), &error_fatal);

    /* LASI 53c710 ports in main memory. */
    memory_region_add_subregion(addr_space, hpa, &s->state.mmio);
    return s;
}

static void lasi_53c710_reset(DeviceState *dev)
{
    // SysBus53C710State *d = SYSBUS_53C710(dev);

    // 53c710_h_reset(&d->state);
}

static void lasi_53c710_instance_init(Object *obj)
{
    // SysBus53C710State *d = SYSBUS_53C710(obj);
    //LSI_53C710State *s = &d->state;
}

static Property lasi_53c710_properties[] = {
    // DEFINE_NIC_PROPERTIES(SysBus53C710State, state.conf),
    DEFINE_PROP_END_OF_LIST(),
};

static void lasi_53c710_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->realize = lasi_53c710_realize;
    set_bit(DEVICE_CATEGORY_STORAGE, dc->categories);
    dc->reset = lasi_53c710_reset;
    dc->vmsd = &vmstate_lasi_53c710;
    dc->user_creatable = false;
    device_class_set_props(dc, lasi_53c710_properties);
}

static const TypeInfo lasi_53c710_info = {
    .name          = TYPE_LASI_53C710,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(SysBus53C710State),
    .class_init    = lasi_53c710_class_init,
    .instance_init = lasi_53c710_instance_init,
};

static void lasi_53c710_register_types(void)
{
    type_register_static(&lasi_53c710_info);
}

type_init(lasi_53c710_register_types)
