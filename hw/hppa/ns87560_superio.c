/*
 * National Semiconductor NS87560UBD Super I/O controller used in
 * HP [BCJ]x000 workstations.
 *
 * This chip is a horrid piece of engineering, and National
 * denies any knowledge of its existence. Thus no datasheet is
 * available off www.national.com. See Linux kernel source
 * code for reference instead.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (c) 2025 Helge Deller <deller@gmx.de>
 */

#include "qemu/osdep.h"
#include "qemu/units.h"
#include "hw/char/serial.h"
#include "hw/irq.h"
#include "hw/pci/pci_device.h"
#include "hw/qdev-properties.h"
#include "hw/qdev-properties-system.h"
#include "migration/vmstate.h"
#include "hw/ide/pci.h"

#define PCI_VENDOR_ID_NS                0x100b
#define PCI_DEVICE_ID_NS_87415          0x0002
#define PCI_DEVICE_ID_NS_87560_LIO      0x000e
#define PCI_DEVICE_ID_NS_87560_USB      0x0012

void create_NS_87560_superio(PCIBus *pci_bus, int major);

typedef struct PCISuperIOState {
    PCIDevice    dev;
    MemoryRegion membar;        /* for serial ports */
    MemoryRegion mailboxbar;    /* for hardware mailbox */
    uint32_t     subvendor;
    uint32_t     ports;
    uint32_t     level;
    qemu_irq     *irqs;
    uint8_t      prog_if;
} PCISuperIOState;

static void superio_pci_exit(PCIDevice *dev)
{
#if 0
    PCISuperIOState *pci = DO_UPCAST(PCISuperIOState, dev, dev);
    SerialState *s;
    int i;

    for (i = 0; i < pci->ports; i++) {
        s = pci->state + i;
        qdev_unrealize(DEVICE(s));
        memory_region_del_subregion(&pci->membar, &s->io);
        g_free(pci->name[i]);
    }
    qemu_free_irqs(pci->irqs, pci->ports);
#endif
}

static void multi_serial_irq_mux(void *opaque, int n, int level)
{
#if 0
    PCISuperIOState *pci = opaque;
    int i, pending = 0;

    pci->level[n] = level;
    for (i = 0; i < pci->ports; i++) {
        if (pci->level[i]) {
            pending = 1;
        }
    }
    pci_set_irq(&pci->dev, pending);
#endif
}

static void superio_pci_realize(PCIDevice *dev, Error **errp)
{
    // PCIDeviceClass *pc = PCI_DEVICE_GET_CLASS(dev);
    PCISuperIOState *pci = DO_UPCAST(PCISuperIOState, dev, dev);

    pci->dev.config[PCI_CLASS_PROG] = pci->prog_if;
    pci->dev.config[PCI_INTERRUPT_PIN] = 0x01;
    // memory_region_init(&pci->membar, OBJECT(pci), "serial_ports", 4096);
    // pci_register_bar(&pci->dev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY, &pci->membar);
    pci->irqs = qemu_allocate_irqs(multi_serial_irq_mux, pci, 10);

#if 0
    for (i = 0; i < di.nports; i++) {
        s = pci->state + i;
        if (!qdev_realize(DEVICE(s), NULL, errp)) {
            superio_pci_exit(dev);
            return;
        }
        s->irq = pci->irqs[i];
        pci->name[i] = g_strdup_printf("uart #%zu", i + 1);
        memory_region_init_io(&s->io, OBJECT(pci), &serial_io_ops, s,
                              pci->name[i], 8);

        /* calculate offset of given port based on bitmask */
        while ((portmask & BIT(0)) == 0) {
            offset += 8;
            portmask >>= 1;
        }
        memory_region_add_subregion(&pci->membar, offset, &s->io);
        offset += 8;
        portmask >>= 1;
        pci->ports++;
    }
#endif
}

static const VMStateDescription vmstate_pci_superio = {
    .name = "pci-superio",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]) {
        VMSTATE_PCI_DEVICE(dev, PCISuperIOState),
#if 0
        VMSTATE_STRUCT_ARRAY(state, PCISuperIOState, PCI_SERIAL_MAX_PORTS,
                             0, vmstate_serial, SerialState),
        VMSTATE_UINT32_ARRAY(level, PCISuperIOState, PCI_SERIAL_MAX_PORTS),
#endif
        VMSTATE_END_OF_LIST()
    }
};

static const Property superio_properties[] = {
#if 0
    DEFINE_PROP_CHR("chardev1",  PCISuperIOState, state[0].chr),
    DEFINE_PROP_CHR("chardev2",  PCISuperIOState, state[1].chr),
    DEFINE_PROP_CHR("chardev3",  PCISuperIOState, state[2].chr),
    DEFINE_PROP_CHR("chardev4",  PCISuperIOState, state[3].chr),
#endif
    DEFINE_PROP_UINT8("prog_if",  PCISuperIOState, prog_if, 0x02),
};

static void superio_class_initfn(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIDeviceClass *pc = PCI_DEVICE_CLASS(klass);
    pc->realize = superio_pci_realize;
    pc->exit = superio_pci_exit;
    pc->vendor_id = PCI_VENDOR_ID_NS;
    pc->device_id = PCI_DEVICE_ID_NS_87560_LIO;
    pc->subsystem_vendor_id = PCI_VENDOR_ID_HP;
    pc->subsystem_id = PCI_DEVICE_ID_NS_87560_LIO;
    pc->revision = 3;
    pc->class_id = PCI_CLASS_COMMUNICATION_SERIAL;
    dc->vmsd = &vmstate_pci_superio;
    device_class_set_props(dc, superio_properties);
    set_bit(DEVICE_CATEGORY_INPUT, dc->categories);
}

static void superio_init(Object *o)
{
#if 0
    PCIDevice *dev = PCI_DEVICE(o);
    PCISuperIOState *pms = DO_UPCAST(PCISuperIOState, dev, dev);
    size_t i;

    for (i = 0; i < di.nports; i++) {
        object_initialize_child(o, "serial[*]", &pms->state[i], TYPE_SERIAL);
    }
#endif
}

static const TypeInfo superio_pci_info = {
    .name          = "superio-pci",
    .parent        = TYPE_PCI_DEVICE,
    .instance_size = sizeof(PCISuperIOState),
    .instance_init = superio_init,
    .class_init    = superio_class_initfn,
    .interfaces = (InterfaceInfo[]) {
        { INTERFACE_CONVENTIONAL_PCI_DEVICE },
        { },
    },
};

static void superio_pci_register_type(void)
{
    type_register_static(&superio_pci_info);
}

type_init(superio_pci_register_type)


void create_NS_87560_superio(PCIBus *pci_bus, int major)
{
    PCIDevice *pci_dev;

    /* function 0 is a PCI IDE Controller */
    pci_dev = pci_new_multifunction(PCI_DEVFN(major, 0), TYPE_PCI_IDE);
    // qdev_prop_set_chr(DEVICE(pci_dev), "chardev1", serial_hd(0));
    pci_realize_and_unref(pci_dev, pci_bus, &error_fatal);

    /* function 1 is a SuperIO chip */

    /* function 2 is a USB chip */
}
