/*
 * QEMU 16550A multi UART emulation
 *
 * SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2003-2004 Fabrice Bellard
 * Copyright (c) 2008 Citrix Systems, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

/* see docs/specs/pci-serial.rst */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "hw/char/serial.h"
#include "hw/irq.h"
#include "hw/pci/pci_device.h"
#include "hw/qdev-properties.h"
#include "hw/qdev-properties-system.h"
#include "migration/vmstate.h"

#define PCI_VENDOR_ID_NS                0x100b
#define PCI_DEVICE_ID_NS_87415          0x0002
#define PCI_DEVICE_ID_NS_87560_LIO      0x000e
#define PCI_DEVICE_ID_NS_87560_USB      0x0012


/****************************************** IDE *******************************/

#include "hw/ide/pci.h"
#include "hw/ide/ide-internal.h"
// #include "trace.h"

#define TYPE_NS87560_ALL "SUPERIO_ALL"
OBJECT_DECLARE_SIMPLE_TYPE(SUPERIO_ALL_State, NS87560_ALL)

struct SUPERIO_ALL_State {
    PCIIDEState ide;

    IRQState i8259_irq;
    qemu_irq cpu_intr;
    qemu_irq *isa_irqs_in;
    uint16_t irq_state[ISA_NUM_IRQS];
    //ViaSuperIOState via_sio;
    // UHCIState uhci[2];
    // ViaPMState pm;
};


/* CMD646 specific */
#define CFR                  0x50
#define   CFR_INTR_CH0       0x04
#define CNTRL                0x51
#define   CNTRL_EN_CH0       0x04
#define   CNTRL_EN_CH1       0x08
#define ARTTIM23             0x57
#define    ARTTIM23_INTR_CH1 0x10
#define MRDMODE              0x71
#define   MRDMODE_INTR_CH0   0x04
#define   MRDMODE_INTR_CH1   0x08
#define   MRDMODE_BLK_CH0    0x10
#define   MRDMODE_BLK_CH1    0x20
#define UDIDETCR0            0x73
#define UDIDETCR1            0x7B

static void cmd646_update_irq(PCIDevice *pd);

static void cmd646_update_dma_interrupts(PCIDevice *pd)
{
    /* Sync DMA interrupt status from UDMA interrupt status */
    if (pd->config[MRDMODE] & MRDMODE_INTR_CH0) {
        pd->config[CFR] |= CFR_INTR_CH0;
    } else {
        pd->config[CFR] &= ~CFR_INTR_CH0;
    }

    if (pd->config[MRDMODE] & MRDMODE_INTR_CH1) {
        pd->config[ARTTIM23] |= ARTTIM23_INTR_CH1;
    } else {
        pd->config[ARTTIM23] &= ~ARTTIM23_INTR_CH1;
    }
}

static void cmd646_update_udma_interrupts(PCIDevice *pd)
{
    /* Sync UDMA interrupt status from DMA interrupt status */
    if (pd->config[CFR] & CFR_INTR_CH0) {
        pd->config[MRDMODE] |= MRDMODE_INTR_CH0;
    } else {
        pd->config[MRDMODE] &= ~MRDMODE_INTR_CH0;
    }

    if (pd->config[ARTTIM23] & ARTTIM23_INTR_CH1) {
        pd->config[MRDMODE] |= MRDMODE_INTR_CH1;
    } else {
        pd->config[MRDMODE] &= ~MRDMODE_INTR_CH1;
    }
}

static uint64_t bmdma_read(void *opaque, hwaddr addr,
                           unsigned size)
{
    BMDMAState *bm = opaque;
    PCIDevice *pci_dev = PCI_DEVICE(bm->pci_dev);
    uint32_t val;

    if (size != 1) {
        return ((uint64_t)1 << (size * 8)) - 1;
    }

    switch(addr & 3) {
    case 0:
        val = bm->cmd;
        break;
    case 1:
        val = pci_dev->config[MRDMODE];
        break;
    case 2:
        val = bm->status;
        break;
    case 3:
        if (bm == &bm->pci_dev->bmdma[0]) {
            val = pci_dev->config[UDIDETCR0];
        } else {
            val = pci_dev->config[UDIDETCR1];
        }
        break;
    default:
        val = 0xff;
        break;
    }

    // trace_bmdma_read_cmd646(addr, val);
    return val;
}

static void bmdma_write(void *opaque, hwaddr addr,
                        uint64_t val, unsigned size)
{
    BMDMAState *bm = opaque;
    PCIDevice *pci_dev = PCI_DEVICE(bm->pci_dev);

    if (size != 1) {
        return;
    }

    // trace_bmdma_write_cmd646(addr, val);
    switch(addr & 3) {
    case 0:
        bmdma_cmd_writeb(bm, val);
        break;
    case 1:
        pci_dev->config[MRDMODE] =
            (pci_dev->config[MRDMODE] & ~0x30) | (val & 0x30);
        cmd646_update_dma_interrupts(pci_dev);
        cmd646_update_irq(pci_dev);
        break;
    case 2:
        bmdma_status_writeb(bm, val);
        break;
    case 3:
        if (bm == &bm->pci_dev->bmdma[0]) {
            pci_dev->config[UDIDETCR0] = val;
        } else {
            pci_dev->config[UDIDETCR1] = val;
        }
        break;
    }
}

static const MemoryRegionOps cmd646_bmdma_ops = {
    .read = bmdma_read,
    .write = bmdma_write,
};

static void bmdma_setup_bar(PCIIDEState *d)
{
    BMDMAState *bm;
    int i;

    memory_region_init(&d->bmdma_bar, OBJECT(d), "cmd646-bmdma", 16);
    for(i = 0;i < 2; i++) {
        bm = &d->bmdma[i];
        memory_region_init_io(&bm->extra_io, OBJECT(d), &cmd646_bmdma_ops, bm,
                              "cmd646-bmdma-bus", 4);
        memory_region_add_subregion(&d->bmdma_bar, i * 8, &bm->extra_io);
        memory_region_init_io(&bm->addr_ioport, OBJECT(d),
                              &bmdma_addr_ioport_ops, bm,
                              "cmd646-bmdma-ioport", 4);
        memory_region_add_subregion(&d->bmdma_bar, i * 8 + 4, &bm->addr_ioport);
    }
}

static void cmd646_update_irq(PCIDevice *pd)
{
    int pci_level;

    pci_level = ((pd->config[MRDMODE] & MRDMODE_INTR_CH0) &&
                 !(pd->config[MRDMODE] & MRDMODE_BLK_CH0)) ||
        ((pd->config[MRDMODE] & MRDMODE_INTR_CH1) &&
         !(pd->config[MRDMODE] & MRDMODE_BLK_CH1));
    pci_set_irq(pd, pci_level);
}

/* the PCI irq level is the logical OR of the two channels */
static void cmd646_set_irq(void *opaque, int channel, int level)
{
    PCIIDEState *d = opaque;
    PCIDevice *pd = PCI_DEVICE(d);
    int irq_mask;

    irq_mask = MRDMODE_INTR_CH0 << channel;
    if (level) {
        pd->config[MRDMODE] |= irq_mask;
    } else {
        pd->config[MRDMODE] &= ~irq_mask;
    }
    cmd646_update_dma_interrupts(pd);
    cmd646_update_irq(pd);
}

static void cmd646_reset(DeviceState *dev)
{
    PCIIDEState *d = PCI_IDE(dev);
    unsigned int i;

    for (i = 0; i < 2; i++) {
        ide_bus_reset(&d->bus[i]);
    }
}

static uint32_t cmd646_pci_config_read(PCIDevice *d,
                                       uint32_t address, int len)
{
    return pci_default_read_config(d, address, len);
}

static void cmd646_pci_config_write(PCIDevice *d, uint32_t addr, uint32_t val,
                                    int l)
{
    uint32_t i;

    pci_default_write_config(d, addr, val, l);

    for (i = addr; i < addr + l; i++) {
        switch (i) {
        case CFR:
        case ARTTIM23:
            cmd646_update_udma_interrupts(d);
            break;
        case MRDMODE:
            cmd646_update_dma_interrupts(d);
            break;
        }
    }

    cmd646_update_irq(d);
}

/* CMD646 PCI IDE controller */
static void pci_cmd646_ide_realize(PCIDevice *dev, Error **errp)
{
    PCIIDEState *d = PCI_IDE(dev);
    DeviceState *ds = DEVICE(dev);
    uint8_t *pci_conf = dev->config;
    int i;

    pci_conf[PCI_CLASS_PROG] = 0x8f;

    pci_conf[CNTRL] = CNTRL_EN_CH0; // enable IDE0
    if (d->secondary) {
        /* XXX: if not enabled, really disable the secondary IDE controller */
        pci_conf[CNTRL] |= CNTRL_EN_CH1; /* enable IDE1 */
    }

    /* Set write-to-clear interrupt bits */
    dev->wmask[CFR] = 0x0;
    dev->w1cmask[CFR] = CFR_INTR_CH0;
    dev->wmask[ARTTIM23] = 0x0;
    dev->w1cmask[ARTTIM23] = ARTTIM23_INTR_CH1;
    dev->wmask[MRDMODE] = 0x0;
    dev->w1cmask[MRDMODE] = MRDMODE_INTR_CH0 | MRDMODE_INTR_CH1;

    memory_region_init_io(&d->data_bar[0], OBJECT(d), &pci_ide_data_le_ops,
                          &d->bus[0], "cmd646-data0", 8);
    pci_register_bar(dev, 0, PCI_BASE_ADDRESS_SPACE_IO, &d->data_bar[0]);

    memory_region_init_io(&d->cmd_bar[0], OBJECT(d), &pci_ide_cmd_le_ops,
                          &d->bus[0], "cmd646-cmd0", 4);
    pci_register_bar(dev, 1, PCI_BASE_ADDRESS_SPACE_IO, &d->cmd_bar[0]);

    memory_region_init_io(&d->data_bar[1], OBJECT(d), &pci_ide_data_le_ops,
                          &d->bus[1], "cmd646-data1", 8);
    pci_register_bar(dev, 2, PCI_BASE_ADDRESS_SPACE_IO, &d->data_bar[1]);

    memory_region_init_io(&d->cmd_bar[1], OBJECT(d), &pci_ide_cmd_le_ops,
                          &d->bus[1], "cmd646-cmd1", 4);
    pci_register_bar(dev, 3, PCI_BASE_ADDRESS_SPACE_IO, &d->cmd_bar[1]);

    bmdma_setup_bar(d);
    pci_register_bar(dev, 4, PCI_BASE_ADDRESS_SPACE_IO, &d->bmdma_bar);

    /* TODO: RST# value should be 0 */
    pci_conf[PCI_INTERRUPT_PIN] = 0x01; // interrupt on pin 1

    qdev_init_gpio_in(ds, cmd646_set_irq, 2);
    for (i = 0; i < 2; i++) {
        ide_bus_init(&d->bus[i], sizeof(d->bus[i]), ds, i, 2);
        ide_bus_init_output_irq(&d->bus[i], qdev_get_gpio_in(ds, i));

        bmdma_init(&d->bus[i], &d->bmdma[i], d);
        ide_bus_register_restart_cb(&d->bus[i]);
    }
}

static void pci_cmd646_ide_exitfn(PCIDevice *dev)
{
    PCIIDEState *d = PCI_IDE(dev);
    unsigned i;

    for (i = 0; i < 2; ++i) {
        memory_region_del_subregion(&d->bmdma_bar, &d->bmdma[i].extra_io);
        memory_region_del_subregion(&d->bmdma_bar, &d->bmdma[i].addr_ioport);
    }
}

static void superio_all_init(Object *obj)
{   
    PCIIDEState *d = PCI_IDE(obj);

    qdev_init_gpio_out_named(DEVICE(d), d->isa_irq, "isa-irq",
                             ARRAY_SIZE(d->isa_irq));

    // NS_ISAState *s = NS87560_ISA(obj);

    // object_initialize_child(obj, "ide", &s->ide, "cmd646-ide");
    // object_initialize_child(obj, "uhci1", &s->uhci[0], TYPE_NS87560b_USB_UHCI);
    // object_initialize_child(obj, "uhci2", &s->uhci[1], TYPE_NS87560b_USB_UHCI);
}

static const Property cmd646_ide_properties[] = {
    DEFINE_PROP_UINT32("secondary", PCIIDEState, secondary, 1),
};

static void cmd646_ide_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);

    device_class_set_legacy_reset(dc, cmd646_reset);
    dc->vmsd = &vmstate_ide_pci;
    k->realize = pci_cmd646_ide_realize;
    k->exit = pci_cmd646_ide_exitfn;
    k->vendor_id = PCI_VENDOR_ID_NS;
    k->device_id = PCI_DEVICE_ID_NS_87415;
    k->revision = 0x03;
    k->class_id = PCI_CLASS_STORAGE_IDE;
    k->config_read = cmd646_pci_config_read;
    k->config_write = cmd646_pci_config_write;
    device_class_set_props(dc, cmd646_ide_properties);
    set_bit(DEVICE_CATEGORY_STORAGE, dc->categories);
}

static const TypeInfo cmd646_ide_info = {
    .name          = TYPE_NS87560_ALL,
    .parent        = TYPE_PCI_IDE,
    .instance_size = sizeof(SUPERIO_ALL_State),
    .instance_init = superio_all_init,
    .class_init    = cmd646_ide_class_init,
};

static void cmd646_ide_register_types(void)
{
    type_register_static(&cmd646_ide_info);
}

type_init(cmd646_ide_register_types)


/****************************************** SERIAL *******************************/

#define PCI_SERIAL_MAX_PORTS 2

typedef struct PCIMultiSerialState {
    PCIDevice    dev;
    MemoryRegion iobar;
    uint32_t     ports;
    char         *name[PCI_SERIAL_MAX_PORTS];
    SerialState  state[PCI_SERIAL_MAX_PORTS];
    uint32_t     level[PCI_SERIAL_MAX_PORTS];
    IRQState     irqs[PCI_SERIAL_MAX_PORTS];
    uint8_t      prog_if;
} PCIMultiSerialState;

static void multi_serial_pci_exit(PCIDevice *dev)
{
    PCIMultiSerialState *pci = DO_UPCAST(PCIMultiSerialState, dev, dev);
    SerialState *s;
    int i;

    for (i = 0; i < pci->ports; i++) {
        s = pci->state + i;
        qdev_unrealize(DEVICE(s));
        memory_region_del_subregion(&pci->iobar, &s->io);
        g_free(pci->name[i]);
    }
}

static void multi_serial_irq_mux(void *opaque, int n, int level)
{
    PCIMultiSerialState *pci = opaque;
    int i, pending = 0;

    pci->level[n] = level;
    for (i = 0; i < pci->ports; i++) {
        if (pci->level[i]) {
            pending = 1;
        }
    }
    pci_set_irq(&pci->dev, pending);
}

static size_t multi_serial_get_port_count(PCIDeviceClass *pc)
{
    switch (pc->device_id) {
    case 0x0003:
        return 2;
    case 0x0004:
        return 4;
    }

    g_assert_not_reached();
}


static void multi_serial_pci_realize(PCIDevice *dev, Error **errp)
{
    PCIDeviceClass *pc = PCI_DEVICE_GET_CLASS(dev);
    PCIMultiSerialState *pci = DO_UPCAST(PCIMultiSerialState, dev, dev);
    SerialState *s;
    size_t i, nports = multi_serial_get_port_count(pc);

    pci->dev.config[PCI_CLASS_PROG] = pci->prog_if;
    pci->dev.config[PCI_INTERRUPT_PIN] = 0x01;
    memory_region_init(&pci->iobar, OBJECT(pci), "multiserial", 8 * nports);
    pci_register_bar(&pci->dev, 0, PCI_BASE_ADDRESS_SPACE_IO, &pci->iobar);

    for (i = 0; i < nports; i++) {
        s = pci->state + i;
        if (!qdev_realize(DEVICE(s), NULL, errp)) {
            multi_serial_pci_exit(dev);
            return;
        }
        s->irq = &pci->irqs[i];
        pci->name[i] = g_strdup_printf("uart #%zu", i + 1);
        memory_region_init_io(&s->io, OBJECT(pci), &serial_io_ops, s,
                              pci->name[i], 8);
        memory_region_add_subregion(&pci->iobar, 8 * i, &s->io);
        pci->ports++;
    }
}

static const VMStateDescription vmstate_pci_multi_serial = {
    .name = "pci-serial-multi",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]) {
        VMSTATE_PCI_DEVICE(dev, PCIMultiSerialState),
        VMSTATE_STRUCT_ARRAY(state, PCIMultiSerialState, PCI_SERIAL_MAX_PORTS,
                             0, vmstate_serial, SerialState),
        VMSTATE_UINT32_ARRAY(level, PCIMultiSerialState, PCI_SERIAL_MAX_PORTS),
        VMSTATE_END_OF_LIST()
    }
};

static const Property multi_2x_serial_pci_properties[] = {
    DEFINE_PROP_CHR("chardev1",  PCIMultiSerialState, state[0].chr),
    DEFINE_PROP_CHR("chardev2",  PCIMultiSerialState, state[1].chr),
    DEFINE_PROP_UINT8("prog_if",  PCIMultiSerialState, prog_if, 0x02),
};

static void multi_2x_serial_pci_class_initfn(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIDeviceClass *pc = PCI_DEVICE_CLASS(klass);
    pc->realize = multi_serial_pci_realize;
    pc->exit = multi_serial_pci_exit;
    pc->vendor_id = PCI_VENDOR_ID_NS;
    pc->device_id = PCI_DEVICE_ID_NS_87560_LIO;
    pc->revision = 1;
    pc->class_id = PCI_CLASS_COMMUNICATION_SERIAL;
    dc->vmsd = &vmstate_pci_multi_serial;
    device_class_set_props(dc, multi_2x_serial_pci_properties);
    set_bit(DEVICE_CATEGORY_INPUT, dc->categories);
}


static void multi_serial_init(Object *o)
{
    PCIDevice *dev = PCI_DEVICE(o);
    PCIMultiSerialState *pms = DO_UPCAST(PCIMultiSerialState, dev, dev);
    size_t i, nports = multi_serial_get_port_count(PCI_DEVICE_GET_CLASS(dev));

    for (i = 0; i < nports; i++) {
        qemu_init_irq(&pms->irqs[i], multi_serial_irq_mux, pms, i);
        object_initialize_child(o, "serial[*]", &pms->state[i], TYPE_SERIAL);
    }
}

static const TypeInfo ns_superio_pci_info = {
    .name          = "pci-superio",
    .parent        = TYPE_PCI_DEVICE,
    .instance_size = sizeof(PCIMultiSerialState),
    .instance_init = multi_serial_init,
    .class_init    = multi_2x_serial_pci_class_initfn,
    .interfaces = (InterfaceInfo[]) {
        { INTERFACE_CONVENTIONAL_PCI_DEVICE },
        { },
    },
};

static void multi_serial_pci_register_types(void)
{
    type_register_static(&ns_superio_pci_info);
}

type_init(multi_serial_pci_register_types)


/****************************************** GLUE *******************************/

void create_PCI_87560_superio(PCIBus *pci_bus, int major);
void create_PCI_87560_superio(PCIBus *pci_bus, int major)
{
    PCIDevice *pci_dev;

    pci_dev = pci_new_multifunction(PCI_DEVFN(major, 0), TYPE_NS87560_ALL);
    pci_realize_and_unref(pci_dev, pci_bus, &error_fatal);

    /* function 0 is a PCI IDE Controller */
    //pci_dev = pci_new_multifunction(PCI_DEVFN(major, 0), "cmd646-ide");
    // qdev_prop_set_chr(DEVICE(pci_dev), "chardev1", serial_hd(0));
    // pci_realize_and_unref(pci_dev, pci_bus, &error_fatal);

    /* function 1 is a SuperIO chip */

    /* function 2 is a USB chip */
}

