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
#include "qemu/log.h"
#include "qapi/error.h"
#include "hw/char/serial.h"
#include "hw/irq.h"
#include "hw/pci/pci_device.h"
#include "hw/qdev-properties.h"
#include "hw/qdev-properties-system.h"
#include "migration/vmstate.h"
#include "hw/isa/superio.h"
#include "hw/ide/pci.h"

#define PCI_VENDOR_ID_NS                0x100b
#define PCI_DEVICE_ID_NS_87415          0x0002
#define PCI_DEVICE_ID_NS_87560_LIO      0x000e
#define PCI_DEVICE_ID_NS_87560_USB      0x0012


#define TYPE_NS87560_ALL "superio-all"

#define TYPE_NS87_ISA "via-isa"
OBJECT_DECLARE_SIMPLE_TYPE(ViaISAState, NS87_ISA)

struct ViaISAState {
    PCIDevice dev;

    IRQState i8259_irq;
    qemu_irq cpu_intr;
    qemu_irq *isa_irqs_in;
    PCIIDEState ide;
    uint16_t irq_state[ISA_NUM_IRQS];
    ISASuperIODevice superio;
    // UHCIState uhci[2];
    // ViaPMState pm;
};

static const VMStateDescription vmstate_via = {
    .name = "via-isa",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]) {
        VMSTATE_PCI_DEVICE(dev, ViaISAState),
        VMSTATE_END_OF_LIST()
    }
};

static void via_isa_init(Object *obj)
{
    ViaISAState *s = NS87_ISA(obj);

    object_initialize_child(obj, "ide", &s->ide, "cmd646-ide");
    // object_initialize_child(obj, "uhci1", &s->uhci[0], TYPE_VT82C686B_USB_UHCI);
    // object_initialize_child(obj, "uhci2", &s->uhci[1], TYPE_VT82C686B_USB_UHCI);
}

static const TypeInfo via_isa_info = {
    .name          = TYPE_NS87_ISA,
    .parent        = TYPE_PCI_DEVICE,
    .instance_size = sizeof(ViaISAState),
    .instance_init = via_isa_init,
    // .abstract      = true,
    .interfaces    = (InterfaceInfo[]) {
        { INTERFACE_CONVENTIONAL_PCI_DEVICE },
        { },
    },
};

static int via_isa_get_pci_irq(const ViaISAState *s, int pin)
{
    switch (pin) {
    case 0:
        return s->dev.config[0x55] >> 4;
    case 1:
        return s->dev.config[0x56] & 0xf;
    case 2:
        return s->dev.config[0x56] >> 4;
    case 3:
        return s->dev.config[0x57] >> 4;
    }
    return 0;
}

static void via_isa_set_irq(PCIDevice *d, int pin, int level)
{
    ViaISAState *s = NS87_ISA(pci_get_function_0(d));
    uint8_t irq = d->config[PCI_INTERRUPT_LINE], max_irq = 15;
    int f = PCI_FUNC(d->devfn);
    uint16_t mask;

    switch (f) {
    case 0: /* PIRQ/PINT inputs */
        irq = via_isa_get_pci_irq(s, pin);
        f = 8 + pin; /* Use function 8-11 for PCI interrupt inputs */
        break;
    case 2: /* USB ports 0-1 */
    case 3: /* USB ports 2-3 */
    case 5: /* AC97 audio */
        max_irq = 14;
        break;
    }

    /* Keep track of the state of all sources */
    mask = BIT(f);
    if (level) {
        s->irq_state[0] |= mask;
    } else {
        s->irq_state[0] &= ~mask;
    }
    if (irq == 0 || irq == 0xff) {
        return; /* disabled */
    }
    if (unlikely(irq > max_irq || irq == 2)) {
        qemu_log_mask(LOG_GUEST_ERROR, "Invalid ISA IRQ routing %d for %d",
                      irq, f);
        return;
    }
    /* Record source state at mapped IRQ */
    if (level) {
        s->irq_state[irq] |= mask;
    } else {
        s->irq_state[irq] &= ~mask;
    }
    /* Make sure there are no stuck bits if mapping has changed */
    s->irq_state[irq] &= s->irq_state[0];
    /* ISA IRQ level is the OR of all sources routed to it */
    qemu_set_irq(s->isa_irqs_in[irq], !!s->irq_state[irq]);
}

static void via_isa_pirq(void *opaque, int pin, int level)
{
    via_isa_set_irq(opaque, pin, level);
}

static void via_isa_request_i8259_irq(void *opaque, int irq, int level)
{
    ViaISAState *s = opaque;
    qemu_set_irq(s->cpu_intr, level);
}

static void via_isa_realize(PCIDevice *d, Error **errp)
{
    ViaISAState *s = NS87_ISA(d);
    DeviceState *dev = DEVICE(d);
    PCIBus *pci_bus = pci_get_bus(d);
    ISABus *isa_bus;

    int i;
    qdev_init_gpio_out_named(dev, &s->cpu_intr, "intr", 1);
    qdev_init_gpio_in_named(dev, via_isa_pirq, "pirq", PCI_NUM_PINS);
    qemu_init_irq(&s->i8259_irq, via_isa_request_i8259_irq, s, 0);
#if 0
    isa_bus = isa_bus_new(dev, pci_address_space(d), pci_address_space_io(d),
                          errp);

    if (!isa_bus) {
        return;
    }

    s->isa_irqs_in = i8259_init(isa_bus, &s->i8259_irq);
    isa_bus_register_input_irqs(isa_bus, s->isa_irqs_in);
    i8254_pit_init(isa_bus, 0x40, 0, NULL);
    i8257_dma_init(OBJECT(d), isa_bus, 0);

    /* RTC */
    qdev_prop_set_int32(DEVICE(&s->rtc), "base_year", 2000);
    if (!qdev_realize(DEVICE(&s->rtc), BUS(isa_bus), errp)) {
        return;
    }
    isa_connect_gpio_out(ISA_DEVICE(&s->rtc), 0, s->rtc.isairq);

    for (i = 0; i < PCI_CONFIG_HEADER_SIZE; i++) {
        if (i < PCI_COMMAND || i >= PCI_REVISION_ID) {
            d->wmask[i] = 0;
        }
    }

    /* Super I/O */
    if (!qdev_realize(DEVICE(&s->via_sio), BUS(isa_bus), errp)) {
        return;
    }

    /* Function 1: IDE */
    qdev_prop_set_int32(DEVICE(&s->ide), "addr", d->devfn + 1);
    if (!qdev_realize(DEVICE(&s->ide), BUS(pci_bus), errp)) {
        return;
    }
    for (i = 0; i < 2; i++) {
        qdev_connect_gpio_out_named(DEVICE(&s->ide), "isa-irq", i,
                                    s->isa_irqs_in[14 + i]);
    }

    /* Functions 2-3: USB Ports */
    for (i = 0; i < ARRAY_SIZE(s->uhci); i++) {
        qdev_prop_set_int32(DEVICE(&s->uhci[i]), "addr", d->devfn + 2 + i);
        if (!qdev_realize(DEVICE(&s->uhci[i]), BUS(pci_bus), errp)) {
            return;
        }
    }

    /* Function 4: Power Management */
    qdev_prop_set_int32(DEVICE(&s->pm), "addr", d->devfn + 4);
    if (!qdev_realize(DEVICE(&s->pm), BUS(pci_bus), errp)) {
        return;
    }
#endif
}

/* TYPE_NS87560_ALL */

static void vt82c686b_write_config(PCIDevice *d, uint32_t addr,
                                   uint32_t val, int len)
{
#if 0
    ViaISAState *s = NS87_ISA(d);

    // trace_via_isa_write(addr, val, len);
    pci_default_write_config(d, addr, val, len);
    if (addr == 0x85) {
        /* BIT(1): enable or disable superio config io ports */
        // via_superio_io_enable(&s->via_sio, val & BIT(1));
    }
#endif
}

static void vt82c686b_isa_reset(DeviceState *dev)
{
    ViaISAState *s = NS87_ISA(dev);
    uint8_t *pci_conf = s->dev.config;

    pci_set_long(pci_conf + PCI_CAPABILITY_LIST, 0x000000c0);
    pci_set_word(pci_conf + PCI_COMMAND, PCI_COMMAND_IO | PCI_COMMAND_MEMORY |
                 PCI_COMMAND_MASTER | PCI_COMMAND_SPECIAL);
    pci_set_word(pci_conf + PCI_STATUS, PCI_STATUS_DEVSEL_MEDIUM);

    pci_conf[0x48] = 0x01; /* Miscellaneous Control 3 */
    pci_conf[0x4a] = 0x04; /* IDE interrupt Routing */
    pci_conf[0x4f] = 0x03; /* DMA/Master Mem Access Control 3 */
    pci_conf[0x50] = 0x2d; /* PnP DMA Request Control */
    pci_conf[0x59] = 0x04;
    pci_conf[0x5a] = 0x04; /* KBC/RTC Control*/
    pci_conf[0x5f] = 0x04;
    pci_conf[0x77] = 0x10; /* GPIO Control 1/2/3/4 */
}

static void vt82c686b_init(Object *obj)
{
    // ViaISAState *s = NS87_ISA(obj);

    // object_initialize_child(obj, "sio", &s->via_sio, TYPE_VT82C686B_SUPERIO);
    // object_initialize_child(obj, "pm", &s->pm, TYPE_VT82C686B_PM);
}

static void vt82c686b_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);

    k->realize = via_isa_realize;
    k->config_write = vt82c686b_write_config;
    k->vendor_id = PCI_VENDOR_ID_VIA;
    k->device_id = PCI_DEVICE_ID_VIA_82C686B_ISA;
    k->class_id = PCI_CLASS_BRIDGE_ISA;
    k->revision = 0x40;
    device_class_set_legacy_reset(dc, vt82c686b_isa_reset);
    dc->desc = "ISA bridge";
    dc->vmsd = &vmstate_via;
    /* Reason: part of VIA VT82C686 southbridge, needs to be wired up */
    dc->user_creatable = false;
}

static const TypeInfo vt82c686b_isa_info = {
    .name          = TYPE_NS87560_ALL,
    .parent        = TYPE_NS87_ISA,
    .instance_size = sizeof(ViaISAState),
    .instance_init = vt82c686b_init,
    .class_init    = vt82c686b_class_init,
};


static void vt82c686b_register_types(void)
{
    type_register_static(&via_isa_info);
    type_register_static(&vt82c686b_isa_info);
}

type_init(vt82c686b_register_types)

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

