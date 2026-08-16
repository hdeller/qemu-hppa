#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/timer.h"
#include "hw/usb/usb.h"
#include "migration/vmstate.h"
#include "hw/pci/pci_device.h"
#include "hw/core/sysbus.h"
#include "hw/core/qdev-dma.h"
#include "hw/core/irq.h"
#include "hw/core/qdev-properties.h"
#include "trace.h"
#include "hcd-ohci.h"
#include "qom/object.h"

#define TYPE_NSC_PCI_OHCI "pc87560-ohci"
OBJECT_DECLARE_SIMPLE_TYPE(OHCIPCIState, NSC_PCI_OHCI)

struct OHCIPCIState {

    PCIDevice parent_obj;
    OHCIState state;
    MemoryRegion nsc_bar;
    char *masterbus;
    uint32_t num_ports;
    uint32_t firstport;
    qemu_irq irq_out[1];
};

static uint64_t nsc_usb_read(void *opaque, hwaddr addr, unsigned size)
{
    return 0;
}

static void pc87560_usb_irq_relay(void *opaque, int n, int level)
{
    OHCIPCIState *ohci = opaque;
    qemu_set_irq(ohci->irq_out[0], level);
}


/* TODO look at the datasheet and write nsc code */
static void nsc_usb_write(void *opaque, hwaddr addr, uint64_t val,
                          unsigned size)
{
}

static const MemoryRegionOps nsc_usb_ops = {
    .read = nsc_usb_read,
    .write = nsc_usb_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {
        .min_access_size = 1,
        .max_access_size = 4,
    },
};

static void ohci_pci_die(struct OHCIState *ohci)
{
    OHCIPCIState *dev = container_of(ohci, OHCIPCIState, state);
    ohci_sysbus_die(ohci);
    pci_set_word(dev->parent_obj.config + PCI_STATUS,
                 PCI_STATUS_DETECTED_PARITY);
}

static uint32_t pc87560_ohci_config_read(PCIDevice *pci, uint32_t addr, int len)
{
    uint32_t val = pci_default_read_config(pci, addr, len);
    return val;
}

static void pc87560_ohci_config_write(PCIDevice *pci, uint32_t addr,
                                       uint32_t val, int len)
{
    pci_default_write_config(pci, addr, val, len);
}

static void usb_ohci_realize_pci(PCIDevice *dev, Error **errp)
{
    Error *err = NULL;
    OHCIPCIState *ohci = NSC_PCI_OHCI(dev);

    dev->config[PCI_CLASS_PROG]    = 0x10;
    dev->wmask[PCI_CLASS_PROG]     = 0xff;
    dev->config[PCI_INTERRUPT_PIN] = 0x01;

    qdev_init_gpio_out(DEVICE(dev), ohci->irq_out, 1);
    ohci->state.irq = qemu_allocate_irq(pc87560_usb_irq_relay, ohci, 0);

    usb_ohci_init(&ohci->state, DEVICE(dev), ohci->num_ports, 0,
                  ohci->masterbus, ohci->firstport,
                  pci_get_address_space(dev), ohci_pci_die, &err);
    if (err) {
        error_propagate(errp, err);
        return;
    }

    pci_register_bar(dev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY, &ohci->state.mem);

    memory_region_init_io(&ohci->nsc_bar, OBJECT(dev), &nsc_usb_ops, ohci,
                          "nsc-usb", 0x1000);
    pci_register_bar(dev, 1, PCI_BASE_ADDRESS_SPACE_MEMORY, &ohci->nsc_bar);

    fprintf(stderr, "USB realize devfn=%02x\n", dev->devfn);
}

static void usb_ohci_exit(PCIDevice *dev)
{
    OHCIPCIState *ohci = NSC_PCI_OHCI(dev);
    OHCIState *s = &ohci->state;

    trace_usb_ohci_exit(s->name);
    ohci_bus_stop(s);

    if (s->async_td) {
        usb_cancel_packet(&s->usb_packet);
        s->async_td = 0;
    }
    ohci_stop_endpoints(s);

    if (!ohci->masterbus) {
        usb_bus_release(&s->bus);
    }

    timer_free(s->eof_timer);
}

static void usb_ohci_reset_pci(DeviceState *d)
{
    PCIDevice *dev = PCI_DEVICE(d);
    OHCIPCIState *ohci = NSC_PCI_OHCI(dev);
    OHCIState *s = &ohci->state;

    ohci_hard_reset(s);
}

static const Property ohci_pci_properties[] = {
    DEFINE_PROP_STRING("masterbus", OHCIPCIState, masterbus),
    DEFINE_PROP_UINT32("num-ports", OHCIPCIState, num_ports, 3),
    DEFINE_PROP_UINT32("firstport", OHCIPCIState, firstport, 0),
};

static const VMStateDescription vmstate_ohci = {
    .name = "pc87560-ohci",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]) {
        VMSTATE_PCI_DEVICE(parent_obj, OHCIPCIState),
        VMSTATE_STRUCT(state, OHCIPCIState, 1, vmstate_ohci_state, OHCIState),
        VMSTATE_END_OF_LIST()
    }
};

static void ohci_pci_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);

    k->realize       = usb_ohci_realize_pci;
    k->exit          = usb_ohci_exit;
    k->config_read   = pc87560_ohci_config_read;
    k->config_write  = pc87560_ohci_config_write;
    k->vendor_id     = 0x100b;
    k->device_id     = 0x0012;
    k->revision      = 0x01;
    k->class_id      = PCI_CLASS_SERIAL_USB;
    k->subsystem_vendor_id = 0x103C;
    k->subsystem_id        = 0x10A7;

    set_bit(DEVICE_CATEGORY_USB, dc->categories);
    dc->desc         = "National Semiconductor USB Controller";
    device_class_set_props(dc, ohci_pci_properties);
    dc->hotpluggable = false;
    dc->user_creatable = false;
    dc->vmsd         = &vmstate_ohci;
    device_class_set_legacy_reset(dc, usb_ohci_reset_pci);
}

static const TypeInfo ohci_pci_info = {
    .name          = TYPE_NSC_PCI_OHCI,
    .parent        = TYPE_PCI_DEVICE,
    .instance_size = sizeof(OHCIPCIState),
    .class_init    = ohci_pci_class_init,
    .interfaces = (const InterfaceInfo[]) {
        { INTERFACE_CONVENTIONAL_PCI_DEVICE },
        { },
    },
};

static void ohci_pci_register_types(void)
{
    type_register_static(&ohci_pci_info);
}

type_init(ohci_pci_register_types)
