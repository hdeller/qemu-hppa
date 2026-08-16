#include "qemu/osdep.h"
#include "hw/pci/pci.h"
#include "migration/vmstate.h"
#include "qemu/module.h"
#include "hw/isa/isa.h"
#include "hw/core/irq.h"
#include "hw/ide/pci.h"
#include "ide-internal.h"
#include "trace.h"

#define PC87560_IDE_DEBUG 1

#define DPRINTF(fmt, ...) \
    do { \
        if (PC87560_IDE_DEBUG) { \
            fprintf(stderr, fmt, ## __VA_ARGS__); \
        } \
    } while (0)

#define IDE_CFR1 0x40
#define IDE_CFR2 0x41
#define IDE_CFR3 0x42
#define IDE_WBS  0x43


/* PC87560 Bus Master IDE Command Register bits (BAR4 offset 0x00/0x08) */
#define PC87560_BM_CMD_START        0x01  /* bit 0: start/stop DMA */
#define PC87560_BM_CMD_WRITE        0x08  /* bit 3: 1=write to disk, 0=read from disk */

/* PC87560 Bus Master IDE Status Register bits (BAR4 offset 0x02/0x0A) */
#define PC87560_BM_SR_ACTIVE        0x01  /* bit 0: DMA active, read-only */
#define PC87560_BM_SR_ERROR         0x02  /* bit 1: error, W1C */
#define PC87560_BM_SR_INT           0x04  /* bit 2: interrupt, W1C */
#define PC87560_BM_SR_DRV1_DMA      0x20  /* bit 5: drive 1 DMA capable */
#define PC87560_BM_SR_DRV2_DMA      0x40  /* bit 6: drive 2 DMA capable */

#define CFR_INTR_CH1    0x01
#define CFR_INTR_CH2    0x02

#define ATA_DMA_START   0x01
#define ATA_DMA_ERR     0x02
#define ATA_DMA_INTR    0x04
#define ATA_DMA_WR      0x08
#define ATA_DMA_ACTIVE  0x01

static qemu_irq pc87560_ide_irq_out;
static void pc87560_update_irq(PCIDevice *pd);

static uint64_t bmdma_read(void *opaque, hwaddr addr, unsigned size)
{
    BMDMAState *bm = opaque;
    uint32_t val;

    if (size != 1) {
        return ((uint64_t)1 << (size * 8)) - 1;
    }

    switch (addr & 3) {
    case 0:
        val = bm->cmd;
        break;
    case 2:
        val = bm->status;
        break;
    default:
        val = 0xff;
        break;
    }
    return val;
}

static void bmdma_write(void *opaque, hwaddr addr, uint64_t val, unsigned size)
{
    BMDMAState *bm = opaque;
    PCIDevice *pd = PCI_DEVICE(bm->bus->qbus.parent);

    if (size != 1) {
        return;
    }

    switch (addr & 3) {
    case 0: {
        uint8_t status_clear = val & (ATA_DMA_INTR | ATA_DMA_ERR);
        uint8_t real_cmd = val & 0x09;  /* only START(0) and WRITE(3) are real cmd bits */

        bm->status &= ~status_clear;

        if (real_cmd != (bm->cmd & 0x09)) {
            bmdma_cmd_writeb(bm, real_cmd);
        }

        pc87560_update_irq(pd);
        break;
    }
    case 2:
        bmdma_status_writeb(bm, val);
        pc87560_update_irq(pd);
        break;
    default:
        break;
    }
}

static void pc87560_update_irq(PCIDevice *pd)
{
    PCIIDEState *d = PCI_IDE(pd);
    uint8_t cntrl2 = pd->config[IDE_CFR2];
    int level = 0;

    if (!(cntrl2 & CFR_INTR_CH1)) {
        level |= !!(d->bmdma[0].status & BM_STATUS_INT);
    }
    if (!(cntrl2 & CFR_INTR_CH2)) {
        level |= !!(d->bmdma[1].status & BM_STATUS_INT);
    }
    qemu_set_irq(pc87560_ide_irq_out, level);
}


static const MemoryRegionOps pc87560_bmdma_ops = {
    .read = bmdma_read,
    .write = bmdma_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
};

static void bmdma_setup_bar(PCIIDEState *d)
{
    BMDMAState *bm;
    int i;

    memory_region_init(&d->bmdma_bar, OBJECT(d), "pc87560-bmdma", 16);
    for (i = 0; i < 2; i++) {
        bm = &d->bmdma[i];
        memory_region_init_io(&bm->extra_io, OBJECT(d), &pc87560_bmdma_ops, bm,
                              "pc87560-bmdma-bus", 4);
        memory_region_add_subregion(&d->bmdma_bar, i * 8, &bm->extra_io);
        memory_region_init_io(&bm->addr_ioport, OBJECT(d),
                              &bmdma_addr_ioport_ops, bm,
                              "pc87560-bmdma-ioport", 4);
        memory_region_add_subregion(&d->bmdma_bar, i * 8 + 4, &bm->addr_ioport);
    }
}


static void pc87560_set_irq(void *opaque, int channel, int level)
{
    PCIIDEState *d = opaque;
    PCIDevice *pd = PCI_DEVICE(d);

    if (level) {
        d->bmdma[channel].status |= BM_STATUS_INT;
    }
    pc87560_update_irq(pd);
}


static void pc87560_reset(Object *dev, ResetType type)
{
    PCIIDEState *d = PCI_IDE(dev);
    unsigned int i;

    for (i = 0; i < 2; i++) {
        ide_bus_reset(&d->bus[i]);
    }
}


static void pc87560_pci_config_write(PCIDevice *d, uint32_t addr, uint32_t val,
                                    int l)
{
    uint32_t i;
    pci_default_write_config(d, addr, val, l);

    for (i = addr; i < addr + l; i++) {
        switch (i) {
        case IDE_CFR2:
            pc87560_update_irq(d);
            break;
        }
    }
}

static void pci_pc87560_ide_realize(PCIDevice *dev, Error **errp)
{

    PCIIDEState *d = PCI_IDE(dev);
    DeviceState *ds = DEVICE(dev);
    uint8_t *pci_conf = dev->config;
    int i;

    dev->cap_present |= QEMU_PCI_CAP_MULTIFUNCTION;
    pci_conf[PCI_HEADER_TYPE] |= PCI_HEADER_TYPE_MULTI_FUNCTION;

    pci_conf[PCI_CLASS_PROG] = 0x8a;
    dev->wmask[PCI_CLASS_PROG] = 0xff;

    pci_conf[PCI_INTERRUPT_PIN] = 0x01;
    qdev_init_gpio_out(ds, &pc87560_ide_irq_out, 1);

    // TODO make all of this with defines instead of values and confirm they are correct
    memset(&dev->wmask[IDE_CFR1], 0xff, 3);
    dev->wmask[IDE_WBS] = 0xff;

    // 0x44 to 0x55 are read/write timing configuration registers
    for (i = 0x44; i <= 0x55; i++) {
        dev->wmask[i] = 0xff;
    }
    // 0x58 to 0x5D are Read-Only values
    for (i = 0x58; i <= 0x5d; i++) {
        dev->wmask[i] = 0x00;
    }

    pci_conf[IDE_CFR1] = 0x00;
    pci_conf[IDE_CFR2] = 0x00;
    pci_conf[IDE_CFR3] = 0x00;
    pci_conf[IDE_WBS]  = 0x60;

    for (i = 0x44; i <= 0x51; i++) {
        if (i != 0x46 && i != 0x47 &&
                i != 0x4A && i != 0x4B && i != 0x4E && i != 0x4F) {
            pci_conf[i] = 0x85;
        }
    }
    pci_conf[0x54] = 0xB7;
    pci_conf[0x55] = 0xEE;

    memory_region_init_io(&d->data_bar[0], OBJECT(d), &pci_ide_data_le_ops,
                          &d->bus[0], "pc87560-data0", 8);
    pci_register_bar(dev, 0, PCI_BASE_ADDRESS_SPACE_IO, &d->data_bar[0]);

    memory_region_init_io(&d->cmd_bar[0], OBJECT(d), &pci_ide_cmd_le_ops,
                          &d->bus[0], "pc87560-cmd0", 4);
    pci_register_bar(dev, 1, PCI_BASE_ADDRESS_SPACE_IO, &d->cmd_bar[0]);

    memory_region_init_io(&d->data_bar[1], OBJECT(d), &pci_ide_data_le_ops,
                          &d->bus[1], "pc87560-data1", 8);
    pci_register_bar(dev, 2, PCI_BASE_ADDRESS_SPACE_IO, &d->data_bar[1]);

    memory_region_init_io(&d->cmd_bar[1], OBJECT(d), &pci_ide_cmd_le_ops,
                          &d->bus[1], "pc87560-cmd1", 4);
    pci_register_bar(dev, 3, PCI_BASE_ADDRESS_SPACE_IO, &d->cmd_bar[1]);

    bmdma_setup_bar(d);
    pci_register_bar(dev, 4, PCI_BASE_ADDRESS_SPACE_IO, &d->bmdma_bar);

    qdev_init_gpio_in(ds, pc87560_set_irq, 2);
    for (i = 0; i < 2; i++) {
        ide_bus_init(&d->bus[i], sizeof(d->bus[i]), ds, i, 2);
        ide_bus_init_output_irq(&d->bus[i], qdev_get_gpio_in(ds, i));

        bmdma_init(&d->bus[i], &d->bmdma[i], d);
        d->bmdma[i].bus = &d->bus[i];
        ide_bus_register_restart_cb(&d->bus[i]);
    }
}

static void pci_pc87560_ide_exitfn(PCIDevice *dev)
{
    PCIIDEState *d = PCI_IDE(dev);
    unsigned i;

    for (i = 0; i < 2; ++i) {
        memory_region_del_subregion(&d->bmdma_bar, &d->bmdma[i].extra_io);
        memory_region_del_subregion(&d->bmdma_bar, &d->bmdma[i].addr_ioport);
    }
}


static void pc87560_ide_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);
    ResettableClass *rc = RESETTABLE_CLASS(klass);

    rc->phases.hold = pc87560_reset;
    dc->vmsd = &vmstate_ide_pci;
    dc->user_creatable = false;
    k->realize = pci_pc87560_ide_realize;
    k->exit = pci_pc87560_ide_exitfn;
    k->vendor_id = 0x100B;
    k->device_id = 0x0002;
    k->revision = 0x02;
    k->subsystem_vendor_id = PCI_VENDOR_ID_HP;
    k->subsystem_id     = 0x10A7;
    k->class_id = PCI_CLASS_STORAGE_IDE;
    k->config_write = pc87560_pci_config_write;
    set_bit(DEVICE_CATEGORY_STORAGE, dc->categories);
}


static const TypeInfo pc87560_ide_info = {
    .name          = "pc87560-ide",
    .parent        = TYPE_PCI_IDE,
    .class_init    = pc87560_ide_class_init,
};

static void pc87560_ide_register_types(void)
{
    type_register_static(&pc87560_ide_info);
}

type_init(pc87560_ide_register_types)

