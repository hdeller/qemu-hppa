#ifndef HW_53C710_H
#define HW_53C710_H

#include "exec/memory.h"
#include "exec/address-spaces.h"

#define PORT_RESET              0x00    /* reset 53c710 */
#define PORT_SELFTEST           0x01    /* selftest */

typedef struct LSI_53C710State_st LSI_53C710State;

struct LSI_53C710State_st {
    MemoryRegion mmio;
    MemoryRegion *as;
    qemu_irq irq;

    int send_irq;
};

void i53c710_h_reset(void *opaque);
void i53c710_ioport_writew(void *opaque, uint32_t addr, uint32_t val);
uint32_t i53c710_ioport_readw(void *opaque, uint32_t addr);
void i53c710_ioport_writel(void *opaque, uint32_t addr, uint32_t val);
uint32_t i53c710_ioport_readl(void *opaque, uint32_t addr);
uint32_t i53c710_bcr_readw(LSI_53C710State *s, uint32_t rap);
ssize_t i53c710_receive(NetClientState *nc, const uint8_t *buf, size_t size_);
bool i53c710_can_receive(NetClientState *nc);
void i53c710_set_link_status(NetClientState *nc);
void i53c710_common_init(DeviceState *dev, LSI_53C710State *s);
extern const VMStateDescription vmstate_i53c710;

extern void lsi710_scsi_init(DeviceState *dev);
extern void lsi710_scsi_reset(DeviceState *dev);

extern void lsi710_mmio_write(void *opaque, hwaddr addr, uint64_t val, unsigned size);
extern uint64_t lsi710_mmio_read(void *opaque, hwaddr addr, unsigned size);

extern int lsi710_common_init(DeviceState *dev, Error **errp);

#endif
