#ifndef HW_I82596_H
#define HW_I82596_H

#define I82596_IOPORT_SIZE       0x20

#include "exec/memory.h"
#include "exec/address-spaces.h"

#define PORT_RESET              0x00    /* reset 82596 */
#define PORT_SELFTEST           0x01    /* selftest */
#define PORT_ALTSCP             0x02    /* alternate SCB address */
#define PORT_ALTDUMP            0x03    /* Alternate DUMP address */
#define PORT_CA                 0x04    /* QEMU-internal CA signal */
#define PORT_BYTEMASK           0x0f    /* all valid bits */

/* modes in which the 82596 can operate */
#define MODE_82586              0       /* 24 bit address space */
#define MODE_32BIT_SEGMENTED    1
#define MODE_LINEAR             2       /* 32 bit address space */
#define MODE_UNKNOWN            3

typedef struct I82596State_st I82596State;

struct I82596State_st {
    MemoryRegion mmio;
    MemoryRegion *as;
    qemu_irq irq;
    NICState *nic;
    NICConf conf;
    QEMUTimer *flush_queue_timer;

    hwaddr scp;         /* pointer to SCP */
    uint8_t send_irq;
    uint32_t scb;       /* SCB */
    uint16_t scb_status;
    uint8_t CUS:3;      /* Command Unit status word in SCB */
    uint8_t RUS:4;      /* Receive Unit status word in SCB */
    uint16_t lnkst;
    uint32_t cmd_p;     /* addr of current command */

    /* Hash register (multicast mask array, multiple individual addresses). */
    uint8_t mult[8];
    uint8_t config[14]; /* config bytes from CONFIGURE command */

    uint8_t tx_buffer[1540];
};

void i82596_h_reset(void *opaque);
void i82596_ioport_writew(void *opaque, uint32_t addr, uint32_t val);
uint32_t i82596_ioport_readw(void *opaque, uint32_t addr);
void i82596_ioport_writel(void *opaque, uint32_t addr, uint32_t val);
uint32_t i82596_ioport_readl(void *opaque, uint32_t addr);
uint32_t i82596_bcr_readw(I82596State *s, uint32_t rap);
ssize_t i82596_receive(NetClientState *nc, const uint8_t *buf, size_t size_);
int i82596_can_receive(NetClientState *nc);
void i82596_set_link_status(NetClientState *nc);
void i82596_common_init(DeviceState *dev, I82596State *s, NetClientInfo *info);
extern const VMStateDescription vmstate_i82596;
#endif
