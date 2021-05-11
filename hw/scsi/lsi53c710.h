#ifndef HW_53C710_H
#define HW_53C710_H

#include "exec/memory.h"
#include "exec/address-spaces.h"
#include "hw/scsi/scsi.h"

#define PORT_RESET              0x00    /* reset 53c710 */
#define PORT_SELFTEST           0x01    /* selftest */

typedef struct lsi_request {
    SCSIRequest *req;
    uint32_t tag;
    uint32_t dma_len;
    uint8_t *dma_buf;
    uint32_t pending;
    int out;
    QTAILQ_ENTRY(lsi_request) next;
} lsi_request;

/* Maximum length of MSG IN data.  */
#define LSI_MAX_MSGIN_LEN 8

typedef struct LSIState710 LSI_53C710State;

struct LSIState710 {
    /*< private >*/
    //PCIDevice parent_obj;
    /*< public >*/

    MemoryRegion mmio;
    MemoryRegion *as;

    qemu_irq irq;

    int carry; /* ??? Should this be an a visible register somewhere?  */
    int status;
    /* Action to take at the end of a MSG IN phase.
       0 = COMMAND, 1 = disconnect, 2 = DATA OUT, 3 = DATA IN.  */
    int msg_action;
    int msg_len;
    uint8_t msg[LSI_MAX_MSGIN_LEN];
    /* 0 if SCRIPTS are running or stopped.
     * 1 if a Wait Reselect instruction has been issued.
     * 2 if processing DMA from lsi_execute_script.
     * 3 if a DMA operation is in progress.  */
    int waiting;
    SCSIBus bus;
    int current_lun;
    /* The tag is a combination of the device ID and the SCSI tag.  */
    uint32_t select_tag;
    int command_complete;
    QTAILQ_HEAD(, lsi_request) queue;
    lsi_request *current;

    uint32_t dsa;
    uint32_t temp;
    uint32_t dnad;
    uint32_t dbc;
    uint8_t istat;
    uint8_t dcmd;
    uint8_t dstat;
    uint8_t dien;
//    uint8_t sist0;
//    uint8_t sist1;
    uint8_t sien0;
    uint8_t ctest2;
    uint8_t ctest3;
    uint8_t ctest4;
    uint8_t ctest5;
    uint32_t dsp;
    uint32_t dsps;
    uint8_t dmode;
    uint8_t dcntl;
    uint8_t scntl0;
    uint8_t scntl1;
    uint8_t sstat0;
    uint8_t sstat1;
    uint8_t scid;
    uint8_t sxfer;
    uint8_t socl;
    uint8_t sdid;
    uint8_t sfbr;
    uint8_t sidl;
    uint32_t sbc;
    uint32_t scratch;
    uint8_t sbr;

	uint8_t ctest0;
	uint8_t ctest1;
	uint8_t ctest6;
	uint8_t ctest7;
	uint8_t ctest8;
	uint8_t lcrc;
	uint8_t sstat2;
	uint8_t dwt;
	uint8_t sbcl;
	uint8_t script_active;
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
