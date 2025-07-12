/*
 * QEMU Intel i82596 (Apricot) emulation
 *
 * Copyright (c) 2019 Helge Deller <deller@gmx.de>
 * Later improved upon and extended by Soumyajyotii Ssarkar <soumyajyotisarkar23@gmail.com>
 * During GSOC 2025
 * This work is licensed under the GNU GPL license version 2 or later.
 *
 * This software was written to be compatible with the specification:
 * https://parisc.docs.kernel.org/en/latest/_downloads/96672be0650d9fc046bbcea40b92482f/82596CA.pdf
 */

#include "qemu/osdep.h"
#include "qemu/timer.h"
#include "net/net.h"
#include "net/eth.h"
#include "hw/irq.h"
#include "hw/qdev-properties.h"
#include "migration/vmstate.h"
#include "exec/address-spaces.h"
#include "qemu/module.h"
#include "trace.h"
#include "i82596.h"
#include <zlib.h> /* for crc32 */

// #define ENABLE_DEBUG    1
#if defined(ENABLE_DEBUG)
#define DBG(x)          x
#else
#define DBG(x)          do { } while (0)
#endif

#define USE_TIMER       1

#define BITS(n, m) (((0xffffffffU << (31 - n)) >> (31 - n + m)) << m)

#define MAX_MC_CNT      64

#define ISCP_BUSY       0x0001
#define TX_TIMEOUT	(HZ/20)


#define I596_NULL       ((uint32_t)0xffffffff)


#define SCB_STATUS_CX   0x8000 /* CU finished command with I bit */
#define SCB_STATUS_FR   0x4000 /* RU finished receiving a frame */
#define SCB_STATUS_CNA  0x2000 /* CU left active state */
#define SCB_STATUS_RNR  0x1000 /* RU left active state */

#define SCB_COMMAND_ACK_MASK \
(SCB_STATUS_CX | SCB_STATUS_FR | SCB_STATUS_CNA | SCB_STATUS_RNR)

#define CU_IDLE         0
#define CU_SUSPENDED    1
#define CU_ACTIVE       2


#define RX_IDLE         0
#define RX_SUSPENDED    1
#define RX_NO_RESOURCES 2
#define RX_READY        4
#define RX_NO_RESO_RBD  (8 + RX_NO_RESOURCES)
#define RX_NO_MORE_RBD  (8 + RX_READY)
#define RFD_STATUS_TRUNC  0x0020  /* Frame truncated */
#define RFD_STATUS_NOBUFS 0x0200  /* Out of buffer space */

#define CMD_EOL         0x8000  /* The last command of the list, stop. */
#define CMD_SUSP        0x4000  /* Suspend after doing cmd. */
#define CMD_INTR        0x2000  /* Interrupt after doing cmd. */

#define CMD_FLEX        0x0008  /* Enable flexible memory model */

enum commands {
        CmdNOp = 0, CmdSASetup = 1, CmdConfigure = 2, CmdMulticastList = 3,
        CmdTx = 4, CmdTDR = 5, CmdDump = 6, CmdDiagnose = 7
};

#define STAT_C          0x8000  /* Set to 0 after execution */
#define STAT_B          0x4000  /* Command being executed */
#define STAT_OK         0x2000  /* Command executed ok */
#define STAT_A          0x1000  /* Command aborted */

#define I596_EOF        0x8000
#define SIZE_MASK       0x3fff

/* various flags in the chip config registers */
#define I596_PREFETCH       (s->config[0] & 0x80)
#define SAVE_BAD_FRAMES     (s->config[2] & 0x80)   /* Save Bad Frames */
#define I596_NO_SRC_ADD_IN  (s->config[3] & 0x08)   /* if 1, do not insert MAC in Tx Packet */
#define I596_LOOPBACK       (s->config[3] >> 6)     /* loopback mode, 3 = external loopback */
#define I596_PROMISC        (s->config[8] & 0x01)
#define I596_BC_DISABLE     (s->config[8] & 0x02)   /* broadcast status */
#define I596_NOCRC_INS      (s->config[8] & 0x08)   /* do not append CRC to Tx frame */
#define I596_CRC16_32       (s->config[8] & 0x10)   /* CRC-16 or CRC-32 */
#define I596_PADDING        (s->config[8] & 0x80)   /* Should we add padding?*/
#define I596_MIN_FRAME_LEN  (s->config[10])         /* minimum frame length */
#define I596_CRCINM         (s->config[11] & 0x04)  /* Rx CRC appended in memory */
#define I596_MC_ALL         (s->config[11] & 0x20)
#define I596_MULTIIA        (s->config[13] & 0x40)


static uint8_t get_byte(uint32_t addr)
{
    return ldub_phys(&address_space_memory, addr);
}

static void set_byte(uint32_t addr, uint8_t c)
{
    return stb_phys(&address_space_memory, addr, c);
}

static uint16_t get_uint16(uint32_t addr)
{
    return lduw_be_phys(&address_space_memory, addr);
}

static void set_uint16(uint32_t addr, uint16_t w)
{
    return stw_be_phys(&address_space_memory, addr, w);
}

static uint32_t get_uint32(uint32_t addr)
{
    uint32_t lo = lduw_be_phys(&address_space_memory, addr);
    uint32_t hi = lduw_be_phys(&address_space_memory, addr + 2);
    return (hi << 16) | lo;
}

static void set_uint32(uint32_t addr, uint32_t val)
{
    set_uint16(addr, (uint16_t) val);
    set_uint16(addr + 2, val >> 16);
}


struct qemu_ether_header {
    uint8_t ether_dhost[6];
    uint8_t ether_shost[6];
    uint16_t ether_type;
};

#define PRINT_PKTHDR(txt, BUF) do {                  \
    struct qemu_ether_header *hdr = (void *)(BUF); \
    printf(txt ": packet dhost=" MAC_FMT ", shost=" MAC_FMT ", type=0x%04x\n",\
           MAC_ARG(hdr->ether_dhost), MAC_ARG(hdr->ether_shost),        \
           be16_to_cpu(hdr->ether_type));       \
} while (0)

static void i82596_transmit(I82596State *s, uint32_t addr)
{
    uint32_t tbd_p; /* Transmit Buffer Descriptor */
    uint16_t cmd;
    uint16_t tcb_bytes = 0;
    uint16_t tx_data_len = 0;
    int insert_crc;

    cmd = get_uint16(addr + 2);
    assert(cmd & CMD_FLEX);    /* check flexible mode */

    /* Get TBD pointer */
    tbd_p = get_uint32(addr + 8);

    /* Get TCB byte count (immediate data in TCB) */
    tcb_bytes = get_uint16(addr + 12);

    /* Copy immediate data from TCB if present */
    if (tcb_bytes > 0) {
        assert(tcb_bytes <= sizeof(s->tx_buffer));
        address_space_read(&address_space_memory, addr + 16,
                           MEMTXATTRS_UNSPECIFIED, s->tx_buffer, tcb_bytes);
        tx_data_len = tcb_bytes;
    }

    /* Process TBD chain if present */
    if (tbd_p != I596_NULL) {
        while (tbd_p != I596_NULL && tx_data_len < sizeof(s->tx_buffer)) {
            uint16_t size;
            uint32_t tba;
            uint16_t buf_len;

            size = get_uint16(tbd_p);
            buf_len = size & SIZE_MASK;
            tba = get_uint32(tbd_p + 8);

            trace_i82596_transmit(buf_len, tba);

            if (buf_len > 0 && (tx_data_len + buf_len) <= sizeof(s->tx_buffer)) {
                address_space_read(&address_space_memory, tba,
                                   MEMTXATTRS_UNSPECIFIED,
                                   &s->tx_buffer[tx_data_len], buf_len);
                tx_data_len += buf_len;
            }

            /* Check if this is the last TBD */
            if (size & I596_EOF) {
                break;
            }

            /* Get next TBD pointer */
            tbd_p = get_uint32(tbd_p + 4);
        }
    }

    /* Check if we should insert CRC */
    insert_crc = (I596_NOCRC_INS == 0) && !I596_LOOPBACK;

    if (s->nic && tx_data_len > 0) {
        DBG(printf("i82596_transmit: insert_crc = %d, len = %d\n", insert_crc, tx_data_len));

        if (insert_crc && (tx_data_len + 4) <= sizeof(s->tx_buffer)) {
            uint32_t crc = crc32(~0, s->tx_buffer, tx_data_len);
            crc = cpu_to_be32(crc);
            memcpy(&s->tx_buffer[tx_data_len], &crc, sizeof(crc));
            tx_data_len += sizeof(crc);
        }

        /* Validate minimum frame size */
        if (tx_data_len < I596_MIN_FRAME_LEN) { /* Minimum Ethernet frame header */
            DBG(printf("Frame too short (%d bytes), aborting transmission\n", tx_data_len));
            DBG(printf("Adding Padding to reach minimum frame length\n"));
            if(I596_PADDING){
                int padding_needed = I596_MIN_FRAME_LEN - tx_data_len;
                if (padding_needed > 0 && (tx_data_len + padding_needed) <= sizeof(s->tx_buffer)) {
                    memset(&s->tx_buffer[tx_data_len], 0x7E, padding_needed);
                    tx_data_len += padding_needed;
                    DBG(printf("Added %d bytes of padding\n", padding_needed));
                } else {
                    /* Buffer overflow would occur if we added padding */
                    DBG(printf("WARNING: Cannot add %d bytes of padding - would overflow buffer (tx_data_len=%d, buffer_size=%zu)\n",
                               padding_needed, tx_data_len, sizeof(s->tx_buffer)));
                }
            }
        }
    }

    DBG(PRINT_PKTHDR("Send", s->tx_buffer));
    DBG(printf("Sending %d bytes (crc_inserted=%d)\n", tx_data_len, insert_crc));

    switch (I596_LOOPBACK) {
    case 0:     /* no loopback, send packet */
        qemu_send_packet_raw(qemu_get_queue(s->nic), s->tx_buffer, tx_data_len);
        break;
    case 1:     /* external loopback enabled */
        i82596_receive(qemu_get_queue(s->nic), s->tx_buffer, tx_data_len);
        break;
    default:    /* all other loopback modes: ignore! */
        break;
    }
}

static void set_individual_address(I82596State *s, uint32_t addr)
{
    NetClientState *nc;
    uint8_t *m;

    nc = qemu_get_queue(s->nic);
    m = s->conf.macaddr.a;
    address_space_read(&address_space_memory, addr + 8,
                       MEMTXATTRS_UNSPECIFIED, m, ETH_ALEN);
    qemu_format_nic_info_str(nc, m);
    trace_i82596_new_mac(nc->info_str);
}

static void i82596_configure(I82596State *s, uint32_t addr)
{
    uint8_t byte_cnt;
    byte_cnt = get_byte(addr + 8) & 0x0f;

    byte_cnt = MAX(byte_cnt, 4);
    byte_cnt = MIN(byte_cnt, sizeof(s->config));
    /* copy byte_cnt max. */
    address_space_read(&address_space_memory, addr + 8,
                       MEMTXATTRS_UNSPECIFIED, s->config, byte_cnt);
    /* config byte according to page 35ff */
    s->config[2] &= 0x82; /* mask valid bits */
    s->config[2] |= 0x40;
    s->config[7]  &= 0xf7; /* clear zero bit */
    // assert(I596_NOCRC_INS == 0); /* do CRC insertion */
    // s->config[10] = MAX(s->config[10], 5); /* min frame length */
    s->config[12] &= 0x40; /* only full duplex field valid */
    s->config[13] |= 0x3f; /* set ones in byte 13 */
}

static void set_multicast_list(I82596State *s, uint32_t addr)
{
    uint16_t mc_count, i;

    memset(&s->mult[0], 0, sizeof(s->mult));
    mc_count = get_uint16(addr + 8) / ETH_ALEN;
    addr += 10;
    if (mc_count > MAX_MC_CNT) {
        mc_count = MAX_MC_CNT;
    }
    for (i = 0; i < mc_count; i++) {
        uint8_t multicast_addr[ETH_ALEN];
        address_space_read(&address_space_memory, addr + i * ETH_ALEN,
                           MEMTXATTRS_UNSPECIFIED, multicast_addr, ETH_ALEN);
        DBG(printf("Add multicast entry " MAC_FMT "\n",
                    MAC_ARG(multicast_addr)));
        unsigned mcast_idx = (net_crc32(multicast_addr, ETH_ALEN) &
                              BITS(7, 2)) >> 2;
        assert(mcast_idx < 8 * sizeof(s->mult));
        s->mult[mcast_idx >> 3] |= (1 << (mcast_idx & 7));
    }
    trace_i82596_set_multicast(mc_count);
}

void i82596_set_link_status(NetClientState *nc)
{
    I82596State *d = qemu_get_nic_opaque(nc);

    d->lnkst = nc->link_down ? 0 : 0x8000;
}

static void update_scb_status(I82596State *s)
{
    s->scb_status = (s->scb_status & 0xf000)
        | (s->cu_status << 8) | (s->rx_status << 4);
    set_uint16(s->scb, s->scb_status);


}

static void i82596_s_reset(I82596State *s)
{
    trace_i82596_s_reset(s);
    s->scp = 0;
    s->scb_status = 0;
    s->cu_status = CU_IDLE;
    s->rx_status = RX_IDLE;
    s->cmd_p = I596_NULL;
    s->lnkst = 0x8000; /* initial link state: up */
    s->ca = s->ca_active = 0;
}


static void command_loop(I82596State *s)
{
    uint16_t cmd;
    uint16_t status;

    DBG(printf("STARTING COMMAND LOOP cmd_p=%08x\n", s->cmd_p));

    while (s->cmd_p != I596_NULL) {
        /* set status */
        status = STAT_B;
        set_uint16(s->cmd_p, status);
        status = STAT_C | STAT_OK; /* update, but write later */

        cmd = get_uint16(s->cmd_p + 2);
        DBG(printf("Running command %04x at %08x\n", cmd, s->cmd_p));

        switch (cmd & 0x07) {
        case CmdNOp:
            break;
        case CmdSASetup:
            set_individual_address(s, s->cmd_p);
            break;
        case CmdConfigure:
            i82596_configure(s, s->cmd_p);
            break;
        case CmdTDR:
            /* get signal LINK */
            set_uint32(s->cmd_p + 8, s->lnkst);
            break;
        case CmdTx:
            i82596_transmit(s, s->cmd_p);
            break;
        case CmdMulticastList:
            set_multicast_list(s, s->cmd_p);
            break;
        case CmdDump:
            // i82596_dump_premature(s, s->cmd_p + 8);
            /* set status */
            status = STAT_C | STAT_OK;
            set_uint16(s->cmd_p, status);
            DBG(printf("Dumped statistics to memory at %08x\n", s->cmd_p + 8));
            break;
        case CmdDiagnose:
            printf("FIXME Command %d !!\n", cmd & 7);
            g_assert_not_reached();
        }

        /* update status */
        set_uint16(s->cmd_p, status);

        s->cmd_p = get_uint32(s->cmd_p + 4); /* get link address */
        DBG(printf("NEXT addr would be %08x\n", s->cmd_p));
        if (s->cmd_p == 0) {
            s->cmd_p = I596_NULL;
        }

        /* Stop when last command of the list. */
        if (cmd & CMD_EOL) {
            s->cmd_p = I596_NULL;
        }
        /* Suspend after doing cmd? */
        if (cmd & CMD_SUSP) {
            s->cu_status = CU_SUSPENDED;
            printf("FIXME SUSPEND !!\n");
        }
        /* Interrupt after doing cmd? */
        if (cmd & CMD_INTR) {
            s->scb_status |= SCB_STATUS_CX;
        } else {
            s->scb_status &= ~SCB_STATUS_CX;
        }
        update_scb_status(s);

        /* Interrupt after doing cmd? */
        if (cmd & CMD_INTR) {
            s->send_irq = 1;
        }

        if (s->cu_status != CU_ACTIVE) {
            break;
        }
    }
    DBG(printf("FINISHED COMMAND LOOP\n"));
    qemu_flush_queued_packets(qemu_get_queue(s->nic));
}

static void i82596_flush_queue_timer(void *opaque)
{
    I82596State *s = opaque;
    if (0) {
        timer_del(s->flush_queue_timer);
        qemu_flush_queued_packets(qemu_get_queue(s->nic));
        timer_mod(s->flush_queue_timer,
              qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + 1000);
    }
}

static void examine_scb(I82596State *s)
{
    uint16_t command, cuc, ruc;

    /* get the scb command word */
    command = get_uint16(s->scb + 2);
    cuc = (command >> 8) & 0x7;
    ruc = (command >> 4) & 0x7;
    DBG(printf("MAIN COMMAND %04x  cuc %02x ruc %02x\n", command, cuc, ruc));
    /* and clear the scb command word */
    set_uint16(s->scb + 2, 0);

    s->scb_status &= ~(command & SCB_COMMAND_ACK_MASK);

    switch (cuc) {
    case 0:     /* no change */
        break;
    case 1:     /* CUC_START */
        s->cu_status = CU_ACTIVE;
        break;
    case 4:     /* CUC_ABORT */
        s->cu_status = CU_SUSPENDED;
        s->scb_status |= SCB_STATUS_CNA; /* CU left active state */
        break;
    default:
        printf("WARNING: Unknown CUC %d!\n", cuc);
    }

    switch (ruc) {
    case 0:     /* no change */
        break;
    case 1:     /* RX_START */
    case 2:     /* RX_RESUME */
        s->rx_status = RX_IDLE;
        if (USE_TIMER) {
            timer_mod(s->flush_queue_timer, qemu_clock_get_ms(
                                QEMU_CLOCK_VIRTUAL) + 1000);
        }
        break;
    case 3:     /* RX_SUSPEND */
    case 4:     /* RX_ABORT */
        s->rx_status = RX_SUSPENDED;
        s->scb_status |= SCB_STATUS_RNR; /* RU left active state */
        break;
    default:
        printf("WARNING: Unknown RUC %d!\n", ruc);
    }

    if (command & 0x80) { /* reset bit set? */
        i82596_s_reset(s);
    }

    /* execute commands from SCBL */
    if (s->cu_status != CU_SUSPENDED) {
        if (s->cmd_p == I596_NULL) {
            s->cmd_p = get_uint32(s->scb + 4);
        }
    }
    /* update scb status */
    update_scb_status(s);

    command_loop(s);
}

static void signal_ca(I82596State *s)
{
    uint32_t iscp = 0;

    /* trace_i82596_channel_attention(s); */
    if (s->scp) {
        /* CA after reset -> do init with new scp. */
        s->sysbus = get_byte(s->scp + 3); /* big endian */
        DBG(printf("SYSBUS = %08x\n", s->sysbus));
        if (((s->sysbus >> 1) & 0x03) != 2) {
            printf("WARNING: NO LINEAR MODE !!\n");
        }
        if ((s->sysbus >> 7)) {
            printf("WARNING: 32BIT LINMODE IN B-STEPPING NOT SUPPORTED !!\n");
        }
        iscp = get_uint32(s->scp + 8);
        s->scb = get_uint32(iscp + 4);
        set_byte(iscp + 1, 0); /* clear BUSY flag in iscp */
        s->scp = 0;
    }

    s->ca++;    /* count ca() */
    if (!s->ca_active) {
        s->ca_active = 1;
        while (s->ca)   {
            examine_scb(s);
            s->ca--;
        }
        s->ca_active = 0;
    }

    if (s->send_irq) {
        s->send_irq = 0;
        qemu_set_irq(s->irq, 1);
    }
}

void i82596_ioport_writew(void *opaque, uint32_t addr, uint32_t val)
{
    I82596State *s = opaque;
    /* printf("i82596_ioport_writew addr=0x%08x val=0x%04x\n", addr, val); */
    switch (addr) {
    case PORT_RESET: /* Reset */
        i82596_s_reset(s);
        break;
    case PORT_ALTSCP:
        s->scp = val;
        break;
    case PORT_ALTDUMP:
        // i82596_dump_premature(s, val);
        break;
    case PORT_CA:
        signal_ca(s);
        break;
    }
}

uint32_t i82596_ioport_readw(void *opaque, uint32_t addr)
{
    return -1;
}

void i82596_h_reset(void *opaque)
{
    I82596State *s = opaque;

    i82596_s_reset(s);
}

bool i82596_can_receive(NetClientState *nc)
{
    I82596State *s = qemu_get_nic_opaque(nc);

    if (s->rx_status == RX_SUSPENDED) {
        return false;
    }
    
    if (!s->lnkst) {
        return false;
    }

    if(s->rx_status == RX_SUSPENDED) {
        return false;
    }

    if (USE_TIMER && !timer_pending(s->flush_queue_timer)) {
        return true;
    }
    
    return true;
}

static void i82596_update_rx_state(I82596State *s, int new_state)
{
<<<<<<< HEAD
    I82596State *s = qemu_get_nic_opaque(nc);
    uint32_t rfd_p;
    uint32_t rbd, last_used_rbd;
    uint16_t is_broadcast = 0,status = 0;
    size_t len = sz; /* length of data for guest (including CRC) */
    size_t bufsz = sz; /* length of data in buf */
    uint32_t crc;
    uint8_t *crc_ptr;
    const uint8_t *cur_buf_ptr;
    static const uint8_t broadcast_macaddr[6] = {
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

    DBG(printf("i82596_receive() start\n"));
    /* Pro larger packets to meet the size*/
    if (sz > PKT_BUF_SZ) {
        sz = PKT_BUF_SZ;
        bufsz = sz;
        len = sz;
    }
    if (USE_TIMER && timer_pending(s->flush_queue_timer)) {
        return 0;
    }

    /* Check receiver state */
=======
    s->rx_status = new_state;
    
    /* Update SCB status bits based on state */
    if (new_state == RX_NO_RESOURCES || new_state == RX_SUSPENDED) {
        s->scb_status |= SCB_STATUS_RNR; /* RU left active state */
    }
    
    update_scb_status(s);
}

static int i82596_validate_receive_state(I82596State *s, size_t *sz, size_t *bufsz, size_t *len)
{
    if (*sz < 14 || *sz > PKT_BUF_SZ - 4) {
        trace_i82596_receive_analysis(">>> Packet size invalid");
        return -1;
    }
    
>>>>>>> 7c53cea43c (hw/net/i82596.c: Fixing the RX function for 82596)
    if (s->rx_status == RX_SUSPENDED) {
        trace_i82596_receive_analysis(">>> Receiving is suspended");
        return -1;
    }
    
    if (!s->lnkst) {
        trace_i82596_receive_analysis(">>> Link is down");
        return -1;
    }

    return 1;
}


static size_t i82596_buffer_boundary_check(size_t buffer_size, size_t used, size_t requested)
{
    if (buffer_size <= used) {
        return 0; /* No space left */
    }
    
    if (requested > (buffer_size - used)) {
        return buffer_size - used; /* Return remaining space */
    }
    
    return requested; /* Entire request fits */
}

static void i82596_record_error(I82596State *s, uint16_t error_type)
{
    uint32_t counter_addr;
    uint16_t count;
    
    /* Map error types to counter addresses */
    switch (error_type) {
    case RFD_STATUS_NOBUFS:
        counter_addr = s->scb + 20;  /* No buffer resources counter */
        break;
    case RFD_STATUS_TRUNC:
        counter_addr = s->scb + 22;  /* Truncated frames counter */
        break;
    default:
        return;
    }
    
    /* Increment the appropriate counter */
    count = get_uint16(counter_addr);
    set_uint16(counter_addr, count + 1);    
}

static void i82596_update_int(I82596State *s, bool send_irq)
{
    /* Similar to TULIP's tulip_update_int */
    update_scb_status(s);
    
    if (send_irq) {
        qemu_set_irq(s->irq, 1);
    }
}

static bool i82596_check_packet_filter(I82596State *s, const uint8_t *buf, uint16_t *is_broadcast)
{
    static const uint8_t broadcast_macaddr[6] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

    /* Handle packet based on MAC address type */
    if (I596_PROMISC || I596_LOOPBACK) { 
        trace_i82596_receive_analysis(">>> packet received in promiscuous mode");
        return true;
    } else {
        if (!memcmp(buf, broadcast_macaddr, 6)) {
            /* broadcast address */
            if (I596_BC_DISABLE) {
                trace_i82596_receive_analysis(">>> broadcast packet rejected");
                return false;
            }
            trace_i82596_receive_analysis(">>> broadcast packet received");
            *is_broadcast = 1;
            return true;
        } else if (buf[0] & 0x01) {
            /* multicast */
            if (!I596_MC_ALL) {
                trace_i82596_receive_analysis(">>> multicast packet rejected");
                return false;
            }
    
            int mcast_idx = (net_crc32(buf, ETH_ALEN) & BITS(7, 2)) >> 2;
            assert(mcast_idx < 8 * sizeof(s->mult));
    
            if (!(s->mult[mcast_idx >> 3] & (1 << (mcast_idx & 7)))) {
                trace_i82596_receive_analysis(">>> multicast address mismatch");
                return false;
            }
    
            trace_i82596_receive_analysis(">>> multicast packet received");
            *is_broadcast = 1;
            return true;
        } else if (!memcmp(s->conf.macaddr.a, buf, 6)) {
            /* match */
            trace_i82596_receive_analysis(">>> physical address matching packet received");
            return true;
        } else {
            trace_i82596_receive_analysis(">>> unknown packet");
            return false;
        }
    }
}

<<<<<<< HEAD
    /* Calculate the ethernet checksum (4 bytes) */
    len += 4;
    crc = cpu_to_be32(crc32(~0, buf, sz));
    crc_ptr = (uint8_t *) &crc;
    cur_buf_ptr = buf;
    rfd_p = get_uint32(s->scb + 8); /* get Receive Frame Descriptor */
    if (!rfd_p || rfd_p == I596_NULL) {
        s->rx_status = RX_NO_RESOURCES;
        s->scb_status |= SCB_STATUS_RNR;
        s->rsc_errs++;
        update_scb_status(s);
        return -1;
    }

    uint16_t command = get_uint16(rfd_p + 2);
    uint32_t next_rfd = get_uint32(rfd_p + 4);

    if ((command >> 3) & 1) {
        /* ---- FLEXIBLE MEMORY STRUCTURE ---- */
        uint16_t rfd_size = get_uint16(rfd_p + 12);
        uint32_t rfd_data_addr = rfd_p + 16; /* RFD data area starts after header */
        uint16_t rfd_data_used = 0;
        rbd = get_uint32(rfd_p + 8); /* first Receive Buffer Descriptor Address */

        if (rbd == I596_NULL) {
            s->rx_status = RX_NO_RESO_RBD;  /* RX_NO_RESOURCES with flag */
            s->scb_status |= SCB_STATUS_RNR;
            s->rsc_errs++;
            update_scb_status(s);
            return -1;
        }

        trace_i82596_receive_packet(len);

        if (rfd_size > 0 && len > 0) {
            rfd_data_used = (len > rfd_size) ? rfd_size : len;

            if (bufsz >= rfd_data_used) {
                address_space_write(&address_space_memory, rfd_data_addr,
                                   MEMTXATTRS_UNSPECIFIED, cur_buf_ptr, rfd_data_used);
                cur_buf_ptr += rfd_data_used;
                bufsz -= rfd_data_used;
                len -= rfd_data_used;
            } else {
                address_space_write(&address_space_memory, rfd_data_addr,
                                   MEMTXATTRS_UNSPECIFIED, cur_buf_ptr, bufsz);
                rfd_data_addr += bufsz;
                uint16_t crc_in_rfd = (rfd_data_used > bufsz) ? (rfd_data_used - bufsz) : 0;
                address_space_write(&address_space_memory, rfd_data_addr,
                                   MEMTXATTRS_UNSPECIFIED, crc_ptr, crc_in_rfd);
                crc_ptr += crc_in_rfd;
                len -= (bufsz + crc_in_rfd);
                bufsz = 0;
            }

            /* All data fit in RFD? means set EOF */
            if (len == 0) {
                status |= I596_EOF;
            }
        }

        /* Process RBD chain */
        last_used_rbd = I596_NULL;
        int rbd_count = 0;
        bool overrun = false;
        while (len > 0 && rbd != I596_NULL) {
            uint16_t buffer_size, count = 0;
            uint32_t rba, next_rbd;
            uint16_t rbd_status = 0;
            rbd_count++;

            if (rbd == 0) {
                if (last_used_rbd != I596_NULL) {
                    uint16_t last_status = get_uint16(last_used_rbd);
                    last_status |= I596_EOF;
                    set_uint16(last_used_rbd, last_status);
                } else {
                    status |= I596_EOF;
                }
                break;
            }

            next_rbd = get_uint32(rbd + 4);

            if (next_rbd != I596_NULL && next_rbd < 0x1000) {
                next_rbd = I596_NULL;
            }

            buffer_size = get_uint16(rbd + 12) & SIZE_MASK;
            if (buffer_size == 0) {
                rbd = next_rbd;
                continue;
            }

            rba = get_uint32(rbd + 8);
            uint16_t bytes_to_copy = (len > buffer_size) ? buffer_size : len;

            if (bufsz > 0) {
                uint16_t data_bytes = (bufsz > bytes_to_copy) ? bytes_to_copy : bufsz;

                address_space_write(&address_space_memory, rba,
                                   MEMTXATTRS_UNSPECIFIED, cur_buf_ptr, data_bytes);
                cur_buf_ptr += data_bytes;
                rba += data_bytes;
                bufsz -= data_bytes;
                len -= data_bytes;
                count += data_bytes;

                if (count >= bytes_to_copy) {
                    rbd_status = count | 0x4000; /* Set F bit */
                    set_uint16(rbd, rbd_status);
                    last_used_rbd = rbd;
                    rbd = next_rbd;
                    continue;
                }
            }

            /* Write as much of the CRC as fits */
            if (len > 0) {
                uint16_t crc_bytes = bytes_to_copy - count;

                address_space_write(&address_space_memory, rba,
                                   MEMTXATTRS_UNSPECIFIED, crc_ptr, crc_bytes);
                crc_ptr += crc_bytes;
                len -= crc_bytes;
                count += crc_bytes;
            }

            /* Set status and flags for this RBD */
            rbd_status = count | 0x4000; /* Set F bit */
            if (len == 0) {
                rbd_status |= I596_EOF; /* Set EOF bit for last buffer */
            }
            else if(next_rbd == I596_NULL) {
                rbd_status |= I596_EOF; /* Set EOF bit if no next RBD */
            }
            set_uint16(rbd, rbd_status);
            last_used_rbd = rbd;

            /* get next rbd */
            rbd = next_rbd;
            /* printf("Next Receive: rbd is %08x\n", rbd); */

            if (len > 0) {
                overrun = true;
                if (last_used_rbd != I596_NULL) {
                    uint16_t last_status = get_uint16(last_used_rbd);
                    last_status |= I596_EOF; /* Set EOF bit on last used RBD */
                    set_uint16(last_used_rbd, last_status);
                } else {
                    status |= I596_EOF; /* No RBDs used, but EOF */
                }
            }
        }
        if(len > 0 || overrun) {
            s->ovrn_errs++;
        }
        if (next_rfd != I596_NULL && next_rfd != 0) {
            if (rbd != I596_NULL) {
                set_uint32(next_rfd + 8, rbd);
            } else {
                set_uint32(next_rfd + 8, I596_NULL);
            }
        }
    } else {
        /* ---- SIMPLIFIED MEMORY STRUCTURE ---- */
        uint32_t data_addr = rfd_p + 16;

        if (sz < I596_MIN_FRAME_LEN) {
            s->shrt_errs++;
            return -1;
        }

        if (bufsz > len) {
            address_space_write(&address_space_memory, data_addr,
                               MEMTXATTRS_UNSPECIFIED, buf, len);
        } else {
            address_space_write(&address_space_memory, data_addr,
                               MEMTXATTRS_UNSPECIFIED, buf, bufsz);
            address_space_write(&address_space_memory, data_addr + bufsz,
                               MEMTXATTRS_UNSPECIFIED, crc_ptr, len - bufsz);
        }

        status |= I596_EOF;
    }

=======
static ssize_t i82596_finalize_reception(I82596State *s, uint32_t rfd_p, 
    uint16_t status, uint16_t command, uint32_t next_rfd, uint16_t is_broadcast, 
    size_t sz)
{
>>>>>>> 7c53cea43c (hw/net/i82596.c: Fixing the RX function for 82596)
    status |= STAT_C | STAT_OK | is_broadcast;
    set_uint16(rfd_p, status);

    if (command & CMD_SUSP) {  /* suspend after command? */
<<<<<<< HEAD
        s->rx_status = RX_SUSPENDED;
        s->scb_status |= SCB_STATUS_RNR; /* RU left active state */
        return sz;
    }
    if (command & CMD_EOL){/* was it last Frame Descriptor? */
        s->rx_status = RX_SUSPENDED;
=======
        i82596_update_rx_state(s, RX_SUSPENDED);
        return sz;
    }
    
    if (command & CMD_EOL) {   /* was it last Frame Descriptor? */
        i82596_update_rx_state(s, RX_SUSPENDED);
>>>>>>> 7c53cea43c (hw/net/i82596.c: Fixing the RX function for 82596)
        return sz;
    }
    
    /* Update SCB to point to next RFD */
    if (s->rx_status == RX_READY) {
        set_uint32(s->scb + 8, next_rfd);
    }
    
    s->scb_status |= SCB_STATUS_FR; /* set "RU finished receiving frame" bit. */
<<<<<<< HEAD
    s->rcvd_frames++;
    update_scb_status(s);
    s->last_irq_time = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);


    /* send IRQ that we received data */
    qemu_set_irq(s->irq, 1);
    /* s->send_irq = 1; */
=======
    i82596_update_int(s, true);
    
    return sz;
}


static int i82596_process_simplified_mode(I82596State *s, uint32_t rfd_p, uint32_t next_rfd,
    const uint8_t *cur_buf_ptr, uint8_t *crc_ptr,
    size_t *len, size_t *bufsz, uint16_t *status)
{
    uint32_t rfd_size, data_offset;
    size_t remaining = *len;
    const uint8_t *data_ptr = cur_buf_ptr;
    uint32_t current_rfd = rfd_p;
    uint16_t rfd_status = 0;
    
    printf("------ SIMPLIFIED MODE PROCESSING ------\n");
    printf("RFD address: 0x%08x\n", rfd_p);
    


    /* Set busy status while processing */
    set_uint16(rfd_p, STAT_B);

    while (remaining > 0 && current_rfd && current_rfd != I596_NULL) {
        /* Get RFD size (available data space) */
        rfd_size = get_uint16(current_rfd + 12); /* Size field in RFD */
        printf("RFD size: %d\n", rfd_size);
        data_offset = 24; /* After STATUS(2), CMD(2), LINK(4), RBD(4), SIZE(2), COUNT(2), DEST(6), SRC(6), TYPE(2) */
        
        /* In Simplified mode, data area starts at offset 28 (after all header fields) */
        printf("RFD data area: 0x%08x\n", current_rfd + data_offset);
        
        uint32_t rfd_count = (remaining > rfd_size) ? rfd_size : remaining;
        printf("Bytes to copy to this RFD: %d\n", rfd_count);
        
        /* Copy data directly to RFD data area */
        if (rfd_count > 0 && *bufsz > 0) {
            uint32_t data_bytes = (*bufsz > rfd_count) ? rfd_count : *bufsz;
            printf("Writing %d bytes from packet to RFD\n", data_bytes);
            
            address_space_write(&address_space_memory, current_rfd + data_offset,
                              MEMTXATTRS_UNSPECIFIED, data_ptr, data_bytes);
            data_ptr += data_bytes;
            *bufsz -= data_bytes;
            remaining -= data_bytes;
            
            /* If we have CRC data to write and room in this RFD */
            if (remaining > 0 && data_bytes < rfd_count) {
                uint32_t crc_bytes = rfd_count - data_bytes;
                if (crc_bytes > remaining) {
                    crc_bytes = remaining;
                }
                
                printf("Writing %d bytes of CRC to RFD\n", crc_bytes);
                address_space_write(&address_space_memory, current_rfd + data_offset + data_bytes,
                                  MEMTXATTRS_UNSPECIFIED, crc_ptr, crc_bytes);
                crc_ptr += crc_bytes;
                remaining -= crc_bytes;
            }
            
            /* Set actual count */
            set_uint16(current_rfd + 14, rfd_count);
        }

        /* Check for truncation as per documentation */
        if (remaining > 0 && (get_uint32(current_rfd + 4) == I596_NULL || \
        get_uint32(current_rfd + 4) == 0)) {
            printf("Frame truncation detected - no more RFDs available\n");
        
            /* Use the new error recording function */
            i82596_record_error(s, RFD_STATUS_TRUNC | RFD_STATUS_NOBUFS);
            
            /* Mark frame truncated in status */
            rfd_status |= RFD_STATUS_TRUNC | RFD_STATUS_NOBUFS;
            
            /* Set receiver to No Resources state */
            i82596_update_rx_state(s, RX_NO_RESOURCES);
            
            break;
        }

        /* If we processed all data, set EOF */
        if (remaining == 0) {
            printf("All data processed, setting EOF on this RFD\n");
            rfd_status |= I596_EOF;
        }

        /* In simplified mode, if we can't fit all data in one RFD, truncate the frame */
        if (remaining > 0) {
            printf("Frame truncation in simplified mode - frame larger than RFD\n");
            i82596_record_error(s, RFD_STATUS_TRUNC | RFD_STATUS_NOBUFS);
            rfd_status |= RFD_STATUS_TRUNC | RFD_STATUS_NOBUFS;

            /* If not configured to save bad frames, prepare RFD for reuse */
            if (!SAVE_BAD_FRAMES) {
                /* Reset the RFD for reuse */
                set_uint16(rfd_p, 0); /* Clear status */
            }
        } else {
            break;
        }
    }

    /* Update the status output parameter */
    *status = rfd_status;
    
    printf("Simplified mode processing complete\n");
    printf("Remaining len: %zu\n", remaining);
    *len = remaining;
    
    return 0;
}

static int i82596_process_flexible_mode(I82596State *s, uint32_t rfd_p, uint32_t next_rfd,
    const uint8_t *cur_buf_ptr, uint8_t *crc_ptr,
    size_t *len, size_t *bufsz, uint16_t *status)
{
    printf("------ FLEXIBLE MODE PROCESSING ------\n");
 
    uint32_t rbd;
    uint32_t last_used_rbd = I596_NULL;

    uint16_t rfd_size = get_uint16(rfd_p + 12);
    uint32_t rfd_data_addr = rfd_p + 16; /* RFD data area after header */
    
    printf("RFD pointer: 0x%08x\n", rfd_p);
    printf("RFD size: %d\n", rfd_size);
    printf("RFD data area: 0x%08x\n", rfd_data_addr);
    
    /* Get first RBD pointer */
    rbd = get_uint32(rfd_p + 8);
    printf("First RBD pointer: 0x%08x\n", rbd);
    printf("Initial data len: %zu, initial bufsz: %zu\n", *len, *bufsz);
    
    /* Set RFD as busy while processing */
    set_uint16(rfd_p, STAT_B);
    
    /* Check if we have valid RBD */
    if (rbd == I596_NULL) {
        printf("No valid RBD, marking RX_NO_RESOURCES\n");
        
        /* Use new structured state update approach */
        i82596_update_rx_state(s, RX_NO_RESO_RBD);
        
        /* Record the error properly */
        i82596_record_error(s, RFD_STATUS_NOBUFS);
        
        *status |= RX_NO_RESO_RBD;
        return -1;
    }
    
    /* If RFD has data area and we have data, check if it all fits in RFD */
    if (rfd_size > 0 && *len <= rfd_size) {
        printf("All data fits in RFD data area\n");
        
        /* Write packet data to RFD */
        uint16_t data_bytes = *bufsz;
        printf("Writing %d bytes of packet data to RFD\n", data_bytes);
        address_space_write(&address_space_memory, rfd_data_addr,
                          MEMTXATTRS_UNSPECIFIED, cur_buf_ptr, data_bytes);
        
        /* Write CRC to RFD after data */
        printf("Writing 4 bytes of CRC to RFD\n");
        address_space_write(&address_space_memory, rfd_data_addr + data_bytes,
                          MEMTXATTRS_UNSPECIFIED, crc_ptr, 4);
        
        /* All data handled in RFD, set EOF */
        *status |= I596_EOF;
        *len = 0;
        *bufsz = 0;
        
        /* Clear RFD's rbd pointer after processing */
        set_uint32(rfd_p + 8, I596_NULL);
        
        printf("All data processed in RFD, no RBDs used\n");
        return 0;
    }
    
    /* If RFD has data area, use it for initial packet data */
    if (rfd_size > 0 && *len > 0) {
        /* Use buffer boundary check for safety */
        uint16_t rfd_data_used = i82596_buffer_boundary_check(rfd_size, 0, *bufsz);
        printf("Writing %d bytes to RFD data area\n", rfd_data_used);
        
        address_space_write(&address_space_memory, rfd_data_addr,
                          MEMTXATTRS_UNSPECIFIED, cur_buf_ptr, rfd_data_used);
        cur_buf_ptr += rfd_data_used;
        *bufsz -= rfd_data_used;
        *len -= rfd_data_used;
        
        printf("After RFD: remaining buffer: %zu, remaining len: %zu\n", *bufsz, *len);
    }
    
    /* Process RBD chain */
    int rbd_count = 0;
    
    while (*len > 0 && rbd != I596_NULL) {
        uint16_t buffer_size = get_uint16(rbd + 12) & SIZE_MASK;
        uint32_t rba = get_uint32(rbd + 8);
        uint32_t next_rbd = get_uint32(rbd + 4);
        uint16_t rbd_status = 0;
        uint16_t used = 0;
        
        rbd_count++;
        printf("Processing RBD #%d at 0x%08x, buffer size: %u, data addr: 0x%08x\n", 
              rbd_count, rbd, buffer_size, rba);
        
        /* Skip zero-sized buffers */
        if (buffer_size == 0) {
            printf("Zero buffer size, skipping\n");
            rbd = next_rbd;
            continue;
        }
        
        /* Process this RBD buffer fully */
        while (used < buffer_size && *len > 0) {
            /* Copy as much data as fits from remaining packet data */
            if (*bufsz > 0) {
                uint16_t to_copy = i82596_buffer_boundary_check(buffer_size, used, *bufsz);

                printf("Writing %d bytes of packet data to RBD\n", to_copy);
                address_space_write(&address_space_memory, rba + used,
                                  MEMTXATTRS_UNSPECIFIED, cur_buf_ptr, to_copy);
                cur_buf_ptr += to_copy;
                used += to_copy;
                *bufsz -= to_copy;
                *len -= to_copy;
                
                printf("Remaining buffer: %zu, remaining len: %zu\n", *bufsz, *len);
                
                /* If we filled the buffer or used all data, continue to next buffer */
                if (used >= buffer_size || *len == 0) {
                    break;
                }
            }

            /* If there is still space, copy CRC if any left */
            if (used < buffer_size && *len > 0 && *bufsz == 0) {
                /* Use buffer boundary check function for safer sizing */
                uint16_t crc_bytes = i82596_buffer_boundary_check(buffer_size, used, *len);
                printf("Writing %d bytes of CRC to RBD\n", crc_bytes);

                address_space_write(&address_space_memory, rba + used,
                                  MEMTXATTRS_UNSPECIFIED, crc_ptr, crc_bytes);
                crc_ptr += crc_bytes;
                used += crc_bytes;
                *len -= crc_bytes;
                
                printf("Remaining len after CRC: %zu\n", *len);
            }
        }
        
        /* Set status and flags for this RBD */
        rbd_status = used;

        /* Set EOF if this is the last buffer - use the bit position Linux expects */
        if (*len == 0 || next_rbd == I596_NULL) {
            printf("All data processed, setting EOF on this RBD\n");
            rbd_status |= 0x4000;  /* This is what Linux checks for EOF (not I596_EOF) */
        }        
        /* Set EOF if this is the last buffer */
        if (*len == 0) {
            printf("All data processed, setting EOF on this RBD\n");
            rbd_status |= I596_EOF;
        } else if (next_rbd == I596_NULL) {
            printf("Last RBD, no more buffers, setting EOF\n");
            rbd_status |= I596_EOF;
        }
        
        set_uint16(rbd, rbd_status);
        last_used_rbd = rbd;
        rbd = next_rbd;
        
        /* Handle buffer overrun */
        if (*len > 0 && rbd == I596_NULL) {
            printf("Data left but no more RBDs: Buffer overrun!\n");

            /* Use structured state management */
            i82596_update_rx_state(s, RX_NO_RESOURCES);

            /* Add frame truncated and no buffers flags to status */
            *status |= RFD_STATUS_TRUNC | RFD_STATUS_NOBUFS;

            /* Use error recording function instead of direct counter update */
            i82596_record_error(s, RFD_STATUS_TRUNC | RFD_STATUS_NOBUFS);

            /* Set EOF on last used RBD */
            if (last_used_rbd != I596_NULL) {
                uint16_t last_status = get_uint16(last_used_rbd);
                last_status |= 0x4000;  /* Use correct EOF bit for Linux driver */
                set_uint16(last_used_rbd, last_status);
            } else {
                *status |= 0x4000;  /* Use correct EOF bit for Linux driver */
            }

            /* Use consistent interrupt management */
            i82596_update_int(s, false);
        }
    }
    
    printf("RBD chain processing done, RBDs used: %d\n", rbd_count);
    printf("Remaining len: %zu\n", *len);
    
    /* Clear RFD rbd pointer after processing */
    set_uint32(rfd_p + 8, I596_NULL);
    
    /* Update next RFD's rbd pointer if needed */
    if (next_rfd != I596_NULL && next_rfd != 0) {
        if (rbd != I596_NULL) {
            printf("Updating next RFD 0x%08x to point to remaining RBD 0x%08x\n", 
                   next_rfd, rbd);
            set_uint32(next_rfd + 8, rbd);
        } else {
            printf("Next RFD 0x%08x has no RBDs left, set NULL\n", next_rfd);
            set_uint32(next_rfd + 8, I596_NULL);
        }
    }
    
    printf("Final RFD status: 0x%04x\n", *status);
    return 0;
}

ssize_t i82596_receive(NetClientState *nc, const uint8_t *buf, size_t sz)
{
    I82596State *s = qemu_get_nic_opaque(nc);
    uint32_t rfd_p, next_rfd;
    uint16_t command, is_broadcast = 0, status = 0;
    size_t len = sz; /* length of data for guest (including CRC) */
    size_t bufsz = sz; /* length of data in buf */
    uint32_t crc;
    uint8_t *crc_ptr;
    const uint8_t *cur_buf_ptr;
    bool sf_bit;
    int result;

    printf("====== i82596_receive() START ======\n");
    printf("Packet size: %zu bytes\n", sz);
    printf("RX status: %d\n", s->rx_status);
    printf("Link state: %04x\n", s->lnkst);

    if (!i82596_validate_receive_state(s, &sz, &bufsz, &len)) {
        printf("ERROR: Invalid RX state, rejecting packet\n");
        return -1;
    }

    if (!i82596_check_packet_filter(s, buf, &is_broadcast)) {
        printf("Packet rejected by filter\n");
        return sz;
    }
>>>>>>> 7c53cea43c (hw/net/i82596.c: Fixing the RX function for 82596)

    printf("Packet passed filters, is_broadcast=%d\n", is_broadcast);

    rfd_p = get_uint32(s->scb + 8); /* get Receive Frame Descriptor */
    printf("Initial RFD pointer: 0x%08x\n", rfd_p);

    if (!rfd_p || rfd_p == I596_NULL) {
        printf("ERROR: No valid RFD pointer (rfd_p=%08x)\n", rfd_p);
        return sz; /* Can't proceed without a valid RFD */
    }

    command = get_uint16(rfd_p + 2);
    printf("RFD command: 0x%04x\n", command);
    
    sf_bit = ((command >> 3) & 1);
    printf("SF bit: %d (%s mode)\n", sf_bit, sf_bit ? "Flexible" : "Simplified");
    
    /* Calculate the ethernet checksum */
    len += 4;
    crc = cpu_to_be32(crc32(~0, buf, sz));
    crc_ptr = (uint8_t *) &crc;
    cur_buf_ptr = buf;
    printf("Data length with CRC: %zu\n", len);
    printf("CRC value: %08x\n", crc);
    
    next_rfd = get_uint32(rfd_p + 4);
    printf("Next RFD pointer: 0x%08x\n", next_rfd);
    
    if (!sf_bit) { /* Simplified Mode Memory Structure */
        printf("Processing in SIMPLIFIED mode\n");
        result = i82596_process_simplified_mode(s, rfd_p, next_rfd, cur_buf_ptr, 
                                             crc_ptr, &len, &bufsz, &status);
        printf("Simplified mode result: %d, remaining len=%zu, status=0x%04x\n", 
               result, len, status);
        if (result < 0) {
            printf("ERROR: Simplified mode processing failed\n");
            return -1;
        }
    } else {
        printf("Processing in FLEXIBLE mode\n");
        result = i82596_process_flexible_mode(s, rfd_p, next_rfd, cur_buf_ptr, 
                                           crc_ptr, &len, &bufsz, &status);
        printf("Flexible mode result: %d, remaining len=%zu, status=0x%04x\n", 
               result, len, status);
        if (result < 0) {
            printf("ERROR: Flexible mode processing failed\n");
            return -1;
        }
    }

    printf("Calling finalize_reception with status=0x%04x\n", status);
    ssize_t ret = i82596_finalize_reception(s, rfd_p, status, command, next_rfd, is_broadcast, sz);
    printf("====== i82596_receive() END - returned %zd ======\n\n", ret);
    return ret;
}

const VMStateDescription vmstate_i82596 = {
    .name = "i82596",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT16(lnkst, I82596State),
        VMSTATE_TIMER_PTR(flush_queue_timer, I82596State),
        VMSTATE_END_OF_LIST()
    }
};

void i82596_common_init(DeviceState *dev, I82596State *s, NetClientInfo *info)
{
    if (s->conf.macaddr.a[0] == 0) {
        qemu_macaddr_default_if_unset(&s->conf.macaddr);
    }
    s->nic = qemu_new_nic(info, &s->conf, object_get_typename(OBJECT(dev)),
                dev->id, &dev->mem_reentrancy_guard, s);
    qemu_format_nic_info_str(qemu_get_queue(s->nic), s->conf.macaddr.a);

    if (USE_TIMER) {
        s->flush_queue_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                    i82596_flush_queue_timer, s);
    }
    s->lnkst = 0x8000; /* initial link state: up */
}
