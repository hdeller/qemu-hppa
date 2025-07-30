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

#define ENABLE_DEBUG    1
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
#define I82596_SPEED_MBPS    10
#define I82596_BYTES_PER_SEC (I82596_SPEED_MBPS * 1000000 / 8)



#define I596_NULL       ((uint32_t)0xffffffff)


#define SCB_STATUS_CX   0x8000 /* CU finished command with I bit */
#define SCB_STATUS_FR   0x4000 /* RU finished receiving a frame */
#define SCB_STATUS_CNA  0x2000 /* CU left active state */
#define SCB_STATUS_RNR  0x1000 /* RU left active state */

#define SCB_COMMAND_ACK_MASK \
(SCB_STATUS_CX | SCB_STATUS_FR | SCB_STATUS_CNA | SCB_STATUS_RNR)

#define I82586_MODE                 0x00
#define I82596_MODE_SEGMENTED       0x01
#define I82596_MODE_LINEAR          0x02

/* SCB commands - Command Unit (CU) */
#define SCB_CUC_NOP            0x00
#define SCB_CUC_START          0x01
#define SCB_CUC_RESUME         0x02
#define SCB_CUC_SUSPEND        0x03
#define SCB_CUC_ABORT          0x04
#define SCB_CUC_LOAD_THROTTLE  0x05
#define SCB_CUC_LOAD_START     0x06

/* SCB commands - Receive Unit (RU) */
#define SCB_RUC_NOP            0x00
#define SCB_RUC_START          0x01
#define SCB_RUC_RESUME         0x02
#define SCB_RUC_SUSPEND        0x03
#define SCB_RUC_ABORT          0x04

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
#define I596_FULL_DUPLEX    (s->config[12] & 0x40)  /* full duplex mode */
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

static inline uint32_t i82596_translate_address(I82596State *s, uint32_t addr, bool is_data_buffer)
{
    if (addr == I596_NULL || addr == 0) {
        return addr;
    }

    switch (s->mode) {
    case I82586_MODE:
        /* 82586 Mode */
        if (is_data_buffer) {
            /* ISCP Address, Rx Buffers, Tx Buffers: 24-bit linear */
            return addr & 0x00FFFFFF;
        } else {
            /* Command Block Pointers, Descriptors: Base (24) + Offset (16) */
            if (s->scb_base) {
                return (s->scb_base & 0x00FFFFFF) + (addr & 0xFFFF);
            } else {
                /* If no base set, treat as 24-bit linear */
                return addr & 0x00FFFFFF;
            }
        }

    case I82596_MODE_SEGMENTED:
        /* 32-bit Segmented Mode */
        if (is_data_buffer) {
            /* ISCP Address, Rx Buffers, Tx Buffers: 32-bit linear */
            return addr;
        } else {
            /* Command Block Pointers, Descriptors: Base (32) + Offset (16) */
            if (s->scb_base) {
                return s->scb_base + (addr & 0xFFFF);
            } else {
                return addr;
            }
        }

    case I82596_MODE_LINEAR:
    default:
        /* 32-bit Linear Mode - all addresses are 32-bit linear */
        return addr;
    }
}

static void i82596_transmit(I82596State *s, uint32_t addr)
{
    uint32_t tbd_p; /* Transmit Buffer Descriptor */
    uint16_t cmd;
    uint16_t tcb_bytes = 0;
    uint16_t tx_data_len = 0;
    int insert_crc;


    if (!s->throttle_state && !I596_FULL_DUPLEX) {
        /* In half duplex mode, defer transmission until throttle is on */
        DBG(printf("TX COLLISION: Half duplex collision detected, deferring transmission\n"));
        timer_mod(s->flush_queue_timer,
                 qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + 10);
        return;
    }
    cmd = get_uint16(addr + 2);
    assert(cmd & CMD_FLEX);    /* check flexible mode */

    /* Get TBD pointer */
    tbd_p = get_uint32(addr + 8);
    tbd_p = i82596_translate_address(s, tbd_p, false);
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
            tba = i82596_translate_address(s, tba, true);  /* true for data buffer */


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
            tbd_p = i82596_translate_address(s, tbd_p, false);
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

static void i82596_bus_throttle_timer(void *opaque)
{
    I82596State *s = opaque;

    if (s->cu_status != CU_ACTIVE) {
        timer_del(s->throttle_timer);
        return;
    }

    if (s->throttle_state) {
        /* Currently ON, switch to OFF */
        DBG(printf("THROTTLE: Switching from ON to OFF (duplex=%s)\n",
                   I596_FULL_DUPLEX ? "full" : "half"));
        s->throttle_state = false;

        if (s->t_off > 0) {
            /* Add jitter for half duplex to simulate CSMA/CD randomness */
            int delay = s->t_off;
            if (!I596_FULL_DUPLEX && s->t_off > 10) {
                int jitter = s->t_off / 5;
                int actual_jitter = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) % jitter;
                delay += actual_jitter;
                DBG(printf("THROTTLE: Half-duplex jitter added: %d microseconds\n",
                           actual_jitter));
            }

            timer_mod(s->throttle_timer,
                     qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) +
                     delay * 1000);
            DBG(printf("THROTTLE: OFF for %d microseconds\n", delay));
        } else {
            s->throttle_state = true;
            DBG(printf("THROTTLE: No OFF time specified, staying ON\n"));
        }
    } else {
        DBG(printf("THROTTLE: Switching from OFF to ON (duplex=%s)\n",
                   I596_FULL_DUPLEX ? "full" : "half"));
        s->throttle_state = true;

        if (s->t_on > 0 && s->t_on != 0xFFFF) {
            timer_mod(s->throttle_timer,
                     qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) +
                     s->t_on * 1000);
            DBG(printf("THROTTLE: ON for %d microseconds\n", s->t_on));
        } else {
            DBG(printf("THROTTLE: Staying ON indefinitely (t_on=%d)\n", s->t_on));
        }
    }
}

static void i82596_load_throttle_timers(I82596State *s, bool start_now)
{
    uint32_t t_on_addr, t_off_addr;

    /* Get previous values for comparison */
    uint16_t prev_t_on = s->t_on;
    uint16_t prev_t_off = s->t_off;

    /* TODO: Change offset based on the Linear or Segmented mode */
    t_on_addr = s->scb + 0x1E;
    t_off_addr = s->scb + 0x20;

    /* Read T-ON and T-OFF values */
    s->t_on = get_uint16(t_on_addr);
    s->t_off = get_uint16(t_off_addr);

    if (!I596_FULL_DUPLEX) {
        /* If t_on is zero or too low, use a reasonable default for half-duplex */
        if (s->t_on < 500) {
            /* ~1200μs corresponds to standard 1500 byte packet at 10Mbps */
            s->t_on = 1200;
            /* Write back to SCB memory */
            set_uint16(t_on_addr, s->t_on);
        }

        /* Ensure t_off is at least 20% of t_on for collision detection */
        if (s->t_off < (s->t_on / 10)) {
            s->t_off = s->t_on / 5;  /* 20% off time */
            set_uint16(t_off_addr, s->t_off);
        }
    } else {
        /* For full-duplex mode, we can have shorter off time */
        if (s->t_on < 100) {
            s->t_on = 1000;  /* Still need some throttling for 10Mbps */
            set_uint16(t_on_addr, s->t_on);
        }
    }

    if (prev_t_on != s->t_on || prev_t_off != s->t_off) {
        DBG(printf("THROTTLE PARAMS: Changed from ON=%d,OFF=%d to ON=%d,OFF=%d\n",
                   prev_t_on, prev_t_off, s->t_on, s->t_off));
    }

    DBG(printf("THROTTLE LOAD: T-ON=%d, T-OFF=%d, start=%d, duplex=%s\n",
               s->t_on, s->t_off, start_now, I596_FULL_DUPLEX ? "full" : "half"));

    if (start_now) {
        if (!s->throttle_timer) {
            s->throttle_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                           i82596_bus_throttle_timer, s);
            DBG(printf("THROTTLE: Created new timer\n"));
        } else {
            timer_del(s->throttle_timer);
            DBG(printf("THROTTLE: Deleted existing timer\n"));
        }

        /* Start with the bus ON */
        s->throttle_state = true;
        DBG(printf("THROTTLE: Starting with state ON\n"));

        /* Schedule the T-ON timer if not infinite */
        if (s->t_on > 0 && s->t_on != 0xFFFF) {
            timer_mod(s->throttle_timer,
                      qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) +
                      s->t_on * 1000);
            DBG(printf("THROTTLE: Scheduled ON timer for %d microseconds\n", s->t_on));
        } else {
            DBG(printf("THROTTLE: No timer scheduled (t_on=%d)\n", s->t_on));
        }
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

    /* Preserve full duplex bit in config[12] - the OS will set this correctly */
    if (byte_cnt > 12) {
        s->config[12] &= 0x40; /* Preserve only full duplex bit */
        DBG(printf("Full duplex mode: %s\n", I596_FULL_DUPLEX ? "ON" : "OFF"));
    }

    s->config[13] |= 0x3f; /* set ones in byte 13 */

    /* Configure throttling parameters to enforce 10Mbps speed limit */
    if (byte_cnt > 12) {
        bool previous_duplex = I596_FULL_DUPLEX;
        s->config[12] &= 0x40; /* Preserve only full duplex bit */

        if (previous_duplex != I596_FULL_DUPLEX) {
            DBG(printf("DUPLEX: Mode changed to %s duplex\n",
                       I596_FULL_DUPLEX ? "FULL" : "HALF"));
        }
        DBG(printf("DUPLEX: Current mode is %s\n", I596_FULL_DUPLEX ? "FULL" : "HALF"));
    }

    /* Configure throttling parameters to enforce 10Mbps speed limit */
    bool duplex_changed = false;
    static bool last_duplex_state = false;

    if (byte_cnt > 12) {
        duplex_changed = ((I596_FULL_DUPLEX) != last_duplex_state);
        if (duplex_changed) {
            DBG(printf("DUPLEX: State transition from %s to %s\n",
                       last_duplex_state ? "FULL" : "HALF",
                       I596_FULL_DUPLEX ? "FULL" : "HALF"));
        }
        last_duplex_state = I596_FULL_DUPLEX;
    }

    /* Only update throttle parameters if they haven't been set or duplex mode changed */
    if (s->t_on == 0xFFFF || duplex_changed) {
        /* Calculate throttling parameters for 10Mbps */
        uint32_t bytes_per_us = I82596_BYTES_PER_SEC / 1000000;
        uint16_t packet_time_us;

        /* Standard 1500 byte packet at 10Mbps takes ~1.2ms */
        packet_time_us = 1500 / bytes_per_us; /* ~1200μs at 10Mbps */

        if (I596_FULL_DUPLEX) {
            /* Full duplex: less throttling needed */
            s->t_on = packet_time_us * 5;
            s->t_off = packet_time_us / 20; /* Very short off time */
            DBG(printf("THROTTLE CONFIG: Full duplex - ON=%d, OFF=%d microseconds\n",
                      s->t_on, s->t_off));
        } else {
            /* Half duplex: more throttling to simulate collisions and CSMA/CD */
            s->t_on = packet_time_us;
            s->t_off = packet_time_us / 5; /* 20% off time */
            DBG(printf("THROTTLE CONFIG: Half duplex - ON=%d, OFF=%d microseconds\n",
                      s->t_on, s->t_off));
        }

        /* Start throttling with new parameters */
        i82596_load_throttle_timers(s, true);
    }

    if (s->rx_status == RX_READY) {
        timer_mod(s->flush_queue_timer,
                qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + 100);
    }
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

static void set_rdt(I82596State *s, uint32_t rfd_p)
{
    /* Schedule with medium delay after descriptor update */
    if (s->rx_status == RX_READY) {
        timer_mod(s->flush_queue_timer,
                 qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + 10);
    }
}

void i82596_set_link_status(NetClientState *nc)
{
    I82596State *s = qemu_get_nic_opaque(nc);
    bool was_up = s->lnkst != 0;

    s->lnkst = nc->link_down ? 0 : 0x8000;
    bool is_up = s->lnkst != 0;

    if (!was_up && is_up && s->rx_status == RX_READY) {
        qemu_flush_queued_packets(qemu_get_queue(s->nic));
    }
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
    s->scp = 0x00FFFFF4; /* SCB pointer */
    s->scb_status = 0;
    s->cu_status = CU_IDLE;
    s->rx_status = RX_IDLE;
    s->cmd_p = I596_NULL;
    s->lnkst = 0x8000; /* initial link state: up */
    s->ca = s->ca_active = 0;
    s->send_irq = 0;

    s->t_on = 0xFFFF; /* Infinite T-ON */
    s->t_off = 0;     /* No idle phase */
    s->throttle_state = true; /* Bus "ON" by default after reset */

    /* Stop throttle timer instead of starting it */
    if (s->throttle_timer) {
        timer_del(s->throttle_timer);
    }

    /* Stop the flush queue timer */
    if (s->flush_queue_timer) {
        timer_del(s->flush_queue_timer);
    }
}

static void command_loop(I82596State *s)
{
    uint16_t cmd, status;
    uint32_t next_cmd_addr;

    DBG(printf("STARTING COMMAND LOOP cmd_p=%08x\n", s->cmd_p));

    while (s->cmd_p != I596_NULL && s->cmd_p != 0 && s->cu_status == CU_ACTIVE) {
        /* To prevent overrlaps,
         * Check if command is already in progress or completed
         */
        status = get_uint16(s->cmd_p);
        if (status & (STAT_C | STAT_B)) {
            /* Command already busy or complete, move to next command */
            next_cmd_addr = get_uint32(s->cmd_p + 4);
            if (next_cmd_addr == 0 || next_cmd_addr == s->cmd_p) {
                s->cmd_p = I596_NULL;
                s->cu_status = CU_IDLE;
                s->scb_status |= SCB_STATUS_CNA;
                break;
            }
            s->cmd_p = next_cmd_addr;
            continue;
        }

        /* Mark command as busy */
        status = STAT_B;
        set_uint16(s->cmd_p, status);

        /* Prepare completed status but write later */
        status = STAT_C | STAT_OK;

        /* Get command word */
        cmd = get_uint16(s->cmd_p + 2);
        DBG(printf("Running command %04x at %08x\n", cmd, s->cmd_p));

        next_cmd_addr = get_uint32(s->cmd_p + 4);
        if (next_cmd_addr == 0) {
            next_cmd_addr = I596_NULL;
        } else {
            next_cmd_addr = i82596_translate_address(s, next_cmd_addr, false);
        }

        /* Execute command based on type */
        switch (cmd & 0x07) {
        case CmdNOp:
            /* No operation */
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
            DBG(printf("Dumped statistics to memory at %08x\n", s->cmd_p + 8));
            break;

        case CmdDiagnose:
            printf("Command Diagnose not implemented\n");
            status = STAT_C; /* Completed but not OK */
            break;
        }

        /* Update command status */
        set_uint16(s->cmd_p, status);

        /* Process command control flags */
        bool end_processing = false;

        /* Interrupt after doing cmd? */
        if (cmd & CMD_INTR) {
            s->scb_status |= SCB_STATUS_CX;
            s->send_irq = 1;
        } else {
            s->scb_status &= ~SCB_STATUS_CX;
        }

        /* Suspend after doing cmd? */
        if (cmd & CMD_SUSP) {
            s->cu_status = CU_SUSPENDED;
            s->scb_status |= SCB_STATUS_CNA;
            end_processing = true;
        }

        /* End of list? */
        if (cmd & CMD_EOL) {
            s->cmd_p = I596_NULL;
            s->cu_status = CU_IDLE;
            s->scb_status |= SCB_STATUS_CNA;
            end_processing = true;
        } else {
            /* Move to next command */
            if (next_cmd_addr == s->cmd_p) {
                /* Circular reference, stop processing */
                s->cmd_p = I596_NULL;
                s->cu_status = CU_IDLE;
                s->scb_status |= SCB_STATUS_CNA;
                end_processing = true;
            } else {
                s->cmd_p = next_cmd_addr;
            }
        }

        update_scb_status(s);

        if (end_processing || s->cu_status != CU_ACTIVE) {
            break;
        }
    }

    update_scb_status(s);

    if (s->rx_status == RX_READY) {
        qemu_flush_queued_packets(qemu_get_queue(s->nic));
    }
}

static void i82596_flush_queue_timer(void *opaque)
{
    I82596State *s = opaque;
    if (s->rx_status == RX_READY) {
        qemu_flush_queued_packets(qemu_get_queue(s->nic));
    }
}

static void examine_scb(I82596State *s)
{
    uint16_t command, cuc, ruc;

    /* Get the SCB command word */
    command = get_uint16(s->scb + 2);
    cuc = (command >> 8) & 0x7; /* Command Unit Command */
    ruc = (command >> 4) & 0x7; /* Receive Unit Command */
    DBG(printf("MAIN COMMAND %04x  cuc %02x ruc %02x\n", command, cuc, ruc));

    /* Clear the SCB command word */
    set_uint16(s->scb + 2, 0);

    /* Handle interrupt acknowledgment */
    s->scb_status &= ~(command & SCB_COMMAND_ACK_MASK);

    /* Process Command Unit Command */
    switch (cuc) {
    case SCB_CUC_NOP:
        /* No operation */
        break;

    case SCB_CUC_START:
        /* Start Command Unit */
        s->cu_status = CU_ACTIVE;
        /* Set the command pointer from SCB */
        uint32_t cmd_ptr = get_uint32(s->scb + 4);
        s->cmd_p = i82596_translate_address(s, cmd_ptr, false);
        break;

    case SCB_CUC_RESUME:
        /* Resume Command Unit */
        if (s->cu_status == CU_SUSPENDED) {
            s->cu_status = CU_ACTIVE;
        }
        break;

    case SCB_CUC_SUSPEND:
        /* Suspend Command Unit */
        s->cu_status = CU_SUSPENDED;
        s->scb_status |= SCB_STATUS_CNA;
        break;

    case SCB_CUC_ABORT:
        /* Abort Command Unit */
        s->cu_status = CU_IDLE;
        s->scb_status |= SCB_STATUS_CNA;
        break;

    case SCB_CUC_LOAD_THROTTLE:
        bool external_trigger = (s->sysbus & 0x01);
        i82596_load_throttle_timers(s, !external_trigger);
        break;

    case SCB_CUC_LOAD_START:
        i82596_load_throttle_timers(s, true);
        break;
    }

    /* Process Receive Unit Command */
    switch (ruc) {
    case SCB_RUC_NOP:
        /* No operation */
        break;
    case SCB_RUC_START:
        s->rx_status = RX_READY;
        uint32_t rfd = get_uint32(s->scb + 8);
        rfd = i82596_translate_address(s, rfd, false);
        if (rfd == 0 || rfd == I596_NULL) {
            s->rx_status = RX_NO_RESOURCES;
            s->scb_status |= SCB_STATUS_RNR;
        } else {
            set_rdt(s, rfd);
        }
        break;

    case SCB_RUC_RESUME:
        /* Resume Receive Unit */
        if (s->rx_status == RX_SUSPENDED) {
            s->rx_status = RX_READY;
            timer_mod(s->flush_queue_timer,
                     qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + 10);
        }
        break;

    case SCB_RUC_SUSPEND:
        /* Suspend Receive Unit */
        s->rx_status = RX_SUSPENDED;
        s->scb_status |= SCB_STATUS_RNR;
        /* Stop the flush timer when suspended */
        timer_del(s->flush_queue_timer);
        break;

    case SCB_RUC_ABORT:
        /* Abort Receive Unit */
        s->rx_status = RX_IDLE;
        s->scb_status |= SCB_STATUS_RNR;
        /* Stop the flush timer when aborted */
        timer_del(s->flush_queue_timer);
        break;
    }

    /* Check for software reset */
    if (command & 0x80) {
        i82596_s_reset(s);
    } else {
        /* Execute commands if CU is active and not already processing commands */
        if (s->cu_status == CU_ACTIVE) {
            if (s->cmd_p == I596_NULL) {
                s->cmd_p = get_uint32(s->scb + 4);
            }
            /* Update SCB status */
            update_scb_status(s);

            /* Process any pending commands */
            command_loop(s);
        } else {
            /* Just update SCB status */
            update_scb_status(s);
        }
    }
}

static void signal_ca(I82596State *s)
{
    uint32_t iscp = 0;

    /* trace_i82596_channel_attention(s); */
    if (s->scp) {
        /* CA after reset -> do init with new scp. */
        s->sysbus = get_byte(s->scp + 3); /* big endian */
        DBG(printf("SYSBUS = %02x\n", s->sysbus));
        s->mode = (s->sysbus >> 1) & 0x03; /* m0 & m1 */

        DBG(printf("Mode set to %d (%s)\n", s->mode,
               s->mode == I82586_MODE ? "82586" :
               s->mode == I82596_MODE_SEGMENTED ? "32-bit Segmented" :
               s->mode == I82596_MODE_LINEAR ? "32-bit Linear" : "Unknown"));

        if (s->mode != I82586_MODE &&
            s->mode != I82596_MODE_SEGMENTED &&
            s->mode != I82596_MODE_LINEAR) {
            /* Unsupported mode */
            fprintf(stderr, "Unsupported i82596 mode: %d\n", s->mode);
            return;
        }

        /* Get ISCP address - always a linear address regardless of mode */
        iscp = get_uint32(s->scp + 8);
        DBG(printf("ISCP address: 0x%08x\n", iscp));

        /* Get SCB address */
        s->scb = get_uint32(iscp + 4);

        /* In segmented modes, we need to get the base address as well */
        if (s->mode == I82586_MODE || s->mode == I82596_MODE_SEGMENTED) {
            s->scb_base = get_uint32(iscp + 8); /* Get SCB base */
            DBG(printf("SCB base set to 0x%08x\n", s->scb_base));
        } else {
            s->scb_base = 0;
        }

        /* If we're not in linear mode, translate the SCB address */
        if (s->mode != I82596_MODE_LINEAR) {
            s->scb = i82596_translate_address(s, s->scb, false);
            DBG(printf("Translated SCB address: 0x%08x\n", s->scb));
        }

        /* When was it busy? we never used the ISCP_BUSY var?? Clear BUSY flag in ISCP */
        set_byte(iscp + 1, 0);
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

uint32_t i82596_ioport_readw(void *opaque, uint32_t addr)
{
    return -1;
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
        if (s->scp){
            uint32_t iscp_addr = get_uint32(s->scp + 8);
            set_uint16(iscp_addr, ISCP_BUSY); /* Set busy flag */
            DBG(printf("ALTSCP: Set ISCP busy"));
        }
        break;
    case PORT_ALTDUMP:
        break;
    case PORT_CA:
        signal_ca(s);
        break;
    }
}


void i82596_h_reset(void *opaque)
{
    I82596State *s = opaque;

    i82596_s_reset(s);
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
    /* Similar to TULIP's tulip_update_int :) */
    update_scb_status(s);

    if (send_irq) {
        qemu_set_irq(s->irq, 1);
    }
}

/*
 * All RX FUNCTIONALITY BELOW
*/

bool i82596_can_receive(NetClientState *nc)
{
    I82596State *s = qemu_get_nic_opaque(nc);

    /* In full duplex, we can receive during transmission */
    if (!s->throttle_state && !I596_FULL_DUPLEX) {
        DBG(printf("CAN_RX: FALSE - throttle off in half duplex\n"));
        return false;
    }

    if (s->rx_status == RX_SUSPENDED) {
        DBG(printf("CAN_RX: FALSE - RX suspended\n"));
        return false;
    }

    if (!s->lnkst) {
        DBG(printf("CAN_RX: FALSE - Link down\n"));
        return false;
    }

    if (timer_pending(s->flush_queue_timer)) {
        bool can_rx = s->rx_status == RX_READY;
        DBG(printf("CAN_RX: %s - flush timer pending, rx_status=%d\n",
                  can_rx ? "TRUE" : "FALSE", s->rx_status));
        return can_rx;
    }

    DBG(printf("CAN_RX: TRUE - all conditions passed\n"));
    return true;
}

static void i82596_update_rx_state(I82596State *s, int new_state)
{
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

static ssize_t i82596_finalize_reception(I82596State *s, uint32_t rfd_p,
    uint16_t status, uint16_t command, uint32_t next_rfd, uint16_t is_broadcast,
    size_t sz)
{
    status |= STAT_C | STAT_OK | is_broadcast;
    set_uint16(rfd_p, status);

    if (command & CMD_SUSP) {  /* suspend after command? */
        i82596_update_rx_state(s, RX_SUSPENDED);
        return sz;
    }

    if (command & CMD_EOL) {   /* was it last Frame Descriptor? */
        i82596_update_rx_state(s, RX_SUSPENDED);
        return sz;
    }

    /* Update SCB to point to next RFD */
    if (s->rx_status == RX_READY) {
        set_uint32(s->scb + 8, next_rfd);
        /* Call set_rdt when updating the RFD pointer */
        set_rdt(s, next_rfd);
    }

    s->scb_status |= SCB_STATUS_FR; /* set "RU finished receiving frame" bit. */
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

    DBG(printf("------ SIMPLIFIED MODE PROCESSING ------\n"));
    DBG(printf("RFD address: 0x%08x\n", rfd_p));

    /* Set busy status while processing */
    set_uint16(rfd_p, STAT_B);

    while (remaining > 0 && current_rfd && current_rfd != I596_NULL) {
        /* Get RFD size (available data space) */
        rfd_size = get_uint16(current_rfd + 12); /* Size field in RFD */
        DBG(printf("RFD size: %d\n", rfd_size));
        data_offset = 24; /* After STATUS(2), CMD(2), LINK(4), RBD(4), SIZE(2), COUNT(2), DEST(6), SRC(6), TYPE(2) */

        /* In Simplified mode, data area starts at offset 28 (after all header fields) */
        DBG(printf("RFD data area: 0x%08x\n", current_rfd + data_offset));

        uint32_t rfd_count = (remaining > rfd_size) ? rfd_size : remaining;
        DBG(printf("Bytes to copy to this RFD: %d\n", rfd_count));

        /* Copy data directly to RFD data area */
        if (rfd_count > 0 && *bufsz > 0) {
            uint32_t data_bytes = (*bufsz > rfd_count) ? rfd_count : *bufsz;
            DBG(printf("Writing %d bytes from packet to RFD\n", data_bytes));

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

                DBG(printf("Writing %d bytes of CRC to RFD\n", crc_bytes));
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
            DBG(printf("Frame truncation detected - no more RFDs available\n"));

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
            DBG(printf("All data processed, setting EOF on this RFD\n"));
            rfd_status |= I596_EOF;
        }

        /* In simplified mode, if we can't fit all data in one RFD, truncate the frame */
        if (remaining > 0) {
            DBG(printf("Frame truncation in simplified mode - frame larger than RFD\n"));
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

    DBG(printf("Simplified mode processing complete\n"));
    DBG(printf("Remaining len: %zu\n", remaining));
    *len = remaining;

    return 0;
}

static int i82596_process_flexible_mode(I82596State *s, uint32_t rfd_p, uint32_t next_rfd,
    const uint8_t *cur_buf_ptr, uint8_t *crc_ptr,
    size_t *len, size_t *bufsz, uint16_t *status)
{
    DBG(printf("------ FLEXIBLE MODE PROCESSING ------\n"));

    uint32_t rbd;
    uint32_t last_used_rbd = I596_NULL;

    uint16_t rfd_size = get_uint16(rfd_p + 12);
    uint32_t rfd_data_addr = rfd_p + 16; /* RFD data area after header */

    DBG(printf("RFD pointer: 0x%08x\n", rfd_p));
    DBG(printf("RFD size: %d\n", rfd_size));
    DBG(printf("RFD data area: 0x%08x\n", rfd_data_addr));

    /* Get first RBD pointer */
    rbd = get_uint32(rfd_p + 8);
    DBG(printf("First RBD pointer: 0x%08x\n", rbd));
    DBG(printf("Initial data len: %zu, initial bufsz: %zu\n", *len, *bufsz));

    /* Set RFD as busy while processing */
    set_uint16(rfd_p, STAT_B);

    /* Check if we have valid RBD */
    if (rbd == I596_NULL) {
        DBG(printf("No valid RBD, marking RX_NO_RESOURCES\n"));

        /* Use new structured state update approach */
        i82596_update_rx_state(s, RX_NO_RESO_RBD);

        /* Record the error properly */
        i82596_record_error(s, RFD_STATUS_NOBUFS);

        *status |= RX_NO_RESO_RBD;
        return -1;
    }

    /* If RFD has data area and we have data, check if it all fits in RFD */
    if (rfd_size > 0 && *len <= rfd_size) {
        DBG(printf("All data fits in RFD data area\n"));

        /* Write packet data to RFD */
        uint16_t data_bytes = *bufsz;
        DBG(printf("Writing %d bytes of packet data to RFD\n", data_bytes));
        address_space_write(&address_space_memory, rfd_data_addr,
                          MEMTXATTRS_UNSPECIFIED, cur_buf_ptr, data_bytes);

        /* Write CRC to RFD after data */
        DBG(printf("Writing 4 bytes of CRC to RFD\n"));
        address_space_write(&address_space_memory, rfd_data_addr + data_bytes,
                          MEMTXATTRS_UNSPECIFIED, crc_ptr, 4);

        /* All data handled in RFD, set EOF */
        *status |= I596_EOF;
        *len = 0;
        *bufsz = 0;

        /* Clear RFD's rbd pointer after processing */
        set_uint32(rfd_p + 8, I596_NULL);

        DBG(printf("All data processed in RFD, no RBDs used\n"));
        return 0;
    }

    /* If RFD has data area, use it for initial packet data */
    if (rfd_size > 0 && *len > 0) {
        /* Use buffer boundary check for safety */
        uint16_t rfd_data_used = i82596_buffer_boundary_check(rfd_size, 0, *bufsz);
        DBG(printf("Writing %d bytes to RFD data area\n", rfd_data_used));

        address_space_write(&address_space_memory, rfd_data_addr,
                          MEMTXATTRS_UNSPECIFIED, cur_buf_ptr, rfd_data_used);
        cur_buf_ptr += rfd_data_used;
        *bufsz -= rfd_data_used;
        *len -= rfd_data_used;

        DBG(printf("After RFD: remaining buffer: %zu, remaining len: %zu\n", *bufsz, *len));
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
        DBG(printf("Processing RBD #%d at 0x%08x, buffer size: %u, data addr: 0x%08x\n",
              rbd_count, rbd, buffer_size, rba));

        /* Skip zero-sized buffers */
        if (buffer_size == 0) {
            DBG(printf("Zero buffer size, skipping\n"));
            rbd = next_rbd;
            continue;
        }

        /* Process this RBD buffer fully */
        while (used < buffer_size && *len > 0) {
            /* Copy as much data as fits from remaining packet data */
            if (*bufsz > 0) {
                uint16_t to_copy = i82596_buffer_boundary_check(buffer_size, used, *bufsz);

                DBG(printf("Writing %d bytes of packet data to RBD\n", to_copy));
                address_space_write(&address_space_memory, rba + used,
                                  MEMTXATTRS_UNSPECIFIED, cur_buf_ptr, to_copy);
                cur_buf_ptr += to_copy;
                used += to_copy;
                *bufsz -= to_copy;
                *len -= to_copy;

                DBG(printf("Remaining buffer: %zu, remaining len: %zu\n", *bufsz, *len));

                /* If we filled the buffer or used all data, continue to next buffer */
                if (used >= buffer_size || *len == 0) {
                    break;
                }
            }

            /* If there is still space, copy CRC if any left */
            if (used < buffer_size && *len > 0 && *bufsz == 0) {
                /* Use buffer boundary check function for safer sizing */
                uint16_t crc_bytes = i82596_buffer_boundary_check(buffer_size, used, *len);
                DBG(printf("Writing %d bytes of CRC to RBD\n", crc_bytes));

                address_space_write(&address_space_memory, rba + used,
                                  MEMTXATTRS_UNSPECIFIED, crc_ptr, crc_bytes);
                crc_ptr += crc_bytes;
                used += crc_bytes;
                *len -= crc_bytes;

                DBG(printf("Remaining len after CRC: %zu\n", *len));
            }
        }

        /* Set status and flags for this RBD */
        rbd_status = used;

        /* Set EOF if this is the last buffer - use the bit position Linux expects */
        if (*len == 0 || next_rbd == I596_NULL) {
            DBG(printf("All data processed, setting EOF on this RBD\n"));
            rbd_status |= 0x4000;  /* This is what Linux checks for EOF (not I596_EOF) */
        }
        /* Set EOF if this is the last buffer */
        if (*len == 0) {
            DBG(printf("All data processed, setting EOF on this RBD\n"));
            rbd_status |= I596_EOF;
        } else if (next_rbd == I596_NULL) {
            DBG(printf("Last RBD, no more buffers, setting EOF\n"));
            rbd_status |= I596_EOF;
        }

        set_uint16(rbd, rbd_status);
        last_used_rbd = rbd;
        rbd = next_rbd;

        /* Handle buffer overrun */
        if (*len > 0 && rbd == I596_NULL) {
            DBG(printf("Data left but no more RBDs: Buffer overrun!\n"));

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

    DBG(printf("RBD chain processing done, RBDs used: %d\n", rbd_count));
    DBG(printf("Remaining len: %zu\n", *len));

    /* Update next RFD's rbd pointer if needed */
    if (next_rfd != I596_NULL && next_rfd != 0) {
        if (rbd != I596_NULL) {
            DBG(printf("Updating next RFD 0x%08x to point to remaining RBD 0x%08x\n",
                   next_rfd, rbd));
            set_uint32(next_rfd + 8, rbd);
        } else {
            DBG(printf("Next RFD 0x%08x has no RBDs left, set NULL\n", next_rfd));
            set_uint32(next_rfd + 8, I596_NULL);
        }
    }

    DBG(printf("Final RFD status: 0x%04x\n", *status));
    return 0;
}

ssize_t i82596_receive_iov(NetClientState *nc, const struct iovec *iov, int iovcnt)
{
    size_t sz = 0;
    uint8_t *buf;
    int i;
    ssize_t ret;

    DBG(printf("====== i82596_receive_iov() START ======\n"));
    DBG(printf("IOV count: %d\n", iovcnt));

    /* Calculate total packet size */
    for (i = 0; i < iovcnt; i++) {
        DBG(printf("IOV[%d] length: %zu\n", i, iov[i].iov_len));
        sz += iov[i].iov_len;
    }
    DBG(printf("Total packet size: %zu bytes\n", sz));

    /* If no data, return immediately */
    if (sz == 0) {
        DBG(printf("ERROR: Zero-sized packet, returning -1\n"));
        return -1;
    }

    /* Allocate temporary buffer for the complete packet */
    buf = g_malloc(sz);
    if (!buf) {
        DBG(printf("ERROR: Memory allocation failed for packet buffer (size=%zu)\n", sz));
        return -1;
    }
    DBG(printf("Buffer allocated successfully at %p\n", (void*)buf));

    /* Copy data from I/O vector elements to the buffer */
    size_t offset = 0;
    for (i = 0; i < iovcnt; i++) {
        DBG(printf("Copying IOV[%d]: %zu bytes to offset %zu\n", i, iov[i].iov_len, offset));
        if (iov[i].iov_base == NULL) {
            DBG(printf("ERROR: IOV[%d] has NULL base pointer\n", i));
            g_free(buf);
            return -1;
        }
        memcpy(buf + offset, iov[i].iov_base, iov[i].iov_len);
        offset += iov[i].iov_len;
    }
    DBG(printf("All IOV segments copied, total size: %zu bytes\n", offset));

    /* Print first few bytes for debugging */
    if (sz >= 14) {
        DBG(printf("Packet header: %02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x, type=%02x%02x\n",
               buf[6], buf[7], buf[8], buf[9], buf[10], buf[11],  /* Source MAC */
               buf[0], buf[1], buf[2], buf[3], buf[4], buf[5],    /* Destination MAC */
               buf[12], buf[13]));                                 /* EtherType */
    }

    /* Call the existing receive function */
    DBG(printf("Calling i82596_receive()...\n"));
    ret = i82596_receive(nc, buf, sz);
    DBG(printf("i82596_receive() returned: %zd\n", ret));

    /* Clean up */
    DBG(printf("Freeing temporary buffer\n"));
    g_free(buf);

    DBG(printf("====== i82596_receive_iov() END ======\n"));
    return ret;
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

    if (!I596_FULL_DUPLEX && !s->throttle_state) {
        /* In half duplex, if we're currently transmitting (bus off),
         * we would have a collision. Just drop the packet. */
        DBG(printf("RX COLLISION: Half duplex collision detected, dropping packet (size=%zu)\n",
                  sz));
        return sz; /* Pretend we received it */
    }

    DBG(printf("====== i82596_receive() START ======\n"));
    DBG(printf("Packet size: %zu bytes\n", sz));
    DBG(printf("RX status: %d\n", s->rx_status));
    DBG(printf("Link state: %04x\n", s->lnkst));

    if (!i82596_validate_receive_state(s, &sz, &bufsz, &len)) {
        DBG(printf("ERROR: Invalid RX state, rejecting packet\n"));
        return -1;
    }

    if (!i82596_check_packet_filter(s, buf, &is_broadcast)) {
        DBG(printf("Packet rejected by filter\n"));
        return sz;
    }

    DBG(printf("Packet passed filters, is_broadcast=%d\n", is_broadcast));

    rfd_p = get_uint32(s->scb + 8); /* get Receive Frame Descriptor */
    DBG(printf("Initial RFD pointer: 0x%08x\n", rfd_p));

    if (!rfd_p || rfd_p == I596_NULL) {
        DBG(printf("ERROR: No valid RFD pointer (rfd_p=%08x)\n", rfd_p));
        return sz; /* Can't proceed without a valid RFD */
    }

    command = get_uint16(rfd_p + 2);
    DBG(printf("RFD command: 0x%04x\n", command));

    sf_bit = ((command >> 3) & 1);
    DBG(printf("SF bit: %d (%s mode)\n", sf_bit, sf_bit ? "Flexible" : "Simplified"));

    /* Calculate the ethernet checksum */
    len += 4;
    crc = cpu_to_be32(crc32(~0, buf, sz));
    crc_ptr = (uint8_t *) &crc;
    cur_buf_ptr = buf;
    DBG(printf("Data length with CRC: %zu\n", len));
    DBG(printf("CRC value: %08x\n", crc));

    next_rfd = get_uint32(rfd_p + 4);
    DBG(printf("Next RFD pointer: 0x%08x\n", next_rfd));

    if (!sf_bit) { /* Simplified Mode Memory Structure */
        DBG(printf("Processing in SIMPLIFIED mode\n"));
        result = i82596_process_simplified_mode(s, rfd_p, next_rfd, cur_buf_ptr,
                                             crc_ptr, &len, &bufsz, &status);
        DBG(printf("Simplified mode result: %d, remaining len=%zu, status=0x%04x\n",
               result, len, status));
        if (result < 0) {
            DBG(printf("ERROR: Simplified mode processing failed\n"));
            return -1;
        }
    } else {
        DBG(printf("Processing in FLEXIBLE mode\n"));
        result = i82596_process_flexible_mode(s, rfd_p, next_rfd, cur_buf_ptr,
                                           crc_ptr, &len, &bufsz, &status);
        DBG(printf("Flexible mode result: %d, remaining len=%zu, status=0x%04x\n",
               result, len, status));
        if (result < 0) {
            DBG(printf("ERROR: Flexible mode processing failed\n"));
            return -1;
        }
    }

    DBG(printf("Calling finalize_reception with status=0x%04x\n", status));
    ssize_t ret = i82596_finalize_reception(s, rfd_p, status, command, next_rfd, is_broadcast, sz);
    DBG(printf("====== i82596_receive() END - returned %zd ======\n\n", ret));
    return ret;
}

const VMStateDescription vmstate_i82596 = {
    .name = "i82596",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]) {
        /* Device mode and configuration */
        VMSTATE_UINT8(mode, I82596State),
        VMSTATE_UINT8(sysbus, I82596State),

        /* Timers and throttle state */
        VMSTATE_TIMER_PTR(flush_queue_timer, I82596State),
        VMSTATE_TIMER_PTR(throttle_timer, I82596State),
        VMSTATE_UINT16(t_on, I82596State),
        VMSTATE_UINT16(t_off, I82596State),
        VMSTATE_BOOL(throttle_state, I82596State),

        /* SCB and status registers */
        VMSTATE_UINT64(scp, I82596State),
        VMSTATE_UINT32(scb, I82596State),
        VMSTATE_UINT32(scb_base, I82596State),
        VMSTATE_UINT16(scb_status, I82596State),
        VMSTATE_UINT8(cu_status, I82596State),
        VMSTATE_UINT8(rx_status, I82596State),
        VMSTATE_UINT16(lnkst, I82596State),

        /* Command processing */
        VMSTATE_UINT32(cmd_p, I82596State),
        VMSTATE_INT32(ca, I82596State),
        VMSTATE_INT32(ca_active, I82596State),
        VMSTATE_INT32(send_irq, I82596State),

        /* Configuration arrays */
        VMSTATE_BUFFER(mult, I82596State),
        VMSTATE_BUFFER(config, I82596State),

        /* Transmit buffer */
        VMSTATE_BUFFER(tx_buffer, I82596State),

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
