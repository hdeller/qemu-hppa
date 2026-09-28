/*
 * SCSI sequential-access (tape) device emulation
 *
 * Copyright (c) 2026 Craig Lalley
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * The medium is a host file in the SIMH ".tap" format: every data record
 * is a 32-bit little-endian length header, the record bytes, one pad byte
 * when the length is odd, and a copy of the length header as a trailer.
 * A filemark is a lone header word of 0x00000000, an erase gap a lone
 * 0xfffffffe, and 0xffffffff (or the end of the file) is end of medium.
 *
 * By default the drive identifies itself as an HP C1537A (DDS-3) with
 * firmware L708; the "vendor", "product" and "ver" properties override
 * that.
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/bitops.h"
#include "qemu/bswap.h"
#include "qemu/cutils.h"
#include "qemu/module.h"
#include "qemu/units.h"
#include "hw/scsi/scsi.h"
#include "scsi/constants.h"
#include "system/block-backend.h"
#include "hw/block/block.h"
#include "hw/core/qdev-properties.h"
#include "hw/core/qdev-properties-system.h"
#include "migration/vmstate.h"
#include "qom/object.h"
#include "trace.h"

#define TYPE_SCSI_TAPE "scsi-tape"
OBJECT_DECLARE_SIMPLE_TYPE(SCSITapeState, SCSI_TAPE)

/* 0 is variable-block mode */
#define SCSI_TAPE_DEFAULT_BLOCK_SIZE    0
#define SCSI_TAPE_MIN_BUFLEN            256
/* Largest data transfer accepted for one command. */
#define SCSI_TAPE_MAX_XFER              (16 * MiB)

/* Fixed-format sense data bits that scsi_build_sense() leaves clear. */
#define SENSE_VALID                     0x80    /* byte 0 */
#define SENSE_FILEMARK                  0x80    /* byte 2 */
#define SENSE_EOM                       0x40    /* byte 2 */
#define SENSE_ILI                       0x20    /* byte 2 */
#define SENSE_INFO_OFFSET               3       /* bytes 3..6 */

/* SIMH .tap markers */
#define TAP_TAPEMARK                    0x00000000U
#define TAP_ERASE_GAP                   0xfffffffeU
#define TAP_END_MEDIUM                  0xffffffffU
#define TAP_LEN_MASK                    0x0fffffffU

#define SCSI_TAPE_DEFAULT_VENDOR        "HP"
#define SCSI_TAPE_DEFAULT_PRODUCT       "C1537A"
#define SCSI_TAPE_DEFAULT_VERSION       "L708"
#define SCSI_TAPE_INQUIRY_LEN           96

struct SCSITapeState {
    SCSIDevice qdev;

    /* Byte offset in the image of the next record header; 0 is BOP. */
    uint64_t pos;

    /*
     * Bytes of the record at @pos already returned by fixed-mode READ(6).
     * With "join-records", fixed-mode blocks need not line up with
     * records, so a read may stop in the middle of a record; 0 means "on
     * a record boundary".
     */
    uint32_t rec_consumed;

    /* Block length used for fixed-mode transfers ("block-size"). */
    uint32_t block_size;
    /* Report EOM at every end of data ("eom-at-eod"). */
    bool eom_at_eod;
    /* Fixed-mode reads cut blocks across records ("join-records"). */
    bool join_records;

    /* Medium capacity in MiB of image file, 0 for unlimited. */
    uint32_t capacity_mb;
    /* The image may be grown (BLK_PERM_RESIZE is held). */
    bool can_resize;

    /* A medium is present and the drive is loaded. */
    bool loaded;

    char *vendor;
    char *product;
    char *ver;
};

typedef struct SCSITapeReq {
    SCSIRequest req;
    uint8_t *buf;
    uint32_t buflen;
    /*
     * The command transfers data and then ends in CHECK CONDITION (a read
     * that stopped at a filemark, end of data or a length mismatch after
     * returning some bytes).  The sense data is built when the command is
     * parsed and the status is reported once the data phase is over.
     */
    bool deferred_check;
    /* A data-out command is waiting for its data to be transferred. */
    bool awaiting_data_out;
} SCSITapeReq;

/* .tap record layer */

typedef enum {
    TAP_REC_DATA,
    TAP_REC_FILEMARK,
    TAP_REC_ERASE_GAP,
    TAP_REC_END_MEDIUM,     /* end-of-medium marker or end of the file */
    TAP_REC_IOERR,
} SCSITapeRecKind;

/* Look at the record header at s->pos without moving. */
static SCSITapeRecKind scsi_tape_peek_record(SCSITapeState *s,
                                             uint32_t *data_len)
{
    BlockBackend *blk = s->qdev.conf.blk;
    int64_t len = blk_getlength(blk);
    uint8_t hdr[4];
    uint32_t raw;

    if (len < 0 || s->pos + 4 > (uint64_t)len) {
        return TAP_REC_END_MEDIUM;
    }
    if (blk_pread(blk, s->pos, 4, hdr, 0) < 0) {
        return TAP_REC_IOERR;
    }
    raw = ldl_le_p(hdr);

    switch (raw) {
    case TAP_TAPEMARK:
        return TAP_REC_FILEMARK;
    case TAP_ERASE_GAP:
        return TAP_REC_ERASE_GAP;
    case TAP_END_MEDIUM:
        return TAP_REC_END_MEDIUM;
    default:
        *data_len = raw & TAP_LEN_MASK;
        return TAP_REC_DATA;
    }
}

/* Size of a data record on the medium: header, data, pad, trailer. */
static uint64_t scsi_tape_record_size(uint32_t data_len)
{
    return 4 + (uint64_t)data_len + (data_len & 1) + 4;
}

static void scsi_tape_skip_data(SCSITapeState *s, uint32_t data_len)
{
    s->pos += scsi_tape_record_size(data_len);
}

static void scsi_tape_skip_filemark(SCSITapeState *s)
{
    s->pos += 4;
}

static void scsi_tape_skip_gap(SCSITapeState *s)
{
    s->pos += 4;
}

static void scsi_tape_rewind(SCSITapeState *s)
{
    s->pos = 0;
    s->rec_consumed = 0;
}

/*
 * Commands that count whole records (SPACE, variable-mode READ) cannot
 * start in the middle of a record.  If a fixed-mode READ with
 * "join-records" stopped inside one, the part already returned counts
 * as read and the record is passed.
 */
static void scsi_tape_sync_to_record_boundary(SCSITapeState *s)
{
    uint32_t len = 0;

    if (s->rec_consumed == 0) {
        return;
    }
    s->rec_consumed = 0;
    if (scsi_tape_peek_record(s, &len) == TAP_REC_DATA) {
        scsi_tape_skip_data(s, len);
    }
}

/*
 * Writing.  The image grows as records are written, up to "capacity-mb"
 * if that is set.  Growing needs BLK_PERM_RESIZE on our own BlockBackend,
 * which blkconf_apply_backend_options() does not take, so it is asked for
 * whenever a writable medium is mounted.
 */
static void scsi_tape_note_mount(SCSITapeState *s)
{
    BlockBackend *blk = s->qdev.conf.blk;
    uint64_t perm, shared;

    blk_get_perm(blk, &perm, &shared);
    s->can_resize = (perm & BLK_PERM_WRITE) &&
                    blk_set_perm(blk, perm | BLK_PERM_RESIZE, shared,
                                 NULL) == 0;
}

static uint64_t scsi_tape_capacity(SCSITapeState *s)
{
    return (uint64_t)s->capacity_mb * MiB;
}

/* Make the image at least @new_len bytes long. */
static bool scsi_tape_grow(SCSITapeState *s, uint64_t new_len)
{
    BlockBackend *blk = s->qdev.conf.blk;
    uint64_t cap = scsi_tape_capacity(s);
    int64_t cur = blk_getlength(blk);

    if (cur < 0 || (cap && new_len > cap)) {
        return false;
    }
    if ((uint64_t)cur >= new_len) {
        return true;
    }
    return s->can_resize &&
           blk_truncate(blk, new_len, false, PREALLOC_MODE_OFF, 0,
                        NULL) == 0;
}

/* Early warning: less than this much capacity is left after a write. */
#define SCSI_TAPE_EARLY_WARNING         (4 * MiB)

static bool scsi_tape_early_warning(SCSITapeState *s)
{
    uint64_t cap = scsi_tape_capacity(s);

    return cap && (cap <= s->pos ||
                   cap - s->pos <= SCSI_TAPE_EARLY_WARNING);
}

/*
 * Write one data record at s->pos.  Room is made first, for the record
 * and for the end-of-medium word behind it, so a failure leaves neither
 * a partial record nor a moved position behind.
 */
static bool scsi_tape_write_record(SCSITapeState *s, const uint8_t *data,
                                   uint32_t len)
{
    BlockBackend *blk = s->qdev.conf.blk;
    uint8_t hdr[4];
    uint8_t pad = 0;

    if (!scsi_tape_grow(s, s->pos + scsi_tape_record_size(len) + 4)) {
        return false;
    }
    stl_le_p(hdr, len);
    if (blk_pwrite(blk, s->pos, 4, hdr, 0) < 0) {
        return false;
    }
    if (len && blk_pwrite(blk, s->pos + 4, len, data, 0) < 0) {
        return false;
    }
    if ((len & 1) && blk_pwrite(blk, s->pos + 4 + len, 1, &pad, 0) < 0) {
        return false;
    }
    if (blk_pwrite(blk, s->pos + 4 + len + (len & 1), 4, hdr, 0) < 0) {
        return false;
    }
    scsi_tape_skip_data(s, len);
    return true;
}

static bool scsi_tape_write_marker(SCSITapeState *s, uint32_t marker)
{
    uint8_t word[4];

    /* The marker, and the end-of-medium word behind it */
    if (!scsi_tape_grow(s, s->pos + 8)) {
        return false;
    }
    stl_le_p(word, marker);
    if (blk_pwrite(s->qdev.conf.blk, s->pos, 4, word, 0) < 0) {
        return false;
    }
    if (marker == TAP_TAPEMARK) {
        scsi_tape_skip_filemark(s);
    } else {
        scsi_tape_skip_gap(s);
    }
    return true;
}

/*
 * Mark end of data after a write, without moving.  Like on a real tape,
 * anything that was recorded beyond the write position is no longer
 * reachable.  The marker also matters because the block layer sizes an
 * image in 512-byte sectors and reads the tail of the last sector as
 * zeros, which would otherwise look like filemarks.  Every write makes
 * room for the marker, so it is written even when the tape is full.
 */
static void scsi_tape_mark_end(SCSITapeState *s)
{
    uint8_t word[4];

    if (scsi_tape_grow(s, s->pos + 4)) {
        stl_le_p(word, TAP_END_MEDIUM);
        blk_pwrite(s->qdev.conf.blk, s->pos, 4, word, 0);
    }
}

/* Sense data */

static const SCSISense scsi_tape_sense_filemark = {
    .key = NO_SENSE, .asc = 0x00, .ascq = 0x01
};

static const SCSISense scsi_tape_sense_eod = {
    .key = BLANK_CHECK, .asc = 0x00, .ascq = 0x05
};

/*
 * EOM accompanies end of data only at or after early warning (SCSI-2
 * 10.2.4 and 10.2.12); with "eom-at-eod" it is set every time.
 */
static uint8_t scsi_tape_eod_bits(SCSITapeState *s)
{
    return (s->eom_at_eod || scsi_tape_early_warning(s)) ? SENSE_EOM : 0;
}

/* END-OF-PARTITION/MEDIUM DETECTED: data could not be written. */
static const SCSISense scsi_tape_sense_overflow = {
    .key = VOLUME_OVERFLOW, .asc = 0x00, .ascq = 0x02
};

/* END-OF-PARTITION/MEDIUM DETECTED: written, but past early warning. */
static const SCSISense scsi_tape_sense_early_warning = {
    .key = NO_SENSE, .asc = 0x00, .ascq = 0x02
};

static void scsi_tape_check_condition(SCSITapeReq *r, SCSISense sense)
{
    scsi_req_build_sense(&r->req, sense);
    scsi_req_complete(&r->req, CHECK_CONDITION);
}

/* Build sense data with FM/EOM/ILI bits and a valid INFORMATION field. */
static void scsi_tape_build_sense_info(SCSITapeReq *r, SCSISense sense,
                                       uint8_t bits, uint32_t information)
{
    scsi_req_build_sense(&r->req, sense);
    r->req.sense[0] |= SENSE_VALID;
    r->req.sense[2] |= bits;
    stl_be_p(&r->req.sense[SENSE_INFO_OFFSET], information);
}

static void scsi_tape_check_condition_info(SCSITapeReq *r, SCSISense sense,
                                           uint8_t bits, uint32_t information)
{
    scsi_tape_build_sense_info(r, sense, bits, information);
    scsi_req_complete(&r->req, CHECK_CONDITION);
}

/* As above, but report the status after the data phase. */
static void scsi_tape_defer_check_condition_info(SCSITapeReq *r,
                                                 SCSISense sense,
                                                 uint8_t bits,
                                                 uint32_t information)
{
    scsi_tape_build_sense_info(r, sense, bits, information);
    r->deferred_check = true;
}

static void scsi_tape_defer_check_condition(SCSITapeReq *r, SCSISense sense)
{
    scsi_req_build_sense(&r->req, sense);
    r->deferred_check = true;
}

/* Commands */

static void scsi_tape_space(SCSITapeReq *r, uint8_t *cdb)
{
    SCSITapeState *s = SCSI_TAPE(r->req.dev);
    BlockBackend *blk = s->qdev.conf.blk;
    uint8_t code = cdb[1] & 0x07;
    int32_t count = sextract32(ldl_be_p(&cdb[1]), 0, 24);
    int32_t done = 0;
    SCSISense sense = SENSE_CODE(NO_SENSE);
    uint8_t bits = 0;
    bool stopped = false;

    /* Only spacing over blocks (0) and filemarks (1) is implemented. */
    if (code != 0 && code != 1) {
        scsi_tape_check_condition(r, SENSE_CODE(INVALID_FIELD));
        return;
    }

    scsi_tape_sync_to_record_boundary(s);

    /* Forward, towards end of partition. */
    while (done < count && !stopped) {
        uint32_t len = 0;

        switch (scsi_tape_peek_record(s, &len)) {
        case TAP_REC_DATA:
            scsi_tape_skip_data(s, len);
            if (code == 0) {
                done++;
            }
            break;
        case TAP_REC_ERASE_GAP:
            scsi_tape_skip_gap(s);
            break;
        case TAP_REC_FILEMARK:
            scsi_tape_skip_filemark(s);
            if (code == 1) {
                done++;
            } else {
                sense = scsi_tape_sense_filemark;
                bits = SENSE_FILEMARK;
                stopped = true;
            }
            break;
        case TAP_REC_END_MEDIUM:
            sense = scsi_tape_sense_eod;
            bits = scsi_tape_eod_bits(s);
            stopped = true;
            break;
        case TAP_REC_IOERR:
            sense = SENSE_CODE(IO_ERROR);
            stopped = true;
            break;
        }
    }

    /*
     * Backward, towards beginning of partition.  The .tap trailer makes
     * this possible without an index: the word before s->pos is either a
     * marker or the length of the record that ends there.
     */
    while (done > count && !stopped) {
        uint8_t word[4];
        uint32_t raw;
        uint64_t size;

        if (s->pos < 4) {
            /* Beginning of partition reached. */
            bits = SENSE_EOM;
            stopped = true;
            break;
        }
        if (blk_pread(blk, s->pos - 4, 4, word, 0) < 0) {
            sense = SENSE_CODE(IO_ERROR);
            stopped = true;
            break;
        }
        raw = ldl_le_p(word);
        switch (raw) {
        case TAP_TAPEMARK:
            s->pos -= 4;
            if (code == 1) {
                done--;
            } else {
                sense = scsi_tape_sense_filemark;
                bits = SENSE_FILEMARK;
                stopped = true;
            }
            break;
        case TAP_ERASE_GAP:
        case TAP_END_MEDIUM:
            s->pos -= 4;
            break;
        default:
            size = scsi_tape_record_size(raw & TAP_LEN_MASK);
            if (size > s->pos) {
                sense = SENSE_CODE(IO_ERROR);
                stopped = true;
                break;
            }
            s->pos -= size;
            if (code == 0) {
                done--;
            }
            break;
        }
    }

    if (stopped) {
        /* INFORMATION is the requested count minus the count done. */
        scsi_tape_check_condition_info(r, sense, bits, count - done);
    }
}

/*
 * Fixed-mode READ(6): @want bytes is the requested number of blocks times
 * the block length.  Each record is one block.  A record of any other
 * length is an incorrect-length block (SCSI-2 10.2.4): the read stops
 * after it with ILI, none of its data is returned, and INFORMATION
 * counts the blocks not read, that one included.
 *
 * With "join-records" the blocks are instead cut from the record stream
 * irrespective of record boundaries, so one record may feed several
 * blocks (and several commands) and one block may span several records.
 */
static int scsi_tape_read6_fixed(SCSITapeReq *r, uint32_t want)
{
    SCSITapeState *s = SCSI_TAPE(r->req.dev);
    uint32_t blocks_req = want / s->block_size;
    uint32_t got = 0;
    bool stopped = false;
    bool has_info = true;
    SCSISense sense = SENSE_CODE(NO_SENSE);
    uint8_t bits = 0;

    while (got < want && !stopped) {
        uint32_t len = 0;
        uint32_t avail, n;

        switch (scsi_tape_peek_record(s, &len)) {
        case TAP_REC_DATA:
            if (!s->join_records && len != s->block_size) {
                scsi_tape_skip_data(s, len);
                bits = SENSE_ILI;
                stopped = true;
                break;
            }
            if (s->rec_consumed >= len) {
                /* Fully consumed (or empty) record: move on. */
                scsi_tape_skip_data(s, len);
                s->rec_consumed = 0;
                break;
            }
            avail = len - s->rec_consumed;
            n = MIN(avail, want - got);
            if (blk_pread(s->qdev.conf.blk, s->pos + 4 + s->rec_consumed,
                          n, r->buf + got, 0) < 0) {
                sense = SENSE_CODE(IO_ERROR);
                has_info = false;
                stopped = true;
                break;
            }
            got += n;
            if (n == avail) {
                scsi_tape_skip_data(s, len);
                s->rec_consumed = 0;
            } else {
                s->rec_consumed += n;
            }
            break;
        case TAP_REC_ERASE_GAP:
            scsi_tape_skip_gap(s);
            break;
        case TAP_REC_FILEMARK:
            /* Stop after the filemark; the records behind it stay. */
            scsi_tape_skip_filemark(s);
            sense = scsi_tape_sense_filemark;
            bits = SENSE_FILEMARK;
            stopped = true;
            break;
        case TAP_REC_END_MEDIUM:
            sense = scsi_tape_sense_eod;
            bits = scsi_tape_eod_bits(s);
            stopped = true;
            break;
        case TAP_REC_IOERR:
            sense = SENSE_CODE(IO_ERROR);
            has_info = false;
            stopped = true;
            break;
        }
    }

    r->buflen = got;
    if (stopped) {
        /*
         * INFORMATION is the number of blocks not read.  An
         * incorrect-length record, or with "join-records" a trailing
         * partial block, is not counted as read and is flagged with ILI.
         */
        uint32_t information = blocks_req - got / s->block_size;
        bool ili = (bits & SENSE_ILI) || (got % s->block_size) != 0;

        trace_scsi_tape_read6(s->qdev.id, r->req.lun, r->req.tag, 1, 0,
                              want, got, ili, information);
        if (got == 0) {
            if (has_info) {
                scsi_tape_check_condition_info(r, sense, bits, information);
            } else {
                scsi_tape_check_condition(r, sense);
            }
            return 0;
        }
        if (!has_info) {
            scsi_tape_defer_check_condition(r, sense);
        } else {
            scsi_tape_defer_check_condition_info(r, sense,
                                                 bits | (ili ? SENSE_ILI : 0),
                                                 information);
        }
        return got;
    }
    trace_scsi_tape_read6(s->qdev.id, r->req.lun, r->req.tag, 1, 0,
                          want, got, 0, 0);
    return got;
}

/* Variable-mode READ(6): one record per command. */
static int scsi_tape_read6_variable(SCSITapeReq *r, uint32_t xfer, bool sili)
{
    SCSITapeState *s = SCSI_TAPE(r->req.dev);
    uint32_t len = 0;
    uint32_t n;
    bool over, under, ili = false;
    int32_t information = 0;

    scsi_tape_sync_to_record_boundary(s);

    switch (scsi_tape_peek_record(s, &len)) {
    case TAP_REC_DATA:
        break;
    case TAP_REC_FILEMARK:
        scsi_tape_skip_filemark(s);
        scsi_tape_check_condition_info(r, scsi_tape_sense_filemark,
                                       SENSE_FILEMARK, xfer);
        return 0;
    case TAP_REC_ERASE_GAP:
        scsi_tape_skip_gap(s);
        return 0;
    case TAP_REC_END_MEDIUM:
        scsi_tape_check_condition_info(r, scsi_tape_sense_eod,
                                       scsi_tape_eod_bits(s), xfer);
        return 0;
    case TAP_REC_IOERR:
    default:
        scsi_tape_check_condition(r, SENSE_CODE(IO_ERROR));
        return 0;
    }

    n = MIN(len, xfer);
    if (n && blk_pread(s->qdev.conf.blk, s->pos + 4, n, r->buf, 0) < 0) {
        scsi_tape_check_condition(r, SENSE_CODE(IO_ERROR));
        return 0;
    }
    scsi_tape_skip_data(s, len);
    r->buflen = n;

    /*
     * Incorrect length: with SILI clear, a record shorter or longer than
     * requested is reported.  With SILI set, only an overlength record is,
     * and only when the block descriptor reports a non-zero block length.
     * INFORMATION is the requested length minus the record length.
     */
    over = len > xfer;
    under = len < xfer;
    if ((!sili && (over || under)) || (sili && over && s->block_size != 0)) {
        ili = true;
        information = (int32_t)xfer - (int32_t)len;
        if (n > 0) {
            scsi_tape_defer_check_condition_info(r, SENSE_CODE(NO_SENSE),
                                                 SENSE_ILI, information);
        } else {
            scsi_tape_check_condition_info(r, SENSE_CODE(NO_SENSE),
                                           SENSE_ILI, information);
        }
    }
    trace_scsi_tape_read6(s->qdev.id, r->req.lun, r->req.tag, 0, sili,
                          xfer, n, ili, information);
    return n;
}

/*
 * A fixed-block transfer of one or more blocks while no block length is
 * set (variable-block mode) has no defined size.
 */
static bool scsi_tape_fixed_without_length(SCSITapeState *s, uint8_t *cdb)
{
    return s->block_size == 0 && (ldl_be_p(&cdb[1]) & 0xffffff) != 0;
}

static int scsi_tape_read6(SCSITapeReq *r, uint8_t *cdb)
{
    SCSITapeState *s = SCSI_TAPE(r->req.dev);
    bool fixed = cdb[1] & 0x01;
    bool sili = cdb[1] & 0x02;
    uint32_t xfer = r->req.cmd.xfer;

    if (fixed && (sili || scsi_tape_fixed_without_length(s, cdb))) {
        scsi_tape_check_condition(r, SENSE_CODE(INVALID_FIELD));
        return 0;
    }
    if (xfer == 0) {
        /* Not an error; nothing is transferred and the tape does not move */
        return 0;
    }
    if (fixed) {
        return scsi_tape_read6_fixed(r, xfer);
    }
    return scsi_tape_read6_variable(r, xfer, sili);
}

/* WRITE(6), called once the data has arrived in r->buf. */
static void scsi_tape_write6(SCSITapeReq *r)
{
    SCSITapeState *s = SCSI_TAPE(r->req.dev);
    bool fixed = r->req.cmd.buf[1] & 0x01;
    uint32_t xfer = r->req.cmd.xfer;
    uint32_t residue = 0;

    scsi_tape_sync_to_record_boundary(s);

    if (fixed) {
        /* One record per block. */
        uint32_t blocks = xfer / s->block_size;
        uint32_t i;

        for (i = 0; i < blocks; i++) {
            if (!scsi_tape_write_record(s, r->buf + i * s->block_size,
                                        s->block_size)) {
                residue = blocks - i;
                break;
            }
        }
    } else if (!scsi_tape_write_record(s, r->buf, xfer)) {
        residue = xfer;
    }
    scsi_tape_mark_end(s);

    if (residue) {
        scsi_tape_check_condition_info(r, scsi_tape_sense_overflow,
                                       SENSE_EOM, residue);
        return;
    }

    /*
     * The data is on the medium, but the early-warning zone has been
     * entered: CHECK CONDITION with NO SENSE and EOM, INFORMATION 0.
     */
    if (scsi_tape_early_warning(s)) {
        scsi_tape_check_condition_info(r, scsi_tape_sense_early_warning,
                                       SENSE_EOM, 0);
    }
}

static void scsi_tape_write_filemarks(SCSITapeReq *r, uint8_t *cdb)
{
    SCSITapeState *s = SCSI_TAPE(r->req.dev);
    uint32_t count = ldl_be_p(&cdb[1]) & 0xffffff;
    uint32_t i;

    if (count == 0) {
        /*
         * Writing zero filemarks only flushes buffered data.  That is
         * not an error on a write-protected medium either.
         */
        scsi_tape_sync_to_record_boundary(s);
        return;
    }
    if (!blk_is_writable(s->qdev.conf.blk)) {
        scsi_tape_check_condition(r, SENSE_CODE(WRITE_PROTECTED));
        return;
    }
    scsi_tape_sync_to_record_boundary(s);
    for (i = 0; i < count; i++) {
        if (!scsi_tape_write_marker(s, TAP_TAPEMARK)) {
            break;
        }
    }
    scsi_tape_mark_end(s);
    if (i < count) {
        scsi_tape_check_condition_info(r, scsi_tape_sense_overflow,
                                       SENSE_EOM, count - i);
    }
}

static void scsi_tape_erase(SCSITapeReq *r, uint8_t *cdb)
{
    SCSITapeState *s = SCSI_TAPE(r->req.dev);
    BlockBackend *blk = s->qdev.conf.blk;
    bool long_erase = cdb[1] & 0x01;

    if (!blk_is_writable(blk)) {
        scsi_tape_check_condition(r, SENSE_CODE(WRITE_PROTECTED));
        return;
    }
    scsi_tape_sync_to_record_boundary(s);
    if (long_erase) {
        /* Erase to end of partition: cut the image at the position. */
        if (!s->can_resize ||
            blk_truncate(blk, s->pos, true, PREALLOC_MODE_OFF, 0,
                         NULL) != 0) {
            scsi_tape_check_condition(r, SENSE_CODE(IO_ERROR));
            return;
        }
    } else if (!scsi_tape_write_marker(s, TAP_ERASE_GAP)) {
        scsi_tape_mark_end(s);
        scsi_tape_check_condition_info(r, scsi_tape_sense_overflow,
                                       SENSE_EOM, 0);
        return;
    }
    scsi_tape_mark_end(s);
}

static int scsi_tape_emulate_inquiry(SCSITapeReq *r, uint8_t *outbuf)
{
    SCSITapeState *s = SCSI_TAPE(r->req.dev);
    uint8_t *cdb = r->req.cmd.buf;

    if (cdb[1] & 0x01) {
        /* EVPD: only the list of supported VPD pages is implemented. */
        if (cdb[2] != 0x00) {
            scsi_tape_check_condition(r, SENSE_CODE(INVALID_FIELD));
            return -1;
        }
        memset(outbuf, 0, 5);
        outbuf[0] = TYPE_TAPE;
        outbuf[1] = 0x00;           /* page code */
        outbuf[3] = 1;              /* page length */
        outbuf[4] = 0x00;           /* supported pages: 0x00 */
        return 5;
    }
    if (cdb[2] != 0) {
        scsi_tape_check_condition(r, SENSE_CODE(INVALID_FIELD));
        return -1;
    }

    memset(outbuf, 0, SCSI_TAPE_INQUIRY_LEN);
    outbuf[0] = TYPE_TAPE;
    outbuf[1] = 0x80;               /* RMB: removable medium */
    outbuf[2] = 0x02;               /* SCSI-2 */
    outbuf[3] = 0x02;               /* response data format */
    outbuf[4] = SCSI_TAPE_INQUIRY_LEN - 5;
    strpadcpy((char *)&outbuf[8], 8, s->vendor, ' ');
    strpadcpy((char *)&outbuf[16], 16, s->product, ' ');
    memcpy(&outbuf[32], s->ver, MIN(4, strlen(s->ver)));
    return SCSI_TAPE_INQUIRY_LEN;
}

static int scsi_tape_emulate_read_block_limits(uint8_t *outbuf)
{
    /* Maximum block length 0 (not specified), minimum block length 1. */
    memset(outbuf, 0, 6);
    outbuf[5] = 1;
    return 6;
}

/* Commands that are answered whether or not a medium is loaded. */
static bool scsi_tape_cmd_needs_no_medium(uint8_t opcode)
{
    switch (opcode) {
    case INQUIRY:
    case REQUEST_SENSE:
        return true;
    default:
        return false;
    }
}

static int32_t scsi_tape_send_command(SCSIRequest *req, uint8_t *buf)
{
    SCSITapeReq *r = DO_UPCAST(SCSITapeReq, req, req);
    SCSITapeState *s = SCSI_TAPE(req->dev);
    uint8_t *outbuf;
    int buflen = 0;

    if (req->cmd.xfer > SCSI_TAPE_MAX_XFER) {
        scsi_tape_check_condition(r, SENSE_CODE(INVALID_FIELD));
        return 0;
    }

    if (!r->buf) {
        r->buflen = MAX(SCSI_TAPE_MIN_BUFLEN, req->cmd.xfer);
        r->buf = g_malloc0(r->buflen);
    }
    outbuf = r->buf;

    if (!s->loaded && !scsi_tape_cmd_needs_no_medium(buf[0])) {
        scsi_tape_check_condition(r, SENSE_CODE(NO_MEDIUM));
        return 0;
    }

    switch (buf[0]) {
    case TEST_UNIT_READY:
        break;

    case INQUIRY:
        buflen = scsi_tape_emulate_inquiry(r, outbuf);
        break;

    case REQUEST_SENSE:
        /* Pending sense data is returned by the SCSI bus layer. */
        buflen = scsi_build_sense_buf(outbuf, r->buflen,
                                      SENSE_CODE(NO_SENSE), true);
        break;

    case READ_BLOCK_LIMITS:
        buflen = scsi_tape_emulate_read_block_limits(outbuf);
        break;

    case REWIND:
        /* The rewind completes before status, whether or not Immed is set */
        scsi_tape_rewind(s);
        break;

    case SPACE:
        scsi_tape_space(r, buf);
        break;

    case READ_6:
        buflen = scsi_tape_read6(r, buf);
        break;

    case WRITE_6:
        if ((buf[1] & 0x01) && scsi_tape_fixed_without_length(s, buf)) {
            scsi_tape_check_condition(r, SENSE_CODE(INVALID_FIELD));
            break;
        }
        if (!blk_is_writable(s->qdev.conf.blk)) {
            scsi_tape_check_condition(r, SENSE_CODE(WRITE_PROTECTED));
            break;
        }
        if (req->cmd.xfer == 0) {
            break;
        }
        r->awaiting_data_out = true;
        return -(int32_t)req->cmd.xfer;

    case WRITE_FILEMARKS:
        scsi_tape_write_filemarks(r, buf);
        break;

    case ERASE:
        scsi_tape_erase(r, buf);
        break;

    default:
        scsi_tape_check_condition(r, SENSE_CODE(INVALID_OPCODE));
        break;
    }

    /* A CHECK CONDITION above has already completed the request. */
    if (req->status != -1) {
        return 0;
    }
    if (buflen <= 0) {
        scsi_req_complete(req, GOOD);
        return 0;
    }
    r->buflen = MAX(r->buflen, (uint32_t)buflen);
    return buflen;
}

static void scsi_tape_read_data(SCSIRequest *req)
{
    SCSITapeReq *r = DO_UPCAST(SCSITapeReq, req, req);
    uint32_t n = MIN(r->buflen, req->cmd.xfer);

    if (n) {
        /* The whole reply is handed over in one go; the next call ends it. */
        r->buflen = 0;
        scsi_req_data(req, n);
        return;
    }
    scsi_req_complete(req, r->deferred_check ? CHECK_CONDITION : GOOD);
}

static void scsi_tape_write_data(SCSIRequest *req)
{
    SCSITapeReq *r = DO_UPCAST(SCSITapeReq, req, req);

    if (r->awaiting_data_out) {
        /* First call: fetch the data; the HBA calls back when it is in. */
        r->awaiting_data_out = false;
        scsi_req_data(req, req->cmd.xfer);
        return;
    }

    switch (req->cmd.buf[0]) {
    case WRITE_6:
        scsi_tape_write6(r);
        break;
    default:
        scsi_tape_check_condition(r, SENSE_CODE(INVALID_OPCODE));
        break;
    }

    if (req->status == -1) {
        scsi_req_complete(req, GOOD);
    }
}

static uint8_t *scsi_tape_get_buf(SCSIRequest *req)
{
    SCSITapeReq *r = DO_UPCAST(SCSITapeReq, req, req);

    return r->buf;
}

static void scsi_tape_free_request(SCSIRequest *req)
{
    SCSITapeReq *r = DO_UPCAST(SCSITapeReq, req, req);

    g_free(r->buf);
}

static const SCSIReqOps scsi_tape_reqops = {
    .size         = sizeof(SCSITapeReq),
    .free_req     = scsi_tape_free_request,
    .send_command = scsi_tape_send_command,
    .read_data    = scsi_tape_read_data,
    .write_data   = scsi_tape_write_data,
    .get_buf      = scsi_tape_get_buf,
};

static SCSIRequest *scsi_tape_new_request(SCSIDevice *d, uint32_t tag,
                                          uint32_t lun, uint8_t *buf,
                                          void *hba_private)
{
    return scsi_req_alloc(&scsi_tape_reqops, d, tag, lun, hba_private);
}

static void scsi_tape_realize(SCSIDevice *dev, Error **errp)
{
    SCSITapeState *s = SCSI_TAPE(dev);
    bool read_only;

    if (!s->qdev.conf.blk) {
        error_setg(errp, "drive property not set");
        return;
    }

    read_only = !blk_is_inserted(s->qdev.conf.blk) ||
                !blk_supports_write_perm(s->qdev.conf.blk);
    if (!blkconf_apply_backend_options(&s->qdev.conf, read_only, false,
                                       errp)) {
        return;
    }
    if (!read_only) {
        scsi_tape_note_mount(s);
    }

    if (!s->vendor) {
        s->vendor = g_strdup(SCSI_TAPE_DEFAULT_VENDOR);
    }
    if (!s->product) {
        s->product = g_strdup(SCSI_TAPE_DEFAULT_PRODUCT);
    }
    if (!s->ver) {
        s->ver = g_strdup(SCSI_TAPE_DEFAULT_VERSION);
    }

    s->qdev.type = TYPE_TAPE;
    s->qdev.blocksize = s->block_size;
    scsi_tape_rewind(s);
    s->loaded = blk_is_inserted(s->qdev.conf.blk);
}

static const VMStateDescription vmstate_scsi_tape = {
    .name = "scsi-tape",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]) {
        VMSTATE_SCSI_DEVICE(qdev, SCSITapeState),
        VMSTATE_UINT64(pos, SCSITapeState),
        VMSTATE_UINT32(rec_consumed, SCSITapeState),
        VMSTATE_BOOL(loaded, SCSITapeState),
        VMSTATE_END_OF_LIST()
    }
};

static const Property scsi_tape_properties[] = {
    DEFINE_PROP_DRIVE("drive", SCSITapeState, qdev.conf.blk),
    DEFINE_PROP_UINT32("block-size", SCSITapeState, block_size,
                       SCSI_TAPE_DEFAULT_BLOCK_SIZE),
    DEFINE_PROP_STRING("vendor", SCSITapeState, vendor),
    DEFINE_PROP_STRING("product", SCSITapeState, product),
    DEFINE_PROP_STRING("ver", SCSITapeState, ver),
    DEFINE_PROP_BOOL("eom-at-eod", SCSITapeState, eom_at_eod, false),
    DEFINE_PROP_BOOL("join-records", SCSITapeState, join_records, false),
    DEFINE_PROP_UINT32("capacity-mb", SCSITapeState, capacity_mb, 0),
};

static void scsi_tape_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    SCSIDeviceClass *sc = SCSI_DEVICE_CLASS(klass);

    sc->realize = scsi_tape_realize;
    sc->alloc_req = scsi_tape_new_request;
    dc->desc = "virtual SCSI tape drive (SIMH .tap image)";
    device_class_set_props(dc, scsi_tape_properties);
    dc->vmsd = &vmstate_scsi_tape;
}

static const TypeInfo scsi_tape_info = {
    .name          = TYPE_SCSI_TAPE,
    .parent        = TYPE_SCSI_DEVICE,
    .instance_size = sizeof(SCSITapeState),
    .class_init    = scsi_tape_class_init,
};

static void scsi_tape_register_types(void)
{
    type_register_static(&scsi_tape_info);
}

type_init(scsi_tape_register_types)
