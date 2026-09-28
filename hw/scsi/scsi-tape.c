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
#include "qemu/cutils.h"
#include "qemu/module.h"
#include "hw/scsi/scsi.h"
#include "scsi/constants.h"
#include "system/block-backend.h"
#include "hw/block/block.h"
#include "hw/core/qdev-properties.h"
#include "hw/core/qdev-properties-system.h"
#include "migration/vmstate.h"
#include "qom/object.h"

#define TYPE_SCSI_TAPE "scsi-tape"
OBJECT_DECLARE_SIMPLE_TYPE(SCSITapeState, SCSI_TAPE)

/* 0 is variable-block mode */
#define SCSI_TAPE_DEFAULT_BLOCK_SIZE    0
#define SCSI_TAPE_MIN_BUFLEN            256

#define SCSI_TAPE_DEFAULT_VENDOR        "HP"
#define SCSI_TAPE_DEFAULT_PRODUCT       "C1537A"
#define SCSI_TAPE_DEFAULT_VERSION       "L708"
#define SCSI_TAPE_INQUIRY_LEN           96

struct SCSITapeState {
    SCSIDevice qdev;

    /* Byte offset in the image of the next record header; 0 is BOP. */
    uint64_t pos;

    /* Block length used for fixed-mode transfers ("block-size"). */
    uint32_t block_size;

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
} SCSITapeReq;

static void scsi_tape_check_condition(SCSITapeReq *r, SCSISense sense)
{
    scsi_req_build_sense(&r->req, sense);
    scsi_req_complete(&r->req, CHECK_CONDITION);
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
    scsi_req_complete(req, GOOD);
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
    s->pos = 0;
    s->loaded = blk_is_inserted(s->qdev.conf.blk);
}

static const VMStateDescription vmstate_scsi_tape = {
    .name = "scsi-tape",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]) {
        VMSTATE_SCSI_DEVICE(qdev, SCSITapeState),
        VMSTATE_UINT64(pos, SCSITapeState),
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
