/*
 * QTest testcase for VirtIO SCSI
 *
 * Copyright (c) 2014 SUSE LINUX Products GmbH
 * Copyright (c) 2015 Red Hat Inc.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "libqtest-single.h"
#include "qemu/bswap.h"
#include "qemu/module.h"
#include "scsi/constants.h"
#include "libqos/libqos-pc.h"
#include "libqos/libqos-spapr.h"
#include "libqos/virtio.h"
#include "libqos/virtio-pci.h"
#include "standard-headers/linux/virtio_ids.h"
#include "standard-headers/linux/virtio_pci.h"
#include "standard-headers/linux/virtio_scsi.h"
#include "libqos/virtio-scsi.h"
#include "libqos/qgraph.h"

#define PCI_SLOT                0x02
#define PCI_FN                  0x00
#define QVIRTIO_SCSI_TIMEOUT_US (1 * 1000 * 1000)

#define MAX_NUM_QUEUES 64

typedef struct {
    QVirtioDevice *dev;
    int num_queues;
    QVirtQueue *vq[MAX_NUM_QUEUES + 2];
} QVirtioSCSIQueues;

static QGuestAllocator *alloc;

static void qvirtio_scsi_pci_free(QVirtioSCSIQueues *vs)
{
    int i;

    for (i = 0; i < vs->num_queues + 2; i++) {
        qvirtqueue_cleanup(vs->dev->bus, vs->vq[i], alloc);
    }
    g_free(vs);
}

static uint64_t qvirtio_scsi_alloc(QVirtioSCSIQueues *vs, size_t alloc_size,
                                   const void *data)
{
    uint64_t addr;

    addr = guest_alloc(alloc, alloc_size);
    if (data) {
        memwrite(addr, data, alloc_size);
    }

    return addr;
}

static uint8_t virtio_scsi_do_command(QVirtioSCSIQueues *vs,
                                      const uint8_t *cdb,
                                      uint8_t *data_in,
                                      size_t data_in_len,
                                      uint8_t *data_out, size_t data_out_len,
                                      struct virtio_scsi_cmd_resp *resp_out)
{
    QVirtQueue *vq;
    struct virtio_scsi_cmd_req req = { { 0 } };
    struct virtio_scsi_cmd_resp resp = { .response = 0xff, .status = 0xff };
    uint64_t req_addr, resp_addr, data_in_addr = 0, data_out_addr = 0;
    uint8_t response;
    uint32_t free_head;
    QTestState *qts = global_qtest;

    vq = vs->vq[2];

    req.lun[0] = 1; /* Select LUN */
    req.lun[1] = 1; /* Select target 1 */
    memcpy(req.cdb, cdb, VIRTIO_SCSI_CDB_SIZE);

    /* XXX: Fix endian if any multi-byte field in req/resp is used */

    /* Add request header */
    req_addr = qvirtio_scsi_alloc(vs, sizeof(req), &req);
    free_head = qvirtqueue_add(qts, vq, req_addr, sizeof(req), false, true);

    if (data_out_len) {
        data_out_addr = qvirtio_scsi_alloc(vs, data_out_len, data_out);
        qvirtqueue_add(qts, vq, data_out_addr, data_out_len, false, true);
    }

    /* Add response header */
    resp_addr = qvirtio_scsi_alloc(vs, sizeof(resp), &resp);
    qvirtqueue_add(qts, vq, resp_addr, sizeof(resp), true, !!data_in_len);

    if (data_in_len) {
        data_in_addr = qvirtio_scsi_alloc(vs, data_in_len, data_in);
        qvirtqueue_add(qts, vq, data_in_addr, data_in_len, true, false);
    }

    qvirtqueue_kick(qts, vs->dev, vq, free_head);
    qvirtio_wait_used_elem(qts, vs->dev, vq, free_head, NULL,
                           QVIRTIO_SCSI_TIMEOUT_US);

    response = readb(resp_addr +
                     offsetof(struct virtio_scsi_cmd_resp, response));

    if (resp_out) {
        memread(resp_addr, resp_out, sizeof(*resp_out));
    }
    if (data_in_len) {
        memread(data_in_addr, data_in, data_in_len);
    }

    guest_free(alloc, req_addr);
    guest_free(alloc, resp_addr);
    guest_free(alloc, data_in_addr);
    guest_free(alloc, data_out_addr);
    return response;
}

static QVirtioSCSIQueues *qvirtio_scsi_init_queues(QVirtioDevice *dev)
{
    QVirtioSCSIQueues *vs;
    uint64_t features;
    int i;

    vs = g_new0(QVirtioSCSIQueues, 1);
    vs->dev = dev;

    features = qvirtio_get_features(dev);
    features &= ~(QVIRTIO_F_BAD_FEATURE | (1ull << VIRTIO_RING_F_EVENT_IDX));
    qvirtio_set_features(dev, features);

    vs->num_queues = qvirtio_config_readl(dev, 0);

    g_assert_cmpint(vs->num_queues, <, MAX_NUM_QUEUES);

    for (i = 0; i < vs->num_queues + 2; i++) {
        vs->vq[i] = qvirtqueue_setup(dev, alloc, i);
    }

    qvirtio_set_driver_ok(dev);
    return vs;
}

static QVirtioSCSIQueues *qvirtio_scsi_init(QVirtioDevice *dev)
{
    QVirtioSCSIQueues *vs = qvirtio_scsi_init_queues(dev);
    const uint8_t test_unit_ready_cdb[VIRTIO_SCSI_CDB_SIZE] = {};
    struct virtio_scsi_cmd_resp resp;

    /* Clear the POWER ON OCCURRED unit attention */
    g_assert_cmpint(virtio_scsi_do_command(vs, test_unit_ready_cdb,
                                           NULL, 0, NULL, 0, &resp),
                    ==, 0);
    g_assert_cmpint(resp.status, ==, CHECK_CONDITION);
    g_assert_cmpint(resp.sense[0], ==, 0x70); /* Fixed format sense buffer */
    g_assert_cmpint(resp.sense[2], ==, UNIT_ATTENTION);
    g_assert_cmpint(resp.sense[12], ==, 0x29); /* POWER ON */
    g_assert_cmpint(resp.sense[13], ==, 0x00);

    return vs;
}

static void hotplug(void *obj, void *data, QGuestAllocator *t_alloc)
{
    QTestState *qts = global_qtest;

    qtest_qmp_device_add(qts, "scsi-hd", "scsihd", "{'drive': 'drv1'}");
    qtest_qmp_device_del(qts, "scsihd");
}

/* Test WRITE SAME with the lba not aligned */
static void test_unaligned_write_same(void *obj, void *data,
                                      QGuestAllocator *t_alloc)
{
    QVirtioSCSI *scsi = obj;
    QVirtioSCSIQueues *vs;
    uint8_t buf1[512] = { 0 };
    uint8_t buf2[512] = { 1 };
    const uint8_t write_same_cdb_1[VIRTIO_SCSI_CDB_SIZE] = {
        0x41, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x02, 0x00
    };
    const uint8_t write_same_cdb_2[VIRTIO_SCSI_CDB_SIZE] = {
        0x41, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x33, 0x00, 0x00
    };
    const uint8_t write_same_cdb_ndob[VIRTIO_SCSI_CDB_SIZE] = {
        0x41, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x33, 0x00, 0x00
    };

    alloc = t_alloc;
    vs = qvirtio_scsi_init(scsi->vdev);

    g_assert_cmphex(0, ==,
        virtio_scsi_do_command(vs, write_same_cdb_1, NULL, 0, buf1, 512,
                               NULL));

    g_assert_cmphex(0, ==,
        virtio_scsi_do_command(vs, write_same_cdb_2, NULL, 0, buf2, 512,
                               NULL));

    g_assert_cmphex(0, ==,
        virtio_scsi_do_command(vs, write_same_cdb_ndob, NULL, 0, NULL, 0,
                               NULL));

    qvirtio_scsi_pci_free(vs);
}

/* Test UNMAP with a large LBA, issue #345 */
static void test_unmap_large_lba(void *obj, void *data,
                                      QGuestAllocator *t_alloc)
{
    QVirtioSCSI *scsi = obj;
    QVirtioSCSIQueues *vs;
    const uint8_t unmap[VIRTIO_SCSI_CDB_SIZE] = {
        0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x00
    };

    /*
     * Default null-co device size is 2**30
     * LBA 0x7fff is ~ 1/8 into device, with 4k blocks
     * if check_lba_range incorrectly using 512 bytes, will trigger sense error
     */
    uint8_t unmap_params[0x18] = {
        0x00, 0x16, /* unmap data length */
        0x00, 0x10, /* unmap block descriptor data length */
        0x00, 0x00, 0x00, 0x00, /* reserved */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7f, 0xff, /* LBA */
        0x00, 0x00, 0x03, 0xff, /* sector count */
        0x00, 0x00, 0x00, 0x00, /* reserved */
    };
    struct virtio_scsi_cmd_resp resp;

    alloc = t_alloc;
    vs = qvirtio_scsi_init(scsi->vdev);

    virtio_scsi_do_command(vs, unmap, NULL, 0, unmap_params,
                           sizeof(unmap_params), &resp);
    g_assert_cmphex(resp.response, ==, 0);
    g_assert_cmphex(resp.status, !=, CHECK_CONDITION);

    qvirtio_scsi_pci_free(vs);
}

static void test_write_to_cdrom(void *obj, void *data,
                                QGuestAllocator *t_alloc)
{
    QVirtioSCSI *scsi = obj;
    QVirtioSCSIQueues *vs;
    uint8_t buf[2048] = { 0 };
    const uint8_t write_cdb[VIRTIO_SCSI_CDB_SIZE] = {
        /* WRITE(10) to LBA 0, transfer length 1 */
        0x2a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00
    };
    struct virtio_scsi_cmd_resp resp;

    alloc = t_alloc;
    vs = qvirtio_scsi_init(scsi->vdev);

    virtio_scsi_do_command(vs, write_cdb, NULL, 0, buf, 2048, &resp);
    g_assert_cmphex(resp.response, ==, 0);
    g_assert_cmphex(resp.status, ==, CHECK_CONDITION);
    g_assert_cmphex(resp.sense[0], ==, 0x70);
    g_assert_cmphex(resp.sense[2], ==, DATA_PROTECT);
    g_assert_cmphex(resp.sense[12], ==, 0x27); /* WRITE PROTECTED */
    g_assert_cmphex(resp.sense[13], ==, 0x00); /* WRITE PROTECTED */

    qvirtio_scsi_pci_free(vs);
}

static void test_iothread_attach_node(void *obj, void *data,
                                      QGuestAllocator *t_alloc)
{
    QVirtioSCSIPCI *scsi_pci = obj;
    QVirtioSCSI *scsi = &scsi_pci->scsi;
    QVirtioSCSIQueues *vs;
    g_autofree char *tmp_path = NULL;
    int fd;
    int ret;

    uint8_t buf[512] = { 0 };
    const uint8_t write_cdb[VIRTIO_SCSI_CDB_SIZE] = {
        /* WRITE(10) to LBA 0, transfer length 1 */
        0x2a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00
    };

    alloc = t_alloc;
    vs = qvirtio_scsi_init(scsi->vdev);

    /* Create a temporary qcow2 overlay*/
    fd = g_file_open_tmp("qtest.XXXXXX", &tmp_path, NULL);
    g_assert(fd >= 0);
    close(fd);

    if (!have_qemu_img()) {
        g_test_message("QTEST_QEMU_IMG not set or qemu-img missing; "
                       "skipping snapshot test");
        goto fail;
    }

    mkqcow2(tmp_path, 64);

    /* Attach the overlay to the null0 node */
    qtest_qmp_assert_success(scsi_pci->pci_vdev.pdev->bus->qts,
                             "{'execute': 'blockdev-add', 'arguments': {"
                             "   'driver': 'qcow2', 'node-name': 'overlay',"
                             "   'backing': 'null0', 'file': {"
                             "     'driver': 'file', 'filename': %s}}}",
                             tmp_path);

    /* Send a request to see if the AioContext is still right */
    ret = virtio_scsi_do_command(vs, write_cdb, NULL, 0, buf, 512, NULL);
    g_assert_cmphex(ret, ==, 0);

fail:
    qvirtio_scsi_pci_free(vs);
    unlink(tmp_path);
}

static void test_iothread_virtio_error(void *obj, void *data,
                                       QGuestAllocator *t_alloc)
{
    QVirtioSCSIPCI *scsi_pci = obj;
    QVirtioSCSI *scsi = &scsi_pci->scsi;
    QVirtioSCSIQueues *vs;
    QVirtQueue *vq;

    alloc = t_alloc;
    vs = qvirtio_scsi_init(scsi->vdev);
    vq = vs->vq[2];

    /* Move avail.idx out of bounds to trigger virtio_error() */
    qvirtqueue_set_avail_idx(global_qtest, scsi->vdev, vq, vq->size * 2);
    scsi->vdev->bus->virtqueue_kick(scsi->vdev, vq);

    /*
     * Reset the device out of the error state. If QEMU hangs or crashes then
     * this will fail.
     */
    qvirtio_reset(scsi->vdev);

    qvirtio_scsi_pci_free(vs);
}

/* scsi-tape */

static char *tape_path;

static uint8_t tape_cmd(QVirtioSCSIQueues *vs, const uint8_t *cdb,
                        uint8_t *data_in, size_t data_in_len,
                        uint8_t *data_out, size_t data_out_len,
                        struct virtio_scsi_cmd_resp *resp)
{
    g_assert_cmpint(virtio_scsi_do_command(vs, cdb, data_in, data_in_len,
                                           data_out, data_out_len, resp),
                    ==, 0);
    return resp->status;
}

static void tape_assert_sense(struct virtio_scsi_cmd_resp *resp,
                              uint8_t flags_key, uint8_t asc, uint8_t ascq)
{
    g_assert_cmphex(resp->status, ==, CHECK_CONDITION);
    g_assert_cmphex(resp->sense[0] & 0x7f, ==, 0x70);
    g_assert_cmphex(resp->sense[2], ==, flags_key);
    g_assert_cmphex(resp->sense[12], ==, asc);
    g_assert_cmphex(resp->sense[13], ==, ascq);
}

static uint32_t tape_sense_info(struct virtio_scsi_cmd_resp *resp)
{
    g_assert(resp->sense[0] & 0x80);    /* VALID */
    return ldl_be_p(&resp->sense[3]);
}

static uint32_t tape_read_position(QVirtioSCSIQueues *vs, bool *bop)
{
    const uint8_t cdb[VIRTIO_SCSI_CDB_SIZE] = { READ_POSITION };
    struct virtio_scsi_cmd_resp resp;
    uint8_t pos[20];

    g_assert_cmphex(tape_cmd(vs, cdb, pos, sizeof(pos), NULL, 0, &resp),
                    ==, GOOD);
    g_assert_cmphex(pos[0] & 0x04, ==, 0);      /* BPU clear */
    *bop = pos[0] & 0x80;
    g_assert_cmpuint(ldl_be_p(&pos[4]), ==, ldl_be_p(&pos[8]));
    return ldl_be_p(&pos[4]);
}

/* MODE SENSE(6): the block length of the block descriptor */
static uint32_t tape_block_length(QVirtioSCSIQueues *vs)
{
    const uint8_t cdb[VIRTIO_SCSI_CDB_SIZE] = { MODE_SENSE, 0, 0, 0, 12 };
    struct virtio_scsi_cmd_resp resp;
    uint8_t hdr[12];

    g_assert_cmphex(tape_cmd(vs, cdb, hdr, sizeof(hdr), NULL, 0, &resp),
                    ==, GOOD);
    g_assert_cmpuint(hdr[3], ==, 8);    /* block descriptor length */
    return ldl_be_p(&hdr[8]) & 0xffffff;
}

/* Consume the unit attention that the reset left behind. */
static void tape_start(QVirtioSCSIQueues *vs)
{
    const uint8_t tur[VIRTIO_SCSI_CDB_SIZE] = { TEST_UNIT_READY };
    struct virtio_scsi_cmd_resp resp;

    tape_cmd(vs, tur, NULL, 0, NULL, 0, &resp);
    g_assert_cmphex(resp.status, ==, CHECK_CONDITION);
    g_assert_cmphex(resp.sense[2], ==, UNIT_ATTENTION);
    g_assert_cmphex(resp.sense[12], ==, 0x29);
    g_assert_cmphex(tape_cmd(vs, tur, NULL, 0, NULL, 0, &resp), ==, GOOD);
}

static void tape_finish(QVirtioSCSIQueues *vs)
{
    qvirtio_scsi_pci_free(vs);
    unlink(tape_path);
    g_free(tape_path);
    tape_path = NULL;
}

/* Append one .tap data record to @tap. */
static void tape_append_record(GByteArray *tap, const uint8_t *data,
                               uint32_t len)
{
    uint8_t word[4];
    uint8_t pad = 0;

    stl_le_p(word, len);
    g_byte_array_append(tap, word, 4);
    g_byte_array_append(tap, data, len);
    if (len & 1) {
        g_byte_array_append(tap, &pad, 1);
    }
    g_byte_array_append(tap, word, 4);
}

/*
 * Default properties.  Write records of both modes and a filemark to an
 * empty image, check the image byte for byte, then position and read
 * everything back.
 */
static void test_tape_round_trip(void *obj, void *data,
                                 QGuestAllocator *t_alloc)
{
    QVirtioSCSI *scsi = obj;
    QVirtioSCSIQueues *vs;
    struct virtio_scsi_cmd_resp resp;
    const uint8_t tur[VIRTIO_SCSI_CDB_SIZE] = { TEST_UNIT_READY };
    const uint8_t inquiry[VIRTIO_SCSI_CDB_SIZE] = { INQUIRY, 0, 0, 0, 96 };
    const uint8_t write_100[VIRTIO_SCSI_CDB_SIZE] = { WRITE_6, 0, 0, 0, 100 };
    const uint8_t write_513[VIRTIO_SCSI_CDB_SIZE] = { WRITE_6, 0, 0, 2, 1 };
    const uint8_t write_2blk[VIRTIO_SCSI_CDB_SIZE] = { WRITE_6, 1, 0, 0, 2 };
    const uint8_t wfm_1[VIRTIO_SCSI_CDB_SIZE] = { WRITE_FILEMARKS, 0, 0, 0, 1 };
    const uint8_t rewind[VIRTIO_SCSI_CDB_SIZE] = { REWIND };
    const uint8_t read_100[VIRTIO_SCSI_CDB_SIZE] = { READ_6, 0, 0, 0, 100 };
    const uint8_t read_1024[VIRTIO_SCSI_CDB_SIZE] = { READ_6, 0, 0, 4, 0 };
    const uint8_t read_1024_sili[VIRTIO_SCSI_CDB_SIZE] = { READ_6, 2, 0, 4, 0 };
    const uint8_t read_2blk[VIRTIO_SCSI_CDB_SIZE] = { READ_6, 1, 0, 0, 2 };
    const uint8_t locate_1[VIRTIO_SCSI_CDB_SIZE] = { LOCATE_10, 0, 0,
                                                     0, 0, 0, 1 };
    const uint8_t space_back_1[VIRTIO_SCSI_CDB_SIZE] = { SPACE, 0,
                                                         0xff, 0xff, 0xff };
    const uint8_t prevent[VIRTIO_SCSI_CDB_SIZE] = { ALLOW_MEDIUM_REMOVAL,
                                                    0, 0, 0, 1 };
    const uint8_t unload[VIRTIO_SCSI_CDB_SIZE] = { LOAD_UNLOAD };
    const uint8_t load[VIRTIO_SCSI_CDB_SIZE] = { LOAD_UNLOAD, 0, 0, 0, 1 };
    const uint8_t select_6[VIRTIO_SCSI_CDB_SIZE] = { MODE_SELECT, 0x10,
                                                     0, 0, 12 };
    /* Header (BUF set) and a block descriptor with block length 512 */
    uint8_t select_512[12] = { 0, 0, 0x10, 8, 0, 0, 0, 0, 0, 0, 2, 0 };
    const uint8_t log_pages[VIRTIO_SCSI_CDB_SIZE] = { LOG_SENSE, 0, 0x00,
                                                      0, 0, 0, 0, 0, 64 };
    uint8_t rec1[100], rec2[513], blocks[1024], buf[1024];
    g_autoptr(GByteArray) expect = g_byte_array_new();
    g_autofree char *contents = NULL;
    const uint8_t tapemark[4] = { 0, 0, 0, 0 };
    const uint8_t end_of_medium[4] = { 0xff, 0xff, 0xff, 0xff };
    gsize len;
    bool bop;
    int i;

    for (i = 0; i < sizeof(rec1); i++) {
        rec1[i] = i;
    }
    for (i = 0; i < sizeof(rec2); i++) {
        rec2[i] = 0xa5 ^ i;
    }
    for (i = 0; i < sizeof(blocks); i++) {
        blocks[i] = i * 7;
    }

    alloc = t_alloc;
    vs = qvirtio_scsi_init_queues(scsi->vdev);
    tape_start(vs);

    g_assert_cmphex(tape_cmd(vs, inquiry, buf, 96, NULL, 0, &resp),
                    ==, GOOD);
    g_assert_cmphex(buf[0], ==, TYPE_TAPE);
    g_assert_cmphex(buf[1], ==, 0x80);          /* removable */
    g_assert(!memcmp(&buf[8], "HP      C1537A          L708", 28));

    /* Variable-block mode by default: fixed-block transfers are refused */
    g_assert_cmpuint(tape_block_length(vs), ==, 0);
    tape_cmd(vs, write_2blk, NULL, 0, NULL, 0, &resp);
    tape_assert_sense(&resp, ILLEGAL_REQUEST, 0x24, 0x00);
    tape_cmd(vs, read_2blk, buf, 1024, NULL, 0, &resp);
    tape_assert_sense(&resp, ILLEGAL_REQUEST, 0x24, 0x00);
    g_assert_cmphex(tape_cmd(vs, select_6, NULL, 0, select_512,
                             sizeof(select_512), &resp), ==, GOOD);
    g_assert_cmpuint(tape_block_length(vs), ==, 512);

    /* Write: 100 bytes, 513 bytes, a filemark, two fixed 512-byte blocks */
    g_assert_cmphex(tape_cmd(vs, write_100, NULL, 0, rec1, sizeof(rec1),
                             &resp), ==, GOOD);
    g_assert_cmphex(tape_cmd(vs, write_513, NULL, 0, rec2, sizeof(rec2),
                             &resp), ==, GOOD);
    g_assert_cmphex(tape_cmd(vs, wfm_1, NULL, 0, NULL, 0, &resp), ==, GOOD);
    g_assert_cmphex(tape_cmd(vs, write_2blk, NULL, 0, blocks, sizeof(blocks),
                             &resp), ==, GOOD);
    g_assert_cmpuint(tape_read_position(vs, &bop), ==, 5);
    g_assert(!bop);

    /* The image is a plain .tap file */
    tape_append_record(expect, rec1, sizeof(rec1));
    tape_append_record(expect, rec2, sizeof(rec2));
    g_byte_array_append(expect, tapemark, 4);
    tape_append_record(expect, blocks, 512);
    tape_append_record(expect, blocks + 512, 512);
    g_byte_array_append(expect, end_of_medium, 4);
    g_assert(g_file_get_contents(tape_path, &contents, &len, NULL));
    g_assert_cmpuint(len, ==, expect->len);
    g_assert(!memcmp(contents, expect->data, len));

    /* Read back */
    g_assert_cmphex(tape_cmd(vs, rewind, NULL, 0, NULL, 0, &resp), ==, GOOD);
    g_assert_cmpuint(tape_read_position(vs, &bop), ==, 0);
    g_assert(bop);

    memset(buf, 0, sizeof(buf));
    g_assert_cmphex(tape_cmd(vs, read_100, buf, 100, NULL, 0, &resp),
                    ==, GOOD);
    g_assert(!memcmp(buf, rec1, sizeof(rec1)));

    /* Short record, SILI clear: data, then ILI with the residue */
    memset(buf, 0, sizeof(buf));
    tape_cmd(vs, read_1024, buf, 1024, NULL, 0, &resp);
    tape_assert_sense(&resp, 0x20 | NO_SENSE, 0x00, 0x00);
    g_assert_cmpuint(tape_sense_info(&resp), ==, 1024 - 513);
    g_assert(!memcmp(buf, rec2, sizeof(rec2)));

    tape_cmd(vs, read_100, buf, 100, NULL, 0, &resp);
    tape_assert_sense(&resp, 0x80 | NO_SENSE, 0x00, 0x01);  /* filemark */

    memset(buf, 0, sizeof(buf));
    g_assert_cmphex(tape_cmd(vs, read_2blk, buf, 1024, NULL, 0, &resp),
                    ==, GOOD);
    g_assert(!memcmp(buf, blocks, sizeof(blocks)));

    tape_cmd(vs, read_100, buf, 100, NULL, 0, &resp);
    /* End of data, before early warning: no EOM */
    tape_assert_sense(&resp, BLANK_CHECK, 0x00, 0x05);

    /* Position: LOCATE to object 1, read it with SILI set */
    g_assert_cmphex(tape_cmd(vs, locate_1, NULL, 0, NULL, 0, &resp), ==, GOOD);
    memset(buf, 0, sizeof(buf));
    g_assert_cmphex(tape_cmd(vs, read_1024_sili, buf, 1024, NULL, 0, &resp),
                    ==, GOOD);
    g_assert(!memcmp(buf, rec2, sizeof(rec2)));
    g_assert_cmpuint(tape_read_position(vs, &bop), ==, 2);
    g_assert_cmphex(tape_cmd(vs, space_back_1, NULL, 0, NULL, 0, &resp),
                    ==, GOOD);
    g_assert_cmpuint(tape_read_position(vs, &bop), ==, 1);

    /*
     * A fixed-block read of the 513-byte record: an incorrect-length
     * block, so ILI, both blocks not read, and the record is passed
     */
    tape_cmd(vs, read_2blk, buf, 1024, NULL, 0, &resp);
    tape_assert_sense(&resp, 0x20 | NO_SENSE, 0x00, 0x00);
    g_assert_cmpuint(tape_sense_info(&resp), ==, 2);
    g_assert_cmpuint(tape_read_position(vs, &bop), ==, 2);

    /*
     * UNLOAD under PREVENT keeps the tape in the drive, rewound, and
     * medium access reports NOT READY until a LOAD.
     */
    g_assert_cmphex(tape_cmd(vs, prevent, NULL, 0, NULL, 0, &resp), ==, GOOD);
    g_assert_cmphex(tape_cmd(vs, unload, NULL, 0, NULL, 0, &resp), ==, GOOD);
    tape_cmd(vs, tur, NULL, 0, NULL, 0, &resp);
    tape_assert_sense(&resp, NOT_READY, 0x3a, 0x00);
    tape_cmd(vs, rewind, NULL, 0, NULL, 0, &resp);
    tape_assert_sense(&resp, NOT_READY, 0x3a, 0x00);
    g_assert_cmphex(tape_cmd(vs, load, NULL, 0, NULL, 0, &resp), ==, GOOD);
    g_assert_cmphex(tape_cmd(vs, tur, NULL, 0, NULL, 0, &resp), ==, GOOD);
    g_assert_cmpuint(tape_read_position(vs, &bop), ==, 0);

    /* LOG SENSE supported pages */
    memset(buf, 0, sizeof(buf));
    g_assert_cmphex(tape_cmd(vs, log_pages, buf, 64, NULL, 0, &resp),
                    ==, GOOD);
    g_assert_cmphex(buf[0], ==, 0x00);
    g_assert_cmphex(lduw_be_p(&buf[2]), ==, 3);
    g_assert_cmphex(buf[4], ==, 0x00);
    g_assert_cmphex(buf[5], ==, 0x02);
    g_assert_cmphex(buf[6], ==, 0x03);

    tape_finish(vs);
}

/*
 * block-size=512, eom-at-eod=on, autoload-after-unload=on and
 * join-records=on: fixed blocks from power-on, a record read as several
 * blocks, EOM at every end of data, and a tape unloaded under PREVENT
 * that the next medium access loads again.
 */
static void test_tape_options(void *obj, void *data,
                              QGuestAllocator *t_alloc)
{
    QVirtioSCSI *scsi = obj;
    QVirtioSCSIQueues *vs;
    struct virtio_scsi_cmd_resp resp;
    const uint8_t tur[VIRTIO_SCSI_CDB_SIZE] = { TEST_UNIT_READY };
    const uint8_t write_2blk[VIRTIO_SCSI_CDB_SIZE] = { WRITE_6, 1, 0, 0, 2 };
    const uint8_t write_1024[VIRTIO_SCSI_CDB_SIZE] = { WRITE_6, 0, 0, 4, 0 };
    const uint8_t rewind[VIRTIO_SCSI_CDB_SIZE] = { REWIND };
    const uint8_t read_2blk[VIRTIO_SCSI_CDB_SIZE] = { READ_6, 1, 0, 0, 2 };
    const uint8_t read_100[VIRTIO_SCSI_CDB_SIZE] = { READ_6, 0, 0, 0, 100 };
    const uint8_t prevent[VIRTIO_SCSI_CDB_SIZE] = { ALLOW_MEDIUM_REMOVAL,
                                                    0, 0, 0, 1 };
    const uint8_t unload[VIRTIO_SCSI_CDB_SIZE] = { LOAD_UNLOAD };
    uint8_t blocks[1024], buf[1024];
    bool bop;
    int i;

    for (i = 0; i < sizeof(blocks); i++) {
        blocks[i] = i * 3;
    }

    alloc = t_alloc;
    vs = qvirtio_scsi_init_queues(scsi->vdev);
    tape_start(vs);

    /* Fixed blocks without a MODE SELECT, then one 1024-byte record */
    g_assert_cmpuint(tape_block_length(vs), ==, 512);
    g_assert_cmphex(tape_cmd(vs, write_2blk, NULL, 0, blocks, sizeof(blocks),
                             &resp), ==, GOOD);
    g_assert_cmphex(tape_cmd(vs, write_1024, NULL, 0, blocks, sizeof(blocks),
                             &resp), ==, GOOD);
    g_assert_cmphex(tape_cmd(vs, rewind, NULL, 0, NULL, 0, &resp), ==, GOOD);
    memset(buf, 0, sizeof(buf));
    g_assert_cmphex(tape_cmd(vs, read_2blk, buf, 1024, NULL, 0, &resp),
                    ==, GOOD);
    g_assert(!memcmp(buf, blocks, sizeof(blocks)));

    /* The 1024-byte record is read as two blocks */
    memset(buf, 0, sizeof(buf));
    g_assert_cmphex(tape_cmd(vs, read_2blk, buf, 1024, NULL, 0, &resp),
                    ==, GOOD);
    g_assert(!memcmp(buf, blocks, sizeof(blocks)));

    /* End of data reports EOM */
    tape_cmd(vs, read_100, buf, 100, NULL, 0, &resp);
    tape_assert_sense(&resp, 0x40 | BLANK_CHECK, 0x00, 0x05);

    /*
     * UNLOAD under PREVENT: only TEST UNIT READY reports NOT READY, the
     * next medium access loads the tape again, and PREVENT has ended.
     */
    g_assert_cmphex(tape_cmd(vs, prevent, NULL, 0, NULL, 0, &resp), ==, GOOD);
    g_assert_cmphex(tape_cmd(vs, unload, NULL, 0, NULL, 0, &resp), ==, GOOD);
    tape_cmd(vs, tur, NULL, 0, NULL, 0, &resp);
    tape_assert_sense(&resp, NOT_READY, 0x3a, 0x00);
    g_assert_cmphex(tape_cmd(vs, rewind, NULL, 0, NULL, 0, &resp), ==, GOOD);
    g_assert_cmphex(tape_cmd(vs, tur, NULL, 0, NULL, 0, &resp), ==, GOOD);
    g_assert_cmpuint(tape_read_position(vs, &bop), ==, 0);
    g_assert(bop);

    /* With PREVENT ended, UNLOAD takes the tape out */
    g_assert_cmphex(tape_cmd(vs, unload, NULL, 0, NULL, 0, &resp), ==, GOOD);
    tape_cmd(vs, rewind, NULL, 0, NULL, 0, &resp);
    tape_assert_sense(&resp, NOT_READY, 0x3a, 0x00);

    tape_finish(vs);
}

/*
 * Default properties and a 1 MiB capacity, which is inside the 4 MiB
 * early-warning zone from the start: a write reports early warning, and
 * end of data comes with EOM.
 */
static void test_tape_early_warning(void *obj, void *data,
                                    QGuestAllocator *t_alloc)
{
    QVirtioSCSI *scsi = obj;
    QVirtioSCSIQueues *vs;
    struct virtio_scsi_cmd_resp resp;
    const uint8_t write_100[VIRTIO_SCSI_CDB_SIZE] = { WRITE_6, 0, 0, 0, 100 };
    const uint8_t rewind[VIRTIO_SCSI_CDB_SIZE] = { REWIND };
    const uint8_t read_100[VIRTIO_SCSI_CDB_SIZE] = { READ_6, 0, 0, 0, 100 };
    uint8_t rec[100], buf[100];
    int i;

    for (i = 0; i < sizeof(rec); i++) {
        rec[i] = i ^ 0x5a;
    }

    alloc = t_alloc;
    vs = qvirtio_scsi_init_queues(scsi->vdev);
    tape_start(vs);

    tape_cmd(vs, write_100, NULL, 0, rec, sizeof(rec), &resp);
    tape_assert_sense(&resp, 0x40 | NO_SENSE, 0x00, 0x02);
    g_assert_cmphex(tape_cmd(vs, rewind, NULL, 0, NULL, 0, &resp), ==, GOOD);
    memset(buf, 0, sizeof(buf));
    g_assert_cmphex(tape_cmd(vs, read_100, buf, 100, NULL, 0, &resp),
                    ==, GOOD);
    g_assert(!memcmp(buf, rec, sizeof(rec)));
    tape_cmd(vs, read_100, buf, 100, NULL, 0, &resp);
    tape_assert_sense(&resp, 0x40 | BLANK_CHECK, 0x00, 0x05);

    tape_finish(vs);
}

static void tape_setup(GString *cmd_line, const char *options)
{
    int fd;

    fd = g_file_open_tmp("qtest-tape.XXXXXX", &tape_path, NULL);
    g_assert(fd >= 0);
    close(fd);
    g_string_append_printf(cmd_line,
                           " -drive file=%s,if=none,id=dr1,format=raw"
                           " -device scsi-tape,drive=dr1,lun=0,scsi-id=1%s",
                           tape_path, options);
}

static void *virtio_scsi_setup_tape(GString *cmd_line, void *arg)
{
    tape_setup(cmd_line, "");
    return arg;
}

static void *virtio_scsi_setup_tape_options(GString *cmd_line, void *arg)
{
    tape_setup(cmd_line, ",block-size=512,eom-at-eod=on"
               ",autoload-after-unload=on,join-records=on");
    return arg;
}

static void *virtio_scsi_setup_tape_capacity(GString *cmd_line, void *arg)
{
    tape_setup(cmd_line, ",capacity-mb=1");
    return arg;
}

static void *virtio_scsi_hotplug_setup(GString *cmd_line, void *arg)
{
    g_string_append(cmd_line,
                    " -drive id=drv1,if=none,file=null-co://,"
                    "file.read-zeroes=on,format=raw");
    return arg;
}

static void *virtio_scsi_setup(GString *cmd_line, void *arg)
{
    g_string_append(cmd_line,
                    " -drive file=blkdebug::null-co://,"
                    "file.image.read-zeroes=on,"
                    "if=none,id=dr1,format=raw,file.align=4k "
                    "-device scsi-hd,drive=dr1,lun=0,scsi-id=1");
    return arg;
}

static void *virtio_scsi_setup_4k(GString *cmd_line, void *arg)
{
    g_string_append(cmd_line,
                    " -drive file=blkdebug::null-co://,"
                    "file.image.read-zeroes=on,"
                    "if=none,id=dr1,format=raw "
                    "-device scsi-hd,drive=dr1,lun=0,scsi-id=1"
                    ",logical_block_size=4k,physical_block_size=4k");
    return arg;
}

static void *virtio_scsi_setup_cd(GString *cmd_line, void *arg)
{
    g_string_append(cmd_line,
                    " -drive file=null-co://,"
                    "file.read-zeroes=on,"
                    "if=none,id=dr1,format=raw "
                    "-device scsi-cd,drive=dr1,lun=0,scsi-id=1");
    return arg;
}

static void *virtio_scsi_setup_iothread(GString *cmd_line, void *arg)
{
    g_string_append(cmd_line,
                    " -object iothread,id=thread0"
                    " -blockdev driver=null-co,read-zeroes=on,node-name=null0"
                    " -device scsi-hd,drive=null0");
    return arg;
}

static void register_virtio_scsi_test(void)
{
    QOSGraphTestOptions opts = { };

    opts.before = virtio_scsi_hotplug_setup;
    qos_add_test("hotplug", "virtio-scsi", hotplug, &opts);

    opts.before = virtio_scsi_setup;
    qos_add_test("unaligned-write-same", "virtio-scsi",
                 test_unaligned_write_same, &opts);

    opts.before = virtio_scsi_setup_4k;
    qos_add_test("large-lba-unmap", "virtio-scsi",
                 test_unmap_large_lba, &opts);

    opts.before = virtio_scsi_setup_cd;
    qos_add_test("write-to-cdrom", "virtio-scsi", test_write_to_cdrom, &opts);

    if (qtest_has_device("scsi-tape")) {
        opts.before = virtio_scsi_setup_tape;
        qos_add_test("tape-round-trip", "virtio-scsi", test_tape_round_trip,
                     &opts);
        opts.before = virtio_scsi_setup_tape_options;
        qos_add_test("tape-options", "virtio-scsi", test_tape_options,
                     &opts);
        opts.before = virtio_scsi_setup_tape_capacity;
        qos_add_test("tape-early-warning", "virtio-scsi",
                     test_tape_early_warning, &opts);
    }

    opts.before = virtio_scsi_setup_iothread;
    opts.edge = (QOSGraphEdgeOptions) {
        .extra_device_opts = "iothread=thread0",
    };
    qos_add_test("iothread-attach-node", "virtio-scsi-pci",
                 test_iothread_attach_node, &opts);

    opts.before = virtio_scsi_setup_iothread;
    opts.edge = (QOSGraphEdgeOptions) {
        .extra_device_opts = "iothread=thread0",
    };
    qos_add_test("iothread-virtio-error", "virtio-scsi-pci",
                 test_iothread_virtio_error, &opts);
}

libqos_init(register_virtio_scsi_test);
