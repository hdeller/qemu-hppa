.. SPDX-License-Identifier: GPL-2.0-or-later
.. Copyright (c) 2026 Craig Lalley

SCSI tape drive (scsi-tape)
===========================

The ``scsi-tape`` device emulates a SCSI sequential-access (tape) drive.
It attaches to any SCSI bus, such as ``virtio-scsi-pci``, ``lsi53c895a``
or the on-board controllers of some machines.  The tape is a host file
in the SIMH ``.tap`` format, which is also used by SIMH and other
emulators, so existing tape images can be used as they are.

By default the drive identifies itself as an HP C1537A (DDS-3) drive with
firmware revision L708.  Its default behaviour follows SCSI-2 in these
points: it starts in variable-block mode; in fixed-block mode each record
is one block, and a record of another length is reported as an incorrect
length (ILI); EOM is reported with end of data only at or after early
warning; and after an unload the tape is NOT READY for medium access
until it is loaded again.  The properties below change these points
where a guest expects otherwise.  Whatever the properties are set to, a
fixed-block READ or WRITE of one or more blocks while the block length
is 0 fails with ILLEGAL REQUEST, the sense key SCSI-2 (10.1.8) lists for
this condition; the additional sense code, INVALID FIELD IN CDB, is the
one SCSI-2 prescribes for the other invalid fixed-block request (SILI
with the fixed bit set).  One further behaviour, listed under "Choices
beyond SCSI-2" below, is the device's own.

Image format
------------

Every data record is stored as a 32-bit little-endian length, the record
bytes, one pad byte if the length is odd, and the length again.  A
filemark is a single word of ``0x00000000``, an erase gap a single word
of ``0xfffffffe``, and a word of ``0xffffffff`` or the end of the file is
the end of the medium.  An empty file is a blank tape.

After every write the drive leaves an end-of-medium word
(``0xffffffff``) behind the data, so, as on a real tape, anything
recorded beyond the write position is no longer reachable.  Images
written by the drive therefore end with that word.  Programs that read
``.tap`` files stop there, so two such images joined with ``cat`` read
as the first image only; remove the last four bytes of the first image
before joining them.

Properties
----------

``drive``
  The block device holding the image.  It can be left out, or point to
  an empty drive (``-drive if=none,id=tape0``), for a drive with no tape
  loaded.

``block-size`` (default 0)
  The block length reported in the MODE SENSE block descriptor and used
  for fixed-block transfers.  0 is variable-block mode, in which a
  fixed-block READ or WRITE is rejected.  The guest can change the value
  with MODE SELECT.

``capacity-mb`` (default 0)
  The capacity of the tape in MiB of image file, including the ``.tap``
  framing and the end-of-medium word.  0 means unlimited: the image grows
  as it is written.  With a capacity set, writes report the early-warning
  condition when less than 4 MiB is left, and fail with VOLUME OVERFLOW
  when the tape is full.

``join-records`` (default off)
  In fixed-block mode, cut the blocks from the data of consecutive
  records regardless of record boundaries, instead of reporting a record
  of another length as an incorrect-length block.

``eom-at-eod`` (default off)
  Set the EOM bit at every end of data, not only at or after early
  warning.

``autoload-after-unload`` (default off)
  After an unload while removal is prevented, report NOT READY only to
  TEST UNIT READY, let the next medium-access command load the tape again,
  and end the prevent state with the unload.

``vendor``, ``product``, ``ver``
  Override the INQUIRY identity, as for ``scsi-hd``.

Supported commands
------------------

TEST UNIT READY, INQUIRY, REQUEST SENSE, READ BLOCK LIMITS, REWIND, SPACE
(blocks and filemarks, both directions), READ(6) and WRITE(6) (fixed and
variable blocks), WRITE FILEMARKS, ERASE, MODE SENSE(6)/(10), MODE
SELECT(6)/(10), LOG SENSE (pages 0x00, 0x02 and 0x03), LOAD UNLOAD,
PREVENT ALLOW MEDIUM REMOVAL, READ POSITION (short form) and LOCATE(10).
The drive has a single partition.

Choices beyond SCSI-2
---------------------

This holds whatever the properties are set to:

* A reset of the drive, including a SCSI bus reset, also ends the NOT
  READY state that follows an unload with removal prevented.  SCSI-2
  names only a load or a new volume for that, so this departs from it.

Changing tapes
--------------

The monitor's ``change`` and ``eject`` commands work on the drive::

  (qemu) change tape0 /path/to/other.tap raw
  (qemu) eject tape0

The guest sees a UNIT ATTENTION after a change.  The drive can also be
unloaded by the guest (LOAD UNLOAD).  PREVENT ALLOW MEDIUM REMOVAL only
affects the guest's own unload requests; the monitor can always change
the tape.  An unload requested by the guest while removal is prevented
rewinds the tape and keeps it in the drive; medium-access commands then
report NOT READY until the guest loads it again (LOAD UNLOAD with the
Load bit set), the tape is changed, or the drive is reset.

Examples
--------

A drive on a ``virtio-scsi`` controller::

  qemu-system-x86_64 ... \
      -device virtio-scsi-pci,id=scsi0 \
      -drive if=none,id=tape0,file=backup.tap,format=raw \
      -device scsi-tape,bus=scsi0.0,drive=tape0

On the ``hppa`` machines with PCI (C3700, A400, B160L) the drive can be
put on an ``lsi53c895a`` controller.  The machines create that
controller themselves only when a disk is given with ``-drive if=scsi``;
otherwise add one explicitly::

  qemu-system-hppa -machine C3700 ... \
      -device lsi53c895a,id=scsi1 \
      -drive if=none,id=tape0,file=install.tap,format=raw,readonly=on \
      -device scsi-tape,bus=scsi1.0,scsi-id=1,drive=tape0

Firmware that boots from tape usually reads it in fixed-length blocks.
Firmware that first selects its block length with MODE SELECT works
with the default properties.  Firmware that reads fixed 512-byte blocks
without selecting a block length needs ``block-size=512``.  Either way
the boot tape must hold records of that block length, as a drive in
fixed-block mode writes them; an image made of longer records can be
read that way with ``join-records=on``.

A read-only image (``readonly=on``, or a file the user cannot write) is
reported as write-protected.  Linux guests use the drive through the
``st`` driver (``/dev/st0``, ``/dev/nst0``) with ``mt`` and ``tar``.

Limitations
-----------

* Images are sized in 512-byte sectors by the block layer.  If an image
  that was not written by this device ends with an incomplete sector and
  has no end-of-medium word, the zeros up to the next sector boundary
  read as filemarks before the end of the medium is reached.
* Migration carries the tape position and the mode state, but not the
  data of a command whose transfer is still in progress on the
  controller.
* Setmarks, SPACE to end of data and multiple partitions are not
  supported.
* No data is compressed; the compression mode page only records the
  setting.
