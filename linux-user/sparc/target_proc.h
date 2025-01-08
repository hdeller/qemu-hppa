/*
 * Sparc specific proc functions for linux-user
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef SPARC_TARGET_PROC_H
#define SPARC_TARGET_PROC_H

static int open_cpuinfo(CPUArchState *cpu_env, int fd)
{
    int i, num_cpus;

    num_cpus = sysconf(_SC_NPROCESSORS_ONLN);

    dprintf(fd, "cpu\t\t: TI UltraSparc II QEMU (BlackBird)\n");
    dprintf(fd, "fpu\t\t: UltraSparc II integrated FPU\n");
    dprintf(fd, "promlib\t\t: Version 3 Revision 17\n");
    dprintf(fd, "prom\t\t: 3.17.0\n");
    dprintf(fd, "type\t\t: sun4u\n");
    dprintf(fd, "ncpus probed\t: %d\n", num_cpus);
    dprintf(fd, "ncpus active\t: %d\n", num_cpus);
    dprintf(fd, "MMU Type\t: Spitfire\n");
    dprintf(fd, "State:\n");
    for (i = 0; i < num_cpus; i++) {
        dprintf(fd, "CPU%d:\t\t: online\n", i);
    }

    return 0;
}
#define HAVE_ARCH_PROC_CPUINFO

#endif /* SPARC_TARGET_PROC_H */
