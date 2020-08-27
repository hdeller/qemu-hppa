/*
 *  HPPA memory access helper routines
 *
 *  Copyright (c) 2017 Helge Deller
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#include <stddef.h>
#include "exec/target_page.h"
#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/exec-all.h"
#include "exec/helper-proto.h"
#include "hw/core/cpu.h"
#include "qemu/timer.h"
#include "trace.h"
#include <gmodule.h>


#ifdef CONFIG_USER_ONLY
bool hppa_cpu_tlb_fill(CPUState *cs, vaddr address, int size,
                       MMUAccessType access_type, int mmu_idx,
                       bool probe, uintptr_t retaddr)
{
    HPPACPU *cpu = HPPA_CPU(cs);

    /* ??? Test between data page fault and data memory protection trap,
       which would affect si_code.  */
    cs->exception_index = EXCP_DMP;
    cpu->env.cr[CR_IOR] = address;
    cpu_loop_exit_restore(cs, retaddr);
}
#else

static hppa_tlb_entry *hppa_find_tlb(CPUHPPAState *env, vaddr addr)
{
    hppa_tlb_entry key;

    key.page = addr >> TARGET_PAGE_BITS;
    hppa_tlb_entry *ent = g_tree_lookup(env->tlb, &key);
    if (ent)
        trace_hppa_tlb_find_entry(env, ent, ent->entry_valid, ent->page << TARGET_PAGE_BITS, ent->pa);
    else
        trace_hppa_tlb_find_entry_not_found(env, addr);
    return ent;
}

static void hppa_flush_tlb_ent(CPUHPPAState *env, hppa_tlb_entry *ent)
{
    CPUState *cs = env_cpu(env);
    trace_hppa_tlb_flush_ent(env, ent, ent->page, ent->pa);

    if (ent->entry_valid)
        tlb_flush_page_by_mmuidx(cs, ent->page << TARGET_PAGE_BITS, 0xf);
    env->tlb_list = g_list_delete_link(env->tlb_list, ent->tlb_list_entry);
    g_tree_remove(env->tlb, ent);
    env->tlb_entries--;
}

int hppa_get_physical_address(CPUHPPAState *env, vaddr addr, int mmu_idx,
                              int type, hwaddr *pphys, int *pprot)
{
    hwaddr phys;
    int prot, r_prot, w_prot, x_prot;
    hppa_tlb_entry *ent;
    int ret = -1;

    /* Virtual translation disabled.  Direct map virtual to physical.  */
    if (mmu_idx == MMU_PHYS_IDX) {
        phys = addr;
        prot = PAGE_READ | PAGE_WRITE | PAGE_EXEC;
        goto egress;
    }

    /* Find a valid tlb entry that matches the virtual address.  */
    ent = hppa_find_tlb(env, addr);
    if (ent == NULL || !ent->entry_valid) {
        phys = 0;
        prot = 0;
        ret = (type == PAGE_EXEC) ? EXCP_ITLB_MISS : EXCP_DTLB_MISS;
        goto egress;
    }

    ent->cycle++;
    /* We now know the physical address.  */
    phys = ent->pa + (addr & ~TARGET_PAGE_MASK);

    /* Map TLB access_rights field to QEMU protection.  */
    r_prot = (mmu_idx <= ent->ar_pl1) * PAGE_READ;
    w_prot = (mmu_idx <= ent->ar_pl2) * PAGE_WRITE;
    x_prot = (ent->ar_pl2 <= mmu_idx && mmu_idx <= ent->ar_pl1) * PAGE_EXEC;
    switch (ent->ar_type) {
    case 0: /* read-only: data page */
        prot = r_prot;
        break;
    case 1: /* read/write: dynamic data page */
        prot = r_prot | w_prot;
        break;
    case 2: /* read/execute: normal code page */
        prot = r_prot | x_prot;
        break;
    case 3: /* read/write/execute: dynamic code page */
        prot = r_prot | w_prot | x_prot;
        break;
    default: /* execute: promote to privilege level type & 3 */
        prot = x_prot;
        break;
    }

    /* access_id == 0 means public page and no check is performed */
    if ((env->psw & PSW_P) && ent->access_id) {
        /* If bits [31:1] match, and bit 0 is set, suppress write.  */
        int match = ent->access_id * 2 + 1;

        if (match == env->cr[CR_PID1] || match == env->cr[CR_PID2] ||
            match == env->cr[CR_PID3] || match == env->cr[CR_PID4]) {
            prot &= PAGE_READ | PAGE_EXEC;
            if (type == PAGE_WRITE) {
                ret = EXCP_DMPI;
                goto egress;
            }
        }
    }

    /* No guest access type indicates a non-architectural access from
       within QEMU.  Bypass checks for access, D, B and T bits.  */
    if (type == 0) {
        goto egress;
    }

    if (unlikely(!(prot & type))) {
        /* The access isn't allowed -- Inst/Data Memory Protection Fault.  */
        ret = (type & PAGE_EXEC) ? EXCP_IMP : EXCP_DMAR;
        goto egress;
    }

    /* In reverse priority order, check for conditions which raise faults.
       As we go, remove PROT bits that cover the condition we want to check.
       In this way, the resulting PROT will force a re-check of the
       architectural TLB entry for the next access.  */
    if (unlikely(!ent->d)) {
        if (type & PAGE_WRITE) {
            /* The D bit is not set -- TLB Dirty Bit Fault.  */
            ret = EXCP_TLB_DIRTY;
        }
        prot &= PAGE_READ | PAGE_EXEC;
    }
    if (unlikely(ent->b)) {
        if (type & PAGE_WRITE) {
            /* The B bit is set -- Data Memory Break Fault.  */
            ret = EXCP_DMB;
        }
        prot &= PAGE_READ | PAGE_EXEC;
    }
    if (unlikely(ent->t)) {
        if (!(type & PAGE_EXEC)) {
            /* The T bit is set -- Page Reference Fault.  */
            ret = EXCP_PAGE_REF;
        }
        prot &= PAGE_EXEC;
    }

 egress:
    *pphys = phys;
    *pprot = prot;
    trace_hppa_tlb_get_physical_address(env, ret, prot, addr, phys);
    return ret;
}

hwaddr hppa_cpu_get_phys_page_debug(CPUState *cs, vaddr addr)
{
    HPPACPU *cpu = HPPA_CPU(cs);
    hwaddr phys;
    int prot, excp;

    /* If the (data) mmu is disabled, bypass translation.  */
    /* ??? We really ought to know if the code mmu is disabled too,
       in order to get the correct debugging dumps.  */
    if (!(cpu->env.psw & PSW_D)) {
        return addr;
    }

    excp = hppa_get_physical_address(&cpu->env, addr, MMU_KERNEL_IDX, 0,
                                     &phys, &prot);

    /* Since we're translating for debugging, the only error that is a
       hard error is no translation at all.  Otherwise, while a real cpu
       access might not have permission, the debugger does.  */
    return excp == EXCP_DTLB_MISS ? -1 : phys;
}

bool hppa_cpu_tlb_fill(CPUState *cs, vaddr addr, int size,
                       MMUAccessType type, int mmu_idx,
                       bool probe, uintptr_t retaddr)
{
    HPPACPU *cpu = HPPA_CPU(cs);
    CPUHPPAState *env = &cpu->env;
    int prot, excp, a_prot;
    hwaddr phys;

    switch (type) {
    case MMU_INST_FETCH:
        a_prot = PAGE_EXEC;
        break;
    case MMU_DATA_STORE:
        a_prot = PAGE_WRITE;
        break;
    default:
        a_prot = PAGE_READ;
        break;
    }

    excp = hppa_get_physical_address(env, addr, mmu_idx,
                                     a_prot, &phys, &prot);
    if (unlikely(excp >= 0)) {
        if (probe) {
            return false;
        }
        trace_hppa_tlb_fill_excp(env, addr, size, type, mmu_idx);
        /* Failure.  Raise the indicated exception.  */
        cs->exception_index = excp;
        if (cpu->env.psw & PSW_Q) {
            /* ??? Needs tweaking for hppa64.  */
            cpu->env.cr[CR_IOR] = addr;
            cpu->env.cr[CR_ISR] = addr >> 32;
        }
        cpu_loop_exit_restore(cs, retaddr);
    }

    trace_hppa_tlb_fill_success(env, addr & TARGET_PAGE_MASK,
                                phys & TARGET_PAGE_MASK, size, type, mmu_idx);
    /* Success!  Store the translation into the QEMU TLB.  */
    tlb_set_page(cs, addr & TARGET_PAGE_MASK, phys & TARGET_PAGE_MASK,
                 prot, mmu_idx, TARGET_PAGE_SIZE);
    return true;
}

static gint hppa_expire_cmp(gconstpointer _a, gconstpointer _b)
{
    hppa_tlb_entry *a = (hppa_tlb_entry *)_a;
    hppa_tlb_entry *b = (hppa_tlb_entry *)_b;
    return a->cycle - b->cycle;
}

/* Insert (Insn/Data) TLB Address.  Note this is PA 1.1 only.  */
void HELPER(itlba)(CPUHPPAState *env, target_ulong addr, target_ureg reg)
{
    unsigned long long page = addr >> TARGET_PAGE_BITS;
    hppa_tlb_entry *entry = NULL, key;
    GList *it, *itn;
    int i;

    if (env->tlb_entries > HPPA_TLB_ENTRIES) {
        env->tlb_list = g_list_sort(env->tlb_list, hppa_expire_cmp);
        for (it = env->tlb_list, i = 0; it && i < HPPA_TLB_ENTRIES/2; i++) {
            itn = g_list_next(it);
            hppa_flush_tlb_ent(env, it->data);
            it = itn;
        }
    }

    key.page = page;
    entry = g_tree_lookup(env->tlb, &key);
    if (entry) {
        if (entry->entry_valid) {
            entry->entry_valid = 0;
            CPUState *cs = env_cpu(env);
            tlb_flush_page_by_mmuidx(cs, page, 0xf);
        }
        entry->page = page;
        entry->cycle = 0;
    } else {
        entry = g_slice_new0(hppa_tlb_entry);
        env->tlb_list = g_list_prepend(env->tlb_list, entry);
        entry->tlb_list_entry = env->tlb_list;
        entry->page = page;
        g_tree_insert(env->tlb, entry, entry);
        env->tlb_entries++;
    }
    entry->pa = extract32(reg, 5, 20) << TARGET_PAGE_BITS;
    trace_hppa_tlb_itlba(env, entry, page << TARGET_PAGE_BITS, entry->pa);

}

/* Insert (Insn/Data) TLB Protection.  Note this is PA 1.1 only.  */
void HELPER(itlbp)(CPUHPPAState *env, target_ulong addr, target_ureg reg)
{
    hppa_tlb_entry *ent = hppa_find_tlb(env, addr);

    if (unlikely(ent == NULL)) {
        qemu_log_mask(LOG_GUEST_ERROR, "ITLBP not following ITLBA\n");
        return;
    }

    ent->access_id = extract32(reg, 1, 18);
    ent->u = extract32(reg, 19, 1);
    ent->ar_pl2 = extract32(reg, 20, 2);
    ent->ar_pl1 = extract32(reg, 22, 2);
    ent->ar_type = extract32(reg, 24, 3);
    ent->b = extract32(reg, 27, 1);
    ent->d = extract32(reg, 28, 1);
    ent->t = extract32(reg, 29, 1);
    ent->entry_valid = 1;
    trace_hppa_tlb_itlbp(env, ent, ent->access_id, ent->u, ent->ar_pl2,
                         ent->ar_pl1, ent->ar_type, ent->b, ent->d, ent->t);
}

/* Purge (Insn/Data) TLB.  This is explicitly page-based, and is
   synchronous across all processors.  */
static void ptlb_work(CPUState *cpu, run_on_cpu_data data)
{
    CPUHPPAState *env = cpu->env_ptr;
    target_ulong addr = (target_ulong) data.target_ptr;
    hppa_tlb_entry *ent = hppa_find_tlb(env, addr);

    if (ent)
        hppa_flush_tlb_ent(env, ent);
}

void HELPER(ptlb)(CPUHPPAState *env, target_ulong addr)
{
    CPUState *src = env_cpu(env);
    CPUState *cpu;
    trace_hppa_tlb_ptlb(env);
    run_on_cpu_data data = RUN_ON_CPU_TARGET_PTR(addr);

    CPU_FOREACH(cpu) {
        if (cpu != src) {
            async_run_on_cpu(cpu, ptlb_work, data);
        }
    }
    async_safe_run_on_cpu(src, ptlb_work, data);
}


/* Purge (Insn/Data) TLB entry.  This affects an implementation-defined
   number of pages/entries (we choose all), and is local to the cpu.  */
void HELPER(ptlbe)(CPUHPPAState *env)
{
    trace_hppa_tlb_ptlbe(env);
    g_list_free(env->tlb_list);
    env->tlb_list = NULL;
    env->tlb_entries = 0;
    alloc_tlb(env);
    tlb_flush_by_mmuidx(env_cpu(env), 0xf);
}

void cpu_hppa_change_prot_id(CPUHPPAState *env)
{
    if (env->psw & PSW_P) {
        tlb_flush_by_mmuidx(env_cpu(env), 0xf);
    }
}

void HELPER(change_prot_id)(CPUHPPAState *env)
{
    cpu_hppa_change_prot_id(env);
}

target_ureg HELPER(lpa)(CPUHPPAState *env, target_ulong addr)
{
    hwaddr phys;
    int prot, excp;

    excp = hppa_get_physical_address(env, addr, MMU_KERNEL_IDX, 0,
                                     &phys, &prot);
    if (excp >= 0) {
        if (env->psw & PSW_Q) {
            /* ??? Needs tweaking for hppa64.  */
            env->cr[CR_IOR] = addr;
            env->cr[CR_ISR] = addr >> 32;
        }
        if (excp == EXCP_DTLB_MISS) {
            excp = EXCP_NA_DTLB_MISS;
        }
        trace_hppa_tlb_lpa_failed(env, addr);
        hppa_dynamic_excp(env, excp, GETPC());
    }
    trace_hppa_tlb_lpa_success(env, addr, phys);
    return phys;
}

/* Return the ar_type of the TLB at VADDR, or -1.  */
int hppa_artype_for_page(CPUHPPAState *env, target_ulong vaddr)
{
    hppa_tlb_entry *ent = hppa_find_tlb(env, vaddr);
    return ent ? ent->ar_type : -1;
}
#endif /* CONFIG_USER_ONLY */
