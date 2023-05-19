/*
 * Copyright (c) 2022 Institute of Parallel And Distributed Systems (IPADS)
 * ChCore-Lab is licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan
 * PSL v1. You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
 * KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
 * NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE. See the
 * Mulan PSL v1 for more details.
 */

#include <common/util.h>
#include <common/vars.h>
#include <common/macro.h>
#include <common/types.h>
#include <common/errno.h>
#include <lib/printk.h>
#include <mm/kmalloc.h>
#include <mm/mm.h>
#include <arch/mmu.h>

#include <arch/mm/page_table.h>

extern void set_ttbr0_el1(paddr_t);

void set_page_table(paddr_t pgtbl)
{
        set_ttbr0_el1(pgtbl);
}

#define USER_PTE 0
/*
 * the 3rd arg means the kind of PTE.
 */
static int set_pte_flags(pte_t *entry, vmr_prop_t flags, int kind)
{
        // Only consider USER PTE now.
        BUG_ON(kind != USER_PTE);

        /*
         * Current access permission (AP) setting:
         * Mapped pages are always readable (No considering XOM).
         * EL1 can directly access EL0 (No restriction like SMAP
         * as ChCore is a microkernel).
         */
        if (flags & VMR_WRITE)
                entry->l3_page.AP = AARCH64_MMU_ATTR_PAGE_AP_HIGH_RW_EL0_RW;
        else
                entry->l3_page.AP = AARCH64_MMU_ATTR_PAGE_AP_HIGH_RO_EL0_RO;

        if (flags & VMR_EXEC)
                entry->l3_page.UXN = AARCH64_MMU_ATTR_PAGE_UX;
        else
                entry->l3_page.UXN = AARCH64_MMU_ATTR_PAGE_UXN;

        // EL1 cannot directly execute EL0 accessiable region.
        entry->l3_page.PXN = AARCH64_MMU_ATTR_PAGE_PXN;
        // Set AF (access flag) in advance.
        entry->l3_page.AF = AARCH64_MMU_ATTR_PAGE_AF_ACCESSED;
        // Mark the mapping as not global
        entry->l3_page.nG = 1;
        // Mark the mappint as inner sharable
        entry->l3_page.SH = INNER_SHAREABLE;
        // Set the memory type
        if (flags & VMR_DEVICE) {
                entry->l3_page.attr_index = DEVICE_MEMORY;
                entry->l3_page.SH = 0;
        } else if (flags & VMR_NOCACHE) {
                entry->l3_page.attr_index = NORMAL_MEMORY_NOCACHE;
        } else {
                entry->l3_page.attr_index = NORMAL_MEMORY;
        }

        return 0;
}

#define GET_PADDR_IN_PTE(entry) \
        (((u64)entry->table.next_table_addr) << PAGE_SHIFT)
#define GET_NEXT_PTP(entry) phys_to_virt(GET_PADDR_IN_PTE(entry))

#define NORMAL_PTP (0)
#define BLOCK_PTP  (1)

/*
 * Find next page table page for the "va".
 *
 * cur_ptp: current page table page
 * level:   current ptp level
 *
 * next_ptp: returns "next_ptp"
 * pte     : returns "pte" (points to next_ptp) in "cur_ptp"
 * @return : success (NORMAL_PTP or BLOCK_PTP) or failure (-ENOMAPPING)
 *
 * alloc: if true, allocate a ptp when missing
 *
 */
static int get_next_ptp(ptp_t *cur_ptp, u32 level, vaddr_t va, ptp_t **next_ptp,
                        pte_t **pte, bool alloc)
{
        u32 index = 0;
        pte_t *entry;

        if (cur_ptp == NULL)
                return -ENOMAPPING;

        switch (level) {
        case 0:
                index = GET_L0_INDEX(va);
                break;
        case 1:
                index = GET_L1_INDEX(va);
                break;
        case 2:
                index = GET_L2_INDEX(va);
                break;
        case 3:
                index = GET_L3_INDEX(va);
                break;
        default:
                BUG_ON(1);
        }

        entry = &(cur_ptp->ent[index]);

        // 'page entry invalid' = 'next level pointer does not exist'
        if (IS_PTE_INVALID(entry->pte)) {
                if (alloc == false) {
                        return -ENOMAPPING;
                } else {
                        /* alloc a new page table page */
                        ptp_t *new_ptp;
                        paddr_t new_ptp_paddr;
                        pte_t new_pte_val;

                        /* alloc a single physical page as a new page table page
                         */
                        new_ptp = get_pages(0);
                        BUG_ON(new_ptp == NULL);
                        memset((void *)new_ptp, 0, PAGE_SIZE);
                        new_ptp_paddr = virt_to_phys((vaddr_t)new_ptp);  // pa is stored in the entry

                        new_pte_val.pte = 0;
                        new_pte_val.table.is_valid = 1;  // the new entry points to something now
                        new_pte_val.table.is_table = 1;  // 'is_table' means not a huge page
                        new_pte_val.table.next_table_addr = new_ptp_paddr
                                                            >> PAGE_SHIFT;

                        /* same effect as: cur_ptp->ent[index] = new_pte_val; */
                        entry->pte = new_pte_val.pte;  // modify the fields of param 'pte'
                }
        }

        *next_ptp = (ptp_t *)GET_NEXT_PTP(entry);
        *pte = entry;  // an example of how ** pointer should be used
        if (IS_PTE_TABLE(entry->pte))
                return NORMAL_PTP;
        else
                return BLOCK_PTP;
}

void free_page_table(void *pgtbl)
{
        ptp_t *l0_ptp, *l1_ptp, *l2_ptp, *l3_ptp;
        pte_t *l0_pte, *l1_pte, *l2_pte;
        int i, j, k;

        if (pgtbl == NULL) {
                kwarn("%s: input arg is NULL.\n", __func__);
                return;
        }

        /* L0 page table */
        l0_ptp = (ptp_t *)pgtbl;

        /* Interate each entry in the l0 page table*/
        for (i = 0; i < PTP_ENTRIES; ++i) {
                l0_pte = &l0_ptp->ent[i];
                if (IS_PTE_INVALID(l0_pte->pte) || !IS_PTE_TABLE(l0_pte->pte))
                        continue;
                l1_ptp = (ptp_t *)GET_NEXT_PTP(l0_pte);

                /* Interate each entry in the l1 page table*/
                for (j = 0; j < PTP_ENTRIES; ++j) {
                        l1_pte = &l1_ptp->ent[j];
                        if (IS_PTE_INVALID(l1_pte->pte)
                            || !IS_PTE_TABLE(l1_pte->pte))
                                continue;
                        l2_ptp = (ptp_t *)GET_NEXT_PTP(l1_pte);

                        /* Interate each entry in the l2 page table*/
                        for (k = 0; k < PTP_ENTRIES; ++k) {
                                l2_pte = &l2_ptp->ent[k];
                                if (IS_PTE_INVALID(l2_pte->pte)
                                    || !IS_PTE_TABLE(l2_pte->pte))
                                        continue;
                                l3_ptp = (ptp_t *)GET_NEXT_PTP(l2_pte);
                                /* Free the l3 page table page */
                                free_pages(l3_ptp);
                        }

                        /* Free the l2 page table page */
                        free_pages(l2_ptp);
                }

                /* Free the l1 page table page */
                free_pages(l1_ptp);
        }

        free_pages(l0_ptp);
}

/*
 * Translate a va to pa, and get its pte for the flags
 */
int query_in_pgtbl(void *pgtbl, vaddr_t va, paddr_t *pa, pte_t **entry)
{
        /* LAB 2 TODO 3 BEGIN */
        /*
         * Hint: Walk through each level of page table using `get_next_ptp`,
         * return the pa and pte until a L0/L1 block or page, return
         * `-ENOMAPPING` if the va is not mapped.
         */

        int ptp_type;
        pte_t *l0_pte, *l1_pte, *l2_pte, *l3_pte;
        ptp_t *l0_ptp, *l1_ptp, *l2_ptp, *l3_ptp;

        if (pgtbl == NULL)
                BUG("pgtbl == NULL\n");

        l0_ptp = (ptp_t *)pgtbl;

        // from level 0 to level 1, no huge page support here
        ptp_type = get_next_ptp(l0_ptp, 0, va, &l1_ptp, &l0_pte, false);
        if (ptp_type == -ENOMAPPING)
                return -ENOMAPPING;
        BUG_ON(ptp_type == BLOCK_PTP);

        // from level 1 to level 2, huge page with size 1GB
        ptp_type = get_next_ptp(l1_ptp, 1, va, &l2_ptp, &l1_pte, false);
        if (ptp_type == -ENOMAPPING) {
                return -ENOMAPPING;
        } else if (ptp_type == BLOCK_PTP) {
                // prepare pa, entry and @return
                *entry = l1_pte;
                *pa = ((paddr_t) l1_pte->l1_block.pfn << L1_INDEX_SHIFT) | GET_VA_OFFSET_L1(va);
                return 0;
        }

        // from level 2 to level 3, huge page with size 2MB
        ptp_type = get_next_ptp(l2_ptp, 2, va, &l3_ptp, &l2_pte, false);
        if (ptp_type == -ENOMAPPING) {
                return -ENOMAPPING;
        } else if (ptp_type == BLOCK_PTP) {
                // prepare pa, entry and @return
                *entry = l2_pte;
                *pa = ((paddr_t) l2_pte->l2_block.pfn << L2_INDEX_SHIFT) | GET_VA_OFFSET_L2(va);
                return 0;
        }

        // at level 3, translate va into pa with 4KB page size
        l3_pte = &l3_ptp->ent[GET_L3_INDEX(va)];
        if (IS_PTE_INVALID(l3_pte->pte))
                return -ENOMAPPING;
        BUG_ON(!IS_PTE_TABLE(l3_pte->pte));  // the physical address has been found
        
        // 'entry = &l3_pte;' is totally different from '*entry = l3_pte;'
        *entry = l3_pte;
        
        *pa = ((paddr_t) l3_pte->table.next_table_addr << PAGE_SHIFT) | GET_VA_OFFSET_L3(va);

        return 0;

        /* LAB 2 TODO 3 END */
}

#define PAGE_NUMBER_MASK (0xfffffffffffff000)
int map_range_in_pgtbl(void *pgtbl, vaddr_t va, paddr_t pa, size_t len,
                       vmr_prop_t flags)
{
        /* LAB 2 TODO 3 BEGIN */
        /*
         * Hint: Walk through each level of page table using `get_next_ptp`,
         * create new page table page if necessary, fill in the final level
         * pte with the help of `set_pte_flags`. Iterate until all pages are
         * mapped.
         */

        pte_t *l0_pte, *l1_pte, *l2_pte, *l3_pte;
        ptp_t *l0_ptp, *l1_ptp, *l2_ptp, *l3_ptp;

        if (pgtbl == NULL)
                BUG("pgtbl == NULL\n");

        l0_ptp = (ptp_t *)pgtbl;

        int page_number = len / PAGE_SIZE;  // 'for' loop, without huge page support
        vaddr_t va_page = va & PAGE_NUMBER_MASK;
        paddr_t pa_page = pa & PAGE_NUMBER_MASK;  // starting page for mapping

        for (int i = 0; i < page_number; ++i) {
                // from level 0 to level 1 (using get_next_ptp func)
                int ptp_type = get_next_ptp(l0_ptp, 0, va_page, &l1_ptp, &l0_pte, true);
                BUG_ON(ptp_type != NORMAL_PTP);  // without huge page support
                // from level 1 to level 2
                ptp_type = get_next_ptp(l1_ptp, 1, va_page, &l2_ptp, &l1_pte, true);
                BUG_ON(ptp_type != NORMAL_PTP);
                // from level 2 to level 3
                ptp_type = get_next_ptp(l2_ptp, 2, va_page, &l3_ptp, &l2_pte, true);
                BUG_ON(ptp_type != NORMAL_PTP);
                // store the pa into the entry at level 3
                l3_pte = &l3_ptp->ent[GET_L3_INDEX(va_page)];
                set_pte_flags(l3_pte, flags, USER_PTE);
                l3_pte->l3_page.is_valid = l3_pte->l3_page.is_page = 1;

                l3_pte->table.next_table_addr = pa_page >> PAGE_SHIFT;

                // move on to the next page address
                va_page += PAGE_SIZE;
                pa_page += PAGE_SIZE;
        }

        return 0;

        /* LAB 2 TODO 3 END */
}

int unmap_range_in_pgtbl(void *pgtbl, vaddr_t va, size_t len)
{
        /* LAB 2 TODO 3 BEGIN */
        /*
         * Hint: Walk through each level of page table using `get_next_ptp`,
         * mark the final level pte as invalid. Iterate until all pages are
         * unmapped.
         */

        pte_t *l0_pte, *l1_pte, *l2_pte, *l3_pte;
        ptp_t *l0_ptp, *l1_ptp, *l2_ptp, *l3_ptp;

        if (pgtbl == NULL)
                BUG("pgtbl == NULL\n");

        l0_ptp = (ptp_t *)pgtbl;

        int page_number = len / PAGE_SIZE;  // 'for' loop, without huge page support
        vaddr_t va_page = va & PAGE_NUMBER_MASK;  // starting page for unmapping

        for (int i = 0; i < page_number; ++i) {
                int ptp_type = get_next_ptp(l0_ptp, 0, va_page, &l1_ptp, &l0_pte, true);
                BUG_ON(ptp_type != NORMAL_PTP);
                ptp_type = get_next_ptp(l1_ptp, 1, va_page, &l2_ptp, &l1_pte, true);
                BUG_ON(ptp_type != NORMAL_PTP);
                ptp_type = get_next_ptp(l2_ptp, 2, va_page, &l3_ptp, &l2_pte, true);
                BUG_ON(ptp_type != NORMAL_PTP);
                l3_pte = &l3_ptp->ent[GET_L3_INDEX(va_page)];  // find the target page table entry
                BUG_ON(l3_pte->l3_page.is_valid == 0);
                l3_pte->l3_page.is_valid = 0;
                va_page += PAGE_SIZE;
        }

        return 0;

        /* LAB 2 TODO 3 END */
}

#define HUGE_PAGE_ALIGNMENT_MASK (0xffffffffc0000000)
int map_range_in_pgtbl_huge(void *pgtbl, vaddr_t va, paddr_t pa, size_t len,
                            vmr_prop_t flags)
{
        /* LAB 2 TODO 4 BEGIN */

        int level_one_huge_page_num = len >> L1_INDEX_SHIFT;
        int level_two_huge_page_num = (len - level_one_huge_page_num * L1_HUGE_PAGE_SIZE) >> L2_INDEX_SHIFT;
        int level_three_normal_page_num = (len - level_one_huge_page_num * L1_HUGE_PAGE_SIZE - level_two_huge_page_num * L2_HUGE_PAGE_SIZE) >> L3_INDEX_SHIFT;

        kdebug("1GB: %d 2MB: %d 4KB: %d\n", level_one_huge_page_num, level_two_huge_page_num, level_three_normal_page_num);

        pte_t *l0_pte, *l1_pte, *l2_pte, *l3_pte;
        ptp_t *l0_ptp, *l1_ptp, *l2_ptp, *l3_ptp;

        if (pgtbl == NULL)
                BUG("pgtbl == NULL\n");

        l0_ptp = (ptp_t *)pgtbl;

        // allocate 1GB, then 2MB, finally 4KB
        // alignment should be checked at the very beginning for merely once
        vaddr_t va_page = va & HUGE_PAGE_ALIGNMENT_MASK;
        vaddr_t pa_page = pa & HUGE_PAGE_ALIGNMENT_MASK;

        for (int i = 0; i < level_one_huge_page_num; ++i) {
                int ptp_type = get_next_ptp(l0_ptp, 0, va_page, &l1_ptp, &l0_pte, true);
                BUG_ON(ptp_type != NORMAL_PTP);
                // level 1 pte points to 1GB huge page
                l1_pte = &l1_ptp->ent[GET_L1_INDEX(va_page)];
                set_pte_flags(l1_pte, flags, USER_PTE);
                l1_pte->table.is_valid = 1;
                l1_pte->table.is_table = 0;

                l1_pte->l1_block.pfn = pa_page >> L1_INDEX_SHIFT;

                va_page += L1_HUGE_PAGE_SIZE;
                pa_page += L1_HUGE_PAGE_SIZE;
        }

        for (int i = 0; i < level_two_huge_page_num; ++i) {
                int ptp_type = get_next_ptp(l0_ptp, 0, va_page, &l1_ptp, &l0_pte, true);
                BUG_ON(ptp_type != NORMAL_PTP);
                ptp_type = get_next_ptp(l1_ptp, 1, va_page, &l2_ptp, &l1_pte, true);
                BUG_ON(ptp_type != NORMAL_PTP);
                // level 2 pte points to 2MB huge page
                l2_pte = &l2_ptp->ent[GET_L2_INDEX(va_page)];
                set_pte_flags(l2_pte, flags, USER_PTE);
                l2_pte->table.is_valid = 1;
                l2_pte->table.is_table = 0;

                l2_pte->l2_block.pfn = pa_page >> L2_INDEX_SHIFT;

                va_page += L2_HUGE_PAGE_SIZE;
                pa_page += L2_HUGE_PAGE_SIZE;
        }

        // invoke existing func to map 4KB pages
        map_range_in_pgtbl(pgtbl, va_page, pa_page, PAGE_SIZE * level_three_normal_page_num, flags);

        return 0;

        /* LAB 2 TODO 4 END */
}

int unmap_range_in_pgtbl_huge(void *pgtbl, vaddr_t va, size_t len)
{
        /* LAB 2 TODO 4 BEGIN */

        pte_t *l0_pte, *l1_pte, *l2_pte, *l3_pte;
        ptp_t *l0_ptp, *l1_ptp, *l2_ptp, *l3_ptp;

        if (pgtbl == NULL)
                BUG("pgtbl == NULL\n");

        l0_ptp = (ptp_t *)pgtbl;

        int level_one_huge_page_num = len >> L1_INDEX_SHIFT;
        int level_two_huge_page_num = (len - level_one_huge_page_num * L1_HUGE_PAGE_SIZE) >> L2_INDEX_SHIFT;
        int level_three_normal_page_num = (len - level_one_huge_page_num * L1_HUGE_PAGE_SIZE - level_two_huge_page_num * L2_HUGE_PAGE_SIZE) >> L3_INDEX_SHIFT;

        vaddr_t va_page = va & HUGE_PAGE_ALIGNMENT_MASK;

        for (int i = 0; i < level_one_huge_page_num; ++i) {
                int ptp_type = get_next_ptp(l0_ptp, 0, va_page, &l1_ptp, &l0_pte, true);
                BUG_ON(ptp_type != NORMAL_PTP);
                l1_pte = &l1_ptp->ent[GET_L1_INDEX(va_page)];
                BUG_ON(l1_pte->l1_block.is_valid == 0);
                BUG_ON(l1_pte->table.is_table == 1);  // huge page is not a table descriptor
                l1_pte->l1_block.is_valid = 0;
                va_page += L1_HUGE_PAGE_SIZE;
        }

        for (int i = 0; i < level_two_huge_page_num; ++i) {
                int ptp_type = get_next_ptp(l0_ptp, 0, va_page, &l1_ptp, &l0_pte, true);
                BUG_ON(ptp_type != NORMAL_PTP);
                ptp_type = get_next_ptp(l1_ptp, 1, va_page, &l2_ptp, &l1_pte, true);
                BUG_ON(ptp_type != NORMAL_PTP);
                l2_pte = &l2_ptp->ent[GET_L2_INDEX(va_page)];
                BUG_ON(l2_pte->l2_block.is_valid == 0);
                BUG_ON(l2_pte->table.is_table == 1);  // huge page is not a table descriptor
                l2_pte->l2_block.is_valid = 0;
                va_page += L2_HUGE_PAGE_SIZE;
        }

        unmap_range_in_pgtbl(pgtbl, va_page, PAGE_SIZE * level_three_normal_page_num);

        return 0;

        /* LAB 2 TODO 4 END */
}

#ifdef CHCORE_KERNEL_TEST
#include <mm/buddy.h>
#include <lab.h>
void lab2_test_page_table(void)
{
        vmr_prop_t flags = VMR_READ | VMR_WRITE;
        {
                bool ok = true;
                void *pgtbl = get_pages(0);  // allocate level 0 page table page
                memset(pgtbl, 0, PAGE_SIZE);
                paddr_t pa;
                pte_t *pte;
                int ret;

                ret = map_range_in_pgtbl(  // user process intends to add a mapping
                        pgtbl, 0x1001000, 0x1000, PAGE_SIZE, flags);
                lab_assert(ret == 0);

                ret = query_in_pgtbl(pgtbl, 0x1001000, &pa, &pte);
                lab_assert(ret == 0 && pa == 0x1000);
                lab_assert(pte && pte->l3_page.is_valid && pte->l3_page.is_page
                           && pte->l3_page.SH == INNER_SHAREABLE);
                ret = query_in_pgtbl(pgtbl, 0x1001050, &pa, &pte);
                lab_assert(ret == 0 && pa == 0x1050);

                ret = unmap_range_in_pgtbl(pgtbl, 0x1001000, PAGE_SIZE);
                lab_assert(ret == 0);
                ret = query_in_pgtbl(pgtbl, 0x1001000, &pa, &pte);
                lab_assert(ret == -ENOMAPPING);

                free_page_table(pgtbl);
                lab_check(ok, "Map & unmap one page");
        }
        {
                bool ok = true;
                void *pgtbl = get_pages(0);
                memset(pgtbl, 0, PAGE_SIZE);
                paddr_t pa;
                pte_t *pte;
                int ret;
                size_t nr_pages = 10;
                size_t len = PAGE_SIZE * nr_pages;

                ret = map_range_in_pgtbl(pgtbl, 0x1001000, 0x1000, len, flags);
                lab_assert(ret == 0);
                ret = map_range_in_pgtbl(
                        pgtbl, 0x1001000 + len, 0x1000 + len, len, flags);
                lab_assert(ret == 0);

                for (int i = 0; i < nr_pages * 2; i++) {
                        ret = query_in_pgtbl(
                                pgtbl, 0x1001050 + i * PAGE_SIZE, &pa, &pte);
                        lab_assert(ret == 0 && pa == 0x1050 + i * PAGE_SIZE);
                        lab_assert(pte && pte->l3_page.is_valid
                                   && pte->l3_page.is_page);
                }

                ret = unmap_range_in_pgtbl(pgtbl, 0x1001000, len);
                lab_assert(ret == 0);
                ret = unmap_range_in_pgtbl(pgtbl, 0x1001000 + len, len);
                lab_assert(ret == 0);

                for (int i = 0; i < nr_pages * 2; i++) {
                        ret = query_in_pgtbl(
                                pgtbl, 0x1001050 + i * PAGE_SIZE, &pa, &pte);
                        lab_assert(ret == -ENOMAPPING);
                }

                free_page_table(pgtbl);
                lab_check(ok, "Map & unmap multiple pages");
        }
        {
                bool ok = true;
                void *pgtbl = get_pages(0);
                memset(pgtbl, 0, PAGE_SIZE);
                paddr_t pa;
                pte_t *pte;
                int ret;
                /* 1GB + 4MB + 40KB */
                size_t len = (1 << 30) + (4 << 20) + 10 * PAGE_SIZE;

                ret = map_range_in_pgtbl(
                        pgtbl, 0x100000000, 0x100000000, len, flags);
                lab_assert(ret == 0);
                ret = map_range_in_pgtbl(pgtbl,
                                         0x100000000 + len,
                                         0x100000000 + len,
                                         len,
                                         flags);
                lab_assert(ret == 0);

                for (vaddr_t va = 0x100000000; va < 0x100000000 + len * 2;
                     va += 5 * PAGE_SIZE + 0x100) {
                        ret = query_in_pgtbl(pgtbl, va, &pa, &pte);
                        lab_assert(ret == 0 && pa == va);
                }

                ret = unmap_range_in_pgtbl(pgtbl, 0x100000000, len);
                lab_assert(ret == 0);
                ret = unmap_range_in_pgtbl(pgtbl, 0x100000000 + len, len);
                lab_assert(ret == 0);

                for (vaddr_t va = 0x100000000; va < 0x100000000 + len;
                     va += 5 * PAGE_SIZE + 0x100) {
                        ret = query_in_pgtbl(pgtbl, va, &pa, &pte);
                        lab_assert(ret == -ENOMAPPING);
                }

                free_page_table(pgtbl);
                lab_check(ok, "Map & unmap huge range");
        }
        {
                bool ok = true;
                void *pgtbl = get_pages(0);
                memset(pgtbl, 0, PAGE_SIZE);
                paddr_t pa;
                pte_t *pte;
                int ret;
                /* 1GB + 4MB + 40KB */
                size_t len = (1 << 30) + (4 << 20) + 10 * PAGE_SIZE;
                size_t free_mem, used_mem;

                free_mem = get_free_mem_size_from_buddy(&global_mem[0]);
                ret = map_range_in_pgtbl_huge(
                        pgtbl, 0x100000000, 0x100000000, len, flags);
                lab_assert(ret == 0);
                used_mem =
                        free_mem - get_free_mem_size_from_buddy(&global_mem[0]);
                lab_assert(used_mem < PAGE_SIZE * 8);

                for (vaddr_t va = 0x100000000; va < 0x100000000 + len;
                     va += 5 * PAGE_SIZE + 0x100) {
                        ret = query_in_pgtbl(pgtbl, va, &pa, &pte);
                        lab_assert(ret == 0 && pa == va);
                }

                ret = unmap_range_in_pgtbl_huge(pgtbl, 0x100000000, len);
                lab_assert(ret == 0);

                for (vaddr_t va = 0x100000000; va < 0x100000000 + len;
                     va += 5 * PAGE_SIZE + 0x100) {
                        ret = query_in_pgtbl(pgtbl, va, &pa, &pte);
                        lab_assert(ret == -ENOMAPPING);
                }

                free_page_table(pgtbl);
                lab_check(ok, "Map & unmap with huge page support");
        }
        printk("[TEST] Page table tests finished\n");
}
#endif /* CHCORE_KERNEL_TEST */
