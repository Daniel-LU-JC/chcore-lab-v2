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

#include "consts.h"
#include <common/asm.h>

.extern arm64_elX_to_el1
.extern boot_cpu_stack
.extern init_c

BEGIN_FUNC(_start)

	/* mrs: move system register to general-purpose register */
	/* mpidr_el1: in a multiprocessor system, provides an additional PE identification mechanism */
	mrs	x8, mpidr_el1

	/* x8 = x8 & #0xFF */
	and	x8, x8,	#0xFF

	/* cbz: compare (the value in the register x8) and branch (to label primary) on zero */
	/* branching indicates that the PE identifier is zero for the current core */
	cbz	x8, primary

	/* hang all secondary processors before we introduce smp */
	/* b is the unconditional branch instruction and . is a shorthand notation for the current PC value */
	/* effectively creating an infinite loop */
	b 	.

primary:
	/* Turn to el1 from other exception levels. */
	/* bl instruction is used to call the subroutine and the return address is stored in the Link Register */
	bl 	arm64_elX_to_el1

	/* Prepare stack pointer and jump to C. */
	ldr 	x0, =boot_cpu_stack
	add 	x0, x0, #INIT_STACK_SIZE
	mov 	sp, x0

	bl 	init_c

	/* Should never be here */
	b	.
END_FUNC(_start)
