/*
* QEMU RISC-V SMMTT Extension
*
* Author: Gregor Haas, gregorhaas1997@gmail.com
*
* This program is free software; you can redistribute it and/or modify it
* under the terms and conditions of the GNU General Public License,
* version 2 or later, as published by the Free Software Foundation.
*
* This program is distributed in the hope it will be useful, but WITHOUT
* ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
* FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
* more details.
*
* You should have received a copy of the GNU General Public License along with
* this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef RISCV_SMMTT_H
#define RISCV_SMMTT_H

#include "qemu/osdep.h"
#include "linux/kvm.h"
#include "cpu.h"

typedef enum {
    SMMTT_BARE = 0,
#if defined(TARGET_RISCV32)
    SMMTT_34,
    SMMTT_34_rw
#elif defined(TARGET_RISCV64)
    SMMTT_46,
    SMMTT_46_rw,
    SMMTT_56,
    SMMTT_56_rw
#else
// We error only here in this case, since otherwise we would need to do
// this preprocessor check everywhere.
#error "SMMTT is for RISC-V only"
#endif
} smmtt_mode_t;

#define MTTP32_MODE_MASK	    _UL(0xC0000000)
#define MTTP32_SDID_MASK	    _UL(0x3F000000)
#define MTTP32_PPN_MASK	        _UL(0x003FFFFF)

#define MTTP32_MODE_SHIFT		30
#define MTTP32_SDID_SHIFT		24

#define MTTP64_MODE_MASK	    _ULL(0xF000000000000000)
#define MTTP64_SDID_MASK	    _ULL(0x0FC0000000000000)
#define MTTP64_PPN_MASK		    _ULL(0x00000FFFFFFFFFFF)

#define MTTP64_MODE_SHIFT		60
#define MTTP64_SDID_SHIFT		54

#if defined(TARGET_RISCV32)
#define MTTP_MODE_MASK			MTTP32_MODE_MASK
#define MTTP_SDID_MASK			MTTP32_SDID_MASK
#define MTTP_PPN_MASK			MTTP32_PPN_MASK

#define MTTP_MODE_SHIFT			MTTP32_MODE_SHIFT
#define MTTP_SDID_SHIFT			MTTP32_SDID_SHIFT
#elif defined(TARGET_RISCV64)
#define MTTP_MODE_MASK			MTTP64_MODE_MASK
#define MTTP_SDID_MASK			MTTP64_SDID_MASK
#define MTTP_PPN_MASK			MTTP64_PPN_MASK

#define MTTP_MODE_SHIFT			MTTP64_MODE_SHIFT
#define MTTP_SDID_SHIFT			MTTP64_SDID_SHIFT
#endif

bool smmtt_hart_has_privs(CPURISCVState *env, hwaddr addr,
                          target_ulong size, int privs,
                          int *allowed_privs, target_ulong mode);

#endif // RISCV_SMMTT_H