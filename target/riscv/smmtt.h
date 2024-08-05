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
#include "cpu.h"

#include "smmtt_defs.h"

bool smmtt_hart_has_privs(CPURISCVState *env, hwaddr addr,
                          target_ulong size, int privs,
                          int *allowed_privs, target_ulong mode);

#endif // RISCV_SMMTT_H
