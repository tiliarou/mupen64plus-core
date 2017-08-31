/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *   Mupen64plus - recomp_dbg_x86.h                                        *
 *   Copyright (C) 2009-2016 Gillou68310                                   *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.          *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#ifndef M64P_R4300_X86_RECOMP_DBG_H
#define M64P_R4300_X86_RECOMP_DBG_H

#if defined(RECOMPILER_DEBUG) && defined(RECOMP_DBG)

#include <capstone.h>
#define ARCHITECTURE CS_ARCH_X86
#define MODE CS_MODE_32
#define INSTRUCTION instr[i].detail->x86
#define CALL_INST 0x38
#define ARCH_NAME "x86"

/* Rename non-static variables */
#define base_addr                               recomp_dbg_base_addr
#define out                                     recomp_dbg_out
#define using_tlb                               recomp_dbg_using_tlb
#define stop_after_jal                          recomp_dbg_stop_after_jal

/* Rename non-static functions */
#define clean_blocks                            recomp_dbg_clean_blocks
#define get_addr                                recomp_dbg_get_addr
#define get_addr_32                             recomp_dbg_get_addr_32
#define get_addr_ht                             recomp_dbg_get_addr_ht
#define invalidate_all_pages                    recomp_dbg_invalidate_all_pages
#define invalidate_block                        recomp_dbg_invalidate_block
#define invalidate_cached_code_new_dynarec      recomp_dbg_invalidate_cached_code_new_dynarec
#define new_dynarec_cleanup                     recomp_dbg_new_dynarec_cleanup
#define new_dynarec_init                        recomp_dbg_new_dynarec_init
#define new_recompile_block                     recomp_dbg_new_recompile_block
#define TLB_refill_exception_new                recomp_dbg_TLB_refill_exception_new
#define new_dynarec_check_interrupt             recomp_dbg_new_dynarec_check_interrupt

#endif

#endif /* M64P_R4300_X86_RECOMP_DBG_H */
