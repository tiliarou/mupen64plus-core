/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *   Mupen64plus - recomp_dbg_arm.h                                        *
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

#ifndef M64P_R4300_ARM_RECOMP_DBG_H
#define M64P_R4300_ARM_RECOMP_DBG_H

#if defined(RECOMPILER_DEBUG) && defined(RECOMP_DBG)

#include <capstone.h>
#define ARCHITECTURE CS_ARCH_ARM
#define MODE CS_MODE_LITTLE_ENDIAN
#define INSTRUCTION instr[i].detail->arm
#define FP_REGISTER 0x4d
#define CALL_INST 0xd
#define ARCH_NAME "ARM"

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

#define jump_vaddr_r0                           recomp_dbg_jump_vaddr_r0
#define jump_vaddr_r1                           recomp_dbg_jump_vaddr_r1
#define jump_vaddr_r2                           recomp_dbg_jump_vaddr_r2
#define jump_vaddr_r3                           recomp_dbg_jump_vaddr_r3
#define jump_vaddr_r4                           recomp_dbg_jump_vaddr_r4
#define jump_vaddr_r5                           recomp_dbg_jump_vaddr_r5
#define jump_vaddr_r6                           recomp_dbg_jump_vaddr_r6
#define jump_vaddr_r7                           recomp_dbg_jump_vaddr_r7
#define jump_vaddr_r8                           recomp_dbg_jump_vaddr_r8
#define jump_vaddr_r9                           recomp_dbg_jump_vaddr_r9
#define jump_vaddr_r10                          recomp_dbg_jump_vaddr_r10
#define jump_vaddr_r12                          recomp_dbg_jump_vaddr_r12
#define invalidate_addr_r0                      recomp_dbg_invalidate_addr_r0
#define invalidate_addr_r1                      recomp_dbg_invalidate_addr_r1
#define invalidate_addr_r2                      recomp_dbg_invalidate_addr_r2
#define invalidate_addr_r3                      recomp_dbg_invalidate_addr_r3
#define invalidate_addr_r4                      recomp_dbg_invalidate_addr_r4
#define invalidate_addr_r5                      recomp_dbg_invalidate_addr_r5
#define invalidate_addr_r6                      recomp_dbg_invalidate_addr_r6
#define invalidate_addr_r7                      recomp_dbg_invalidate_addr_r7
#define invalidate_addr_r8                      recomp_dbg_invalidate_addr_r8
#define invalidate_addr_r9                      recomp_dbg_invalidate_addr_r9
#define invalidate_addr_r10                     recomp_dbg_invalidate_addr_r10
#define invalidate_addr_r12                     recomp_dbg_invalidate_addr_r12
#define indirect_jump_indexed                   recomp_dbg_indirect_jump_indexed
#define indirect_jump                           recomp_dbg_indirect_jump
#define verify_code                             recomp_dbg_verify_code
#define verify_code_vm                          recomp_dbg_verify_code_vm
#define verify_code_ds                          recomp_dbg_verify_code_ds
#define cc_interrupt                            recomp_dbg_cc_interrupt
#define do_interrupt                            recomp_dbg_do_interrupt
#define fp_exception                            recomp_dbg_fp_exception
#define fp_exception_ds                         recomp_dbg_fp_exception_ds
#define jump_syscall                            recomp_dbg_jump_syscall
#define jump_eret                               recomp_dbg_jump_eret
#define read_nomem_new                          recomp_dbg_read_nomem_new
#define read_nomemd_new                         recomp_dbg_read_nomemd_new
#define write_nomem_new                         recomp_dbg_write_nomem_new
#define write_nomemd_new                        recomp_dbg_write_nomemd_new
#define write_rdram_new                         recomp_dbg_write_rdram_new
#define write_rdramd_new                        recomp_dbg_write_rdramd_new
#define __clear_cache                           recomp_dbg_clear_cache

static void recomp_dbg_jump_vaddr_r0(void){}
static void recomp_dbg_jump_vaddr_r1(void){}
static void recomp_dbg_jump_vaddr_r2(void){}
static void recomp_dbg_jump_vaddr_r3(void){}
static void recomp_dbg_jump_vaddr_r4(void){}
static void recomp_dbg_jump_vaddr_r5(void){}
static void recomp_dbg_jump_vaddr_r6(void){}
static void recomp_dbg_jump_vaddr_r7(void){}
static void recomp_dbg_jump_vaddr_r8(void){}
static void recomp_dbg_jump_vaddr_r9(void){}
static void recomp_dbg_jump_vaddr_r10(void){}
static void recomp_dbg_jump_vaddr_r12(void){}
static void recomp_dbg_invalidate_addr_r0(void){}
static void recomp_dbg_invalidate_addr_r1(void){}
static void recomp_dbg_invalidate_addr_r2(void){}
static void recomp_dbg_invalidate_addr_r3(void){}
static void recomp_dbg_invalidate_addr_r4(void){}
static void recomp_dbg_invalidate_addr_r5(void){}
static void recomp_dbg_invalidate_addr_r6(void){}
static void recomp_dbg_invalidate_addr_r7(void){}
static void recomp_dbg_invalidate_addr_r8(void){}
static void recomp_dbg_invalidate_addr_r9(void){}
static void recomp_dbg_invalidate_addr_r10(void){}
static void recomp_dbg_invalidate_addr_r12(void){}
static void recomp_dbg_indirect_jump_indexed(void){}
static void recomp_dbg_indirect_jump(void){}
static void recomp_dbg_verify_code(void){}
static void recomp_dbg_verify_code_vm(void){}
static void recomp_dbg_verify_code_ds(void){}
static void recomp_dbg_cc_interrupt(void){}
static void recomp_dbg_do_interrupt(void){}
static void recomp_dbg_fp_exception(void){}
static void recomp_dbg_fp_exception_ds(void){}
static void recomp_dbg_jump_syscall(void){}
static void recomp_dbg_jump_eret(void){}
static void recomp_dbg_read_nomem_new(void){}
static void recomp_dbg_read_nomemd_new(void){}
static void recomp_dbg_write_nomem_new(void){}
static void recomp_dbg_write_nomemd_new(void){}
static void recomp_dbg_write_rdram_new(void){}
static void recomp_dbg_write_rdramd_new(void){}
static void recomp_dbg_clear_cache(char* begin, char *end){}

/* arm_cpu_features.c */
static arm_cpu_features_t arm_cpu_features;
static void detect_arm_cpu_features(void){}
static void print_arm_cpu_features(void){}

#endif

#endif /* M64P_R4300_ARM_RECOMP_DBG_H */
