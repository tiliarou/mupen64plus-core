/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *   Mupen64plus - linkage_arm64.S                                         *
 *   Copyright (C) 2009-2011 Ari64                                         *
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

#define GLOBAL_FUNCTION(name)  \
    .align 3;                  \
    .globl name;               \
    .hidden name;              \
    .type name, %function;     \
    name

#define LOCAL_FUNCTION(name)  \
    .align 3;                 \
    .hidden name;             \
    .type name, %function;    \
    name

#define GLOBAL_VARIABLE(name, size_) \
    .global name;                    \
    .hidden name;                    \
    .type   name, %object;           \
    .size   name, size_

#define BSS_SECTION .bss
#define TEXT_SECTION .text
#define END_SECTION

BSS_SECTION

    .align 12
    GLOBAL_VARIABLE(extra_memory, 33554432)
    GLOBAL_VARIABLE(dynarec_local, 256)
    GLOBAL_VARIABLE(next_interupt, 4)
    GLOBAL_VARIABLE(cycle_count, 4)
    GLOBAL_VARIABLE(last_count, 4)
    GLOBAL_VARIABLE(pending_exception, 4)
    GLOBAL_VARIABLE(pcaddr, 4)
    GLOBAL_VARIABLE(stop, 4)
    GLOBAL_VARIABLE(invc_ptr, 8)
    GLOBAL_VARIABLE(address, 4)
    GLOBAL_VARIABLE(readmem_dword, 8)
    GLOBAL_VARIABLE(cpu_dword, 8)
    GLOBAL_VARIABLE(cpu_word, 4)
    GLOBAL_VARIABLE(cpu_hword, 2)
    GLOBAL_VARIABLE(cpu_byte, 1)
    GLOBAL_VARIABLE(FCR0, 4)
    GLOBAL_VARIABLE(FCR31, 4)
    GLOBAL_VARIABLE(reg, 256)
    GLOBAL_VARIABLE(hi, 8)
    GLOBAL_VARIABLE(lo, 8)
    GLOBAL_VARIABLE(g_cp0_regs, 128)
    GLOBAL_VARIABLE(reg_cop1_simple, 256)
    GLOBAL_VARIABLE(reg_cop1_double, 256)
    GLOBAL_VARIABLE(rounding_modes, 16)
    GLOBAL_VARIABLE(branch_target, 4)
    GLOBAL_VARIABLE(PC, 8)
    GLOBAL_VARIABLE(fake_pc, 208)
    GLOBAL_VARIABLE(ram_offset, 8)
    GLOBAL_VARIABLE(mini_ht, 256)
    GLOBAL_VARIABLE(restore_candidate, 512)
    GLOBAL_VARIABLE(memory_map, 8388608)

extra_memory:
    .space    33554432+256+4+4+4+4+4+4+8+8+8+8+4+2+4+4+4+256+8+8+128+256+256+16+8+8+192+8+256+512+8388608

    dynarec_local     = extra_memory      + 33554432
    next_interupt     = dynarec_local     + 256
    cycle_count       = next_interupt     + 4
    last_count        = cycle_count       + 4
    pending_exception = last_count        + 4
    pcaddr            = pending_exception + 4
    stop              = pcaddr            + 4
    invc_ptr          = stop              + 4
    address           = invc_ptr          + 8
    readmem_dword     = address           + 8 /* 4 byte free */
    cpu_dword         = readmem_dword     + 8
    cpu_word          = cpu_dword         + 8
    cpu_hword         = cpu_word          + 4
    cpu_byte          = cpu_hword         + 2 /* 1 byte free */
    FCR0              = cpu_hword         + 4
    FCR31             = FCR0              + 4
    reg               = FCR31             + 4
    hi                = reg               + 256
    lo                = hi                + 8
    g_cp0_regs        = lo                + 8
    reg_cop1_simple   = g_cp0_regs        + 128
    reg_cop1_double   = reg_cop1_simple   + 256
    rounding_modes    = reg_cop1_double   + 256
    branch_target     = rounding_modes    + 16
    PC                = branch_target     + 8 /* 4 byte free */
    fake_pc           = PC                + 8
    ram_offset        = fake_pc           + 208
    mini_ht           = ram_offset        + 8
    restore_candidate = mini_ht           + 256
    memory_map        = restore_candidate + 512

END_SECTION

TEXT_SECTION

GLOBAL_FUNCTION(dyna_linker):
    nop
    
GLOBAL_FUNCTION(dyna_linker_ds):
    nop
    
GLOBAL_FUNCTION(jump_vaddr_r0):
    nop
    
GLOBAL_FUNCTION(jump_vaddr_r1):
    nop
    
GLOBAL_FUNCTION(jump_vaddr_r2):
    nop
    
GLOBAL_FUNCTION(jump_vaddr_r3):
    nop
    
GLOBAL_FUNCTION(jump_vaddr_r4):
    nop
    
GLOBAL_FUNCTION(jump_vaddr_r5):
    nop
    
GLOBAL_FUNCTION(jump_vaddr_r6):
    nop
    
GLOBAL_FUNCTION(jump_vaddr_r8):
    nop
    
GLOBAL_FUNCTION(jump_vaddr_r9):
    nop
    
GLOBAL_FUNCTION(jump_vaddr_r10):
    nop
    
GLOBAL_FUNCTION(jump_vaddr_r12):
    nop
    
GLOBAL_FUNCTION(jump_vaddr_r7):
    nop
    
GLOBAL_FUNCTION(jump_vaddr):
    nop
    
GLOBAL_FUNCTION(verify_code_ds):
    nop
    
GLOBAL_FUNCTION(verify_code_vm):
    nop
    
GLOBAL_FUNCTION(verify_code):
    nop
    
GLOBAL_FUNCTION(cc_interrupt):
    nop
    
GLOBAL_FUNCTION(do_interrupt):
    nop
    
GLOBAL_FUNCTION(fp_exception):
    nop
    
GLOBAL_FUNCTION(fp_exception_ds):
    nop
    
GLOBAL_FUNCTION(jump_syscall):
    nop
    
GLOBAL_FUNCTION(indirect_jump_indexed):
    nop
    
GLOBAL_FUNCTION(indirect_jump):
    nop
    
GLOBAL_FUNCTION(jump_eret):
    nop
    
GLOBAL_FUNCTION(new_dyna_start):
    adrp   x16, dynarec_local
    add    x16, x16, :lo12:dynarec_local
    add    x16, x16, #152
    adrp   x1, base_addr
    add    x1, x1, :lo12:base_addr
    mov    w0, #0xa4000000
    stp    x19,x20,[x16,#0]
    stp    x21,x22,[x16,#16]
    stp    x23,x24,[x16,#32]
    stp    x25,x26,[x16,#48]
    stp    x27,x28,[x16,#64]
    stp    x29,x30,[x16,#80]
    sub    x29, x16, #152
    ldr    x19, [x1]
    add    w0, w0, #0x40
    bl     new_recompile_block
    ldr    w0, [x29, #next_interupt-dynarec_local]
    ldr    w20, [x29, #g_cp0_regs+36-dynarec_local] /* Count */
    str    w0, [x29, #last_count-dynarec_local]
    sub    w20, w20, w0
    br     x19
    
GLOBAL_FUNCTION(invalidate_addr_r0):
    nop
    
GLOBAL_FUNCTION(invalidate_addr_r1):
    nop
    
GLOBAL_FUNCTION(invalidate_addr_r2):
    nop
    
GLOBAL_FUNCTION(invalidate_addr_r3):
    nop
    
GLOBAL_FUNCTION(invalidate_addr_r4):
    nop
    
GLOBAL_FUNCTION(invalidate_addr_r5):
    nop
    
GLOBAL_FUNCTION(invalidate_addr_r6):
    nop
    
GLOBAL_FUNCTION(invalidate_addr_r7):
    nop
    
GLOBAL_FUNCTION(invalidate_addr_r8):
    nop
    
GLOBAL_FUNCTION(invalidate_addr_r9):
    nop
    
GLOBAL_FUNCTION(invalidate_addr_r10):
    nop
    
GLOBAL_FUNCTION(invalidate_addr_r12):
    nop
    
GLOBAL_FUNCTION(write_rdram_new):
    nop
    
GLOBAL_FUNCTION(write_rdramb_new):
    nop
    
GLOBAL_FUNCTION(write_rdramh_new):
    nop
    
GLOBAL_FUNCTION(write_rdramd_new):
    nop
    
GLOBAL_FUNCTION(read_nomem_new):
    nop
    
GLOBAL_FUNCTION(read_nomemb_new):
    nop
    
GLOBAL_FUNCTION(read_nomemh_new):
    nop
    
GLOBAL_FUNCTION(read_nomemd_new):
    nop
    
GLOBAL_FUNCTION(write_nomem_new):
    nop
    
GLOBAL_FUNCTION(write_nomemb_new):
    nop
    
GLOBAL_FUNCTION(write_nomemh_new):
    nop
    
GLOBAL_FUNCTION(write_nomemd_new):
    nop
    
GLOBAL_FUNCTION(breakpoint):
    nop
    
GLOBAL_FUNCTION(__clear_cache_bugfix):
    nop

END_SECTION