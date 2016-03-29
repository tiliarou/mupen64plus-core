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
    GLOBAL_VARIABLE(mini_ht, 512)
    GLOBAL_VARIABLE(restore_candidate, 512)
    GLOBAL_VARIABLE(memory_map, 8388608)

extra_memory:
    .space    33554432+256+4+4+4+4+4+4+8+8+8+8+4+2+4+4+4+256+8+8+128+256+256+16+8+8+192+8+512+512+8388608

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
    restore_candidate = mini_ht           + 512
    memory_map        = restore_candidate + 512

END_SECTION

TEXT_SECTION

GLOBAL_FUNCTION(dyna_linker):
    brk 0
    
GLOBAL_FUNCTION(dyna_linker_ds):
    brk 0
    
GLOBAL_FUNCTION(jump_vaddr_x0):
    brk 0
    
GLOBAL_FUNCTION(jump_vaddr_x1):
    brk 0
    
GLOBAL_FUNCTION(jump_vaddr_x2):
    brk 0
    
GLOBAL_FUNCTION(jump_vaddr_x3):
    brk 0
    
GLOBAL_FUNCTION(jump_vaddr_x4):
    brk 0
    
GLOBAL_FUNCTION(jump_vaddr_x5):
    brk 0
    
GLOBAL_FUNCTION(jump_vaddr_x6):
    brk 0
    
GLOBAL_FUNCTION(jump_vaddr_x7):
    brk 0
    
GLOBAL_FUNCTION(jump_vaddr_x8):
    brk 0
    
GLOBAL_FUNCTION(jump_vaddr_x9):
    brk 0
    
GLOBAL_FUNCTION(jump_vaddr_x10):
    brk 0
    
GLOBAL_FUNCTION(jump_vaddr_x11):
    brk 0
    
GLOBAL_FUNCTION(jump_vaddr_x12):
    brk 0
    
GLOBAL_FUNCTION(jump_vaddr_x13):
    brk 0
    
GLOBAL_FUNCTION(jump_vaddr_x14):
    brk 0
    
GLOBAL_FUNCTION(jump_vaddr_x15):
    brk 0
    
GLOBAL_FUNCTION(jump_vaddr_x16):
    brk 0
    
GLOBAL_FUNCTION(jump_vaddr_x17):
    brk 0
    
GLOBAL_FUNCTION(jump_vaddr_x18):
    brk 0
    
GLOBAL_FUNCTION(jump_vaddr_x19):
    brk 0
    
GLOBAL_FUNCTION(jump_vaddr_x20):
    brk 0
    
GLOBAL_FUNCTION(jump_vaddr_x21):
    brk 0
    
GLOBAL_FUNCTION(jump_vaddr_x22):
    brk 0
    
GLOBAL_FUNCTION(jump_vaddr_x23):
    brk 0
    
GLOBAL_FUNCTION(jump_vaddr_x24):
    brk 0
    
GLOBAL_FUNCTION(jump_vaddr_x25):
    brk 0
    
GLOBAL_FUNCTION(jump_vaddr_x26):
    brk 0
    
GLOBAL_FUNCTION(jump_vaddr_x27):
    brk 0
    
GLOBAL_FUNCTION(jump_vaddr_x28):
    brk 0
    
GLOBAL_FUNCTION(jump_vaddr):
    brk 0
    
GLOBAL_FUNCTION(verify_code_ds):
    brk 0
    
GLOBAL_FUNCTION(verify_code_vm):
    brk 0
    
GLOBAL_FUNCTION(verify_code):
    brk 0
    
GLOBAL_FUNCTION(cc_interrupt):
    ldr    w0, [x29, #last_count-dynarec_local]
    add    w20, w0, w20 /* Count */
    str    wzr, [x29, #pending_exception-dynarec_local]
    mov    w1, #0x1fc
    lsr    w0, w20, #19
    and    w1, w1, w0 
    add    x0, x29, #restore_candidate-dynarec_local
    str    w20, [x29, #g_cp0_regs+36-dynarec_local] /* Count */
    ldr    w2, [x1, x0]
    mov    x20, x30 /* Save link register */
    tst    w2, w2
    b.ne   .E4
.E1:
    bl     gen_interupt
    mov    x30, x20 /* Restore link register */
    ldr    w20, [x29, #g_cp0_regs+36-dynarec_local] /* Count */
    ldr    w0, [x29, #next_interupt-dynarec_local]
    ldr    w1, [x29, #pending_exception-dynarec_local]
    ldr    w2, [x29, #stop-dynarec_local]
    str    w0, [x29, #last_count-dynarec_local]
    sub    w20, w20, w0
    tst    w2, w2
    b.ne   .E3
    tst    w1, w1
    b.ne   .E2
    ret    /* br x30 */
.E2:
    ldr    w0, [x29, #pcaddr-dynarec_local]
    bl     get_addr_ht
    br     x0
.E3:
    add    x16, x29, #152
    ldp    x19,x20,[x16,#0]
    ldp    x21,x22,[x16,#16]
    ldp    x23,x24,[x16,#32]
    ldp    x25,x26,[x16,#48]
    ldp    x27,x28,[x16,#64]
    ldp    x29,x30,[x16,#80]
.E4:
    /* Move 'dirty' blocks to the 'clean' list */
    str    wzr, [x1, x0]
    lsl    w1, w1, #3
    mov    w3, #0
.E5:
    and    w0, w2, #1
    tst    w0, w0
    add    w0, w1, w3
    b.ne   .E6
    bl     clean_blocks
.E6:
    lsr    w2, w2, #1
    add    w3, w3, #1
    tst    w3, #31
    b.ne   .E5
    b      .E1
    
GLOBAL_FUNCTION(do_interrupt):
    brk 0
    
GLOBAL_FUNCTION(fp_exception):
    brk 0
    
GLOBAL_FUNCTION(fp_exception_ds):
    brk 0
    
GLOBAL_FUNCTION(jump_syscall):
    brk 0
    
GLOBAL_FUNCTION(indirect_jump_indexed):
    ldr    x0, [x0, x1, lsl #3]

GLOBAL_FUNCTION(indirect_jump):
    ldr    w18, [x29, #last_count-dynarec_local]
    add    w2, w2, w18 
    str    w2, [x29, #g_cp0_regs+36-dynarec_local] /* Count */
    br     x0
    
GLOBAL_FUNCTION(jump_eret):
    brk 0
    
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
    
GLOBAL_FUNCTION(invalidate_addr_x0):
    brk 0
    
GLOBAL_FUNCTION(invalidate_addr_x1):
    brk 0
    
GLOBAL_FUNCTION(invalidate_addr_x2):
    brk 0
    
GLOBAL_FUNCTION(invalidate_addr_x3):
    brk 0
    
GLOBAL_FUNCTION(invalidate_addr_x4):
    brk 0
    
GLOBAL_FUNCTION(invalidate_addr_x5):
    brk 0
    
GLOBAL_FUNCTION(invalidate_addr_x6):
    brk 0
    
GLOBAL_FUNCTION(invalidate_addr_x7):
    brk 0
    
GLOBAL_FUNCTION(invalidate_addr_x8):
    brk 0
    
GLOBAL_FUNCTION(invalidate_addr_x9):
    brk 0
    
GLOBAL_FUNCTION(invalidate_addr_x10):
    brk 0
    
GLOBAL_FUNCTION(invalidate_addr_x11):
    brk 0
    
GLOBAL_FUNCTION(invalidate_addr_x12):
    brk 0
    
GLOBAL_FUNCTION(invalidate_addr_x13):
    brk 0
    
GLOBAL_FUNCTION(invalidate_addr_x14):
    brk 0
    
GLOBAL_FUNCTION(invalidate_addr_x15):
    brk 0
    
GLOBAL_FUNCTION(invalidate_addr_x16):
    brk 0
    
GLOBAL_FUNCTION(invalidate_addr_x17):
    brk 0
    
GLOBAL_FUNCTION(invalidate_addr_x18):
    brk 0
    
GLOBAL_FUNCTION(invalidate_addr_x19):
    brk 0
    
GLOBAL_FUNCTION(invalidate_addr_x20):
    brk 0
    
GLOBAL_FUNCTION(invalidate_addr_x21):
    brk 0
    
GLOBAL_FUNCTION(invalidate_addr_x22):
    brk 0
    
GLOBAL_FUNCTION(invalidate_addr_x23):
    brk 0
    
GLOBAL_FUNCTION(invalidate_addr_x24):
    brk 0
    
GLOBAL_FUNCTION(invalidate_addr_x25):
    brk 0
    
GLOBAL_FUNCTION(invalidate_addr_x26):
    brk 0
    
GLOBAL_FUNCTION(invalidate_addr_x27):
    brk 0
    
GLOBAL_FUNCTION(invalidate_addr_x28):
    brk 0
    
GLOBAL_FUNCTION(write_rdram_new):
    brk 0
    
GLOBAL_FUNCTION(write_rdramb_new):
    brk 0
    
GLOBAL_FUNCTION(write_rdramh_new):
    brk 0
    
GLOBAL_FUNCTION(write_rdramd_new):
    brk 0
    
GLOBAL_FUNCTION(read_nomem_new):
    brk 0
    
GLOBAL_FUNCTION(read_nomemb_new):
    brk 0
    
GLOBAL_FUNCTION(read_nomemh_new):
    brk 0
    
GLOBAL_FUNCTION(read_nomemd_new):
    brk 0
    
GLOBAL_FUNCTION(write_nomem_new):
    brk 0
    
GLOBAL_FUNCTION(write_nomemb_new):
    brk 0
    
GLOBAL_FUNCTION(write_nomemh_new):
    brk 0
    
GLOBAL_FUNCTION(write_nomemd_new):
    brk 0
    
GLOBAL_FUNCTION(breakpoint):
    brk 0
    
GLOBAL_FUNCTION(__clear_cache_bugfix):
    nop

END_SECTION