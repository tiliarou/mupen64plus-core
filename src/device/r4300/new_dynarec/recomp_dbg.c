/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *   Mupen64plus - recomp_dbg.c                                            *
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

#ifdef RECOMPILER_DEBUG
#define RECOMP_DBG

extern unsigned int using_tlb;

static int disasm_block[] = {0xa4000040};

#include "new_dynarec.c"

typedef struct{
  intptr_t addr;
  int32_t size;
  char * name;
}Variable_t;

static Variable_t var[] = {
  {(intptr_t)NULL /*RDRAM*/, 0, "rdram - 0x80000000"},
  {(intptr_t)g_dev.r4300.cached_interp.invalid_code, sizeof(g_dev.r4300.cached_interp.invalid_code), "invalid_code"},
  {(intptr_t)g_dev.mem.readmem, sizeof(g_dev.mem.readmem), "mem_readmem"},
  {(intptr_t)g_dev.mem.readmemd, sizeof(g_dev.mem.readmemd), "mem_readmemd"},
  {(intptr_t)g_dev.mem.writemem, sizeof(g_dev.mem.writemem), "mem_writemem"},
  {(intptr_t)g_dev.mem.writememd, sizeof(g_dev.mem.writememd), "mem_writememd"},

  {(intptr_t)&g_dev.r4300.new_dynarec_hot_state.dynarec_local, sizeof(g_dev.r4300.new_dynarec_hot_state.dynarec_local), "dynarec_local"},
  {(intptr_t)&g_dev.r4300.new_dynarec_hot_state.next_interrupt, sizeof(g_dev.r4300.new_dynarec_hot_state.next_interrupt), "next_interrupt"},
  {(intptr_t)&g_dev.r4300.new_dynarec_hot_state.cycle_count, sizeof(g_dev.r4300.new_dynarec_hot_state.cycle_count), "cycle_count"},
  {(intptr_t)&g_dev.r4300.new_dynarec_hot_state.last_count, sizeof(g_dev.r4300.new_dynarec_hot_state.last_count), "last_count"},
  {(intptr_t)&g_dev.r4300.new_dynarec_hot_state.pending_exception, sizeof(g_dev.r4300.new_dynarec_hot_state.pending_exception), "pending_exception"},
  {(intptr_t)&g_dev.r4300.new_dynarec_hot_state.pcaddr, sizeof(g_dev.r4300.new_dynarec_hot_state.pcaddr), "pcaddr"},
  {(intptr_t)&g_dev.r4300.new_dynarec_hot_state.stop, sizeof(g_dev.r4300.new_dynarec_hot_state.stop), "r4300_stop"},
  {(intptr_t)&g_dev.r4300.new_dynarec_hot_state.invc_ptr, sizeof(g_dev.r4300.new_dynarec_hot_state.invc_ptr), "invc_ptr"},
  {(intptr_t)&g_dev.r4300.new_dynarec_hot_state.address, sizeof(g_dev.r4300.new_dynarec_hot_state.address), "mem_address"},
  {(intptr_t)&g_dev.r4300.new_dynarec_hot_state.rdword, sizeof(g_dev.r4300.new_dynarec_hot_state.rdword), "readmem_dword"},
  {(intptr_t)&g_dev.r4300.new_dynarec_hot_state.wdword, sizeof(g_dev.r4300.new_dynarec_hot_state.wdword), "mem_wdword"},
  {(intptr_t)&g_dev.r4300.new_dynarec_hot_state.wword, sizeof(g_dev.r4300.new_dynarec_hot_state.wword), "mem_wword"},
  {(intptr_t)&g_dev.r4300.new_dynarec_hot_state.fcr0, sizeof(g_dev.r4300.new_dynarec_hot_state.fcr0), "cp1_fcr0"},
  {(intptr_t)&g_dev.r4300.new_dynarec_hot_state.fcr31, sizeof(g_dev.r4300.new_dynarec_hot_state.fcr31), "cp1_fcr31"},
  {(intptr_t)&g_dev.r4300.new_dynarec_hot_state.regs, sizeof(g_dev.r4300.new_dynarec_hot_state.regs), "r4300_regs"},
  {(intptr_t)&g_dev.r4300.new_dynarec_hot_state.hi, sizeof(g_dev.r4300.new_dynarec_hot_state.hi), "r4300_hi"},
  {(intptr_t)&g_dev.r4300.new_dynarec_hot_state.lo, sizeof(g_dev.r4300.new_dynarec_hot_state.lo), "r4300_lo"},
  {(intptr_t)&g_dev.r4300.new_dynarec_hot_state.cp0_regs, sizeof(g_dev.r4300.new_dynarec_hot_state.cp0_regs), "cp0_regs"},
  {(intptr_t)&g_dev.r4300.new_dynarec_hot_state.cp1_regs_simple, sizeof(g_dev.r4300.new_dynarec_hot_state.cp1_regs_simple), "cp1_regs_simple"},
  {(intptr_t)&g_dev.r4300.new_dynarec_hot_state.cp1_regs_double, sizeof(g_dev.r4300.new_dynarec_hot_state.cp1_regs_double), "cp1_regs_double"},
  {(intptr_t)&g_dev.r4300.new_dynarec_hot_state.rounding_modes, sizeof(g_dev.r4300.new_dynarec_hot_state.rounding_modes), "rounding_modes"},
  {(intptr_t)&g_dev.r4300.new_dynarec_hot_state.branch_target, sizeof(g_dev.r4300.new_dynarec_hot_state.branch_target), "branch_target"},
  {(intptr_t)&g_dev.r4300.new_dynarec_hot_state.pc, sizeof(g_dev.r4300.new_dynarec_hot_state.pc), "r4300_pc"},
  {(intptr_t)&g_dev.r4300.new_dynarec_hot_state.fake_pc, sizeof(g_dev.r4300.new_dynarec_hot_state.fake_pc), "fake_pc"},
  {(intptr_t)&g_dev.r4300.new_dynarec_hot_state.ram_offset, sizeof(g_dev.r4300.new_dynarec_hot_state.ram_offset), "ram_offset"},
  {(intptr_t)&g_dev.r4300.new_dynarec_hot_state.mini_ht, sizeof(g_dev.r4300.new_dynarec_hot_state.mini_ht), "mini_ht"},
  {(intptr_t)&g_dev.r4300.new_dynarec_hot_state.restore_candidate, sizeof(g_dev.r4300.new_dynarec_hot_state.restore_candidate), "restore_candidate"},
  {(intptr_t)&g_dev.r4300.new_dynarec_hot_state.memory_map, sizeof(g_dev.r4300.new_dynarec_hot_state.memory_map), "memory_map"},
  {-1, -1, NULL}
};

typedef struct{
  intptr_t addr;
  char * name;
}Function_t;

static Function_t func[] = {
  {(intptr_t)NULL /*MFC0*/, "MFC0"},
  {(intptr_t)NULL /*MTC0*/, "MTC0"},
  {(intptr_t)NULL /*TLBR*/, "TLBR"},
  {(intptr_t)NULL /*TLBP*/, "TLBP"},
#if RECOMPILER_DEBUG >= NEW_DYNAREC_ARM
  {(intptr_t)invalidate_addr, "invalidate_addr"},
  {(intptr_t)indirect_jump_indexed, "indirect_jump_indexed"},
  {(intptr_t)indirect_jump, "indirect_jump"},
#if RECOMPILER_DEBUG == NEW_DYNAREC_ARM64
  {(intptr_t)jump_vaddr_x0, "jump_vaddr_x0"},
  {(intptr_t)jump_vaddr_x1, "jump_vaddr_x1"},
  {(intptr_t)jump_vaddr_x2, "jump_vaddr_x2"},
  {(intptr_t)jump_vaddr_x3, "jump_vaddr_x3"},
  {(intptr_t)jump_vaddr_x4, "jump_vaddr_x4"},
  {(intptr_t)jump_vaddr_x5, "jump_vaddr_x5"},
  {(intptr_t)jump_vaddr_x6, "jump_vaddr_x6"},
  {(intptr_t)jump_vaddr_x7, "jump_vaddr_x7"},
  {(intptr_t)jump_vaddr_x8, "jump_vaddr_x8"},
  {(intptr_t)jump_vaddr_x9, "jump_vaddr_x9"},
  {(intptr_t)jump_vaddr_x10, "jump_vaddr_x10"},
  {(intptr_t)jump_vaddr_x11, "jump_vaddr_x11"},
  {(intptr_t)jump_vaddr_x12, "jump_vaddr_x12"},
  {(intptr_t)jump_vaddr_x13, "jump_vaddr_x13"},
  {(intptr_t)jump_vaddr_x14, "jump_vaddr_x14"},
  {(intptr_t)jump_vaddr_x15, "jump_vaddr_x15"},
  {(intptr_t)jump_vaddr_x16, "jump_vaddr_x16"},
  {(intptr_t)jump_vaddr_x17, "jump_vaddr_x17"},
  {(intptr_t)jump_vaddr_x18, "jump_vaddr_x18"},
  {(intptr_t)jump_vaddr_x19, "jump_vaddr_x19"},
  {(intptr_t)jump_vaddr_x20, "jump_vaddr_x20"},
  {(intptr_t)jump_vaddr_x21, "jump_vaddr_x21"},
  {(intptr_t)jump_vaddr_x22, "jump_vaddr_x22"},
  {(intptr_t)jump_vaddr_x23, "jump_vaddr_x23"},
  {(intptr_t)jump_vaddr_x24, "jump_vaddr_x24"},
  {(intptr_t)jump_vaddr_x25, "jump_vaddr_x25"},
  {(intptr_t)jump_vaddr_x26, "jump_vaddr_x26"},
  {(intptr_t)jump_vaddr_x27, "jump_vaddr_x27"},
  {(intptr_t)jump_vaddr_x28, "jump_vaddr_x28"},
  {(intptr_t)invalidate_addr_x0," invalidate_addr_x0"},
  {(intptr_t)invalidate_addr_x1," invalidate_addr_x1"},
  {(intptr_t)invalidate_addr_x2," invalidate_addr_x2"},
  {(intptr_t)invalidate_addr_x3," invalidate_addr_x3"},
  {(intptr_t)invalidate_addr_x4," invalidate_addr_x4"},
  {(intptr_t)invalidate_addr_x5," invalidate_addr_x5"},
  {(intptr_t)invalidate_addr_x6," invalidate_addr_x6"},
  {(intptr_t)invalidate_addr_x7," invalidate_addr_x7"},
  {(intptr_t)invalidate_addr_x8," invalidate_addr_x8"},
  {(intptr_t)invalidate_addr_x9," invalidate_addr_x9"},
  {(intptr_t)invalidate_addr_x10," invalidate_addr_x10"},
  {(intptr_t)invalidate_addr_x11," invalidate_addr_x11"},
  {(intptr_t)invalidate_addr_x12," invalidate_addr_x12"},
  {(intptr_t)invalidate_addr_x13," invalidate_addr_x13"},
  {(intptr_t)invalidate_addr_x14," invalidate_addr_x14"},
  {(intptr_t)invalidate_addr_x15," invalidate_addr_x15"},
  {(intptr_t)invalidate_addr_x16," invalidate_addr_x16"},
  {(intptr_t)invalidate_addr_x17," invalidate_addr_x17"},
  {(intptr_t)invalidate_addr_x18," invalidate_addr_x18"},
  {(intptr_t)invalidate_addr_x19," invalidate_addr_x19"},
  {(intptr_t)invalidate_addr_x20," invalidate_addr_x20"},
  {(intptr_t)invalidate_addr_x21," invalidate_addr_x21"},
  {(intptr_t)invalidate_addr_x22," invalidate_addr_x22"},
  {(intptr_t)invalidate_addr_x23," invalidate_addr_x23"},
  {(intptr_t)invalidate_addr_x24," invalidate_addr_x24"},
  {(intptr_t)invalidate_addr_x25," invalidate_addr_x25"},
  {(intptr_t)invalidate_addr_x26," invalidate_addr_x26"},
  {(intptr_t)invalidate_addr_x27," invalidate_addr_x27"},
  {(intptr_t)invalidate_addr_x28," invalidate_addr_x28"},
#else
  {(intptr_t)jump_vaddr_r0, "jump_vaddr_r0"},
  {(intptr_t)jump_vaddr_r1, "jump_vaddr_r1"},
  {(intptr_t)jump_vaddr_r2, "jump_vaddr_r2"},
  {(intptr_t)jump_vaddr_r3, "jump_vaddr_r3"},
  {(intptr_t)jump_vaddr_r4, "jump_vaddr_r4"},
  {(intptr_t)jump_vaddr_r5, "jump_vaddr_r5"},
  {(intptr_t)jump_vaddr_r6, "jump_vaddr_r6"},
  {(intptr_t)jump_vaddr_r7, "jump_vaddr_r7"},
  {(intptr_t)jump_vaddr_r8, "jump_vaddr_r8"},
  {(intptr_t)jump_vaddr_r9, "jump_vaddr_r9"},
  {(intptr_t)jump_vaddr_r10, "jump_vaddr_r10"},
  {(intptr_t)jump_vaddr_r12, "jump_vaddr_r12"},
  {(intptr_t)invalidate_addr_r0," invalidate_addr_r0"},
  {(intptr_t)invalidate_addr_r1," invalidate_addr_r1"},
  {(intptr_t)invalidate_addr_r2," invalidate_addr_r2"},
  {(intptr_t)invalidate_addr_r3," invalidate_addr_r3"},
  {(intptr_t)invalidate_addr_r4," invalidate_addr_r4"},
  {(intptr_t)invalidate_addr_r5," invalidate_addr_r5"},
  {(intptr_t)invalidate_addr_r6," invalidate_addr_r6"},
  {(intptr_t)invalidate_addr_r7," invalidate_addr_r7"},
  {(intptr_t)invalidate_addr_r8," invalidate_addr_r8"},
  {(intptr_t)invalidate_addr_r9," invalidate_addr_r9"},
  {(intptr_t)invalidate_addr_r10," invalidate_addr_r10"},
  {(intptr_t)invalidate_addr_r12," invalidate_addr_r12"},
#endif
#else
  {(intptr_t)jump_vaddr_eax, "jump_vaddr_eax"},
  {(intptr_t)jump_vaddr_ecx, "jump_vaddr_ecx"},
  {(intptr_t)jump_vaddr_edx, "jump_vaddr_edx"},
  {(intptr_t)jump_vaddr_ebx, "jump_vaddr_ebx"},
  {(intptr_t)jump_vaddr_ebp, "jump_vaddr_ebp"},
  {(intptr_t)jump_vaddr_edi, "jump_vaddr_edi"},
  {(intptr_t)invalidate_block_eax, "invalidate_block_eax"},
  {(intptr_t)invalidate_block_ecx, "invalidate_block_ecx"},
  {(intptr_t)invalidate_block_edx, "invalidate_block_edx"},
  {(intptr_t)invalidate_block_ebx, "invalidate_block_ebx"},
  {(intptr_t)invalidate_block_ebp, "invalidate_block_ebp"},
  {(intptr_t)invalidate_block_esi, "invalidate_block_esi"},
  {(intptr_t)invalidate_block_edi, "invalidate_block_edi"},
#endif
  {(intptr_t)dyna_linker, "dyna_linker"},
  {(intptr_t)dyna_linker_ds, "dyna_linker_ds"},
  {(intptr_t)TLBWI_new, "TLBWI_new"},
  {(intptr_t)TLBWR_new, "TLBWR_new"},
  {(intptr_t)verify_code, "verify_code"},
  {(intptr_t)verify_code_vm, "verify_code_vm"},
  {(intptr_t)verify_code_ds, "verify_code_ds"},
  {(intptr_t)cc_interrupt, "cc_interrupt"},
  {(intptr_t)fp_exception, "fp_exception"},
  {(intptr_t)fp_exception_ds, "fp_exception_ds"},
  {(intptr_t)jump_syscall, "jump_syscall"},
  {(intptr_t)jump_eret, "jump_eret"},
  {(intptr_t)do_interrupt, "do_interrupt"},
  {(intptr_t)div64, "div64"},
  {(intptr_t)divu64, "divu64"},
  {(intptr_t)cvt_s_w, "cvt_s_w"},
  {(intptr_t)cvt_d_w, "cvt_d_w"},
  {(intptr_t)cvt_s_l, "cvt_s_l"},
  {(intptr_t)cvt_d_l, "cvt_d_l"},
  {(intptr_t)cvt_w_s, "cvt_w_s"},
  {(intptr_t)cvt_w_d, "cvt_w_d"},
  {(intptr_t)cvt_l_s, "cvt_l_s"},
  {(intptr_t)cvt_l_d, "cvt_l_d"},
  {(intptr_t)cvt_d_s, "cvt_d_s"},
  {(intptr_t)cvt_s_d, "cvt_s_d"},
  {(intptr_t)round_l_s, "round_l_s"},
  {(intptr_t)round_w_s, "round_w_s"},
  {(intptr_t)trunc_l_s, "trunc_l_s"},
  {(intptr_t)trunc_w_s, "trunc_w_s"},
  {(intptr_t)ceil_l_s, "ceil_l_s"},
  {(intptr_t)ceil_w_s, "ceil_w_s"},
  {(intptr_t)floor_l_s, "floor_l_s"},
  {(intptr_t)floor_w_s, "floor_w_s"},
  {(intptr_t)round_l_d, "round_l_d"},
  {(intptr_t)round_w_d, "round_w_d"},
  {(intptr_t)trunc_l_d, "trunc_l_d"},
  {(intptr_t)trunc_w_d, "trunc_w_d"},
  {(intptr_t)ceil_l_d, "ceil_l_d"},
  {(intptr_t)ceil_w_d, "ceil_w_d"},
  {(intptr_t)floor_l_d, "floor_l_d"},
  {(intptr_t)floor_w_d, "floor_w_d"},
  {(intptr_t)c_f_s, "c_f_s"},
  {(intptr_t)c_un_s, "c_un_s"},
  {(intptr_t)c_eq_s, "c_eq_s"},
  {(intptr_t)c_ueq_s, "c_ueq_s"},
  {(intptr_t)c_olt_s, "c_olt_s"},
  {(intptr_t)c_ult_s, "c_ult_s"},
  {(intptr_t)c_ole_s, "c_ole_s"},
  {(intptr_t)c_ule_s, "c_ule_s"},
  {(intptr_t)c_sf_s, "c_sf_s"},
  {(intptr_t)c_ngle_s, "c_ngle_s"},
  {(intptr_t)c_seq_s, "c_seq_s"},
  {(intptr_t)c_ngl_s, "c_ngl_s"},
  {(intptr_t)c_lt_s, "c_lt_s"},
  {(intptr_t)c_nge_s, "c_nge_s"},
  {(intptr_t)c_le_s, "c_le_s"},
  {(intptr_t)c_ngt_s, "c_ngt_s"},
  {(intptr_t)c_f_d, "c_f_d"},
  {(intptr_t)c_un_d, "c_un_d"},
  {(intptr_t)c_eq_d, "c_eq_d"},
  {(intptr_t)c_ueq_d, "c_ueq_d"},
  {(intptr_t)c_olt_d, "c_olt_d"},
  {(intptr_t)c_ult_d, "c_ult_d"},
  {(intptr_t)c_ole_d, "c_ole_d"},
  {(intptr_t)c_ule_d, "c_ule_d"},
  {(intptr_t)c_sf_d, "c_sf_d"},
  {(intptr_t)c_ngle_d, "c_ngle_d"},
  {(intptr_t)c_seq_d, "c_seq_d"},
  {(intptr_t)c_ngl_d, "c_ngl_d"},
  {(intptr_t)c_lt_d, "c_lt_d"},
  {(intptr_t)c_nge_d, "c_nge_d"},
  {(intptr_t)c_le_d, "c_le_d"},
  {(intptr_t)c_ngt_d, "c_ngt_d"},
  {(intptr_t)add_s, "add_s"},
  {(intptr_t)sub_s, "sub_s"},
  {(intptr_t)mul_s, "mul_s"},
  {(intptr_t)div_s, "div_s"},
  {(intptr_t)sqrt_s, "sqrt_s"},
  {(intptr_t)abs_s, "abs_s"},
  {(intptr_t)mov_s, "mov_s"},
  {(intptr_t)neg_s, "neg_s"},
  {(intptr_t)add_d, "add_d"},
  {(intptr_t)sub_d, "sub_d"},
  {(intptr_t)mul_d, "mul_d"},
  {(intptr_t)div_d, "div_d"},
  {(intptr_t)sqrt_d, "sqrt_d"},
  {(intptr_t)abs_d, "abs_d"},
  {(intptr_t)mov_d, "mov_d"},
  {(intptr_t)neg_d, "neg_d"},
  {-1, NULL}
};

static csh handle;

void recomp_dbg_init(void)
{
  var[0].addr = (uintptr_t)g_dev.ri.rdram.dram - 0x80000000;
  var[0].size = g_dev.ri.rdram.dram_size;

  func[0].addr = (uintptr_t)cached_interpreter_table.MFC0;
  func[1].addr = (uintptr_t)cached_interpreter_table.MTC0;
  func[2].addr = (uintptr_t)cached_interpreter_table.TLBR;
  func[3].addr = (uintptr_t)cached_interpreter_table.TLBP;

#if RECOMPILER_DEBUG >= NEW_DYNAREC_ARM
  base_addr = (void*)BASE_ADDR;
#else
  base_addr = VirtualAlloc(NULL, 1<<TARGET_SIZE_2, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
#endif

  /* New dynarec init */
  out=(u_char *)base_addr;

  for(int n=0;n<65536;n++)
    hash_table[n][0]=hash_table[n][2]=-1;

  copy_size=0;
  expirep=16384; // Expiry pointer, +2 blocks
  literalcount=0;

  arch_init();

  /* Capstone init */
  if(cs_open(ARCHITECTURE, MODE, &handle) != CS_ERR_OK) return;
  cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
}

void recomp_dbg_cleanup(void)
{
  /* New dynarec cleanup */
  for(int n=0;n<4096;n++) ll_clear(jump_in+n);
  for(int n=0;n<4096;n++) ll_clear(jump_out+n);
  for(int n=0;n<4096;n++) ll_clear(jump_dirty+n);
  assert(copy_size==0);

  VirtualFree(base_addr, 0, MEM_RELEASE);

  /* Capstone cleanup */
  if(handle == 0) return;
  cs_close(&handle);
}

void recomp_dbg_block(int addr)
{
  uint32_t * beginning;
  uint32_t * end;
  cs_insn *instr;
  size_t count;
  int32_t size = 0;
  int32_t sum = 0;
  char filename[32];

  /* Copy data from running dynarec */
#undef using_tlb

  recomp_dbg_using_tlb = using_tlb;

  /* Warning: invalid_code is shared between both running and debugged recompiler*/
  beginning=(uint32_t *)out;
  new_recompile_block(addr);
  end=(uint32_t *)out;

#if 0
  for(int i=0;i<linkcount;i++){
    if(!link_addr[i][2])
      dynamic_linker((void*)link_addr[i][0],0xa4000044);
  }

  for(int i = 0; i < 4096; i++)
  {
    struct ll_entry *head;
    head=jump_out[i];
    while(head!=NULL) {
      intptr_t addr=get_pointer(head->addr);
      addr=(intptr_t)kill_pointer(head->addr);
      head=head->next;
    }

    head=jump_dirty[i];
    while(head!=NULL) {
      verify_dirty(head->addr);
      uintptr_t start,end;
      get_bounds((intptr_t)head->addr, &start, &end);
      isclean((intptr_t)head->addr);
      uintptr_t clean=get_clean_addr((intptr_t)head->addr);
      head=head->next;
    }

    head=jump_in[i];
    while(head!=NULL) {
      isclean((intptr_t)head->addr);
      head=head->next;
    }
  }
#endif

  int disasm=0;
  int block, inst;
  for(block=0;block<(sizeof(disasm_block)>>2);block++) {
    for(inst=0;inst<slen;inst++) {
      if((start+inst*4)==disasm_block[block]) {
        disasm=1;
        break;
      }
    }
  }

  if((disasm == 0) || (handle == 0)) return;

  sprintf(filename, "%s_0x%.8x.txt",ARCH_NAME,addr);
  FILE * pFile = fopen (filename,"w");
  size = (intptr_t)end - (intptr_t)beginning;
  size = (size < 0) ? (-size) : size;

  count = cs_disasm(handle, (uint8_t*)beginning, size, (uintptr_t)beginning, 0, &instr);
  if(count <= 0) return;

  for (uint32_t i = 0; i < count; i++) {
    sum += instr[i].size;
 #if RECOMPILER_DEBUG >= NEW_DYNAREC_ARM
    if(INSTRUCTION.operands[1].reg == FP_REGISTER) {
      uint32_t j = 0;
      uint32_t imm;

      if(INSTRUCTION.op_count > 2)
        imm = INSTRUCTION.operands[2].mem.base;
      else
        imm = INSTRUCTION.operands[1].mem.disp;

      assert(imm>=0 && imm<4096);

      while(var[j].addr != -1) {
        uint32_t offset = var[j].addr - (uintptr_t)&g_dev.r4300.new_dynarec_hot_state.dynarec_local;
        if(imm >= offset && imm < (offset + var[j].size))
          break;
        j++;
      }
      if(var[j].addr != -1) {
        if((imm - (var[j].addr - (uintptr_t)&g_dev.r4300.new_dynarec_hot_state.dynarec_local)) == 0)
          fprintf(pFile, "0x%x: %s %s (%s)\n", (uintptr_t)instr[i].address, instr[i].mnemonic, instr[i].op_str, var[j].name);
        else
          fprintf(pFile, "0x%x: %s %s (%s+%d)\n", (uintptr_t)instr[i].address, instr[i].mnemonic, instr[i].op_str, var[j].name, imm - (var[j].addr - (uintptr_t)&g_dev.r4300.new_dynarec_hot_state.dynarec_local));
        continue;
      }
    }
#else
    if(INSTRUCTION.disp) {
      uint32_t j = 0;

      while(var[j].addr != -1) {
        if(INSTRUCTION.disp >= var[j].addr && INSTRUCTION.disp < (var[j].addr + var[j].size))
          break;
        j++;
      }
      if(var[j].addr != -1) {
        char addr_str[16];
        char op_str[160];
        char op_str2[160];
        char * ptr;

        sprintf(addr_str, "0x%.8x", INSTRUCTION.disp);
        memcpy(op_str, instr[i].op_str, sizeof(op_str));
        ptr = strstr(op_str, addr_str);

        if(ptr == NULL) {
          sprintf(addr_str, "0x%.8x", -INSTRUCTION.disp);
          ptr = strstr(op_str, addr_str);
          assert(ptr != NULL);
          assert(*(ptr-2) == '-');
          *(ptr-2) = '+';
        }

        *ptr = '\0';
        memcpy(op_str2, (ptr + 10), sizeof(op_str) - (ptr - op_str)); /* copy right part after address */

        if((INSTRUCTION.disp - var[j].addr) == 0)
          fprintf(pFile, "0x%x: %s %s%s%s\n", (uintptr_t)instr[i].address, instr[i].mnemonic, op_str, var[j].name, op_str2);
        else
          fprintf(pFile, "0x%x: %s %s%s + %d%s\n", (uintptr_t)instr[i].address, instr[i].mnemonic, op_str, var[j].name, (INSTRUCTION.disp - var[j].addr), op_str2);
        continue;
      }
    }
#endif

    if(instr[i].id == CALL_INST) {
      uint32_t j = 0;
      intptr_t addr = (intptr_t)INSTRUCTION.operands[0].imm;

      while(func[j].addr != -1) {
        if(addr == func[j].addr)
          break;
        j++;
      }
      if(func[j].addr != -1) {
        fprintf(pFile, "0x%x: %s %s\n", (uintptr_t)instr[i].address, instr[i].mnemonic, func[j].name);
        continue;
      }
    }
    fprintf(pFile, "0x%x: %s %s\n", (uintptr_t)instr[i].address, instr[i].mnemonic, instr[i].op_str);
  }

  if(size != sum)
    fprintf(pFile, "Failed to disassemble code at: 0x%.8x\n", (uintptr_t)beginning + sum);

  cs_free(instr, count);
  fflush(pFile);
  fclose(pFile);
}

#endif