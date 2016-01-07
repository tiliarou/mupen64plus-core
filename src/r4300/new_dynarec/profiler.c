/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *   Mupen64plus - profiler.c                                              *
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

#ifdef NEW_DYNAREC_PROFILER
#undef NEW_DYNAREC
#define NEW_DYNAREC NEW_DYNAREC_PROFILER
#define PROFILER

#include "new_dynarec_arm64.c"

typedef struct{
  uintptr_t addr;
  uint32_t size;
  char * name;
}Variable_t;

static const Variable_t var[] = {
#if NEW_DYNAREC_PROFILER >= NEW_DYNAREC_ARM
  {(uintptr_t)&dynarec_local, sizeof(dynarec_local), "dynarec_local"},
  {(uintptr_t)&invc_ptr, sizeof(invc_ptr), "invc_ptr"},
  {(uintptr_t)&ram_offset, sizeof(ram_offset), "ram_offset"},
#endif
  {(uintptr_t)&next_interupt, sizeof(next_interupt), "next_interupt"},
  {(uintptr_t)&cycle_count, sizeof(cycle_count), "cycle_count"},
  {(uintptr_t)&last_count, sizeof(last_count), "last_count"},
  {(uintptr_t)&pending_exception, sizeof(pending_exception), "pending_exception"},
  {(uintptr_t)&pcaddr, sizeof(pcaddr), "pcaddr"},
  {(uintptr_t)&stop, sizeof(stop), "stop"},
  {(uintptr_t)&address, sizeof(address), "address"},
  {(uintptr_t)&readmem_dword, sizeof(readmem_dword), "readmem_dword"},
  {(uintptr_t)&cpu_dword, sizeof(cpu_dword), "cpu_dword"},
  {(uintptr_t)&cpu_word, sizeof(cpu_word), "cpu_word"},
  {(uintptr_t)&cpu_hword, sizeof(cpu_hword), "cpu_hword"},
  {(uintptr_t)&cpu_byte, sizeof(cpu_byte), "cpu_byte"},
  {(uintptr_t)&FCR0, sizeof(FCR0), "FCR0"},
  {(uintptr_t)&FCR31, sizeof(FCR31), "FCR31"},
  {(uintptr_t)&reg, sizeof(reg), "reg"},
  {(uintptr_t)&hi, sizeof(hi), "hi"},
  {(uintptr_t)&lo, sizeof(lo), "lo"},
  {(uintptr_t)&g_cp0_regs, sizeof(g_cp0_regs), "g_cp0_regs"},
  {(uintptr_t)&reg_cop1_simple, sizeof(reg_cop1_simple), "reg_cop1_simple"},
  {(uintptr_t)&reg_cop1_double, sizeof(reg_cop1_double), "reg_cop1_double"},
  {(uintptr_t)&rounding_modes, sizeof(rounding_modes), "rounding_modes"},
  {(uintptr_t)&branch_target, sizeof(branch_target), "branch_target"},
  {(uintptr_t)&PC, sizeof(PC), "PC"},
  {(uintptr_t)&fake_pc, sizeof(fake_pc), "fake_pc"},
  {(uintptr_t)&mini_ht, sizeof(mini_ht), "mini_ht"},
  {(uintptr_t)&restore_candidate, sizeof(restore_candidate), "restore_candidate"},
  {(uintptr_t)&memory_map, sizeof(memory_map), "memory_map"},
  {-1, -1, NULL},
};

typedef struct{
  uintptr_t addr;
  char * name;
}Function_t;

static Function_t func[] = {
  {(uintptr_t)NULL /*MFC0*/, "MFC0"},
  {(uintptr_t)NULL /*MTC0*/, "MTC0"},
  {(uintptr_t)NULL /*TLBR*/, "TLBR"},
  {(uintptr_t)NULL /*TLBP*/, "TLBP"},
#if NEW_DYNAREC_PROFILER >= NEW_DYNAREC_ARM
  {(uintptr_t)invalidate_addr, "invalidate_addr"},
  {(uintptr_t)jump_vaddr, "jump_vaddr"},
  {(uintptr_t)indirect_jump_indexed, "indirect_jump_indexed"},
  {(uintptr_t)indirect_jump, "indirect_jump"},
  {(uintptr_t)jump_vaddr_r0, "jump_vaddr_r0"},
  {(uintptr_t)jump_vaddr_r1, "jump_vaddr_r1"},
  {(uintptr_t)jump_vaddr_r2, "jump_vaddr_r2"},
  {(uintptr_t)jump_vaddr_r3, "jump_vaddr_r3"},
  {(uintptr_t)jump_vaddr_r4, "jump_vaddr_r4"},
  {(uintptr_t)jump_vaddr_r5, "jump_vaddr_r5"},
  {(uintptr_t)jump_vaddr_r6, "jump_vaddr_r6"},
  {(uintptr_t)jump_vaddr_r7, "jump_vaddr_r7"},
  {(uintptr_t)jump_vaddr_r8, "jump_vaddr_r8"},
  {(uintptr_t)jump_vaddr_r9, "jump_vaddr_r9"},
  {(uintptr_t)jump_vaddr_r10, "jump_vaddr_r10"},
  {(uintptr_t)jump_vaddr_r12, "jump_vaddr_r12"},
  {(uintptr_t)invalidate_addr_r0, "invalidate_addr_r0"},
  {(uintptr_t)invalidate_addr_r1, "invalidate_addr_r1"},
  {(uintptr_t)invalidate_addr_r2, "invalidate_addr_r2"},
  {(uintptr_t)invalidate_addr_r3, "invalidate_addr_r3"},
  {(uintptr_t)invalidate_addr_r4, "invalidate_addr_r4"},
  {(uintptr_t)invalidate_addr_r5, "invalidate_addr_r5"},
  {(uintptr_t)invalidate_addr_r6, "invalidate_addr_r6"},
  {(uintptr_t)invalidate_addr_r7, "invalidate_addr_r7"},
  {(uintptr_t)invalidate_addr_r8, "invalidate_addr_r8"},
  {(uintptr_t)invalidate_addr_r9, "invalidate_addr_r9"},
  {(uintptr_t)invalidate_addr_r10, "invalidate_addr_r10"},
  {(uintptr_t)invalidate_addr_r12, "invalidate_addr_r12"},
#else
  {(uintptr_t)jump_vaddr_eax, "jump_vaddr_eax"},
  {(uintptr_t)jump_vaddr_ecx, "jump_vaddr_ecx"},
  {(uintptr_t)jump_vaddr_edx, "jump_vaddr_edx"},
  {(uintptr_t)jump_vaddr_ebx, "jump_vaddr_ebx"},
  {(uintptr_t)jump_vaddr_ebp, "jump_vaddr_ebp"},
  {(uintptr_t)jump_vaddr_edi, "jump_vaddr_edi"},
  {(uintptr_t)invalidate_block_eax, "invalidate_block_eax"},
  {(uintptr_t)invalidate_block_ecx, "invalidate_block_ecx"},
  {(uintptr_t)invalidate_block_edx, "invalidate_block_edx"},
  {(uintptr_t)invalidate_block_ebx, "invalidate_block_ebx"},
  {(uintptr_t)invalidate_block_ebp, "invalidate_block_ebp"},
  {(uintptr_t)invalidate_block_esi, "invalidate_block_esi"},
  {(uintptr_t)invalidate_block_edi, "invalidate_block_edi"},
#endif
  {(uintptr_t)dynamic_linker, "dynamic_linker"},
  {(uintptr_t)dynamic_linker_ds, "dynamic_linker_ds"},
  {(uintptr_t)TLBWI_new, "TLBWI_new"},
  {(uintptr_t)TLBWR_new, "TLBWR_new"},
  {(uintptr_t)verify_code, "verify_code"},
  {(uintptr_t)verify_code_vm, "verify_code_vm"},
  {(uintptr_t)verify_code_ds, "verify_code_ds"},
  {(uintptr_t)cc_interrupt, "cc_interrupt"},
  {(uintptr_t)fp_exception, "fp_exception"},
  {(uintptr_t)fp_exception_ds, "fp_exception_ds"},
  {(uintptr_t)jump_syscall, "jump_syscall"},
  {(uintptr_t)jump_eret, "jump_eret"},
  {(uintptr_t)do_interrupt, "do_interrupt"},
  {(uintptr_t)div64, "div64"},
  {(uintptr_t)divu64, "divu64"},
  {(uintptr_t)cvt_s_w, "cvt_s_w"},
  {(uintptr_t)cvt_d_w, "cvt_d_w"},
  {(uintptr_t)cvt_s_l, "cvt_s_l"},
  {(uintptr_t)cvt_d_l, "cvt_d_l"},
  {(uintptr_t)cvt_w_s, "cvt_w_s"},
  {(uintptr_t)cvt_w_d, "cvt_w_d"},
  {(uintptr_t)cvt_l_s, "cvt_l_s"},
  {(uintptr_t)cvt_l_d, "cvt_l_d"},
  {(uintptr_t)cvt_d_s, "cvt_d_s"},
  {(uintptr_t)cvt_s_d, "cvt_s_d"},
  {(uintptr_t)round_l_s, "round_l_s"},
  {(uintptr_t)round_w_s, "round_w_s"},
  {(uintptr_t)trunc_l_s, "trunc_l_s"},
  {(uintptr_t)trunc_w_s, "trunc_w_s"},
  {(uintptr_t)ceil_l_s, "ceil_l_s"},
  {(uintptr_t)ceil_w_s, "ceil_w_s"},
  {(uintptr_t)floor_l_s, "floor_l_s"},
  {(uintptr_t)floor_w_s, "floor_w_s"},
  {(uintptr_t)round_l_d, "round_l_d"},
  {(uintptr_t)round_w_d, "round_w_d"},
  {(uintptr_t)trunc_l_d, "trunc_l_d"},
  {(uintptr_t)trunc_w_d, "trunc_w_d"},
  {(uintptr_t)ceil_l_d, "ceil_l_d"},
  {(uintptr_t)ceil_w_d, "ceil_w_d"},
  {(uintptr_t)floor_l_d, "floor_l_d"},
  {(uintptr_t)floor_w_d, "floor_w_d"},
  {(uintptr_t)c_f_s, "c_f_s"},
  {(uintptr_t)c_un_s, "c_un_s"},
  {(uintptr_t)c_eq_s, "c_eq_s"},
  {(uintptr_t)c_ueq_s, "c_ueq_s"},
  {(uintptr_t)c_olt_s, "c_olt_s"},
  {(uintptr_t)c_ult_s, "c_ult_s"},
  {(uintptr_t)c_ole_s, "c_ole_s"},
  {(uintptr_t)c_ule_s, "c_ule_s"},
  {(uintptr_t)c_sf_s, "c_sf_s"},
  {(uintptr_t)c_ngle_s, "c_ngle_s"},
  {(uintptr_t)c_seq_s, "c_seq_s"},
  {(uintptr_t)c_ngl_s, "c_ngl_s"},
  {(uintptr_t)c_lt_s, "c_lt_s"},
  {(uintptr_t)c_nge_s, "c_nge_s"},
  {(uintptr_t)c_le_s, "c_le_s"},
  {(uintptr_t)c_ngt_s, "c_ngt_s"},
  {(uintptr_t)c_f_d, "c_f_d"},
  {(uintptr_t)c_un_d, "c_un_d"},
  {(uintptr_t)c_eq_d, "c_eq_d"},
  {(uintptr_t)c_ueq_d, "c_ueq_d"},
  {(uintptr_t)c_olt_d, "c_olt_d"},
  {(uintptr_t)c_ult_d, "c_ult_d"},
  {(uintptr_t)c_ole_d, "c_ole_d"},
  {(uintptr_t)c_ule_d, "c_ule_d"},
  {(uintptr_t)c_sf_d, "c_sf_d"},
  {(uintptr_t)c_ngle_d, "c_ngle_d"},
  {(uintptr_t)c_seq_d, "c_seq_d"},
  {(uintptr_t)c_ngl_d, "c_ngl_d"},
  {(uintptr_t)c_lt_d, "c_lt_d"},
  {(uintptr_t)c_nge_d, "c_nge_d"},
  {(uintptr_t)c_le_d, "c_le_d"},
  {(uintptr_t)c_ngt_d, "c_ngt_d"},
  {(uintptr_t)add_s, "add_s"},
  {(uintptr_t)sub_s, "sub_s"},
  {(uintptr_t)mul_s, "mul_s"},
  {(uintptr_t)div_s, "div_s"},
  {(uintptr_t)sqrt_s, "sqrt_s"},
  {(uintptr_t)abs_s, "abs_s"},
  {(uintptr_t)mov_s, "mov_s"},
  {(uintptr_t)neg_s, "neg_s"},
  {(uintptr_t)add_d, "add_d"},
  {(uintptr_t)sub_d, "sub_d"},
  {(uintptr_t)mul_d, "mul_d"},
  {(uintptr_t)div_d, "div_d"},
  {(uintptr_t)sqrt_d, "sqrt_d"},
  {(uintptr_t)abs_d, "abs_d"},
  {(uintptr_t)mov_d, "mov_d"},
  {(uintptr_t)neg_d, "neg_d"},
  {-1, NULL}
};

#undef address
#undef reg

static FILE * pFile;
static csh handle;

void profiler_init(void)
{
  if(cs_open(ARCHITECTURE, MODE, &handle) != CS_ERR_OK) return;
  cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
  pFile = fopen ("profiler.txt","w");
  base_addr = extra_memory;
  new_dynarec_init();

  func[0].addr = (uintptr_t)cached_interpreter_table.MFC0;
  func[1].addr = (uintptr_t)cached_interpreter_table.MTC0;
  func[2].addr = (uintptr_t)cached_interpreter_table.TLBR;
  func[3].addr = (uintptr_t)cached_interpreter_table.TLBP;
}

void profiler_cleanup(void)
{
  if(handle == 0) return;
  new_dynarec_cleanup();
  cs_close(&handle);
  fclose(pFile);
}

void profiler_block(int addr)
{
  uint32_t * beginning;
  uint32_t * end;
  cs_insn *insn;
  size_t count;
  int32_t size = 0;
  int32_t sum = 0;

  if(handle == 0) return;

  fprintf(pFile, "Recompiled block: %.8x\n", addr);
  beginning=(uint32_t *)out;
  new_recompile_block(addr);
  end=(uint32_t *)out;

  size = (intptr_t)end - (intptr_t)beginning;
  size = (size < 0) ? (-size) : size;

  count = cs_disasm(handle, (uint8_t*)beginning, size, (uintptr_t)beginning, 0, &insn);
  if(count <= 0) return;

  for (uint32_t i = 0; i < count; i++) {
    sum += insn[i].size;
 #if NEW_DYNAREC_PROFILER >= NEW_DYNAREC_ARM
    if(INSTRUCTION.operands[1].reg == FP_REGISTER) {
      uint32_t j;
      uint32_t imm;

      if(INSTRUCTION.op_count > 2)
        imm = INSTRUCTION.operands[2].mem.base;
      else
        imm = INSTRUCTION.operands[1].mem.disp;

      assert(imm>=0 && imm<4096);

      for(j = 0; j < 30; j++) {
        uint32_t offset = var[j].addr - (uintptr_t)&dynarec_local;
        if(imm >= offset && imm < (offset + var[j].size))
          break;
      }
      if(j < 30) {
        fprintf(pFile, "0x%.8x: %s %s (%s+%d)\n", (uintptr_t)insn[i].address, insn[i].mnemonic, insn[i].op_str, var[j].name, imm - (var[j].addr - (uintptr_t)&dynarec_local));
        continue;
      }
    }
#else
    // TODO: x86
#endif

    if(insn[i].id == CALL_INST) {
      uint32_t j;
      uintptr_t addr = INSTRUCTION.operands[0].imm;

      for(j = 0; j < 121; j++) {
        if(addr == func[j].addr)
          break;
      }
      if(j < 121) {
        fprintf(pFile, "0x%.8x: %s %s (%s)\n", (uintptr_t)insn[i].address, insn[i].mnemonic, insn[i].op_str, func[j].name);
        continue;
      }
    }
    fprintf(pFile, "0x%.8x: %s %s\n", (uintptr_t)insn[i].address, insn[i].mnemonic, insn[i].op_str);
  }

  if(size != sum)
    fprintf(pFile, "Failed to disassemble code at: 0x%.8x\n", (uintptr_t)beginning + sum);

  cs_free(insn, count);
  fflush(pFile);
}

#endif