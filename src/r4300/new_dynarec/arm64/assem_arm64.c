/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *   Mupen64plus - assem_arm64.c                                           *
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

typedef enum {
  EQ,
  NE,
  CS,
  CC,
  MI,
  PL,
  VS,
  VC,
  HI,
  LS,
  GE,
  LT,
  GT,
  LE,
  AW,
  NV
} eCond;

static void *dynamic_linker(void * src, u_int vaddr);
static void *dynamic_linker_ds(void * src, u_int vaddr);
static void invalidate_addr(u_int addr);

static u_int literals[1024][2];
static unsigned int needs_clear_cache[1<<(TARGET_SIZE_2-17)];

static const uintptr_t jump_vaddr_reg[32] = {
  (intptr_t)jump_vaddr_x0,
  (intptr_t)jump_vaddr_x1,
  (intptr_t)jump_vaddr_x2,
  (intptr_t)jump_vaddr_x3,
  (intptr_t)jump_vaddr_x4,
  (intptr_t)jump_vaddr_x5,
  (intptr_t)jump_vaddr_x6,
  (intptr_t)jump_vaddr_x7,
  (intptr_t)jump_vaddr_x8,
  (intptr_t)jump_vaddr_x9,
  (intptr_t)jump_vaddr_x10,
  (intptr_t)jump_vaddr_x11,
  (intptr_t)jump_vaddr_x12,
  (intptr_t)jump_vaddr_x13,
  (intptr_t)jump_vaddr_x14,
  (intptr_t)jump_vaddr_x15,
  (intptr_t)jump_vaddr_x16,
  (intptr_t)jump_vaddr_x17,
  (intptr_t)jump_vaddr_x18,
  (intptr_t)jump_vaddr_x19,
  (intptr_t)jump_vaddr_x20,
  (intptr_t)jump_vaddr_x21,
  (intptr_t)jump_vaddr_x22,
  (intptr_t)jump_vaddr_x23,
  (intptr_t)jump_vaddr_x24,
  (intptr_t)jump_vaddr_x25,
  (intptr_t)jump_vaddr_x26,
  (intptr_t)jump_vaddr_x27,
  (intptr_t)jump_vaddr_x28,
  (intptr_t)breakpoint,
  (intptr_t)breakpoint,
  (intptr_t)breakpoint};

static const uintptr_t invalidate_addr_reg[32] = {
  (intptr_t)invalidate_addr_x0,
  (intptr_t)invalidate_addr_x1,
  (intptr_t)invalidate_addr_x2,
  (intptr_t)invalidate_addr_x3,
  (intptr_t)invalidate_addr_x4,
  (intptr_t)invalidate_addr_x5,
  (intptr_t)invalidate_addr_x6,
  (intptr_t)invalidate_addr_x7,
  (intptr_t)invalidate_addr_x8,
  (intptr_t)invalidate_addr_x9,
  (intptr_t)invalidate_addr_x10,
  (intptr_t)invalidate_addr_x11,
  (intptr_t)invalidate_addr_x12,
  (intptr_t)invalidate_addr_x13,
  (intptr_t)invalidate_addr_x14,
  (intptr_t)invalidate_addr_x15,
  (intptr_t)invalidate_addr_x16,
  (intptr_t)invalidate_addr_x17,
  (intptr_t)invalidate_addr_x18,
  (intptr_t)invalidate_addr_x19,
  (intptr_t)invalidate_addr_x20,
  (intptr_t)invalidate_addr_x21,
  (intptr_t)invalidate_addr_x22,
  (intptr_t)invalidate_addr_x23,
  (intptr_t)invalidate_addr_x24,
  (intptr_t)invalidate_addr_x25,
  (intptr_t)invalidate_addr_x26,
  (intptr_t)invalidate_addr_x27,
  (intptr_t)invalidate_addr_x28,
  (intptr_t)breakpoint,
  (intptr_t)breakpoint,
  (intptr_t)breakpoint};

static uintptr_t jump_table_symbols[] = {
  (intptr_t)invalidate_addr,
  (intptr_t)jump_vaddr,
  (intptr_t)dynamic_linker,
  (intptr_t)dynamic_linker_ds,
  (intptr_t)verify_code,
  (intptr_t)verify_code_vm,
  (intptr_t)verify_code_ds,
  (intptr_t)cc_interrupt,
  (intptr_t)fp_exception,
  (intptr_t)fp_exception_ds,
  (intptr_t)jump_syscall,
  (intptr_t)jump_eret,
  (intptr_t)indirect_jump_indexed,
  (intptr_t)indirect_jump,
  (intptr_t)do_interrupt,
  (intptr_t)NULL /*MFC0*/,
  (intptr_t)NULL /*MTC0*/,
  (intptr_t)NULL /*TLBR*/,
  (intptr_t)NULL /*TLBP*/,
  (intptr_t)TLBWI_new,
  (intptr_t)TLBWR_new,
  (intptr_t)jump_vaddr_x0,
  (intptr_t)jump_vaddr_x1,
  (intptr_t)jump_vaddr_x2,
  (intptr_t)jump_vaddr_x3,
  (intptr_t)jump_vaddr_x4,
  (intptr_t)jump_vaddr_x5,
  (intptr_t)jump_vaddr_x6,
  (intptr_t)jump_vaddr_x7,
  (intptr_t)jump_vaddr_x8,
  (intptr_t)jump_vaddr_x9,
  (intptr_t)jump_vaddr_x10,
  (intptr_t)jump_vaddr_x11,
  (intptr_t)jump_vaddr_x12,
  (intptr_t)jump_vaddr_x13,
  (intptr_t)jump_vaddr_x14,
  (intptr_t)jump_vaddr_x15,
  (intptr_t)jump_vaddr_x16,
  (intptr_t)jump_vaddr_x17,
  (intptr_t)jump_vaddr_x18,
  (intptr_t)jump_vaddr_x19,
  (intptr_t)jump_vaddr_x20,
  (intptr_t)jump_vaddr_x21,
  (intptr_t)jump_vaddr_x22,
  (intptr_t)jump_vaddr_x23,
  (intptr_t)jump_vaddr_x24,
  (intptr_t)jump_vaddr_x25,
  (intptr_t)jump_vaddr_x26,
  (intptr_t)jump_vaddr_x27,
  (intptr_t)jump_vaddr_x28,
  (intptr_t)invalidate_addr_x0,
  (intptr_t)invalidate_addr_x1,
  (intptr_t)invalidate_addr_x2,
  (intptr_t)invalidate_addr_x3,
  (intptr_t)invalidate_addr_x4,
  (intptr_t)invalidate_addr_x5,
  (intptr_t)invalidate_addr_x6,
  (intptr_t)invalidate_addr_x7,
  (intptr_t)invalidate_addr_x8,
  (intptr_t)invalidate_addr_x9,
  (intptr_t)invalidate_addr_x10,
  (intptr_t)invalidate_addr_x11,
  (intptr_t)invalidate_addr_x12,
  (intptr_t)invalidate_addr_x13,
  (intptr_t)invalidate_addr_x14,
  (intptr_t)invalidate_addr_x15,
  (intptr_t)invalidate_addr_x16,
  (intptr_t)invalidate_addr_x17,
  (intptr_t)invalidate_addr_x18,
  (intptr_t)invalidate_addr_x19,
  (intptr_t)invalidate_addr_x20,
  (intptr_t)invalidate_addr_x21,
  (intptr_t)invalidate_addr_x22,
  (intptr_t)invalidate_addr_x23,
  (intptr_t)invalidate_addr_x24,
  (intptr_t)invalidate_addr_x25,
  (intptr_t)invalidate_addr_x26,
  (intptr_t)invalidate_addr_x27,
  (intptr_t)invalidate_addr_x28,
  (intptr_t)div64,
  (intptr_t)divu64,
  (intptr_t)cvt_s_w,
  (intptr_t)cvt_d_w,
  (intptr_t)cvt_s_l,
  (intptr_t)cvt_d_l,
  (intptr_t)cvt_w_s,
  (intptr_t)cvt_w_d,
  (intptr_t)cvt_l_s,
  (intptr_t)cvt_l_d,
  (intptr_t)cvt_d_s,
  (intptr_t)cvt_s_d,
  (intptr_t)round_l_s,
  (intptr_t)round_w_s,
  (intptr_t)trunc_l_s,
  (intptr_t)trunc_w_s,
  (intptr_t)ceil_l_s,
  (intptr_t)ceil_w_s,
  (intptr_t)floor_l_s,
  (intptr_t)floor_w_s,
  (intptr_t)round_l_d,
  (intptr_t)round_w_d,
  (intptr_t)trunc_l_d,
  (intptr_t)trunc_w_d,
  (intptr_t)ceil_l_d,
  (intptr_t)ceil_w_d,
  (intptr_t)floor_l_d,
  (intptr_t)floor_w_d,
  (intptr_t)c_f_s,
  (intptr_t)c_un_s,
  (intptr_t)c_eq_s,
  (intptr_t)c_ueq_s,
  (intptr_t)c_olt_s,
  (intptr_t)c_ult_s,
  (intptr_t)c_ole_s,
  (intptr_t)c_ule_s,
  (intptr_t)c_sf_s,
  (intptr_t)c_ngle_s,
  (intptr_t)c_seq_s,
  (intptr_t)c_ngl_s,
  (intptr_t)c_lt_s,
  (intptr_t)c_nge_s,
  (intptr_t)c_le_s,
  (intptr_t)c_ngt_s,
  (intptr_t)c_f_d,
  (intptr_t)c_un_d,
  (intptr_t)c_eq_d,
  (intptr_t)c_ueq_d,
  (intptr_t)c_olt_d,
  (intptr_t)c_ult_d,
  (intptr_t)c_ole_d,
  (intptr_t)c_ule_d,
  (intptr_t)c_sf_d,
  (intptr_t)c_ngle_d,
  (intptr_t)c_seq_d,
  (intptr_t)c_ngl_d,
  (intptr_t)c_lt_d,
  (intptr_t)c_nge_d,
  (intptr_t)c_le_d,
  (intptr_t)c_ngt_d,
  (intptr_t)add_s,
  (intptr_t)sub_s,
  (intptr_t)mul_s,
  (intptr_t)div_s,
  (intptr_t)sqrt_s,
  (intptr_t)abs_s,
  (intptr_t)mov_s,
  (intptr_t)neg_s,
  (intptr_t)add_d,
  (intptr_t)sub_d,
  (intptr_t)mul_d,
  (intptr_t)div_d,
  (intptr_t)sqrt_d,
  (intptr_t)abs_d,
  (intptr_t)mov_d,
  (intptr_t)neg_d
};

/* Linker */
static void set_jump_target(intptr_t addr,uintptr_t target)
{
  u_char *ptr=(u_char *)addr;
  u_int *ptr2=(u_int *)ptr;

  int offset=target-(intptr_t)addr;

  if((ptr[3]&0xfc)==0x14) {
    assert(offset>=-134217728&&offset<134217728);
    *ptr2=(*ptr2&0xFC000000)|(((u_int)offset>>2)&0x3ffffff);
  }
  else if((ptr[3]&0xff)==0x54) {
    //Conditional branch are limited to +/- 1MB
    //block max size is 256k so branching beyond the +/- 1MB limit
    //should only happen when jumping to an already compiled block (see add_link)
    //a workaround would be to do a trampoline jump via a stub at the end of the block
    assert(offset>=-1048576&&offset<1048576);
    *ptr2=(*ptr2&0xFF00000F)|((((u_int)offset>>2)&0x7ffff)<<5);
  }
  else if((ptr[3]&0x9f)==0x10) { //adr
    //generated by do_miniht_insert
    assert(offset>=-1048576&&offset<1048576);
    *ptr2=(*ptr2&0x9F00001F)|((u_int)offset&0x3)<<29|(((u_int)offset>>2)&0x7ffff)<<5;
  }
  else
    assert(0);

  /*if(ptr[3]==0xe2) {
    assert((target-(u_int)ptr2-8)<1024);
    assert((addr&3)==0);
    assert((target&3)==0);
    *ptr2=(*ptr2&0xFFFFF000)|((target-(u_int)ptr2-8)>>2)|0xF00;
    //DebugMessage(M64MSG_VERBOSE, "target=%x addr=%x insn=%x",target,addr,*ptr2);
  }
  else if(ptr[3]==0x72) {
    // generated by emit_jno_unlikely
    if((target-(u_int)ptr2-8)<1024) {
      assert((addr&3)==0);
      assert((target&3)==0);
      *ptr2=(*ptr2&0xFFFFF000)|((target-(u_int)ptr2-8)>>2)|0xF00;
    }
    else if((target-(u_int)ptr2-8)<4096&&!((target-(u_int)ptr2-8)&15)) {
      assert((addr&3)==0);
      assert((target&3)==0);
      *ptr2=(*ptr2&0xFFFFF000)|((target-(u_int)ptr2-8)>>4)|0xE00;
    }
    else *ptr2=(0x7A000000)|(((target-(u_int)ptr2-8)<<6)>>8);
  }
  else {
    assert((ptr[3]&0x0e)==0xa);
    *ptr2=(*ptr2&0xFF000000)|(((target-(u_int)ptr2-8)<<6)>>8);
  }*/
}

// This optionally copies the instruction from the target of the branch into
// the space before the branch.  Works, but the difference in speed is
// usually insignificant.
/*
static void set_jump_target_fillslot(int addr,u_int target,int copy)
{
  u_char *ptr=(u_char *)addr;
  u_int *ptr2=(u_int *)ptr;
  assert(!copy||ptr2[-1]==0xe28dd000);
  if(ptr[3]==0xe2) {
    assert(!copy);
    assert((target-(u_int)ptr2-8)<4096);
    *ptr2=(*ptr2&0xFFFFF000)|(target-(u_int)ptr2-8);
  }
  else {
    assert((ptr[3]&0x0e)==0xa);
    u_int target_insn=*(u_int *)target;
    if((target_insn&0x0e100000)==0) { // ALU, no immediate, no flags
      copy=0;
    }
    if((target_insn&0x0c100000)==0x04100000) { // Load
      copy=0;
    }
    if(target_insn&0x08000000) {
      copy=0;
    }
    if(copy) {
      ptr2[-1]=target_insn;
      target+=4;
    }
    *ptr2=(*ptr2&0xFF000000)|(((target-(u_int)ptr2-8)<<6)>>8);
  }
}
*/

static void *dynamic_linker(void * src, u_int vaddr)
{
  u_int page=(vaddr^0x80000000)>>12;
  u_int vpage=page;
  if(page>262143&&tlb_LUT_r[vaddr>>12]) page=(tlb_LUT_r[vaddr>>12]^0x80000000)>>12;
  if(page>2048) page=2048+(page&2047);
  if(vpage>262143&&tlb_LUT_r[vaddr>>12]) vpage&=2047; // jump_dirty uses a hash of the virtual address instead
  if(vpage>2048) vpage=2048+(vpage&2047);
  struct ll_entry *head;
  head=jump_in[page];

  while(head!=NULL) {
    if(head->vaddr==vaddr&&head->reg32==0) {
      int *ptr=(int*)src;
      assert(((*ptr&0xfc000000)==0x14000000)||((*ptr&0xff000000)==0x54000000)); //b or b.cond
      //TOBEDONE: Avoid disabling link between blocks for conditional branches
      if((*ptr&0xfc000000)==0x14000000) { //b
        int offset=((signed int)(*ptr<<6)>>6)<<2;
        u_int *ptr2=(u_int*)((intptr_t)ptr+offset);
        assert((ptr2[0]&0xffe00000)==0x52a00000); //movz
        assert((ptr2[1]&0xffe00000)==0x72800000); //movk
        assert((ptr2[2]&0x9f000000)==0x10000000); //adr
        assert((ptr2[3]&0xfc000000)==0x94000000); //bl
        assert((ptr2[4]&0xfffffc1f)==0xd61f0000); //br
        add_link(vaddr, ptr2);
        set_jump_target((intptr_t)ptr, (uintptr_t)head->addr);
        __clear_cache((void*)ptr, (void*)((uintptr_t)ptr+4));
      }
      #ifdef NEW_DYNAREC_DEBUG
      print_debug_info(vaddr);
      #endif
      return head->addr;
    }
    head=head->next;
  }

  uintptr_t *ht_bin=hash_table[((vaddr>>16)^vaddr)&0xFFFF];
  if(ht_bin[0]==vaddr){
    #ifdef NEW_DYNAREC_DEBUG
    print_debug_info(vaddr);
    #endif
    return (void *)ht_bin[1];
  }
  if(ht_bin[2]==vaddr){
    #ifdef NEW_DYNAREC_DEBUG
    print_debug_info(vaddr);
    #endif
    return (void *)ht_bin[3];
  }

  head=jump_dirty[vpage];
  while(head!=NULL) {
    if(head->vaddr==vaddr&&head->reg32==0) {
      //DebugMessage(M64MSG_VERBOSE, "TRACE: count=%d next=%d (get_addr match dirty %x: %x)",g_cp0_regs[CP0_COUNT_REG],next_interupt,vaddr,(int)head->addr);
      // Don't restore blocks which are about to expire from the cache
      if((((uintptr_t)head->addr-(uintptr_t)out)<<(32-TARGET_SIZE_2))>0x60000000+(MAX_OUTPUT_BLOCK_SIZE<<(32-TARGET_SIZE_2))) {
        if(verify_dirty(head->addr)) {
          //DebugMessage(M64MSG_VERBOSE, "restore candidate: %x (%d) d=%d",vaddr,page,invalid_code[vaddr>>12]);
          invalid_code[vaddr>>12]=0;
          memory_map[vaddr>>12]|=WRITE_PROTECT;
          if(vpage<2048) {
            if(tlb_LUT_r[vaddr>>12]) {
              invalid_code[tlb_LUT_r[vaddr>>12]>>12]=0;
              memory_map[tlb_LUT_r[vaddr>>12]>>12]|=WRITE_PROTECT;
            }
            restore_candidate[vpage>>3]|=1<<(vpage&7);
          }
          else restore_candidate[page>>3]|=1<<(page&7);
          uintptr_t *ht_bin=hash_table[((vaddr>>16)^vaddr)&0xFFFF];
          if(ht_bin[0]==vaddr) {
            ht_bin[1]=(intptr_t)head->addr; // Replace existing entry
          }
          else
          {
            ht_bin[3]=ht_bin[1];
            ht_bin[2]=ht_bin[0];
            ht_bin[1]=(intptr_t)head->addr;
            ht_bin[0]=vaddr;
          }
          #ifdef NEW_DYNAREC_DEBUG
          print_debug_info(vaddr);
          #endif
          return head->addr;
        }
      }
    }
    head=head->next;
  }

  int r=new_recompile_block(vaddr);
  if(r==0) return dynamic_linker(src, vaddr);
  // Execute in unmapped page, generate pagefault exception
  g_cp0_regs[CP0_STATUS_REG]|=2;
  g_cp0_regs[CP0_CAUSE_REG]=0x8;
  g_cp0_regs[CP0_EPC_REG]=vaddr;
  g_cp0_regs[CP0_BADVADDR_REG]=vaddr;
  g_cp0_regs[CP0_CONTEXT_REG]=(g_cp0_regs[CP0_CONTEXT_REG]&0xFF80000F)|((g_cp0_regs[CP0_BADVADDR_REG]>>9)&0x007FFFF0);
  g_cp0_regs[CP0_ENTRYHI_REG]=g_cp0_regs[CP0_BADVADDR_REG]&0xFFFFE000;
  return get_addr_ht(0x80000000);
}

static void *dynamic_linker_ds(void * src, u_int vaddr)
{
  assert(0);
  u_int page=(vaddr^0x80000000)>>12;
  u_int vpage=page;
  if(page>262143&&tlb_LUT_r[vaddr>>12]) page=(tlb_LUT_r[vaddr>>12]^0x80000000)>>12;
  if(page>2048) page=2048+(page&2047);
  if(vpage>262143&&tlb_LUT_r[vaddr>>12]) vpage&=2047; // jump_dirty uses a hash of the virtual address instead
  if(vpage>2048) vpage=2048+(vpage&2047);
  struct ll_entry *head;
  head=jump_in[page];

  while(head!=NULL) {
    if(head->vaddr==vaddr&&head->reg32==0) {
      int *ptr=(int*)src;
      assert(((*ptr&0xfc000000)==0x14000000)||((*ptr&0xff000000)==0x54000000)); //b or b.cond
      //TOBEDONE: Avoid disabling link between blocks for conditional branches
      if((*ptr&0xfc000000)==0x14000000) { //b
        int offset=((signed int)(*ptr<<6)>>6)<<2;
        u_int *ptr2=(u_int*)((intptr_t)ptr+offset);
        assert((ptr2[0]&0xffe00000)==0x52a00000); //movz
        assert((ptr2[1]&0xffe00000)==0x72800000); //movk
        assert((ptr2[2]&0x9f000000)==0x10000000); //adr
        assert((ptr2[3]&0xfc000000)==0x94000000); //bl
        assert((ptr2[4]&0xfffffc1f)==0xd61f0000); //br
        add_link(vaddr, ptr2);
        set_jump_target((intptr_t)ptr, (uintptr_t)head->addr);
        __clear_cache((void*)ptr, (void*)((uintptr_t)ptr+4));
      }
      #ifdef NEW_DYNAREC_DEBUG
      print_debug_info(vaddr);
      #endif
      return head->addr;
    }
    head=head->next;
  }

  uintptr_t *ht_bin=hash_table[((vaddr>>16)^vaddr)&0xFFFF];
  if(ht_bin[0]==vaddr){
    #ifdef NEW_DYNAREC_DEBUG
    print_debug_info(vaddr);
    #endif
    return (void *)ht_bin[1];
  }
  if(ht_bin[2]==vaddr){
    #ifdef NEW_DYNAREC_DEBUG
    print_debug_info(vaddr);
    #endif
    return (void *)ht_bin[3];
  }

  head=jump_dirty[vpage];
  while(head!=NULL) {
    if(head->vaddr==vaddr&&head->reg32==0) {
      //DebugMessage(M64MSG_VERBOSE, "TRACE: count=%d next=%d (get_addr match dirty %x: %x)",g_cp0_regs[CP0_COUNT_REG],next_interupt,vaddr,(int)head->addr);
      // Don't restore blocks which are about to expire from the cache
      if((((uintptr_t)head->addr-(uintptr_t)out)<<(32-TARGET_SIZE_2))>0x60000000+(MAX_OUTPUT_BLOCK_SIZE<<(32-TARGET_SIZE_2))) {
        if(verify_dirty(head->addr)) {
          //DebugMessage(M64MSG_VERBOSE, "restore candidate: %x (%d) d=%d",vaddr,page,invalid_code[vaddr>>12]);
          invalid_code[vaddr>>12]=0;
          memory_map[vaddr>>12]|=WRITE_PROTECT;
          if(vpage<2048) {
            if(tlb_LUT_r[vaddr>>12]) {
              invalid_code[tlb_LUT_r[vaddr>>12]>>12]=0;
              memory_map[tlb_LUT_r[vaddr>>12]>>12]|=WRITE_PROTECT;
            }
            restore_candidate[vpage>>3]|=1<<(vpage&7);
          }
          else restore_candidate[page>>3]|=1<<(page&7);
          uintptr_t *ht_bin=hash_table[((vaddr>>16)^vaddr)&0xFFFF];
          if(ht_bin[0]==vaddr) {
            ht_bin[1]=(intptr_t)head->addr; // Replace existing entry
          }
          else
          {
            ht_bin[3]=ht_bin[1];
            ht_bin[2]=ht_bin[0];
            ht_bin[1]=(intptr_t)head->addr;
            ht_bin[0]=vaddr;
          }
          #ifdef NEW_DYNAREC_DEBUG
          print_debug_info(vaddr);
          #endif
          return head->addr;
        }
      }
    }
    head=head->next;
  }

  int r=new_recompile_block((vaddr&0xFFFFFFF8)+1);
  if(r==0) return dynamic_linker_ds(src, vaddr);
  // Execute in unmapped page, generate pagefault exception
  g_cp0_regs[CP0_STATUS_REG]|=2;
  g_cp0_regs[CP0_CAUSE_REG]=0x80000008;
  g_cp0_regs[CP0_EPC_REG]=(vaddr&0xFFFFFFF8)-4;
  g_cp0_regs[CP0_BADVADDR_REG]=vaddr&0xFFFFFFF8;
  g_cp0_regs[CP0_CONTEXT_REG]=(g_cp0_regs[CP0_CONTEXT_REG]&0xFF80000F)|((g_cp0_regs[CP0_BADVADDR_REG]>>9)&0x007FFFF0);
  g_cp0_regs[CP0_ENTRYHI_REG]=g_cp0_regs[CP0_BADVADDR_REG]&0xFFFFE000;
  return get_addr_ht(0x80000000);
}

/* Literal pool */
static void add_literal(int addr,int val)
{
  assert(0);
  literals[literalcount][0]=addr;
  literals[literalcount][1]=val;
  literalcount++; 
} 

static void *kill_pointer(void *stub)
{
  int *ptr=(int *)((intptr_t)stub+8);
  assert((*ptr&0x9f000000)==0x10000000); //adr
  int *i_ptr=(int*)((intptr_t)ptr+(((signed int)(*ptr<<8)>>11)|(*ptr>>29)&0x3));
  assert((*i_ptr&0xfc000000)==0x14000000); //b
  set_jump_target((intptr_t)i_ptr,(intptr_t)stub);
  return i_ptr;
}

static intptr_t get_pointer(void *stub)
{
  int *ptr=(int *)((intptr_t)stub+8);
  assert((*ptr&0x9f000000)==0x10000000); //adr
  int *i_ptr=(int*)((intptr_t)ptr+(((signed int)(*ptr<<8)>>11)|(*ptr>>29)&0x3));
  assert((*i_ptr&0xfc000000)==0x14000000); //b
  return (intptr_t)i_ptr+(((signed int)(*i_ptr<<6)>>6)<<2);
}

// Find the "clean" entry point from a "dirty" entry point
// by skipping past the call to verify_code
static uintptr_t get_clean_addr(intptr_t addr)
{
  int *ptr=(int *)addr;
  while((*ptr&0xfc000000)!=0x94000000){ //bl
    ptr++;
    assert(((uintptr_t)ptr-(uintptr_t)addr)<=0x1C);
  }
  ptr++;
  if((*ptr&0xfc000000)==0x14000000) { //b
    return (intptr_t)ptr+(((signed int)(*ptr<<6)>>6)<<2); // follow branch
  }
  return (uintptr_t)ptr;
}

static int verify_dirty(void *addr)
{
  u_int *ptr=(u_int *)addr;

  uintptr_t source=0;
  if((*ptr&0xffe00000)==0x52a00000){ //movz
    assert((ptr[1]&0xffe00000)==0x72800000); //movk
    source=(((ptr[0]>>5)&0xffff)<<16)|(ptr[1]>>5)&0xffff;
    ptr+=2;
  }
  else if((*ptr&0x9f000000)==0x10000000){ //adr
    source=(intptr_t)ptr+(((signed int)(*ptr<<8)>>11)|(*ptr>>29)&0x3);
    ptr++;
  }
  else if((*ptr&0x9f000000)==0x90000000){ //adrp
    source=((intptr_t)ptr&(intptr_t)(~0xfff))+((((signed int)(*ptr<<8)>>11)|(*ptr>>29)&0x3)<<12);
    ptr++;
    if((*ptr&0xff000000)==0x91000000){//add
      source|=(*ptr>>10)&0xfff;
      ptr++;
    }
  }
  else
    assert(0);

  uintptr_t copy=0;
  if((*ptr&0x9f000000)==0x10000000){ //adr
    copy=(intptr_t)ptr+(((signed int)(*ptr<<8)>>11)|(*ptr>>29)&0x3);
    ptr++;
  }
  else if((*ptr&0x9f000000)==0x90000000){ //adrp
    copy=((intptr_t)ptr&(intptr_t)(~0xfff))+((((signed int)(*ptr<<8)>>11)|(*ptr>>29)&0x3)<<12);
    ptr++;
    if((*ptr&0xff000000)==0x91000000){//add
      copy|=(*ptr>>10)&0xfff;
      ptr++;
    }
  }
  else
    assert(0);

  assert((*ptr&0xffe00000)==0x52800000); //movz
  u_int len=(*ptr>>5)&0xffff;
  ptr+=2;

  if((*ptr&0xfc000000)!=0x94000000) ptr++;
  assert((*ptr&0xfc000000)==0x94000000); // bl instruction

  uintptr_t verifier=((signed int)(*ptr<<6)>>4)+(intptr_t)ptr;
  assert(verifier==(uintptr_t)verify_code||verifier==(uintptr_t)verify_code_vm||verifier==(uintptr_t)verify_code_ds);

  if(verifier==(uintptr_t)verify_code_vm||verifier==(uintptr_t)verify_code_ds) {
    assert(0);
    unsigned int page=(u_int)source>>12;
    uint64_t map_value=memory_map[page];
    if(map_value>=0x80000000) return 0; //TOBEDONE: Why 0x80000000?
    while(page<(((u_int)source+len-1)>>12)) {
      if((memory_map[++page]<<2)!=(map_value<<2)) return 0;
    }
    source = source+(map_value<<2);
  }
  //DebugMessage(M64MSG_VERBOSE, "verify_dirty: %x %x %x",source,copy,len);
  return !memcmp((void *)source,(void *)copy,len);
}

// This doesn't necessarily find all clean entry points, just
// guarantees that it's not dirty
static int isclean(intptr_t addr)
{
  int *ptr=(int *)addr;
  while((*ptr&0xfc000000)!=0x94000000){ //bl
    if((*ptr&0xfc000000)==0x14000000) //b
      return 1;
    ptr++;
    if(((uintptr_t)ptr-(uintptr_t)addr)>0x1C)
      return 1;
  }
  uintptr_t verifier=(intptr_t)ptr+(((signed int)(*ptr<<6)>>6)<<2); // follow branch
  if(verifier==(uintptr_t)verify_code) return 0;
  if(verifier==(uintptr_t)verify_code_vm) return 0;
  if(verifier==(uintptr_t)verify_code_ds) return 0;
  assert(0); //if this happens it's likely a bug
  return 0;
}

static void get_bounds(intptr_t addr,uintptr_t *start,uintptr_t *end)
{
  u_int *ptr=(u_int *)addr;

  uintptr_t source=0;
  if((*ptr&0xffe00000)==0x52a00000){ //movz
    assert((ptr[1]&0xffe00000)==0x72800000); //movk
    source=(((ptr[0]>>5)&0xffff)<<16)|(ptr[1]>>5)&0xffff;
    ptr+=2;
  }
  else if((*ptr&0x9f000000)==0x10000000){ //adr
    source=(intptr_t)ptr+(((signed int)(*ptr<<8)>>11)|(*ptr>>29)&0x3);
    ptr++;
  }
  else if((*ptr&0x9f000000)==0x90000000){ //adrp
    source=((intptr_t)ptr&(intptr_t)(~0xfff))+((((signed int)(*ptr<<8)>>11)|(*ptr>>29)&0x3)<<12);
    ptr++;
    if((*ptr&0xff000000)==0x91000000){//add
      source|=(*ptr>>10)&0xfff;
      ptr++;
    }
  }
  else
    assert(0);

  ptr++;
  if((*ptr&0xffe00000)!=0x52800000) ptr++;
  assert((*ptr&0xffe00000)==0x52800000); //movz
  u_int len=(*ptr>>5)&0xffff;
  ptr+=2;

  if((*ptr&0xfc000000)!=0x94000000) ptr++;
  assert((*ptr&0xfc000000)==0x94000000); // bl instruction

  uintptr_t verifier=((signed int)(*ptr<<6)>>4)+(intptr_t)ptr;
  assert(verifier==(uintptr_t)verify_code||verifier==(uintptr_t)verify_code_vm||verifier==(uintptr_t)verify_code_ds);

  if(verifier==(uintptr_t)verify_code_vm||verifier==(uintptr_t)verify_code_ds) {
    assert(0);
    if(memory_map[source>>12]>=0x80000000) source=0;  //TOBEDONE: Why 0x80000000?
    else source+=(memory_map[source>>12]<<2);
  }
  *start=source;
  *end=source+len;
}

/* Register allocation */

// Note: registers are allocated clean (unmodified state)
// if you intend to modify the register, you must call dirty_reg().
static void alloc_reg(struct regstat *cur,int i,signed char tr)
{
  int r,hr;
  int preferred_reg = (tr&7);
  if(tr==CCREG) preferred_reg=HOST_CCREG;
  if(tr==PTEMP||tr==FTEMP) preferred_reg=12;
  
  // Don't allocate unused registers
  if((cur->u>>tr)&1) return;
  
  // see if it's already allocated
  for(hr=0;hr<HOST_REGS;hr++)
  {
    if(cur->regmap[hr]==tr) return;
  }
  
  // Keep the same mapping if the register was already allocated in a loop
  preferred_reg = loop_reg(i,tr,preferred_reg);
  
  // Try to allocate the preferred register
  if(cur->regmap[preferred_reg]==-1) {
    cur->regmap[preferred_reg]=tr;
    cur->dirty&=~(1<<preferred_reg);
    cur->isconst&=~(1<<preferred_reg);
    return;
  }
  r=cur->regmap[preferred_reg];
  if(r<64&&((cur->u>>r)&1)) {
    cur->regmap[preferred_reg]=tr;
    cur->dirty&=~(1<<preferred_reg);
    cur->isconst&=~(1<<preferred_reg);
    return;
  }
  if(r>=64&&((cur->uu>>(r&63))&1)) {
    cur->regmap[preferred_reg]=tr;
    cur->dirty&=~(1<<preferred_reg);
    cur->isconst&=~(1<<preferred_reg);
    return;
  }
  
  // Clear any unneeded registers
  // We try to keep the mapping consistent, if possible, because it
  // makes branches easier (especially loops).  So we try to allocate
  // first (see above) before removing old mappings.  If this is not
  // possible then go ahead and clear out the registers that are no
  // longer needed.
  for(hr=0;hr<HOST_REGS;hr++)
  {
    r=cur->regmap[hr];
    if(r>=0) {
      if(r<64) {
        if((cur->u>>r)&1) {cur->regmap[hr]=-1;break;}
      }
      else
      {
        if((cur->uu>>(r&63))&1) {cur->regmap[hr]=-1;break;}
      }
    }
  }
  // Try to allocate any available register, but prefer
  // registers that have not been used recently.
  if(i>0) {
    for(hr=0;hr<HOST_REGS;hr++) {
      if(hr!=EXCLUDE_REG&&cur->regmap[hr]==-1) {
        if(regs[i-1].regmap[hr]!=rs1[i-1]&&regs[i-1].regmap[hr]!=rs2[i-1]&&regs[i-1].regmap[hr]!=rt1[i-1]&&regs[i-1].regmap[hr]!=rt2[i-1]) {
          cur->regmap[hr]=tr;
          cur->dirty&=~(1<<hr);
          cur->isconst&=~(1<<hr);
          return;
        }
      }
    }
  }
  // Try to allocate any available register
  for(hr=0;hr<HOST_REGS;hr++) {
    if(hr!=EXCLUDE_REG&&cur->regmap[hr]==-1) {
      cur->regmap[hr]=tr;
      cur->dirty&=~(1<<hr);
      cur->isconst&=~(1<<hr);
      return;
    }
  }
  
  // Ok, now we have to evict someone
  // Pick a register we hopefully won't need soon
  u_char hsn[MAXREG+1];
  memset(hsn,10,sizeof(hsn));
  int j;
  lsn(hsn,i,&preferred_reg);
  //DebugMessage(M64MSG_VERBOSE, "eax=%d ecx=%d edx=%d ebx=%d ebp=%d esi=%d edi=%d",cur->regmap[0],cur->regmap[1],cur->regmap[2],cur->regmap[3],cur->regmap[5],cur->regmap[6],cur->regmap[7]);
  //DebugMessage(M64MSG_VERBOSE, "hsn(%x): %d %d %d %d %d %d %d",start+i*4,hsn[cur->regmap[0]&63],hsn[cur->regmap[1]&63],hsn[cur->regmap[2]&63],hsn[cur->regmap[3]&63],hsn[cur->regmap[5]&63],hsn[cur->regmap[6]&63],hsn[cur->regmap[7]&63]);
  if(i>0) {
    // Don't evict the cycle count at entry points, otherwise the entry
    // stub will have to write it.
    if(bt[i]&&hsn[CCREG]>2) hsn[CCREG]=2;
    if(i>1&&hsn[CCREG]>2&&(itype[i-2]==RJUMP||itype[i-2]==UJUMP||itype[i-2]==CJUMP||itype[i-2]==SJUMP||itype[i-2]==FJUMP)) hsn[CCREG]=2;
    for(j=10;j>=3;j--)
    {
      // Alloc preferred register if available
      if(hsn[r=cur->regmap[preferred_reg]&63]==j) {
        for(hr=0;hr<HOST_REGS;hr++) {
          // Evict both parts of a 64-bit register
          if((cur->regmap[hr]&63)==r) {
            cur->regmap[hr]=-1;
            cur->dirty&=~(1<<hr);
            cur->isconst&=~(1<<hr);
          }
        }
        cur->regmap[preferred_reg]=tr;
        return;
      }
      for(r=1;r<=MAXREG;r++)
      {
        if(hsn[r]==j&&r!=rs1[i-1]&&r!=rs2[i-1]&&r!=rt1[i-1]&&r!=rt2[i-1]) {
          for(hr=0;hr<HOST_REGS;hr++) {
            if(hr!=HOST_CCREG||j<hsn[CCREG]) {
              if(cur->regmap[hr]==r+64) {
                cur->regmap[hr]=tr;
                cur->dirty&=~(1<<hr);
                cur->isconst&=~(1<<hr);
                return;
              }
            }
          }
          for(hr=0;hr<HOST_REGS;hr++) {
            if(hr!=HOST_CCREG||j<hsn[CCREG]) {
              if(cur->regmap[hr]==r) {
                cur->regmap[hr]=tr;
                cur->dirty&=~(1<<hr);
                cur->isconst&=~(1<<hr);
                return;
              }
            }
          }
        }
      }
    }
  }
  for(j=10;j>=0;j--)
  {
    for(r=1;r<=MAXREG;r++)
    {
      if(hsn[r]==j) {
        for(hr=0;hr<HOST_REGS;hr++) {
          if(cur->regmap[hr]==r+64) {
            cur->regmap[hr]=tr;
            cur->dirty&=~(1<<hr);
            cur->isconst&=~(1<<hr);
            return;
          }
        }
        for(hr=0;hr<HOST_REGS;hr++) {
          if(cur->regmap[hr]==r) {
            cur->regmap[hr]=tr;
            cur->dirty&=~(1<<hr);
            cur->isconst&=~(1<<hr);
            return;
          }
        }
      }
    }
  }
  DebugMessage(M64MSG_ERROR, "This shouldn't happen (alloc_reg)");exit(1);
}

static void alloc_reg64(struct regstat *cur,int i,signed char tr)
{
  int preferred_reg = 8+(tr&1);
  int r,hr;
  
  // allocate the lower 32 bits
  alloc_reg(cur,i,tr);
  
  // Don't allocate unused registers
  if((cur->uu>>tr)&1) return;
  
  // see if the upper half is already allocated
  for(hr=0;hr<HOST_REGS;hr++)
  {
    if(cur->regmap[hr]==tr+64) return;
  }
  
  // Keep the same mapping if the register was already allocated in a loop
  preferred_reg = loop_reg(i,tr,preferred_reg);
  
  // Try to allocate the preferred register
  if(cur->regmap[preferred_reg]==-1) {
    cur->regmap[preferred_reg]=tr|64;
    cur->dirty&=~(1<<preferred_reg);
    cur->isconst&=~(1<<preferred_reg);
    return;
  }
  r=cur->regmap[preferred_reg];
  if(r<64&&((cur->u>>r)&1)) {
    cur->regmap[preferred_reg]=tr|64;
    cur->dirty&=~(1<<preferred_reg);
    cur->isconst&=~(1<<preferred_reg);
    return;
  }
  if(r>=64&&((cur->uu>>(r&63))&1)) {
    cur->regmap[preferred_reg]=tr|64;
    cur->dirty&=~(1<<preferred_reg);
    cur->isconst&=~(1<<preferred_reg);
    return;
  }
  
  // Clear any unneeded registers
  // We try to keep the mapping consistent, if possible, because it
  // makes branches easier (especially loops).  So we try to allocate
  // first (see above) before removing old mappings.  If this is not
  // possible then go ahead and clear out the registers that are no
  // longer needed.
  for(hr=HOST_REGS-1;hr>=0;hr--)
  {
    r=cur->regmap[hr];
    if(r>=0) {
      if(r<64) {
        if((cur->u>>r)&1) {cur->regmap[hr]=-1;break;}
      }
      else
      {
        if((cur->uu>>(r&63))&1) {cur->regmap[hr]=-1;break;}
      }
    }
  }
  // Try to allocate any available register, but prefer
  // registers that have not been used recently.
  if(i>0) {
    for(hr=0;hr<HOST_REGS;hr++) {
      if(hr!=EXCLUDE_REG&&cur->regmap[hr]==-1) {
        if(regs[i-1].regmap[hr]!=rs1[i-1]&&regs[i-1].regmap[hr]!=rs2[i-1]&&regs[i-1].regmap[hr]!=rt1[i-1]&&regs[i-1].regmap[hr]!=rt2[i-1]) {
          cur->regmap[hr]=tr|64;
          cur->dirty&=~(1<<hr);
          cur->isconst&=~(1<<hr);
          return;
        }
      }
    }
  }
  // Try to allocate any available register
  for(hr=0;hr<HOST_REGS;hr++) {
    if(hr!=EXCLUDE_REG&&cur->regmap[hr]==-1) {
      cur->regmap[hr]=tr|64;
      cur->dirty&=~(1<<hr);
      cur->isconst&=~(1<<hr);
      return;
    }
  }
  
  // Ok, now we have to evict someone
  // Pick a register we hopefully won't need soon
  u_char hsn[MAXREG+1];
  memset(hsn,10,sizeof(hsn));
  int j;
  lsn(hsn,i,&preferred_reg);
  //DebugMessage(M64MSG_VERBOSE, "eax=%d ecx=%d edx=%d ebx=%d ebp=%d esi=%d edi=%d",cur->regmap[0],cur->regmap[1],cur->regmap[2],cur->regmap[3],cur->regmap[5],cur->regmap[6],cur->regmap[7]);
  //DebugMessage(M64MSG_VERBOSE, "hsn(%x): %d %d %d %d %d %d %d",start+i*4,hsn[cur->regmap[0]&63],hsn[cur->regmap[1]&63],hsn[cur->regmap[2]&63],hsn[cur->regmap[3]&63],hsn[cur->regmap[5]&63],hsn[cur->regmap[6]&63],hsn[cur->regmap[7]&63]);
  if(i>0) {
    // Don't evict the cycle count at entry points, otherwise the entry
    // stub will have to write it.
    if(bt[i]&&hsn[CCREG]>2) hsn[CCREG]=2;
    if(i>1&&hsn[CCREG]>2&&(itype[i-2]==RJUMP||itype[i-2]==UJUMP||itype[i-2]==CJUMP||itype[i-2]==SJUMP||itype[i-2]==FJUMP)) hsn[CCREG]=2;
    for(j=10;j>=3;j--)
    {
      // Alloc preferred register if available
      if(hsn[r=cur->regmap[preferred_reg]&63]==j) {
        for(hr=0;hr<HOST_REGS;hr++) {
          // Evict both parts of a 64-bit register
          if((cur->regmap[hr]&63)==r) {
            cur->regmap[hr]=-1;
            cur->dirty&=~(1<<hr);
            cur->isconst&=~(1<<hr);
          }
        }
        cur->regmap[preferred_reg]=tr|64;
        return;
      }
      for(r=1;r<=MAXREG;r++)
      {
        if(hsn[r]==j&&r!=rs1[i-1]&&r!=rs2[i-1]&&r!=rt1[i-1]&&r!=rt2[i-1]) {
          for(hr=0;hr<HOST_REGS;hr++) {
            if(hr!=HOST_CCREG||j<hsn[CCREG]) {
              if(cur->regmap[hr]==r+64) {
                cur->regmap[hr]=tr|64;
                cur->dirty&=~(1<<hr);
                cur->isconst&=~(1<<hr);
                return;
              }
            }
          }
          for(hr=0;hr<HOST_REGS;hr++) {
            if(hr!=HOST_CCREG||j<hsn[CCREG]) {
              if(cur->regmap[hr]==r) {
                cur->regmap[hr]=tr|64;
                cur->dirty&=~(1<<hr);
                cur->isconst&=~(1<<hr);
                return;
              }
            }
          }
        }
      }
    }
  }
  for(j=10;j>=0;j--)
  {
    for(r=1;r<=MAXREG;r++)
    {
      if(hsn[r]==j) {
        for(hr=0;hr<HOST_REGS;hr++) {
          if(cur->regmap[hr]==r+64) {
            cur->regmap[hr]=tr|64;
            cur->dirty&=~(1<<hr);
            cur->isconst&=~(1<<hr);
            return;
          }
        }
        for(hr=0;hr<HOST_REGS;hr++) {
          if(cur->regmap[hr]==r) {
            cur->regmap[hr]=tr|64;
            cur->dirty&=~(1<<hr);
            cur->isconst&=~(1<<hr);
            return;
          }
        }
      }
    }
  }
  DebugMessage(M64MSG_ERROR, "This shouldn't happen");exit(1);
}

// Allocate a temporary register.  This is done without regard to
// dirty status or whether the register we request is on the unneeded list
// Note: This will only allocate one register, even if called multiple times
static void alloc_reg_temp(struct regstat *cur,int i,signed char tr)
{
  int r,hr;
  int preferred_reg = -1;
  
  // see if it's already allocated
  for(hr=0;hr<HOST_REGS;hr++)
  {
    if(hr!=EXCLUDE_REG&&cur->regmap[hr]==tr) return;
  }
  
  // Try to allocate any available register
  for(hr=HOST_REGS-1;hr>=0;hr--) {
    if(hr!=EXCLUDE_REG&&cur->regmap[hr]==-1) {
      cur->regmap[hr]=tr;
      cur->dirty&=~(1<<hr);
      cur->isconst&=~(1<<hr);
      return;
    }
  }
  
  // Find an unneeded register
  for(hr=HOST_REGS-1;hr>=0;hr--)
  {
    r=cur->regmap[hr];
    if(r>=0) {
      if(r<64) {
        if((cur->u>>r)&1) {
          if(i==0||((unneeded_reg[i-1]>>r)&1)) {
            cur->regmap[hr]=tr;
            cur->dirty&=~(1<<hr);
            cur->isconst&=~(1<<hr);
            return;
          }
        }
      }
      else
      {
        if((cur->uu>>(r&63))&1) {
          if(i==0||((unneeded_reg_upper[i-1]>>(r&63))&1)) {
            cur->regmap[hr]=tr;
            cur->dirty&=~(1<<hr);
            cur->isconst&=~(1<<hr);
            return;
          }
        }
      }
    }
  }
  
  // Ok, now we have to evict someone
  // Pick a register we hopefully won't need soon
  // TODO: we might want to follow unconditional jumps here
  // TODO: get rid of dupe code and make this into a function
  u_char hsn[MAXREG+1];
  memset(hsn,10,sizeof(hsn));
  int j;
  lsn(hsn,i,&preferred_reg);
  //DebugMessage(M64MSG_VERBOSE, "hsn: %d %d %d %d %d %d %d",hsn[cur->regmap[0]&63],hsn[cur->regmap[1]&63],hsn[cur->regmap[2]&63],hsn[cur->regmap[3]&63],hsn[cur->regmap[5]&63],hsn[cur->regmap[6]&63],hsn[cur->regmap[7]&63]);
  if(i>0) {
    // Don't evict the cycle count at entry points, otherwise the entry
    // stub will have to write it.
    if(bt[i]&&hsn[CCREG]>2) hsn[CCREG]=2;
    if(i>1&&hsn[CCREG]>2&&(itype[i-2]==RJUMP||itype[i-2]==UJUMP||itype[i-2]==CJUMP||itype[i-2]==SJUMP||itype[i-2]==FJUMP)) hsn[CCREG]=2;
    for(j=10;j>=3;j--)
    {
      for(r=1;r<=MAXREG;r++)
      {
        if(hsn[r]==j&&r!=rs1[i-1]&&r!=rs2[i-1]&&r!=rt1[i-1]&&r!=rt2[i-1]) {
          for(hr=0;hr<HOST_REGS;hr++) {
            if(hr!=HOST_CCREG||hsn[CCREG]>2) {
              if(cur->regmap[hr]==r+64) {
                cur->regmap[hr]=tr;
                cur->dirty&=~(1<<hr);
                cur->isconst&=~(1<<hr);
                return;
              }
            }
          }
          for(hr=0;hr<HOST_REGS;hr++) {
            if(hr!=HOST_CCREG||hsn[CCREG]>2) {
              if(cur->regmap[hr]==r) {
                cur->regmap[hr]=tr;
                cur->dirty&=~(1<<hr);
                cur->isconst&=~(1<<hr);
                return;
              }
            }
          }
        }
      }
    }
  }
  for(j=10;j>=0;j--)
  {
    for(r=1;r<=MAXREG;r++)
    {
      if(hsn[r]==j) {
        for(hr=0;hr<HOST_REGS;hr++) {
          if(cur->regmap[hr]==r+64) {
            cur->regmap[hr]=tr;
            cur->dirty&=~(1<<hr);
            cur->isconst&=~(1<<hr);
            return;
          }
        }
        for(hr=0;hr<HOST_REGS;hr++) {
          if(cur->regmap[hr]==r) {
            cur->regmap[hr]=tr;
            cur->dirty&=~(1<<hr);
            cur->isconst&=~(1<<hr);
            return;
          }
        }
      }
    }
  }
  DebugMessage(M64MSG_ERROR, "This shouldn't happen");exit(1);
}
// Allocate a specific ARM64 register.
static void alloc_arm64_reg(struct regstat *cur,int i,signed char tr,char hr)
{
  int n;
  int dirty=0;
  
  // see if it's already allocated (and dealloc it)
  for(n=0;n<HOST_REGS;n++)
  {
    if(n!=EXCLUDE_REG&&cur->regmap[n]==tr) {
      dirty=(cur->dirty>>n)&1;
      cur->regmap[n]=-1;
    }
  }
  
  cur->regmap[hr]=tr;
  cur->dirty&=~(1<<hr);
  cur->dirty|=dirty<<hr;
  cur->isconst&=~(1<<hr);
}

// Alloc cycle count into dedicated register
static void alloc_cc(struct regstat *cur,int i)
{
  alloc_arm64_reg(cur,i,CCREG,HOST_CCREG);
}

/* Special alloc */


/* Assembler */

static char regname[32][4] = {
 "w0",
 "w1",
 "w2",
 "w3",
 "w4",
 "w5",
 "w6",
 "w7",
 "w8",
 "w9",
 "w10",
 "w11",
 "w12",
 "w13",
 "w14",
 "w15",
 "w16",
 "w17",
 "w18",
 "w19",
 "w20",
 "w21",
 "w22",
 "w23",
 "w24",
 "w25",
 "w26",
 "w27",
 "w28",
 "w29",
 "w30",
 "wzr"};

static char regname64[32][4] = {
 "x0",
 "x1",
 "x2",
 "x3",
 "x4",
 "x5",
 "x6",
 "x7",
 "x8",
 "x9",
 "x10",
 "x11",
 "x12",
 "x13",
 "x14",
 "x15",
 "x16",
 "x17",
 "x18",
 "x19",
 "x20",
 "x21",
 "x22",
 "x23",
 "x24",
 "x25",
 "x26",
 "x27",
 "x28",
 "fp",
 "lr",
 "sp"};

static void output_byte(u_char byte)
{
  *(out++)=byte;
}
static void output_modrm(u_char mod,u_char rm,u_char ext)
{
  assert(0);
  assert(mod<4);
  assert(rm<8);
  assert(ext<8);
  u_char byte=(mod<<6)|(ext<<3)|rm;
  *(out++)=byte;
}

static void output_w32(u_int word)
{
  *((u_int *)out)=word;
  out+=4;
}
static u_int rd_rn_rm(u_int rd, u_int rn, u_int rm)
{
  assert(0);
  assert(rd!=29);
  assert(rn!=29);
  assert(rm!=29);
  return((rn<<16)|(rd<<12)|rm);
}
static u_int rd_rn_imm_shift(u_int rd, u_int rn, u_int imm, u_int shift)
{
  assert(0);
  assert(rd!=29);
  assert(rn!=29);
  assert(imm<256);
  assert((shift&1)==0);
  return((rn<<16)|(rd<<12)|(((32-shift)&30)<<7)|imm);
}
static u_int genimm_(u_int imm,u_int *encoded)
{
  assert(0);
  if(imm==0) {*encoded=0;return 1;}
  int i=32;
  while(i>0)
  {
    if(imm<256) {
      *encoded=((i&30)<<7)|imm;
      return 1;
    }
    imm=(imm>>2)|(imm<<30);i-=2;
  }
  return 0;
}
static u_int genjmp(uintptr_t addr)
{
  if(addr<4) return 0;
  int offset=addr-(intptr_t)out;
  assert(offset>=-134217728&&offset<134217728);
  return ((u_int)offset>>2)&0x3ffffff;
}

static u_int gencondjmp(uintptr_t addr)
{
  if(addr<4) return 0;
  int offset=addr-(intptr_t)out;
  assert(offset>=-1048576&&offset<1048576);
  return ((u_int)offset>>2)&0x7ffff;
}

uint32_t count_trailing_zeros(uint64_t value)
{
#ifdef _MSC_VER
  uint32_t trailing_zero = 0;
#ifdef _M_X64
  if (_BitScanForward64(&trailing_zero,value))
    return trailing_zero;
  else
    return 64;
#else
  if (_BitScanForward(&trailing_zero,(uint32_t)value))
    return trailing_zero;
  else
    return 32;
#endif
#else /* ARM64 */
  return __builtin_ctzll(value);
#endif
}

uint32_t count_leading_zeros(uint64_t value)
{
#ifdef _MSC_VER
  uint32_t leading_zero = 0;
#ifdef _M_X64
  if (_BitScanReverse64(&leading_zero,value))
     return 63 - leading_zero;
  else
    return 64;
#else
  if (_BitScanReverse(&leading_zero,(uint32_t)value))
     return 31 - leading_zero;
  else
    return 32;
#endif
#else /* ARM64 */
  return __builtin_clzll(value);
#endif
}

// This function returns true if the argument is a non-empty
// sequence of ones starting at the least significant bit with the remainder
// zero.
static uint32_t is_mask(uint64_t value) {
  return value && ((value + 1) & value) == 0;
}

// This function returns true if the argument contains a
// non-empty sequence of ones with the remainder zero.
static uint32_t is_shifted_mask(uint64_t Value) {
  return Value && is_mask((Value - 1) | Value);
}

// Determine if an immediate value can be encoded
// as the immediate operand of a logical instruction for the given register
// size. If so, return 1 with "encoding" set to the encoded value in
// the form N:immr:imms.
static uint32_t genimm(uint64_t imm, uint32_t regsize, uint32_t * encoded) {
  // First, determine the element size.
  uint32_t size = regsize;
  do {
    size /= 2;
    uint64_t mask = (1ULL << size) - 1;

    if ((imm & mask) != ((imm >> size) & mask)) {
      size *= 2;
      break;
    }
  } while (size > 2);

  // Second, determine the rotation to make the element be: 0^m 1^n.
  uint32_t trailing_one, trailing_zero;
  uint64_t mask = ((uint64_t)-1LL) >> (64 - size);
  imm &= mask;

  if (is_shifted_mask(imm)) {
    trailing_zero = count_trailing_zeros(imm);
    assert(trailing_zero < 64);
    trailing_one = count_trailing_zeros(~(imm >> trailing_zero));
  } else {
    imm |= ~mask;
    if (!is_shifted_mask(~imm))
      return 0;
  
    uint32_t leading_one = count_leading_zeros(~imm);
    trailing_zero = 64 - leading_one;
    trailing_one = leading_one + count_trailing_zeros(~imm) - (64 - size);
  }

  // Encode in immr the number of RORs it would take to get *from* 0^m 1^n
  // to our target value, where trailing_zero is the number of RORs to go the opposite
  // direction.
  assert(size > trailing_zero);
  uint32_t immr = (size - trailing_zero) & (size - 1);

  // If size has a 1 in the n'th bit, create a value that has zeroes in
  // bits [0, n] and ones above that.
  uint64_t Nimms = ~(size-1) << 1;

  // Or the trailing_one value into the low bits, which must be below the Nth bit
  // bit mentioned above.
  Nimms |= (trailing_one-1);

  // Extract the seventh bit and toggle it to create the N field.
  uint32_t N = ((Nimms >> 6) & 1) ^ 1;

  *encoded = (N << 12) | (immr << 6) | (Nimms & 0x3f);
  return 1;
}

static void emit_mov(int rs,int rt)
{
  assert(rs!=29);
  assert(rt!=29);
  assem_debug("mov %s,%s",regname[rt],regname[rs]);
  output_w32(0x2a000000|rs<<16|WZR<<5|rt);
}

static void emit_movs(int rs,int rt)
{
  assert(0);
  assert(rs!=29);
  assert(rt!=29);
  assem_debug("movs %s,%s",regname[rt],regname[rs]);
  output_w32(0xe1b00000|rd_rn_rm(rt,0,rs));
}

static void emit_add(int rs1,int rs2,int rt)
{
  assert(rs1!=29);
  assert(rs2!=29);
  assert(rt!=29);
  assem_debug("add %s,%s,%s",regname[rt],regname[rs1],regname[rs2]);
  output_w32(0x0b000000|rs2<<16|rs1<<5|rt);
}

static void emit_addne(int rs1,int rs2,int rt)
{
  assert(0);
  assert(rs1!=29);
  assert(rs2!=29);
  assert(rt!=29);
  assem_debug("addne %s,%s,%s",regname[rt],regname[rs1],regname[rs2]);
  output_w32(0x12800000|rd_rn_rm(rt,rs1,rs2));
}

static void emit_addsarimm(int rs1,int rs2,int rt,int imm)
{
  assert(0);
  assert(rs1!=29);
  assert(rs2!=29);
  assert(rt!=29);
  assert(imm>0);
  assert(imm<32);
  assem_debug("add %s,%s,%s,ASR#%d",regname[rt],regname[rs1],regname[rs2],imm);
  output_w32(0xe0a00000|rd_rn_rm(rt,rs1,rs2)|0x40|(imm<<7));
}

static void emit_adds(int rs1,int rs2,int rt)
{
  assert(0);
  assert(rs1!=29);
  assert(rs2!=29);
  assert(rt!=29);
  assem_debug("adds %s,%s,%s",regname[rt],regname[rs1],regname[rs2]);
  output_w32(0xe0900000|rd_rn_rm(rt,rs1,rs2));
}

static void emit_adc(int rs1,int rs2,int rt)
{
  assert(0);
  assert(rs1!=29);
  assert(rs2!=29);
  assert(rt!=29);
  assem_debug("adc %s,%s,%s",regname[rt],regname[rs1],regname[rs2]);
  output_w32(0xe0a00000|rd_rn_rm(rt,rs1,rs2));
}

static void emit_adcs(int rs1,int rs2,int rt)
{
  assert(0);
  assert(rs1!=29);
  assert(rs2!=29);
  assert(rt!=29);
  assem_debug("adcs %s,%s,%s",regname[rt],regname[rs1],regname[rs2]);
  output_w32(0xe0b00000|rd_rn_rm(rt,rs1,rs2));
}

static void emit_sbc(int rs1,int rs2,int rt)
{
  assert(0);
  assert(rs1!=29);
  assert(rs2!=29);
  assert(rt!=29);
  assem_debug("sbc %s,%s,%s",regname[rt],regname[rs1],regname[rs2]);
  output_w32(0xe0c00000|rd_rn_rm(rt,rs1,rs2));
}

static void emit_sbcs(int rs1,int rs2,int rt)
{
  assert(rs1!=29);
  assert(rs2!=29);
  assert(rt!=29);
  assem_debug("sbcs %s,%s,%s",regname[rt],regname[rs1],regname[rs2]);
  output_w32(0x7a000000|rs2<<16|rs1<<5|rt);
}

static void emit_neg(int rs, int rt)
{
  assert(rs!=29);
  assert(rt!=29);
  assem_debug("neg %s,%s",regname[rt],regname[rs]);
  output_w32(0x4b000000|rs<<16|WZR<<5|rt);
}

static void emit_negs(int rs, int rt)
{
  assert(0);
  assert(rs!=29);
  assert(rt!=29);
  assem_debug("rsbs %s,%s,#0",regname[rt],regname[rs]);
  output_w32(0xe2700000|rd_rn_rm(rt,rs,0));
}

static void emit_sub(int rs1,int rs2,int rt)
{
  assert(rs1!=29);
  assert(rs2!=29);
  assert(rt!=29);
  assem_debug("sub %s,%s,%s",regname[rt],regname[rs1],regname[rs2]);
  output_w32(0x4b000000|rs2<<16|rs1<<5|rt);
}

static void emit_subs(int rs1,int rs2,int rt)
{
  assert(0);
  assert(rs1!=29);
  assert(rs2!=29);
  assert(rt!=29);
  assem_debug("subs %s,%s,%s",regname[rt],regname[rs1],regname[rs2]);
  output_w32(0xe0500000|rd_rn_rm(rt,rs1,rs2));
}

static void emit_zeroreg(int rt)
{
  assert(rt!=29);
  assem_debug("movz %s,#0",regname[rt]);
  output_w32(0x52800000|rt);
}

static void emit_zeroreg64(int rt)
{
  assert(rt!=29);
  assem_debug("movz %s,#0",regname64[rt]);
  output_w32(0xd2800000|rt);
}

static void emit_loadlp(u_int imm,u_int rt)
{
  assert(0);
  assert(rt!=29);
  add_literal((int)out,imm);
  assem_debug("ldr %s,pc+? [=%x]",regname[rt],imm);
  output_w32(0xe5900000|rd_rn_rm(rt,15,0));
}
static void emit_movw(u_int imm,u_int rt)
{
  assert(0);
  assert(rt!=29);
  assert(imm<65536);
  assem_debug("movw %s,#%d (0x%x)",regname[rt],imm,imm);
  output_w32(0xe3000000|rd_rn_rm(rt,0,0)|(imm&0xfff)|((imm<<4)&0xf0000));
}
static void emit_movt(u_int imm,u_int rt)
{
  assert(0);
  assert(rt!=29);
  assem_debug("movt %s,#%d (0x%x)",regname[rt],imm&0xffff0000,imm&0xffff0000);
  output_w32(0xe3400000|rd_rn_rm(rt,0,0)|((imm>>16)&0xfff)|((imm>>12)&0xf0000));
}
static void emit_movz(u_int imm,u_int rt)
{
  assert(rt!=29);
  assert(imm<65536);
  assem_debug("movz %s,#%d",regname[rt],imm);
  output_w32(0x52800000|imm<<5|rt);
}
static void emit_movz_lsl16(u_int imm,u_int rt)
{
  assert(rt!=29);
  assert(imm<65536);
  assem_debug("movz %s, #%d, lsl #%d",regname[rt],imm,16);
  output_w32(0x52a00000|imm<<5|rt);
}
static void emit_movn(u_int imm,u_int rt)
{
  assert(rt!=29);
  assert(imm<65536);
  assem_debug("movn %s,#%d",regname[rt],imm);
  output_w32(0x12800000|imm<<5|rt);
}
static void emit_movn_lsl16(u_int imm,u_int rt)
{
  assert(rt!=29);
  assert(imm<65536);
  assem_debug("movn %s, #%d, lsl #%d",regname[rt],imm,16);
  output_w32(0x12a00000|imm<<5|rt);
}
static void emit_movk(u_int imm,u_int rt)
{
  assert(rt!=29);
  assert(imm<65536);
  assem_debug("movk %s,#%d",regname[rt],imm);
  output_w32(0x72800000|imm<<5|rt);
}
static void emit_movk_lsl16(u_int imm,u_int rt)
{
  assert(rt!=29);
  assert(imm<65536);
  assem_debug("movk %s, #%d, lsl #%d",regname[rt],imm,16);
  output_w32(0x72a00000|imm<<5|rt);
}
static void emit_movk64(u_int imm,u_int rt)
{
  assert(rt!=29);
  assert(imm<65536);
  assem_debug("movk %s,#%d",regname64[rt],imm);
  output_w32(0xf2800000|imm<<5|rt);
}
static void emit_movk64_lsl16(u_int imm,u_int rt)
{
  assert(rt!=29);
  assert(imm<65536);
  assem_debug("movk %s, #%d, lsl #%d",regname64[rt],imm,16);
  output_w32(0xf2a00000|imm<<5|rt);
}
static void emit_movk64_lsl32(u_int imm,u_int rt)
{
  assert(rt!=29);
  assert(imm<65536);
  assem_debug("movk %s, #%d, lsl #%d",regname64[rt],imm,32);
  output_w32(0xf2c00000|imm<<5|rt);
}
static void emit_movz64_lsl48(u_int imm,u_int rt)
{
  assert(rt!=29);
  assert(imm<65536);
  assem_debug("movz %s, #%d, lsl #%d",regname64[rt],imm,48);
  output_w32(0xd2e00000|imm<<5|rt);
}
static void emit_movimm(u_int imm,u_int rt)
{
  assert(rt!=29);
  uint32_t armval=0;
  if(imm<65536) {
    emit_movz(imm,rt);
  }else if((~imm)<65536) {
    emit_movn(~imm,rt);
  }else if((imm&0xffff)==0) {
    emit_movz_lsl16((imm>>16)&0xffff,rt);
  }else if(((~imm)&0xffff)==0) {
    emit_movn_lsl16((~imm>>16)&0xffff,rt);
  }else if(genimm((uint64_t)imm,32,&armval)) {
    assem_debug("orr %s, wzr, #%d (0x%x)",regname[rt],imm,imm);
    output_w32(0x32000000|armval<<10|WZR<<5|rt);
  }else{
    emit_movz_lsl16((imm>>16)&0xffff,rt);
    emit_movk(imm&0xffff,rt);
  }
}
static void emit_movimm64(uint64_t imm,u_int rt){
  assert(0);
  uint32_t armval=0;
  if(genimm(imm,64,&armval)){
    assem_debug("orr %s, xzr, #%d (0x%x)",regname64[rt],imm,imm);
    output_w32(0xb2000000|armval<<10|XZR<<5|rt);
  }else{
    emit_movz64_lsl48((imm>>48)&0xffff,rt);
    if(((imm>>32)&0xffff)!=0)emit_movk64_lsl32((imm>>32)&0xffff,rt);
    if(((imm>>16)&0xffff)!=0)emit_movk64_lsl16((imm>>16)&0xffff,rt);
    if((imm&0xffff)!=0)emit_movk64(imm&0xffff,rt);
  }
}

static void emit_pcreladdr(u_int rt)
{
  assert(0);
  assert(rt!=29);
  assem_debug("add %s,pc,#?",regname[rt]);
  output_w32(0xe2800000|rd_rn_rm(rt,15,0));
}

static void emit_loadreg(int r, int hr)
{
  assert(hr!=29);
  if((r&63)==0)
    emit_zeroreg(hr);
  else if(r==MMREG)
    emit_movimm(((intptr_t)memory_map-(intptr_t)&dynarec_local)>>2,hr);
  else if(r==INVCP||r==ROREG){
    intptr_t addr=0;
    if(r==INVCP) addr=(intptr_t)&invc_ptr;
    if(r==ROREG) addr=(intptr_t)&ram_offset;
    u_int offset = addr-(uintptr_t)&dynarec_local;
    assert(offset<4096);
    assert(offset%8 == 0); /* 8 bytes aligned */
    assem_debug("ldr %s,fp+%d",regname[hr],offset);
    output_w32(0xf9400000|((offset>>3)<<10)|(FP<<5)|hr);
  }
  else {
    intptr_t addr=((intptr_t)reg)+((r&63)<<3)+((r&64)>>4);
    if((r&63)==HIREG) addr=(intptr_t)&hi+((r&64)>>4);
    if((r&63)==LOREG) addr=(intptr_t)&lo+((r&64)>>4);
    if(r==CCREG) addr=(intptr_t)&cycle_count;
    if(r==CSREG) addr=(intptr_t)&g_cp0_regs[CP0_STATUS_REG];
    if(r==FSREG) addr=(intptr_t)&FCR31;
    u_int offset = addr-(uintptr_t)&dynarec_local;
    assert(offset<4096);
    assert(offset%4 == 0); /* 4 bytes aligned */
    assem_debug("ldr %s,fp+%d",regname[hr],offset);
    output_w32(0xb9400000|((offset>>2)<<10)|(FP<<5)|hr);
  }
}
static void emit_storereg(int r, int hr)
{
  assert(hr!=29);
  intptr_t addr=((intptr_t)reg)+((r&63)<<3)+((r&64)>>4);
  if((r&63)==HIREG) addr=(intptr_t)&hi+((r&64)>>4);
  if((r&63)==LOREG) addr=(intptr_t)&lo+((r&64)>>4);
  if(r==CCREG) addr=(intptr_t)&cycle_count;
  if(r==FSREG) addr=(intptr_t)&FCR31;
  u_int offset = addr-(intptr_t)&dynarec_local;
  assert(offset<4096);
  assert(offset%4 == 0); /* 4 bytes aligned */
  assem_debug("str %s,fp+%d",regname[hr],offset);
  output_w32(0xb9000000|((offset>>2)<<10)|(FP<<5)|hr);
}

static void emit_test(int rs, int rt)
{
  assert(rs!=29);
  assert(rt!=29);
  assem_debug("tst %s,%s",regname[rs],regname[rt]);
  output_w32(0x6a000000|rt<<16|rs<<5|WZR);
}

static void emit_testimm(int rs,int imm)
{
  assert(rs!=29);
  u_int armval, ret;
  assem_debug("tst %s,#%d",regname[rs],imm);
  ret=genimm(imm,32,&armval);
  assert(ret);
  output_w32(0x72000000|armval<<10|rs<<5|WZR);
}

static void emit_testimm64(int rs,int imm)
{
  assert(rs!=29);
  u_int armval, ret;
  assem_debug("tst %s,#%d",regname64[rs],imm);
  ret=genimm(imm,64,&armval);
  assert(ret);
  output_w32(0xf2000000|armval<<10|rs<<5|WZR);
}

static void emit_not(int rs,int rt)
{
  assert(0);
  assert(rs!=29);
  assert(rt!=29);
  assem_debug("mvn %s,%s",regname[rt],regname[rs]);
  output_w32(0xe1e00000|rd_rn_rm(rt,0,rs));
}

static void emit_and(u_int rs1,u_int rs2,u_int rt)
{
  assert(rs1!=29);
  assert(rs2!=29);
  assert(rt!=29);
  assem_debug("and %s,%s,%s",regname[rt],regname[rs1],regname[rs2]);
  output_w32(0x0a000000|rs2<<16|rs1<<5|rt);
}

static void emit_or(u_int rs1,u_int rs2,u_int rt)
{
  assert(rs1!=29);
  assert(rs2!=29);
  assert(rt!=29);
  assem_debug("orr %s,%s,%s",regname[rt],regname[rs1],regname[rs2]);
  output_w32(0x2a000000|rs2<<16|rs1<<5|rt);
}
static void emit_or_and_set_flags(int rs1,int rs2,int rt)
{
  assert(0);
  assert(rs1!=29);
  assert(rs2!=29);
  assert(rt!=29);
  assem_debug("orrs %s,%s,%s",regname[rt],regname[rs1],regname[rs2]);
  output_w32(0xe1900000|rd_rn_rm(rt,rs1,rs2));
}

static void emit_xor(u_int rs1,u_int rs2,u_int rt)
{
  assert(rs1!=29);
  assert(rs2!=29);
  assert(rt!=29);
  assem_debug("eor %s,%s,%s",regname[rt],regname[rs1],regname[rs2]);
  output_w32(0x4a000000|rs2<<16|rs1<<5|rt);
}

static void emit_addimm64(u_int rs,int imm,u_int rt)
{
  assert(rt!=29);
  assert(imm>0&&imm<4096);
  assem_debug("add %s, %s, #%d",regname64[rt],regname64[rs],imm);
  output_w32(0x91000000|imm<<10|rs<<5|rt);
}

static void emit_addimm(u_int rs,int imm,u_int rt)
{
  assert(rt!=29);
  assert(rs!=29);

  if(imm!=0) {
    assert(imm>-65536&&imm<65536);
    //assert(imm>-16777216&&imm<16777216);
    if(imm<0&&imm>-4096) {
      assem_debug("sub %s, %s, #%d",regname[rt],regname[rs],-imm&0xfff);
      output_w32(0x51000000|((-imm)&0xfff)<<10|rs<<5|rt);
    }else if(imm>0&&imm<4096) {
      assem_debug("add %s, %s, #%d",regname[rt],regname[rs],imm&0xfff);
      output_w32(0x11000000|(imm&0xfff)<<10|rs<<5|rt);
    }else if(imm<0) {
      assem_debug("sub %s, %s, #%d lsl #%d",regname[rt],regname[rt],((-imm)>>12)&0xfff,12);
      output_w32(0x51400000|(((-imm)>>12)&0xfff)<<10|rs<<5|rt);
      if((-imm&0xfff)!=0) {
        assem_debug("sub %s, %s, #%d",regname[rt],regname[rs],(-imm&0xfff));
        output_w32(0x51000000|((-imm)&0xfff)<<10|rt<<5|rt);
      }
    }else {
      assem_debug("add %s, %s, #%d lsl #%d",regname[rt],regname[rt],(imm>>12)&0xfff,12);
      output_w32(0x11400000|((imm>>12)&0xfff)<<10|rs<<5|rt);
      if((imm&0xfff)!=0) {
        assem_debug("add %s, %s, #%d",regname[rt],regname[rs],imm&0xfff);
        output_w32(0x11000000|(imm&0xfff)<<10|rt<<5|rt);
      }
    }
  }
  else if(rs!=rt) emit_mov(rs,rt);
}

static void emit_addimm_and_set_flags(int imm,int rt)
{
  assert(rt!=29);
  assert(imm>-65536&&imm<65536);
  //assert(imm>-16777216&&imm<16777216);
  if(imm<0&&imm>-4096) {
    assem_debug("subs %s, %s, #%d",regname[rt],regname[rt],-imm&0xfff);
    output_w32(0x71000000|((-imm)&0xfff)<<10|rt<<5|rt);
  }else if(imm>0&&imm<4096) {
    assem_debug("adds %s, %s, #%d",regname[rt],regname[rt],imm&0xfff);
    output_w32(0x31000000|(imm&0xfff)<<10|rt<<5|rt);
  }else if(imm<0) {
    if((-imm&0xfff)!=0) {
      assem_debug("sub %s, %s, #%d lsl #%d",regname[rt],regname[rt],((-imm)>>12)&0xfff,12);
      output_w32(0x51400000|(((-imm)>>12)&0xfff)<<10|rt<<5|rt);
      assem_debug("subs %s, %s, #%d",regname[rt],regname[rt],(-imm&0xfff));
      output_w32(0x71000000|((-imm)&0xfff)<<10|rt<<5|rt);
    }else{
      assem_debug("subs %s, %s, #%d lsl #%d",regname[rt],regname[rt],((-imm)>>12)&0xfff,12);
      output_w32(0x71400000|(((-imm)>>12)&0xfff)<<10|rt<<5|rt);
    }
  }else {
    if((imm&0xfff)!=0) {
      assem_debug("add %s, %s, #%d lsl #%d",regname[rt],regname[rt],(imm>>12)&0xfff,12);
      output_w32(0x11400000|((imm>>12)&0xfff)<<10|rt<<5|rt);
      assem_debug("adds %s, %s, #%d",regname[rt],regname[rt],imm&0xfff);
      output_w32(0x31000000|(imm&0xfff)<<10|rt<<5|rt);
    }else{
      assem_debug("adds %s, %s, #%d lsl #%d",regname[rt],regname[rt],(imm>>12)&0xfff,12);
      output_w32(0x31400000|((imm>>12)&0xfff)<<10|rt<<5|rt);
    }
  }
}

#ifndef RAM_OFFSET
static void emit_addimm_no_flags(u_int imm,u_int rt)
{
  emit_addimm(rt,imm,rt);
}
#endif

static void emit_addnop(u_int r)
{
  assert(r!=29);
  assem_debug("nop");
  output_w32(0xd503201f);
  /*assem_debug("add %s,%s,#0 (nop)",regname[r],regname[r]);
  output_w32(0x11000000|r<<5|r);*/
}

static void emit_adcimm(u_int rs,int imm,u_int rt)
{
  assert(0);
  assert(rs!=29);
  assert(rt!=29);
  u_int armval, ret;
  ret = genimm_(imm,&armval);
  assert(ret);
  assem_debug("adc %s,%s,#%d",regname[rt],regname[rs],imm);
  output_w32(0xe2a00000|rd_rn_rm(rt,rs,0)|armval);
}
/*static void emit_sbcimm(int imm,u_int rt)
{
  u_int armval, ret;
  ret = genimm_(imm,&armval);
  assert(ret);
  assem_debug("sbc %s,%s,#%d",regname[rt],regname[rt],imm);
  output_w32(0xe2c00000|rd_rn_rm(rt,rt,0)|armval);
}*/

static void emit_rscimm(int rs,int imm,u_int rt)
{
  assert(0);
  assert(rs!=29);
  assert(rt!=29);
  u_int armval, ret;
  ret = genimm_(imm,&armval);
  assert(ret);
  assem_debug("rsc %s,%s,#%d",regname[rt],regname[rs],imm);
  output_w32(0xe2e00000|rd_rn_rm(rt,rs,0)|armval);
}

static void emit_addimm64_32(int rsh,int rsl,int imm,int rth,int rtl)
{
  assert(0);
  assert(rsh!=29);
  assert(rsl!=29);
  assert(rth!=29);
  assert(rtl!=29);
  // TODO: if(genimm_(imm,&armval)) ...
  // else
  emit_movimm(imm,HOST_TEMPREG);
  emit_adds(HOST_TEMPREG,rsl,rtl);
  emit_adcimm(rsh,0,rth);
}
#ifdef INVERTED_CARRY
static void emit_sbb(int rs1,int rs2)
{
  assem_debug("sbb %%%s,%%%s",regname[rs2],regname[rs1]);
  output_byte(0x19);
  output_modrm(3,rs1,rs2);
}
#endif

static void emit_andimm(int rs,int imm,int rt)
{
  assert(rs!=29);
  assert(rt!=29);
  u_int armval;
  if(imm==0) {
    emit_zeroreg(rt);
  }else if(genimm((uint64_t)imm,32,&armval)) {
    assem_debug("and %s,%s,#%d",regname[rt],regname[rs],imm);
    output_w32(0x12000000|armval<<10|rs<<5|rt);
  }else{
    assert(imm>0&&imm<65535);
    emit_movz(imm,HOST_TEMPREG);
    assem_debug("and %s,%s,%s",regname[rt],regname[rs],regname[HOST_TEMPREG]);
    output_w32(0x0a000000|HOST_TEMPREG<<16|rs<<5|rt);
  }
}

static void emit_andimm64(int rs,int imm,int rt)
{
  assert(0);
}

static void emit_orimm(int rs,int imm,int rt)
{
  assert(rs!=29);
  assert(rt!=29);
  u_int armval;
  if(imm==0) {
    if(rs!=rt) emit_mov(rs,rt);
  }else if(genimm(imm,32,&armval)) {
    assem_debug("orr %s,%s,#%d",regname[rt],regname[rs],imm);
    output_w32(0x32000000|armval<<10|rs<<5|rt);
  }else{
    assert(imm>0&&imm<65536);
    emit_movz(imm,HOST_TEMPREG);
    assem_debug("orr %s,%s,%s",regname[rt],regname[rs],regname[HOST_TEMPREG]);
    output_w32(0x2a000000|HOST_TEMPREG<<16|rs<<5|rt);
  }
}

static void emit_xorimm(int rs,int imm,int rt)
{
  assert(rs!=29);
  assert(rt!=29);
  u_int armval;
  if(imm==0) {
    if(rs!=rt) emit_mov(rs,rt);
  }else if(genimm((uint64_t)imm,32,&armval)) {
    assem_debug("eor %s,%s,#%d",regname[rt],regname[rs],imm);
    output_w32(0x52000000|armval<<10|rs<<5|rt);
  }else{
    assert(imm>0&&imm<65536);
    emit_movz(imm,HOST_TEMPREG);
    assem_debug("eor %s,%s,%s",regname[rt],regname[rs],regname[HOST_TEMPREG]);
    output_w32(0x4a000000|HOST_TEMPREG<<16|rs<<5|rt);
  }
}

static void emit_shlimm(int rs,u_int imm,int rt)
{
  assert(rs!=29);
  assert(rt!=29);
  assert(imm>0);
  assert(imm<32);
  //if(imm==1) ...
  assem_debug("lsl %s,%s,#%d",regname[rt],regname[rs],imm);
  output_w32(0x53000000|((31-imm)+1)<<16|(31-imm)<<10|rs<<5|rt);
}

static void emit_shlimm64(int rs,u_int imm,int rt)
{
  assert(rs!=29);
  assert(rt!=29);
  assert(imm>0);
  assert(imm<64);
  assem_debug("lsl %s,%s,#%d",regname64[rt],regname64[rs],imm);
  output_w32(0xd3400000|((63-imm)+1)<<16|(63-imm)<<10|rs<<5|rt);
}

static void emit_shrimm(int rs,u_int imm,int rt)
{
  assert(rs!=29);
  assert(rt!=29);
  assert(imm>0);
  assert(imm<32);
  assem_debug("lsr %s,%s,#%d",regname[rt],regname[rs],imm);
  output_w32(0x53000000|imm<<16|0x1f<<10|rs<<5|rt);
}

static void emit_shrimm64(int rs,u_int imm,int rt)
{
  assert(rs!=29);
  assert(rt!=29);
  assert(imm>0);
  assert(imm<64);
  assem_debug("lsr %s,%s,#%d",regname64[rt],regname64[rs],imm);
  output_w32(0xd3400000|imm<<16|0x3f<<10|rs<<5|rt);
}

static void emit_sarimm(int rs,u_int imm,int rt)
{
  assert(rs!=29);
  assert(rt!=29);
  assert(imm>0);
  assert(imm<32);
  assem_debug("asr %s,%s,#%d",regname[rt],regname[rs],imm);
  output_w32(0x13000000|imm<<16|0x1f<<10|rs<<5|rt);
}

static void emit_rorimm(int rs,u_int imm,int rt)
{
  assert(0);
  assert(rs!=29);
  assert(rt!=29);
  assert(imm>0);
  assert(imm<32);
  assem_debug("ror %s,%s,#%d",regname[rt],regname[rs],imm);
  output_w32(0xe1a00000|rd_rn_rm(rt,0,rs)|0x60|(imm<<7));
}

static void emit_shldimm(int rs,int rs2,u_int imm,int rt)
{
  assert(0);
  assert(rs!=29);
  assert(rs2!=29);
  assert(rt!=29);
  assem_debug("shld %%%s,%%%s,%d",regname[rt],regname[rs2],imm);
  assert(imm>0);
  assert(imm<32);
  //if(imm==1) ...
  assem_debug("lsl %s,%s,#%d",regname[rt],regname[rs],imm);
  output_w32(0xe1a00000|rd_rn_rm(rt,0,rs)|(imm<<7));
  assem_debug("orr %s,%s,%s,lsr #%d",regname[rt],regname[rt],regname[rs2],32-imm);
  output_w32(0xe1800020|rd_rn_rm(rt,rt,rs2)|((32-imm)<<7));
}

static void emit_shrdimm(int rs,int rs2,u_int imm,int rt)
{
  assert(0);
  assert(rs!=29);
  assert(rs2!=29);
  assert(rt!=29);
  assem_debug("shrd %%%s,%%%s,%d",regname[rt],regname[rs2],imm);
  assert(imm>0);
  assert(imm<32);
  //if(imm==1) ...
  assem_debug("lsr %s,%s,#%d",regname[rt],regname[rs],imm);
  output_w32(0xe1a00020|rd_rn_rm(rt,0,rs)|(imm<<7));
  assem_debug("orr %s,%s,%s,lsl #%d",regname[rt],regname[rt],regname[rs2],32-imm);
  output_w32(0xe1800000|rd_rn_rm(rt,rt,rs2)|((32-imm)<<7));
}

static void emit_shl(u_int rs,u_int shift,u_int rt)
{
  assert(rs!=29);
  assert(rt!=29);
  assert(shift!=29);
  //if(imm==1) ...
  assem_debug("lsl %s,%s,%s",regname[rt],regname[rs],regname[shift]);
  output_w32(0x1ac02000|shift<<16|rs<<5|rt);
}
static void emit_shr(u_int rs,u_int shift,u_int rt)
{
  assert(rs!=29);
  assert(rt!=29);
  assert(shift!=29);
  assem_debug("lsr %s,%s,%s",regname[rt],regname[rs],regname[shift]);
  output_w32(0x1ac02400|shift<<16|rs<<5|rt);
}
static void emit_sar(u_int rs,u_int shift,u_int rt)
{
  assert(rs!=29);
  assert(rt!=29);
  assert(shift!=29);
  assem_debug("asr %s,%s,%s",regname[rt],regname[rs],regname[shift]);
  output_w32(0x1ac02800|shift<<16|rs<<5|rt);
}

static void emit_orrshl(u_int rs,u_int shift,u_int rt)
{
  assert(0);
  assert(rs!=29);
  assert(rt!=29);
  assert(shift!=29);
  assem_debug("orr %s,%s,%s,lsl %s",regname[rt],regname[rt],regname[rs],regname[shift]);
  output_w32(0xe1800000|rd_rn_rm(rt,rt,rs)|0x10|(shift<<8));
}
static void emit_orrshl64(u_int rs,u_int shift,u_int rt)
{
  assert(rs!=29);
  assert(rt!=29);
  assert(shift<64);
  assem_debug("orr %s,%s,%s,lsl %d",regname64[rt],regname64[rt],regname64[rs],shift);
  output_w32(0xaa000000|rs<<16|shift<<10|rt<<5|rt);
}
static void emit_orrshr(u_int rs,u_int shift,u_int rt)
{
  assert(0);
  assert(rs!=29);
  assert(rt!=29);
  assert(shift!=29);
  assem_debug("orr %s,%s,%s,lsr %s",regname[rt],regname[rt],regname[rs],regname[shift]);
  output_w32(0xe1800000|rd_rn_rm(rt,rt,rs)|0x30|(shift<<8));
}

static void emit_cmpimm(int rs,int imm)
{
  assert(rs!=29);
  if(imm<0&&imm>-4096) {
    assem_debug("cmn %s,#%d",regname[rs],-imm&0xfff);
    output_w32(0x31000000|((-imm)&0xfff)<<10|rs<<5|WZR);
  }else if(imm>0&&imm<4096) {
    assem_debug("cmp %s,#%d",regname[rs],imm&0xfff);
    output_w32(0x71000000|(imm&0xfff)<<10|rs<<5|WZR);
  }else if(imm<0) {
    if((-imm&0xfff)==0) {
      assem_debug("cmn %s,#%d,lsl #12",regname[rs],-imm&0xfff);
      output_w32(0x31400000|((-imm>>12)&0xfff)<<10|rs<<5|WZR);
    }else{
      assert(imm>-65536);
      emit_movz(-imm,HOST_TEMPREG);
      assem_debug("cmn %s,%s",regname[rs],regname[HOST_TEMPREG]);
      output_w32(0x2b000000|HOST_TEMPREG<<16|rs<<5|WZR);
    }
  }else {                                                                                                                                  
    if((imm&0xfff)==0) {
      assem_debug("cmp %s,#%d,lsl #12",regname[rs],imm&0xfff);
      output_w32(0x71400000|((imm>>12)&0xfff)<<10|rs<<5|WZR);
    }else{
      assert(imm<65536);
      emit_movz(imm,HOST_TEMPREG);
      assem_debug("cmp %s,%s",regname[rs],regname[HOST_TEMPREG]);
      output_w32(0x6b000000|HOST_TEMPREG<<16|rs<<5|WZR);
    }
  }
}

static void emit_cmovne_imm(int imm,int rt)
{
  assert(imm==0||imm==1);
  assert(rt!=29);
  if(imm){
    assem_debug("csinc %s,%s,%s,eq",regname[rt],regname[rt],regname[WZR]);
    output_w32(0x1a800400|WZR<<16|EQ<<12|rt<<5|rt);
  }else{
    assem_debug("csel %s,%s,%s,ne",regname[rt],regname[WZR],regname[rt]);
    output_w32(0x1a800000|rt<<16|NE<<12|WZR<<5|rt);
  }
}
static void emit_cmovl_imm(int imm,int rt)
{
  assert(imm==0||imm==1);
  assert(rt!=29);
  if(imm){
    assem_debug("csinc %s,%s,%s,ge",regname[rt],regname[rt],regname[WZR]);
    output_w32(0x1a800400|WZR<<16|GE<<12|rt<<5|rt);
  }else{
    assem_debug("csel %s,%s,%s,lt",regname[rt],regname[WZR],regname[rt]);
    output_w32(0x1a800000|rt<<16|LT<<12|WZR<<5|rt);
  }
}
static void emit_cmovb_imm(int imm,int rt)
{
  assert(imm==0||imm==1);
  assert(rt!=29);
  if(imm){
    assem_debug("csinc %s,%s,%s,cs",regname[rt],regname[rt],regname[WZR]);
    output_w32(0x1a800400|WZR<<16|CS<<12|rt<<5|rt);
  }else{
    assem_debug("csel %s,%s,%s,cc",regname[rt],regname[WZR],regname[rt]);
    output_w32(0x1a800000|rt<<16|CC<<12|WZR<<5|rt);
  }
}
static void emit_cmovs_imm(int imm,int rt)
{
  assert(imm==0||imm==1);
  assert(rt!=29);
  if(imm){
    assem_debug("csinc %s,%s,%s,pl",regname[rt],regname[rt],regname[WZR]);
    output_w32(0x1a800400|WZR<<16|PL<<12|rt<<5|rt);
  }else{
    assem_debug("csel %s,%s,%s,mi",regname[rt],regname[WZR],regname[rt]);
    output_w32(0x1a800000|rt<<16|MI<<12|WZR<<5|rt);
  }
}
static void emit_cmove_reg(int rs,int rt)
{
  assert(rs!=29);
  assert(rt!=29);
  assem_debug("csel %s,%s,%s,eq",regname[rt],regname[rs],regname[rt]);
  output_w32(0x1a800000|rt<<16|EQ<<12|rs<<5|rt);
}
static void emit_cmovne_reg(int rs,int rt)
{
  assert(rs!=29);
  assert(rt!=29);
  assem_debug("csel %s,%s,%s,ne",regname[rt],regname[rs],regname[rt]);
  output_w32(0x1a800000|rt<<16|NE<<12|rs<<5|rt);
}
static void emit_cmovl_reg(int rs,int rt)
{
  assert(rs!=29);
  assert(rt!=29);
  assem_debug("csel %s,%s,%s,lt",regname[rt],regname[rs],regname[rt]);
  output_w32(0x1a800000|rt<<16|LT<<12|rs<<5|rt);
}
static void emit_cmovs_reg(int rs,int rt)
{
  assert(rs!=29);
  assert(rt!=29);
  assem_debug("csel %s,%s,%s,lt",regname[rt],regname[rs],regname[rt]);
  output_w32(0x1a800000|rt<<16|MI<<12|rs<<5|rt);
}

static void emit_slti32(int rs,int imm,int rt)
{
  assert(rs!=29);
  assert(rt!=29);
  if(rs!=rt) emit_zeroreg(rt);
  emit_cmpimm(rs,imm);
  if(rs==rt) emit_movimm(0,rt);
  emit_cmovl_imm(1,rt);
}
static void emit_sltiu32(int rs,int imm,int rt)
{
  assert(rs!=29);
  assert(rt!=29);
  if(rs!=rt) emit_zeroreg(rt);
  emit_cmpimm(rs,imm);
  if(rs==rt) emit_movimm(0,rt);
  emit_cmovb_imm(1,rt);
}
static void emit_slti64_32(int rsh,int rsl,int imm,int rt)
{
  assert(rsh!=29);
  assert(rsl!=29);
  assert(rt!=29);
  assert(rsh!=rt);
  emit_slti32(rsl,imm,rt);
  if(imm>=0)
  {
    emit_test(rsh,rsh);
    emit_cmovne_imm(0,rt);
    emit_cmovs_imm(1,rt);
  }
  else
  {
    emit_cmpimm(rsh,-1);
    emit_cmovne_imm(0,rt);
    emit_cmovl_imm(1,rt);
  }
}
static void emit_sltiu64_32(int rsh,int rsl,int imm,int rt)
{
  assert(0);
  assert(rsh!=29);
  assert(rsl!=29);
  assert(rt!=29);
  assert(rsh!=rt);
  emit_sltiu32(rsl,imm,rt);
  if(imm>=0)
  {
    emit_test(rsh,rsh);
    emit_cmovne_imm(0,rt);
  }
  else
  {
    emit_cmpimm(rsh,-1);
    emit_cmovne_imm(1,rt);
  }
}

static void emit_cmp(int rs,int rt)
{
  assert(rs!=29);
  assert(rt!=29);
  assem_debug("cmp %s,%s",regname[rs],regname[rt]);
  output_w32(0x6b000000|rt<<16|rs<<5|WZR);
}
static void emit_set_gz32(int rs, int rt)
{
  assert(0);
  assert(rs!=29);
  assert(rt!=29);
  //assem_debug("set_gz32");
  emit_cmpimm(rs,1);
  emit_movimm(1,rt);
  emit_cmovl_imm(0,rt);
}
static void emit_set_nz32(int rs, int rt)
{
  assert(0);
  assert(rs!=29);
  assert(rt!=29);
  //assem_debug("set_nz32");
  if(rs!=rt) emit_movs(rs,rt);
  else emit_test(rs,rs);
  emit_cmovne_imm(1,rt);
}
static void emit_set_gz64_32(int rsh, int rsl, int rt)
{
  assert(0);
  assert(rsh!=29);
  assert(rsl!=29);
  assert(rt!=29);
  //assem_debug("set_gz64");
  emit_set_gz32(rsl,rt);
  emit_test(rsh,rsh);
  emit_cmovne_imm(1,rt);
  emit_cmovs_imm(0,rt);
}
static void emit_set_nz64_32(int rsh, int rsl, int rt)
{
  assert(0);
  assert(rsh!=29);
  assert(rsl!=29);
  assert(rt!=29);
  //assem_debug("set_nz64");
  emit_or_and_set_flags(rsh,rsl,rt);
  emit_cmovne_imm(1,rt);
}
static void emit_set_if_less32(int rs1, int rs2, int rt)
{
  assert(rs1!=29);
  assert(rs2!=29);
  assert(rt!=29);
  //assem_debug("set if less (%%%s,%%%s),%%%s",regname[rs1],regname[rs2],regname[rt]);
  if(rs1!=rt&&rs2!=rt) emit_zeroreg(rt);
  emit_cmp(rs1,rs2);
  if(rs1==rt||rs2==rt) emit_movimm(0,rt);
  emit_cmovl_imm(1,rt);
}
static void emit_set_if_carry32(int rs1, int rs2, int rt)
{
  assert(rs1!=29);
  assert(rs2!=29);
  assert(rt!=29);
  //assem_debug("set if carry (%%%s,%%%s),%%%s",regname[rs1],regname[rs2],regname[rt]);
  if(rs1!=rt&&rs2!=rt) emit_zeroreg(rt);
  emit_cmp(rs1,rs2);
  if(rs1==rt||rs2==rt) emit_movimm(0,rt);
  emit_cmovb_imm(1,rt);
}
static void emit_set_if_less64_32(int u1, int l1, int u2, int l2, int rt)
{
  assert(u1!=29);
  assert(l1!=29);
  assert(u2!=29);
  assert(l2!=29);
  assert(rt!=29);
  //assem_debug("set if less64 (%%%s,%%%s,%%%s,%%%s),%%%s",regname[u1],regname[l1],regname[u2],regname[l2],regname[rt]);
  assert(u1!=rt);
  assert(u2!=rt);
  emit_cmp(l1,l2);
  emit_movimm(0,rt);
  emit_sbcs(u1,u2,HOST_TEMPREG);
  emit_cmovl_imm(1,rt);
}
static void emit_set_if_carry64_32(int u1, int l1, int u2, int l2, int rt)
{
  assert(u1!=29);
  assert(l1!=29);
  assert(u2!=29);
  assert(l2!=29);
  assert(rt!=29);
  //assem_debug("set if carry64 (%%%s,%%%s,%%%s,%%%s),%%%s",regname[u1],regname[l1],regname[u2],regname[l2],regname[rt]);
  assert(u1!=rt);
  assert(u2!=rt);
  emit_cmp(l1,l2);
  emit_movimm(0,rt);
  emit_sbcs(u1,u2,HOST_TEMPREG);
  emit_cmovb_imm(1,rt);
}

static void emit_call(intptr_t a)
{
  assem_debug("bl %x (%x+%x)",a,(intptr_t)out,a-(intptr_t)out);
  u_int offset=genjmp(a);
  output_w32(0x94000000|offset);
}
static void emit_jmp(intptr_t a)
{
  assem_debug("b %x (%x+%x)",a,(intptr_t)out,a-(intptr_t)out);
  u_int offset=genjmp(a);
  output_w32(0x14000000|offset);
}
static void emit_jne(intptr_t a)
{
  assem_debug("bne %x",a);
  u_int offset=gencondjmp(a);
  output_w32(0x54000000|offset<<5|NE);
}
static void emit_jeq(intptr_t a)
{
  assem_debug("beq %x",a);
  u_int offset=gencondjmp(a);
  output_w32(0x54000000|offset<<5|EQ);
}
static void emit_js(intptr_t a)
{
  assem_debug("bmi %x",a);
  u_int offset=gencondjmp(a);
  output_w32(0x54000000|offset<<5|MI);
}
static void emit_jns(intptr_t a)
{
  assem_debug("bpl %x",a);
  u_int offset=gencondjmp(a);
  output_w32(0x54000000|offset<<5|PL);
}
static void emit_jl(intptr_t a)
{
  assem_debug("blt %x",a);
  u_int offset=gencondjmp(a);
  output_w32(0x54000000|offset<<5|LT);
}
static void emit_jge(intptr_t a)
{
  assem_debug("bge %x",a);
  u_int offset=gencondjmp(a);
  output_w32(0x54000000|offset<<5|GE);
}
static void emit_jno(intptr_t a)
{
  assem_debug("bvc %x",a);
  u_int offset=gencondjmp(a);
  output_w32(0x54000000|offset<<5|VC);
}

static void emit_jcc(intptr_t a)
{
  assem_debug("bcc %x",a);
  u_int offset=gencondjmp(a);
  output_w32(0x54000000|offset<<5|CC);
}
static void emit_jae(intptr_t a)
{
  assem_debug("bcs %x",a);
  u_int offset=gencondjmp(a);
  output_w32(0x54000000|offset<<5|CS);
}
static void emit_jb(intptr_t a)
{
  assem_debug("bcc %x",a);
  u_int offset=gencondjmp(a);
  output_w32(0x54000000|offset<<5|CC);
}

static void emit_pushreg(u_int r)
{
  assert(0);
  assem_debug("push %%%s",regname[r]);
}
static void emit_popreg(u_int r)
{
  assert(0);
  assem_debug("pop %%%s",regname[r]);
}
/*
static void emit_callreg(u_int r)
{
  assem_debug("call *%%%s",regname[r]);
  assert(0);
}*/
static void emit_jmpreg(u_int r)
{
  assem_debug("br %s",regname64[r]);
  output_w32(0xd61f0000|r<<5);
}
static void emit_readword_indexed(int offset, int rs, int rt)
{
  assert(rs!=29);
  assert(rt!=29);
  assert(offset>-256&&offset<256);
  assem_debug("ldur %s,%s+%d",regname[rt],regname64[rs],offset);
  output_w32(0xb8400000|((u_int)offset&0x1ff)<<12|rs<<5|rt);
}
static void emit_readword_dualindexedx4(int rs1, int rs2, int rt)
{
  assert(rs1!=29);
  assert(rs2!=29);
  assert(rt!=29);
  assem_debug("ldr %s, [%s,%s lsl #2]",regname[rt],regname64[rs1],regname64[rs2]);
  output_w32(0xb8607800|rs2<<16|rs1<<5|rt);
}
static void emit_readword_indexed_tlb(int addr, int rs, int map, int rt)
{
  assert(rs!=29);
  assert(map!=29);
  assert(rt!=29);
  if(map<0) emit_readword_indexed(addr, rs, rt);
  else {
    assert(addr==0);
    emit_readword_dualindexedx4(rs, map, rt);
  }
}
static void emit_readdword_indexed_tlb(int addr, int rs, int map, int rh, int rl)
{
  assert(rs!=29);
  assert(map!=29);
  assert(rh!=29);
  assert(rl!=29);
  if(map<0) {
    if(rh>=0) emit_readword_indexed(addr, rs, rh);
    emit_readword_indexed(addr+4, rs, rl);
  }else{
    assert(rh!=rs);
    if(rh>=0) emit_readword_indexed_tlb(addr, rs, map, rh);
    emit_addimm64(map,1,HOST_TEMPREG);
    emit_readword_indexed_tlb(addr, rs, HOST_TEMPREG, rl);
  }
}
static void emit_movsbl_indexed(int offset, int rs, int rt)
{
  assert(0);
  assert(rs!=29);
  assert(rt!=29);
  assert(offset>-256&&offset<256);
  assem_debug("ldrsb %s,%s+%d",regname[rt],regname[rs],offset);
  if(offset>=0) {
    output_w32(0xe1d000d0|rd_rn_rm(rt,rs,0)|((offset<<4)&0xf00)|(offset&0xf));
  }else{
    output_w32(0xe15000d0|rd_rn_rm(rt,rs,0)|(((-offset)<<4)&0xf00)|((-offset)&0xf));
  }
}
static void emit_movsbl_indexed_tlb(int addr, int rs, int map, int rt)
{
  assert(0);
  assert(rs!=29);
  assert(map!=29);
  assert(rt!=29);
  if(map<0) emit_movsbl_indexed(addr, rs, rt);
  else {
    if(addr==0) {
      emit_shlimm(map,2,HOST_TEMPREG);
      assem_debug("ldrsb %s,%s+%s",regname[rt],regname[rs],regname[HOST_TEMPREG]);
      output_w32(0xe19000d0|rd_rn_rm(rt,rs,HOST_TEMPREG));
    }else{
      assert(addr>-256&&addr<256);
      assem_debug("add %s,%s,%s,lsl #2",regname[rt],regname[rs],regname[map]);
      output_w32(0xe0800000|rd_rn_rm(rt,rs,map)|(2<<7));
      emit_movsbl_indexed(addr, rt, rt);
    }
  }
}
static void emit_movswl_indexed(int offset, int rs, int rt)
{
  assert(0);
  assert(rs!=29);
  assert(rt!=29);
  assert(offset>-256&&offset<256);
  assem_debug("ldrsh %s,%s+%d",regname[rt],regname[rs],offset);
  if(offset>=0) {
    output_w32(0xe1d000f0|rd_rn_rm(rt,rs,0)|((offset<<4)&0xf00)|(offset&0xf));
  }else{
    output_w32(0xe15000f0|rd_rn_rm(rt,rs,0)|(((-offset)<<4)&0xf00)|((-offset)&0xf));
  }
}
static void emit_movzbl_indexed(int offset, int rs, int rt)
{
  assert(0);
  assert(rs!=29);
  assert(rt!=29);
  assert(offset>-4096&&offset<4096);
  assem_debug("ldrb %s,%s+%d",regname[rt],regname[rs],offset);
  if(offset>=0) {
    output_w32(0xe5d00000|rd_rn_rm(rt,rs,0)|offset);
  }else{
    output_w32(0xe5500000|rd_rn_rm(rt,rs,0)|(-offset));
  }
}
static void emit_movzbl_dualindexedx4(int rs1, int rs2, int rt)
{
  assert(0);
  assert(rs1!=29);
  assert(rs2!=29);
  assert(rt!=29);
  assem_debug("ldrb %s,%s,%s lsl #2",regname[rt],regname[rs1],regname[rs2]);
  output_w32(0xe7d00000|rd_rn_rm(rt,rs1,rs2)|0x100);
}
static void emit_movzbl_indexed_tlb(int addr, int rs, int map, int rt)
{
  assert(rt!=29&&rt!=HOST_TEMPREG);
  assert(rs!=29&&rt!=HOST_TEMPREG);
  assert(map!=29&&rt!=HOST_TEMPREG);
  if(map<0) emit_movzbl_indexed(addr, rs, rt);
  else {
    if(addr==0) {
      emit_shlimm64(map,2,HOST_TEMPREG);
      assem_debug("ldrb %s,[%s,%s]",regname[rt],regname64[rs],regname64[HOST_TEMPREG]);
      output_w32(0x38606800|HOST_TEMPREG<<16|rs<<5|rt);
    }else{
      emit_addimm(rs,addr,rt);
      emit_shlimm64(map,2,HOST_TEMPREG);
      assem_debug("ldrb %s,[%s,%s]",regname[rt],regname64[rt],regname64[HOST_TEMPREG]);
      output_w32(0x38606800|HOST_TEMPREG<<16|rt<<5|rt);
    }
  }
}
static void emit_movzwl_indexed(int offset, int rs, int rt)
{
  assert(0);
  assert(rs!=29);
  assert(rt!=29);
  assert(offset>-256&&offset<256);
  assem_debug("ldrh %s,%s+%d",regname[rt],regname[rs],offset);
  if(offset>=0) {
    output_w32(0xe1d000b0|rd_rn_rm(rt,rs,0)|((offset<<4)&0xf00)|(offset&0xf));
  }else{
    output_w32(0xe15000b0|rd_rn_rm(rt,rs,0)|(((-offset)<<4)&0xf00)|((-offset)&0xf));
  }
}
static void emit_readword(intptr_t addr, int rt)
{
  assert(rt!=29);
  u_int offset = addr-(uintptr_t)&dynarec_local;
  assert(offset<4096);
  assert(offset%4 == 0); /* 4 bytes aligned */
  assem_debug("ldr %s,fp+%d",regname[rt],offset);
  output_w32(0xb9400000|((offset>>2)<<10)|(FP<<5)|rt);
}
static void emit_movsbl(int addr, int rt)
{
  assert(0);
  assert(rt!=29);
  u_int offset = addr-(u_int)&dynarec_local;
  assert(offset<256);
  assem_debug("ldrsb %s,fp+%d",regname[rt],offset);
  output_w32(0xe1d000d0|rd_rn_rm(rt,FP,0)|((offset<<4)&0xf00)|(offset&0xf));
}
static void emit_movswl(int addr, int rt)
{
  assert(0);
  assert(rt!=29);
  u_int offset = addr-(u_int)&dynarec_local;
  assert(offset<256);
  assem_debug("ldrsh %s,fp+%d",regname[rt],offset);
  output_w32(0xe1d000f0|rd_rn_rm(rt,FP,0)|((offset<<4)&0xf00)|(offset&0xf));
}
static void emit_movzbl(intptr_t addr, int rt)
{
  assert(rt!=29);
  u_int offset = addr-(uintptr_t)&dynarec_local;
  assert(offset<4096);
  assem_debug("ldrb %s,fp+%d",regname[rt],offset);
  output_w32(0x39400000|offset<<10|FP<<5|rt);
}
static void emit_movzwl(int addr, int rt)
{
  assert(0);
  assert(rt!=29);
  u_int offset = addr-(u_int)&dynarec_local;
  assert(offset<256);
  assem_debug("ldrh %s,fp+%d",regname[rt],offset);
  output_w32(0xe1d000b0|rd_rn_rm(rt,FP,0)|((offset<<4)&0xf00)|(offset&0xf));
}

/*
static void emit_movzwl_reg(int rs, int rt)
{
  assem_debug("movzwl %%%s,%%%s",regname[rs]+1,regname[rt]);
  assert(0);
}
*/

static void emit_writeword_indexed(int rt, int offset, int rs)
{
  assert(rs!=29);
  assert(rt!=29);
  assert(offset>-256&&offset<256);
  assem_debug("stur %s,%s+%d",regname[rt],regname64[rs],offset);
  output_w32(0xb8000000|(((u_int)offset)&0x1ff)<<12|rs<<5|rt);
}
static void emit_writeword_dualindexedx4(int rt, int rs1, int rs2)
{
  assert(rs1!=29);
  assert(rs2!=29);
  assert(rt!=29);
  assem_debug("str %s,[%s,%s lsl #2]",regname[rt],regname64[rs1],regname64[rs2]);
  output_w32(0xb8207800|rs2<<16|rs1<<5|rt);
}
static void emit_writeword_indexed_tlb(int rt, int addr, int rs, int map, int temp)
{
  assert(rs!=29);
  assert(map!=29);
  assert(rt!=29);
  if(map<0) emit_writeword_indexed(rt, addr, rs);
  else {
    assert(addr==0);
    emit_writeword_dualindexedx4(rt, rs, map);
  }
}
static void emit_writedword_indexed_tlb(int rh, int rl, int addr, int rs, int map, int temp)
{
  assert(0);
  assert(rh!=29);
  assert(rl!=29);
  assert(map!=29);
  assert(rs!=29);
  assert(temp!=29);
  if(map<0) {
    if(rh>=0) emit_writeword_indexed(rh, addr, rs);
    emit_writeword_indexed(rl, addr+4, rs);
  }else{
    assert(rh>=0);
    if(temp!=rs) emit_addimm(map,1,temp);
    emit_writeword_indexed_tlb(rh, addr, rs, map, temp);
    if(temp!=rs) emit_writeword_indexed_tlb(rl, addr, rs, temp, temp);
    else {
      emit_addimm(rs,4,rs);
      emit_writeword_indexed_tlb(rl, addr, rs, map, temp);
    }
  }
}
static void emit_writehword_indexed(int rt, int offset, int rs)
{
  assert(rs!=29);
  assert(rt!=29);
  assert(offset>-256&&offset<256);
  assem_debug("sturh %s,%s+%d",regname[rt],regname64[rs],offset);
  output_w32(0x78000000|(((u_int)offset)&0x1ff)<<12|rs<<5|rt);
}
static void emit_writebyte_indexed(int rt, int offset, int rs)
{
  assert(rs!=29);
  assert(rt!=29);
  assert(offset>-256&&offset<256);
  assem_debug("sturb %s,%s+%d",regname[rt],regname64[rs],offset);
  output_w32(0x38000000|(((u_int)offset)&0x1ff)<<12|rs<<5|rt);
}
static void emit_writebyte_dualindexedx4(int rt, int rs1, int rs2)
{
  assert(0);
  assert(rs1!=29);
  assert(rs2!=29);
  assert(rt!=29);
  assem_debug("strb %s,%s,%s lsl #2",regname[rt],regname[rs1],regname[rs2]);
  output_w32(0xe7c00000|rd_rn_rm(rt,rs1,rs2)|0x100);
}
static void emit_writebyte_indexed_tlb(int rt, int addr, int rs, int map, int temp)
{
  assert(rt!=29&&rt!=HOST_TEMPREG);
  assert(rs!=29&&rt!=HOST_TEMPREG);
  assert(map!=29&&rt!=HOST_TEMPREG);
  assert(temp!=29&&rt!=HOST_TEMPREG);
  if(map<0) emit_writebyte_indexed(rt, addr, rs);
  else {
    if(addr==0) {
      emit_shlimm64(map,2,HOST_TEMPREG);
      assem_debug("strb %s,[%s,%s]",regname[rt],regname64[rs],regname64[HOST_TEMPREG]);
      output_w32(0x38206800|HOST_TEMPREG<<16|rs<<5|rt);
    }else{
      emit_addimm(rs,addr,temp);
      emit_shlimm64(map,2,HOST_TEMPREG);
      assem_debug("strb %s,[%s,%s]",regname[rt],regname64[temp],regname64[HOST_TEMPREG]);
      output_w32(0x38206800|HOST_TEMPREG<<16|temp<<5|rt);
    }
  }
}
static void emit_writeword(int rt, intptr_t addr)
{
  assert(rt!=29);
  u_int offset = addr-(uintptr_t)&dynarec_local;
  assert(offset<4096);
  assert(offset%4 == 0); /* 4 bytes aligned */
  assem_debug("str %s,fp+%d",regname[rt],offset);
  output_w32(0xb9000000|((offset>>2)<<10)|(FP<<5)|rt);
}
static void emit_writeword64(int rt, intptr_t addr)
{
  assert(rt!=29);
  u_int offset = addr-(uintptr_t)&dynarec_local;
  assert(offset<4096);
  assert(offset%8 == 0); /* 8 bytes aligned */
  assem_debug("str %s,fp+%d",regname[rt],offset);
  output_w32(0xf9000000|((offset>>3)<<10)|(FP<<5)|rt);
}
static void emit_writehword(int rt, int addr)
{
  assert(0);
  assert(rt!=29);
  u_int offset = addr-(u_int)&dynarec_local;
  assert(offset<256);
  assem_debug("strh %s,fp+%d",regname[rt],offset);
  output_w32(0xe1c000b0|rd_rn_rm(rt,FP,0)|((offset<<4)&0xf00)|(offset&0xf));
}
static void emit_writebyte(int rt, intptr_t addr)
{
  assert(rt!=29);
  u_int offset = addr-(uintptr_t)&dynarec_local;
  assert(offset<4096);
  assem_debug("strb %s,fp+%d",regname[rt],offset);
  output_w32(0x39000000|offset<<10|(FP<<5)|rt);
}

static void emit_mul(u_int rs1,u_int rs2,u_int rt)
{
  assert(0);
  assert(rs1!=29);
  assert(rs2!=29);
  assert(rt!=29);
  assem_debug("mul %s,%s,%s",regname[rt],regname[rs1],regname[rs2]);
  output_w32(0xe0000090|(rt<<16)|(rs2<<8)|rs1);
}
static void emit_mul64(u_int rs1,u_int rs2,u_int rt)
{
  assert(rs1!=29);
  assert(rs2!=29);
  assert(rt!=29);
  assem_debug("mul %s,%s,%s",regname64[rt],regname64[rs1],regname64[rs2]);
  output_w32(0x9b000000|(rs2<<16)|(WZR<<10)|(rs1<<5)|rt);
}
static void emit_umull(u_int rs1, u_int rs2, u_int rt)
{
  assem_debug("umull %s, %s, %s",regname64[rt],regname[rs1],regname[rs2]);
  assert(rs1!=29);
  assert(rs2!=29);
  assert(rt!=29);
  output_w32(0x9ba00000|(rs2<<16)|(WZR<<10)|(rs1<<5)|rt);
}
static void emit_umulh(u_int rs1, u_int rs2, u_int rt)
{
  assem_debug("umulh %s, %s, %s",regname64[rt],regname64[rs1],regname64[rs2]);
  assert(rs1!=29);
  assert(rs2!=29);
  assert(rt!=29);
  output_w32(0x9bc00000|(rs2<<16)|(WZR<<10)|(rs1<<5)|rt);
}
static void emit_umlal(u_int rs1, u_int rs2, u_int high, u_int low)
{
  assert(0);
  assem_debug("umlal %s, %s, %s, %s",regname[low],regname[high],regname[rs1],regname[rs2]);
  assert(rs1!=29);
  assert(rs2!=29);
  assert(high!=29);
  assert(low!=29);
  output_w32(0xe0a00090|(high<<16)|(low<<12)|(rs2<<8)|rs1);
}
static void emit_smull(u_int rs1, u_int rs2, u_int high, u_int low)
{
  assert(0);
  assem_debug("smull %s, %s, %s, %s",regname[low],regname[high],regname[rs1],regname[rs2]);
  assert(rs1!=29);
  assert(rs2!=29);
  assert(high!=29);
  assert(low!=29);
  output_w32(0xe0c00090|(high<<16)|(low<<12)|(rs2<<8)|rs1);
}
static void emit_smlal(u_int rs1, u_int rs2, u_int high, u_int low)
{
  assert(0);
  assem_debug("smlal %s, %s, %s, %s",regname[low],regname[high],regname[rs1],regname[rs2]);
  assert(rs1!=29);
  assert(rs2!=29);
  assert(high!=29);
  assert(low!=29);
  output_w32(0xe0e00090|(high<<16)|(low<<12)|(rs2<<8)|rs1);
}

static void emit_sdiv(u_int rs1,u_int rs2,u_int rt)
{
  assert(0);
  assert(rs1!=29);
  assert(rs2!=29);
  assert(rt!=29);
  //assert(arm_cpu_features.IDIVa);
  assem_debug("sdiv %s,%s,%s",regname[rt],regname[rs1],regname[rs2]);
  output_w32(0xe710f010|(rt<<16)|(rs2<<8)|rs1);
}
static void emit_udiv(u_int rs1,u_int rs2,u_int rt)
{
  assert(0);
  assert(rs1!=29);
  assert(rs2!=29);
  assert(rt!=29);
  //assert(arm_cpu_features.IDIVa);
  assem_debug("udiv %s,%s,%s",regname[rt],regname[rs1],regname[rs2]);
  output_w32(0xe730f010|(rt<<16)|(rs2<<8)|rs1);
}

static void emit_clz(int rs,int rt)
{
  assert(0);
  assert(rs!=29);
  assert(rt!=29);
  assem_debug("clz %s,%s",regname[rt],regname[rs]);
  output_w32(0xe16f0f10|rd_rn_rm(rt,0,rs));
}

static void emit_subcs(int rs1,int rs2,int rt)
{
  assert(0);
  assert(rs1!=29);
  assert(rs2!=29);
  assert(rt!=29);
  assem_debug("subcs %s,%s,%s",regname[rt],regname[rs1],regname[rs2]);
  output_w32(0x20400000|rd_rn_rm(rt,rs1,rs2));
}

static void emit_shrcc_imm(int rs,u_int imm,int rt)
{
  assert(0);
  assert(rs!=29);
  assert(rt!=29);
  assert(imm>0);
  assert(imm<32);
  assem_debug("lsrcc %s,%s,#%d",regname[rt],regname[rs],imm);
  output_w32(0x31a00000|rd_rn_rm(rt,0,rs)|0x20|(imm<<7));
}

static void emit_negmi(int rs, int rt)
{
  assert(0);
  assert(rs!=29);
  assert(rt!=29);
  assem_debug("rsbmi %s,%s,#0",regname[rt],regname[rs]);
  output_w32(0x42600000|rd_rn_rm(rt,rs,0));
}

static void emit_orreq(u_int rs1,u_int rs2,u_int rt)
{
  assert(0);
  assert(rs1!=29);
  assert(rs2!=29);
  assert(rt!=29);
  assem_debug("orreq %s,%s,%s",regname[rt],regname[rs1],regname[rs2]);
  output_w32(0x01800000|rd_rn_rm(rt,rs1,rs2));
}

static void emit_orrne(u_int rs1,u_int rs2,u_int rt)
{
  assert(0);
  assert(rs1!=29);
  assert(rs2!=29);
  assert(rt!=29);
  assem_debug("orrne %s,%s,%s",regname[rt],regname[rs1],regname[rs2]);
  output_w32(0x11800000|rd_rn_rm(rt,rs1,rs2));
}

static void emit_bic_lsl(u_int rs1,u_int rs2,u_int shift,u_int rt)
{
  assert(0);
  assert(rs1!=29);
  assert(rs2!=29);
  assert(rt!=29);
  assem_debug("bic %s,%s,%s lsl %s",regname[rt],regname[rs1],regname[rs2],regname[shift]);
  output_w32(0xe1C00000|rd_rn_rm(rt,rs1,rs2)|0x10|(shift<<8));
}

static void emit_biceq_lsl(u_int rs1,u_int rs2,u_int shift,u_int rt)
{
  assert(0);
  assert(rs1!=29);
  assert(rs2!=29);
  assert(rt!=29);
  assem_debug("biceq %s,%s,%s lsl %s",regname[rt],regname[rs1],regname[rs2],regname[shift]);
  output_w32(0x01C00000|rd_rn_rm(rt,rs1,rs2)|0x10|(shift<<8));
}

static void emit_bicne_lsl(u_int rs1,u_int rs2,u_int shift,u_int rt)
{
  assert(0);
  assert(rs1!=29);
  assert(rs2!=29);
  assert(rt!=29);
  assem_debug("bicne %s,%s,%s lsl %s",regname[rt],regname[rs1],regname[rs2],regname[shift]);
  output_w32(0x11C00000|rd_rn_rm(rt,rs1,rs2)|0x10|(shift<<8));
}

static void emit_bic_lsr(u_int rs1,u_int rs2,u_int shift,u_int rt)
{
  assert(0);
  assert(rs1!=29);
  assert(rs2!=29);
  assert(rt!=29);
  assem_debug("bic %s,%s,%s lsr %s",regname[rt],regname[rs1],regname[rs2],regname[shift]);
  output_w32(0xe1C00000|rd_rn_rm(rt,rs1,rs2)|0x30|(shift<<8));
}

static void emit_biceq_lsr(u_int rs1,u_int rs2,u_int shift,u_int rt)
{
  assert(0);
  assert(rs1!=29);
  assert(rs2!=29);
  assert(rt!=29);
  assem_debug("biceq %s,%s,%s lsr %s",regname[rt],regname[rs1],regname[rs2],regname[shift]);
  output_w32(0x01C00000|rd_rn_rm(rt,rs1,rs2)|0x30|(shift<<8));
}

static void emit_bicne_lsr(u_int rs1,u_int rs2,u_int shift,u_int rt)
{
  assert(0);
  assert(rs1!=29);
  assert(rs2!=29);
  assert(rt!=29);
  assem_debug("bicne %s,%s,%s lsr %s",regname[rt],regname[rs1],regname[rs2],regname[shift]);
  output_w32(0x11C00000|rd_rn_rm(rt,rs1,rs2)|0x30|(shift<<8));
}

static void emit_bic(u_int rs1,u_int rs2,u_int rt)
{
  assert(rs1!=29);
  assert(rs2!=29);
  assert(rt!=29);
  assem_debug("bic %s,%s,%s",regname[rt],regname[rs1],regname[rs2]);
  output_w32(0x0a200000|rs2<<16|rs1<<5|rt);
}

static void emit_teq(int rs, int rt)
{
  assert(0);
  assert(rs!=29);
  assert(rt!=29);
  assem_debug("teq %s,%s",regname[rs],regname[rt]);
  output_w32(0xe1300000|rd_rn_rm(0,rs,rt));
}

static void emit_rsbimm(int rs, int imm, int rt)
{
  assert(0);
  assert(rs!=29);
  assert(rt!=29);
  u_int armval, ret;
  ret = genimm_(imm,&armval);
  assert(ret);
  assem_debug("rsb %s,%s,#%d",regname[rt],regname[rs],imm);
  output_w32(0xe2600000|rd_rn_rm(rt,rs,0)|armval);
}

// Load 2 immediates optimizing for small code size
static void emit_mov2imm_compact(int imm1,u_int rt1,int imm2,u_int rt2)
{
  assert(rt1!=29);
  assert(rt2!=29);
  emit_movimm(imm1,rt1);
  int imm=imm2-imm1;
  if(imm<0&&imm>-4096) {
    assem_debug("sub %s, %s, #%d",regname[rt2],regname[rt1],-imm&0xfff);
    output_w32(0x51000000|((-imm)&0xfff)<<10|rt1<<5|rt2);
  }else if(imm>=0&&imm<4096) {
    assem_debug("add %s, %s, #%d",regname[rt2],regname[rt1],imm&0xfff);
    output_w32(0x11000000|(imm&0xfff)<<10|rt1<<5|rt2);
  }else if(imm<0&&(-imm&0xfff)==0) {
    assem_debug("sub %s, %s, #%d lsl #%d",regname[rt2],regname[rt1],((-imm)>>12)&0xfff,12);
    output_w32(0x51400000|(((-imm)>>12)&0xfff)<<10|rt1<<5|rt2);
  }else if(imm>=0&&(imm&0xfff)==0) {
    assem_debug("add %s, %s, #%d lsl #%d",regname[rt2],regname[rt1],(imm>>12)&0xfff,12);
    output_w32(0x11400000|((imm>>12)&0xfff)<<10|rt1<<5|rt2);
  }
  else emit_movimm(imm2,rt2);
}

// Conditionally select one of two immediates, optimizing for small code size
// This will only be called if HAVE_CMOV_IMM is defined
static void emit_cmov2imm_e_ne_compact(int imm1,int imm2,u_int rt)
{
  assert(0);
  assert(rt!=29);
  u_int armval;
  if(genimm_(imm2-imm1,&armval)) {
    emit_movimm(imm1,rt);
    assem_debug("addne %s,%s,#%d",regname[rt],regname[rt],imm2-imm1);
    output_w32(0x12800000|rd_rn_rm(rt,rt,0)|armval);
  }else if(genimm_(imm1-imm2,&armval)) {
    emit_movimm(imm1,rt);
    assem_debug("subne %s,%s,#%d",regname[rt],regname[rt],imm1-imm2);
    output_w32(0x12400000|rd_rn_rm(rt,rt,0)|armval);
  }
  else {
    #ifdef ARMv5_ONLY
    emit_movimm(imm1,rt);
    add_literal((int)out,imm2);
    assem_debug("ldrne %s,pc+? [=%x]",regname[rt],imm2);
    output_w32(0x15900000|rd_rn_rm(rt,15,0));
    #else
    emit_movw(imm1&0x0000FFFF,rt);
    if((imm1&0xFFFF)!=(imm2&0xFFFF)) {
      assem_debug("movwne %s,#%d (0x%x)",regname[rt],imm2&0xFFFF,imm2&0xFFFF);
      output_w32(0x13000000|rd_rn_rm(rt,0,0)|(imm2&0xfff)|((imm2<<4)&0xf0000));
    }
    emit_movt(imm1&0xFFFF0000,rt);
    if((imm1&0xFFFF0000)!=(imm2&0xFFFF0000)) {
      assem_debug("movtne %s,#%d (0x%x)",regname[rt],imm2&0xffff0000,imm2&0xffff0000);
      output_w32(0x13400000|rd_rn_rm(rt,0,0)|((imm2>>16)&0xfff)|((imm2>>12)&0xf0000));
    }
    #endif
  }
}

#if !defined(HOST_IMM8)
// special case for checking invalid_code
static void emit_cmpmem_indexedsr12_imm(int addr,int r,int imm)
{
  assert(0);
}
#endif

// special case for checking invalid_code
static void emit_cmpmem_indexedsr12_reg(int base,int r,int imm)
{
  assert(imm<128&&imm>=0);
  assert(r>=0&&r<29);
  emit_shrimm(r,12,HOST_TEMPREG);
  assem_debug("ldrb %s,[%s,%s]",regname[HOST_TEMPREG],regname64[base],regname64[HOST_TEMPREG]);
  output_w32(0x38606800|HOST_TEMPREG<<16|base<<5|HOST_TEMPREG);
  emit_cmpimm(HOST_TEMPREG,imm);
}

// special case for tlb mapping
static void emit_addsr12(int rs1,int rs2,int rt)
{
  assert(0);
  assert(rs1!=29);
  assert(rs2!=29);
  assert(rt!=29);
  assem_debug("add %s,%s,%s lsr #12",regname[rt],regname[rs1],regname[rs2]);
  output_w32(0xe0800620|rd_rn_rm(rt,rs1,rs2));
}

static void emit_callne(intptr_t a)
{
  assert(0);
}

#ifdef IMM_PREFETCH
// Used to preload hash table entries
static void emit_prefetch(void *addr)
{
  assem_debug("prefetch %x",(int)addr);
  output_byte(0x0F);
  output_byte(0x18);
  output_modrm(0,5,1);
  output_w32((int)addr);
}
#endif

#ifdef REG_PREFETCH
static void emit_prefetchreg(int r)
{
  assem_debug("pld %s",regname[r]);
  output_w32(0xf5d0f000|rd_rn_rm(0,r,0));
}
#endif

// Special case for mini_ht
static void emit_ldreq_indexed(int rs, u_int offset, int rt)
{
  assert(0);
  assert(rs!=29);
  assert(rt!=29);
  assert(offset<4096);
  assem_debug("ldreq %s,[%s, #%d]",regname[rt],regname[rs],offset);
  output_w32(0x05900000|rd_rn_rm(rt,rs,0)|offset);
}

static void emit_flds(int r,int sr)
{
  assert(0);
  assert(r!=29);
  assem_debug("flds s%d,[%s]",sr,regname[r]);
  output_w32(0xed900a00|((sr&14)<<11)|((sr&1)<<22)|(r<<16));
} 

static void emit_vldr(int r,int vr)
{
  assert(0);
  assert(r!=29);
  assem_debug("vldr d%d,[%s]",vr,regname[r]);
  output_w32(0xed900b00|(vr<<12)|(r<<16));
} 

static void emit_fsts(int sr,int r)
{
  assert(0);
  assert(r!=29);
  assem_debug("fsts s%d,[%s]",sr,regname[r]);
  output_w32(0xed800a00|((sr&14)<<11)|((sr&1)<<22)|(r<<16));
} 

static void emit_vstr(int vr,int r)
{
  assert(0);
  assert(r!=29);
  assem_debug("vstr d%d,[%s]",vr,regname[r]);
  output_w32(0xed800b00|(vr<<12)|(r<<16));
} 

static void emit_ftosizs(int s,int d)
{
  assert(0);
  assem_debug("ftosizs s%d,s%d",d,s);
  output_w32(0xeebd0ac0|((d&14)<<11)|((d&1)<<22)|((s&14)>>1)|((s&1)<<5));
} 

static void emit_ftosizd(int s,int d)
{
  assert(0);
  assem_debug("ftosizd s%d,d%d",d,s);
  output_w32(0xeebd0bc0|((d&14)<<11)|((d&1)<<22)|(s&7));
} 

static void emit_fsitos(int s,int d)
{
  assert(0);
  assem_debug("fsitos s%d,s%d",d,s);
  output_w32(0xeeb80ac0|((d&14)<<11)|((d&1)<<22)|((s&14)>>1)|((s&1)<<5));
} 

static void emit_fsitod(int s,int d)
{
  assert(0);
  assem_debug("fsitod d%d,s%d",d,s);
  output_w32(0xeeb80bc0|((d&7)<<12)|((s&14)>>1)|((s&1)<<5));
} 

static void emit_fcvtds(int s,int d)
{
  assert(0);
  assem_debug("fcvtds d%d,s%d",d,s);
  output_w32(0xeeb70ac0|((d&7)<<12)|((s&14)>>1)|((s&1)<<5));
} 

static void emit_fcvtsd(int s,int d)
{
  assert(0);
  assem_debug("fcvtsd s%d,d%d",d,s);
  output_w32(0xeeb70bc0|((d&14)<<11)|((d&1)<<22)|(s&7));
} 

static void emit_fsqrts(int s,int d)
{
  assert(0);
  assem_debug("fsqrts d%d,s%d",d,s);
  output_w32(0xeeb10ac0|((d&14)<<11)|((d&1)<<22)|((s&14)>>1)|((s&1)<<5));
} 

static void emit_fsqrtd(int s,int d)
{
  assert(0);
  assem_debug("fsqrtd s%d,d%d",d,s);
  output_w32(0xeeb10bc0|((d&7)<<12)|(s&7));
} 

static void emit_fabss(int s,int d)
{
  assert(0);
  assem_debug("fabss d%d,s%d",d,s);
  output_w32(0xeeb00ac0|((d&14)<<11)|((d&1)<<22)|((s&14)>>1)|((s&1)<<5));
} 

static void emit_fabsd(int s,int d)
{
  assert(0);
  assem_debug("fabsd s%d,d%d",d,s);
  output_w32(0xeeb00bc0|((d&7)<<12)|(s&7));
} 

static void emit_fnegs(int s,int d)
{
  assert(0);
  assem_debug("fnegs d%d,s%d",d,s);
  output_w32(0xeeb10a40|((d&14)<<11)|((d&1)<<22)|((s&14)>>1)|((s&1)<<5));
} 

static void emit_fnegd(int s,int d)
{
  assert(0);
  assem_debug("fnegd s%d,d%d",d,s);
  output_w32(0xeeb10b40|((d&7)<<12)|(s&7));
} 

static void emit_fadds(int s1,int s2,int d)
{
  assert(0);
  assem_debug("fadds s%d,s%d,s%d",d,s1,s2);
  output_w32(0xee300a00|((d&14)<<11)|((d&1)<<22)|((s1&14)<<15)|((s1&1)<<7)|((s2&14)>>1)|((s2&1)<<5));
} 

static void emit_faddd(int s1,int s2,int d)
{
  assert(0);
  assem_debug("faddd d%d,d%d,d%d",d,s1,s2);
  output_w32(0xee300b00|((d&7)<<12)|((s1&7)<<16)|(s2&7));
} 

static void emit_fsubs(int s1,int s2,int d)
{
  assert(0);
  assem_debug("fsubs s%d,s%d,s%d",d,s1,s2);
  output_w32(0xee300a40|((d&14)<<11)|((d&1)<<22)|((s1&14)<<15)|((s1&1)<<7)|((s2&14)>>1)|((s2&1)<<5));
} 

static void emit_fsubd(int s1,int s2,int d)
{
  assert(0);
  assem_debug("fsubd d%d,d%d,d%d",d,s1,s2);
  output_w32(0xee300b40|((d&7)<<12)|((s1&7)<<16)|(s2&7));
} 

static void emit_fmuls(int s1,int s2,int d)
{
  assert(0);
  assem_debug("fmuls s%d,s%d,s%d",d,s1,s2);
  output_w32(0xee200a00|((d&14)<<11)|((d&1)<<22)|((s1&14)<<15)|((s1&1)<<7)|((s2&14)>>1)|((s2&1)<<5));
} 

static void emit_fmuld(int s1,int s2,int d)
{
  assert(0);
  assem_debug("fmuld d%d,d%d,d%d",d,s1,s2);
  output_w32(0xee200b00|((d&7)<<12)|((s1&7)<<16)|(s2&7));
} 

static void emit_fdivs(int s1,int s2,int d)
{
  assert(0);
  assem_debug("fdivs s%d,s%d,s%d",d,s1,s2);
  output_w32(0xee800a00|((d&14)<<11)|((d&1)<<22)|((s1&14)<<15)|((s1&1)<<7)|((s2&14)>>1)|((s2&1)<<5));
} 

static void emit_fdivd(int s1,int s2,int d)
{
  assert(0);
  assem_debug("fdivd d%d,d%d,d%d",d,s1,s2);
  output_w32(0xee800b00|((d&7)<<12)|((s1&7)<<16)|(s2&7));
} 

static void emit_fcmps(int x,int y)
{
  assert(0);
  assem_debug("fcmps s14, s15");
  output_w32(0xeeb47a67);
} 

static void emit_fcmpd(int x,int y)
{
  assert(0);
  assem_debug("fcmpd d6, d7");
  output_w32(0xeeb46b47);
} 

static void emit_fmstat(void)
{
  assert(0);
  assem_debug("fmstat");
  output_w32(0xeef1fa10);
} 

static void emit_bicne_imm(int rs,int imm,int rt)
{
  assert(0);
  assert(rs!=29);
  assert(rt!=29);
  u_int armval, ret;
  ret = genimm_(imm,&armval);
  assert(ret);
  assem_debug("bicne %s,%s,#%d",regname[rt],regname[rs],imm);
  output_w32(0x13c00000|rd_rn_rm(rt,rs,0)|armval);
}

static void emit_biccs_imm(int rs,int imm,int rt)
{
  assert(0);
  assert(rs!=29);
  assert(rt!=29);
  u_int armval, ret;
  ret = genimm_(imm,&armval);
  assert(ret);
  assem_debug("biccs %s,%s,#%d",regname[rt],regname[rs],imm);
  output_w32(0x23c00000|rd_rn_rm(rt,rs,0)|armval);
}

static void emit_bicvc_imm(int rs,int imm,int rt)
{
  assert(0);
  assert(rs!=29);
  assert(rt!=29);
  u_int armval, ret;
  ret = genimm_(imm,&armval);
  assert(ret);
  assem_debug("bicvc %s,%s,#%d",regname[rt],regname[rs],imm);
  output_w32(0x73c00000|rd_rn_rm(rt,rs,0)|armval);
}

static void emit_bichi_imm(int rs,int imm,int rt)
{
  assert(0);
  assert(rs!=29);
  assert(rt!=29);
  u_int armval, ret;
  ret = genimm_(imm,&armval);
  assert(ret);
  assem_debug("bichi %s,%s,#%d",regname[rt],regname[rs],imm);
  output_w32(0x83c00000|rd_rn_rm(rt,rs,0)|armval);
}

static void emit_orrvs_imm(int rs,int imm,int rt)
{
  assert(0);
  assert(rs!=29);
  assert(rt!=29);
  u_int armval, ret;
  ret = genimm_(imm,&armval);
  assert(ret);
  assem_debug("orrvs %s,%s,#%d",regname[rt],regname[rs],imm);
  output_w32(0x63800000|rd_rn_rm(rt,rs,0)|armval);
}

static void emit_jno_unlikely(int a)
{
  //TOBEDONE
  emit_jno(a);
  //assem_debug("addvc pc,pc,#? (%x)",/*a-(int)out-8,*/a);
  //output_w32(0x72800000|rd_rn_rm(15,15,0));
}

static void emit_breakpoint(u_int imm)
{
  assem_debug("brk #%d",imm);
  output_w32(0xd4200000|imm<<5);
}

static void emit_adr(intptr_t addr, int rt)
{
  int offset=addr-(intptr_t)out;
  assert(offset>=-1048576&&offset<1048576);
  assem_debug("adr %d,#%d",regname64[rt],offset);
  output_w32(0x10000000|((u_int)offset&0x3)<<29|(((u_int)offset>>2)&0x7ffff)<<5|rt);
}

static void emit_read_ptr(intptr_t addr, int rt)
{
  int offset=addr-(intptr_t)out;
  if(offset>=-1048576&&offset<1048576){
    assem_debug("adr %d,#%d",regname64[rt],offset);
    output_w32(0x10000000|((u_int)offset&0x3)<<29|(((u_int)offset>>2)&0x7ffff)<<5|rt);
  }
  else{
    offset=((addr&(intptr_t)~0xfff)-((intptr_t)out&(intptr_t)~0xfff))>>12;
    assert((((intptr_t)out&(intptr_t)~0xfff)+(offset<<12))==(addr&(intptr_t)~0xfff));
    assem_debug("adrp %d,#%d",regname64[rt],offset);
    output_w32(0x90000000|((u_int)offset&0x3)<<29|(((u_int)offset>>2)&0x7ffff)<<5|rt);
    if((addr&(intptr_t)0xfff)!=0)
      assem_debug("add %s, %s, #%d",regname64[rt],regname64[rt],addr&0xfff);
      output_w32(0x91000000|(addr&0xfff)<<10|rt<<5|rt);
  }
}

// Save registers before function call
static void save_regs(u_int reglist)
{
  signed char rt[2];
  int index=0;
  int offset=0;

  reglist&=0x7ffff; // only save the caller-save registers, x0-x18
  if(!reglist) return;

  int i;
  for(i=0; reglist!=0; i++){
    if(reglist&1){
      rt[index]=i;
      index++;
    }
    if(index>1){
      assert(offset>=0&&offset<=136);
      assem_debug("stp %s,%s,[fp+#%d]",regname64[rt[0]],regname64[rt[1]],offset);
      output_w32(0xa9000000|(offset>>3)<<15|rt[1]<<10|FP<<5|rt[0]);
      offset+=16;
      index=0;
    }
    reglist>>=1;
  }

  if(index!=0) {
    assert(index==1);
    assert(offset>=0&&offset<=144);
    assem_debug("str %s,[fp+#%d]",regname64[rt[0]],offset);
    output_w32(0xf9000000|(offset>>3)<<10|FP<<5|rt[0]);
  }
}
// Restore registers after function call
static void restore_regs(u_int reglist)
{
  signed char rt[2];
  int index=0;
  int offset=0;

  reglist&=0x7ffff; // only restore the caller-save registers, x0-x18
  if(!reglist) return;

  int i;
  for(i=0; reglist!=0; i++){
    if(reglist&1){
      rt[index]=i;
      index++;
    }
    if(index>1){
      assert(offset>=0&&offset<=136);
      assem_debug("ldp %s,%s,[fp+#%d]",regname[rt[0]],regname[rt[1]],offset);
      output_w32(0xa9400000|(offset>>3)<<15|rt[1]<<10|FP<<5|rt[0]);
      offset+=16;
      index=0;
    }
    reglist>>=1;
  }

  if(index!=0) {
    assert(index==1);
    assert(offset>=0&&offset<=144);
    assem_debug("ldr %s,[fp+#%d]",regname[rt[0]],offset);
    output_w32(0xf9400000|(offset>>3)<<10|FP<<5|rt[0]);
  }
}

// Write back consts using LR so we don't disturb the other registers
static void wb_consts(signed char i_regmap[],uint64_t i_is32,u_int i_dirty,int i)
{
  int hr;
  for(hr=0;hr<HOST_REGS;hr++) {
    if(hr!=EXCLUDE_REG&&i_regmap[hr]>=0&&((i_dirty>>hr)&1)) {
      if(((regs[i].isconst>>hr)&1)&&i_regmap[hr]>0) {
        if(i_regmap[hr]<64 || !((i_is32>>(i_regmap[hr]&63))&1) ) {
          int value=constmap[i][hr];
          if(value==0) {
            emit_zeroreg(HOST_TEMPREG);
          }
          else {
            emit_movimm(value,HOST_TEMPREG);
          }
          emit_storereg(i_regmap[hr],HOST_TEMPREG);
          if((i_is32>>i_regmap[hr])&1) {
            if(value!=-1&&value!=0) emit_sarimm(HOST_TEMPREG,31,HOST_TEMPREG);
            emit_storereg(i_regmap[hr]|64,HOST_TEMPREG);
          }
        }
      }
    }
  }
}

/* Stubs/epilogue */

static void literal_pool(int n)
{
  if(!literalcount) return;
  assert(0);
  if(n) {
    if((int)out-literals[0][0]<4096-n) return;
  }
  u_int *ptr;
  int i;
  for(i=0;i<literalcount;i++)
  {
    ptr=(u_int *)literals[i][0];
    u_int offset=(u_int)out-(u_int)ptr-8;
    assert(offset<4096);
    assert(!(offset&3));
    *ptr|=offset;
    output_w32(literals[i][1]);
  }
  literalcount=0;
}

static void literal_pool_jumpover(int n)
{
  if(!literalcount) return;
  assert(0);
  if(n) {
    if((int)out-literals[0][0]<4096-n) return;
  }
  int jaddr=(int)out;
  emit_jmp(0);
  literal_pool(0);
  set_jump_target(jaddr,(int)out);
}

static void emit_extjump2(intptr_t addr, int target, intptr_t linker)
{
  u_char *ptr=(u_char *)addr;
  assert(((ptr[3]&0xfc)==0x14)||((ptr[3]&0xff)==0x54)); //b or b.cond

  emit_movz_lsl16(((u_int)target>>16)&0xffff,1);
  emit_movk((u_int)target&0xffff,1);

  //addr is in the current recompiled block (max 256k)
  //offset shouldn't exceed +/-1MB 
  emit_adr(addr,0);

#ifdef DEBUG_CYCLE_COUNT
  emit_readword((intptr_t)&last_count,ECX);
  emit_add(HOST_CCREG,ECX,HOST_CCREG);
  emit_readword((intptr_t)&next_interupt,ECX);
  emit_writeword(HOST_CCREG,(intptr_t)&g_cp0_regs[CP0_COUNT_REG]);
  emit_sub(HOST_CCREG,ECX,HOST_CCREG);
  emit_writeword(ECX,(intptr_t)&last_count);
#endif
  emit_call(linker);
  emit_jmpreg(0);
}

static void emit_extjump(intptr_t addr, int target)
{
  emit_extjump2(addr, target, (intptr_t)dynamic_linker);
}
static void emit_extjump_ds(intptr_t addr, int target)
{
  emit_extjump2(addr, target, (intptr_t)dynamic_linker_ds);
}

static void do_readstub(int n)
{
  assem_debug("do_readstub %x",start+stubs[n][3]*4);
  literal_pool(256);
  set_jump_target(stubs[n][1],(intptr_t)out);
  int type=stubs[n][0];
  int i=stubs[n][3];
  int rs=stubs[n][4];
  struct regstat *i_regs=(struct regstat *)stubs[n][5];
  u_int reglist=stubs[n][7];
  signed char *i_regmap=i_regs->regmap;
  int addr=get_reg(i_regmap,AGEN1+(i&1));
  int rth,rt;
  int ds;
  if(itype[i]==C1LS||itype[i]==LOADLR) {
    rth=get_reg(i_regmap,FTEMP|64);
    rt=get_reg(i_regmap,FTEMP);
  }else{
    rth=get_reg(i_regmap,rt1[i]|64);
    rt=get_reg(i_regmap,rt1[i]);
  }
  assert(rs>=0);
  if(addr<0) addr=rt;
  if(addr<0&&itype[i]!=C1LS&&itype[i]!=LOADLR) addr=get_reg(i_regmap,-1);
  assert(addr>=0);
  intptr_t ftable=0;
  if(type==LOADB_STUB||type==LOADBU_STUB)
    ftable=(intptr_t)readmemb;
  if(type==LOADH_STUB||type==LOADHU_STUB)
    ftable=(intptr_t)readmemh;
  if(type==LOADW_STUB)
    ftable=(intptr_t)readmem;
  if(type==LOADD_STUB)
    ftable=(intptr_t)readmemd;
  emit_writeword(rs,(intptr_t)&address);
  //emit_pusha();
  save_regs(reglist);
  ds=i_regs!=&regs[i];
  int real_rs=(itype[i]==LOADLR)?-1:get_reg(i_regmap,rs1[i]);
  u_int cmask=ds?-1:(0x7ffff|~i_regs->wasconst);
  if(!ds) load_all_consts(regs[i].regmap_entry,regs[i].was32,regs[i].wasdirty&~(1<<addr)&(real_rs<0?-1:~(1<<real_rs))&0x7ffff,i);
  wb_dirtys(i_regs->regmap_entry,i_regs->was32,i_regs->wasdirty&cmask&~(1<<addr)&(real_rs<0?-1:~(1<<real_rs)));
  if(!ds) wb_consts(regs[i].regmap_entry,regs[i].was32,regs[i].wasdirty&~(1<<addr)&(real_rs<0?-1:~(1<<real_rs))&~0x7ffff,i);
  emit_shrimm(rs,16,1);
  int cc=get_reg(i_regmap,CCREG);
  if(cc<0) {
    emit_loadreg(CCREG,2);
  }
  emit_read_ptr(ftable,0);
  emit_addimm(cc<0?2:cc,2*stubs[n][6]+2,2);
  emit_movimm(start+stubs[n][3]*4+(((regs[i].was32>>rs1[i])&1)<<1)+ds,3);
  //emit_readword((int)&last_count,temp);
  //emit_add(cc,temp,cc);
  //emit_writeword(cc,(int)&g_cp0_regs[CP0_COUNT_REG]);
  //emit_mov(15,14);
  emit_call((intptr_t)&indirect_jump_indexed);
  //emit_callreg(rs);
  //emit_readword_dualindexedx4(rs,HOST_TEMPREG,15);
  // We really shouldn't need to update the count here,
  // but not doing so causes random crashes...
  emit_readword((intptr_t)&g_cp0_regs[CP0_COUNT_REG],HOST_TEMPREG);
  emit_readword((intptr_t)&next_interupt,2);
  emit_addimm(HOST_TEMPREG,-2*stubs[n][6]-2,HOST_TEMPREG);
  emit_writeword(2,(intptr_t)&last_count);
  emit_sub(HOST_TEMPREG,2,cc<0?HOST_TEMPREG:cc);
  if(cc<0) {
    emit_storereg(CCREG,HOST_TEMPREG);
  }
  //emit_popa();
  restore_regs(reglist);
  //if((cc=get_reg(regmap,CCREG))>=0) {
  //  emit_loadreg(CCREG,cc);
  //}
  if(rt>=0) {
    if(type==LOADB_STUB)
      emit_movsbl((intptr_t)&readmem_dword,rt);
    if(type==LOADBU_STUB)
      emit_movzbl((intptr_t)&readmem_dword,rt);
    if(type==LOADH_STUB)
      emit_movswl((intptr_t)&readmem_dword,rt);
    if(type==LOADHU_STUB)
      emit_movzwl((intptr_t)&readmem_dword,rt);
    if(type==LOADW_STUB)
      emit_readword((intptr_t)&readmem_dword,rt);
    if(type==LOADD_STUB) {
      emit_readword((intptr_t)&readmem_dword,rt);
      if(rth>=0) emit_readword(((intptr_t)&readmem_dword)+4,rth);
    }
  }
  emit_jmp(stubs[n][2]); // return address
}

static void inline_readstub(int type, int i, u_int addr, signed char regmap[], int target, int adj, u_int reglist)
{
  int rs=get_reg(regmap,target);
  int rth=get_reg(regmap,target|64);
  int rt=get_reg(regmap,target);
  if(rs<0) rs=get_reg(regmap,-1);
  assert(rs>=0);
  intptr_t ftable=0;
  if(type==LOADB_STUB||type==LOADBU_STUB)
    ftable=(intptr_t)readmemb;
  if(type==LOADH_STUB||type==LOADHU_STUB)
    ftable=(intptr_t)readmemh;
  if(type==LOADW_STUB)
    ftable=(intptr_t)readmem;
  if(type==LOADD_STUB)
    ftable=(intptr_t)readmemd;
  emit_writeword(rs,(intptr_t)&address);
  //emit_pusha();
  save_regs(reglist);
  if((signed int)addr>=(signed int)0xC0000000) {
    // Theoretically we can have a pagefault here, if the TLB has never
    // been enabled and the address is outside the range 80000000..BFFFFFFF
    // Write out the registers so the pagefault can be handled.  This is
    // a very rare case and likely represents a bug.
    int ds=regmap!=regs[i].regmap;
    if(!ds) load_all_consts(regs[i].regmap_entry,regs[i].was32,regs[i].wasdirty,i);
    if(!ds) wb_dirtys(regs[i].regmap_entry,regs[i].was32,regs[i].wasdirty);
    else wb_dirtys(branch_regs[i-1].regmap_entry,branch_regs[i-1].was32,branch_regs[i-1].wasdirty);
  }
  //emit_shrimm(rs,16,1);
  int cc=get_reg(regmap,CCREG);
  if(cc<0) {
    emit_loadreg(CCREG,2);
  }
  //emit_movimm(ftable,0);
  emit_read_ptr(((uintptr_t *)ftable)[addr>>16],0);
  //emit_readword((int)&last_count,12);
  emit_addimm(cc<0?2:cc,CLOCK_DIVIDER*(adj+1),2);
  if((signed int)addr>=(signed int)0xC0000000) {
    // Pagefault address
    int ds=regmap!=regs[i].regmap;
    emit_movimm(start+i*4+(((regs[i].was32>>rs1[i])&1)<<1)+ds,3);
  }
  //emit_add(12,2,2);
  //emit_writeword(2,(int)&g_cp0_regs[CP0_COUNT_REG]);
  //emit_call(((u_int *)ftable)[addr>>16]);
  emit_call((intptr_t)&indirect_jump);
  // We really shouldn't need to update the count here,
  // but not doing so causes random crashes...
  emit_readword((intptr_t)&g_cp0_regs[CP0_COUNT_REG],HOST_TEMPREG);
  emit_readword((intptr_t)&next_interupt,2);
  emit_addimm(HOST_TEMPREG,-(int)CLOCK_DIVIDER*(adj+1),HOST_TEMPREG);
  emit_writeword(2,(intptr_t)&last_count);
  emit_sub(HOST_TEMPREG,2,cc<0?HOST_TEMPREG:cc);
  if(cc<0) {
    emit_storereg(CCREG,HOST_TEMPREG);
  }
  //emit_popa();
  restore_regs(reglist);
  if(rt>=0) {
    if(type==LOADB_STUB)
      emit_movsbl((intptr_t)&readmem_dword,rt);
    if(type==LOADBU_STUB)
      emit_movzbl((intptr_t)&readmem_dword,rt);
    if(type==LOADH_STUB)
      emit_movswl((intptr_t)&readmem_dword,rt);
    if(type==LOADHU_STUB)
      emit_movzwl((intptr_t)&readmem_dword,rt);
    if(type==LOADW_STUB)
      emit_readword((intptr_t)&readmem_dword,rt);
    if(type==LOADD_STUB) {
      emit_readword((intptr_t)&readmem_dword,rt);
      if(rth>=0) emit_readword(((intptr_t)&readmem_dword)+4,rth);
    }
  }
}

static void do_writestub(int n)
{
  assem_debug("do_writestub %x",start+stubs[n][3]*4);
  literal_pool(256);
  set_jump_target(stubs[n][1],(intptr_t)out);
  int type=stubs[n][0];
  int i=stubs[n][3];
  int rs=stubs[n][4];
  struct regstat *i_regs=(struct regstat *)stubs[n][5];
  u_int reglist=stubs[n][7];
  signed char *i_regmap=i_regs->regmap;
  int addr=get_reg(i_regmap,AGEN1+(i&1));
  int rth,rt,r;
  int ds;
  if(itype[i]==C1LS) {
    rth=get_reg(i_regmap,FTEMP|64);
    rt=get_reg(i_regmap,r=FTEMP);
  }else{
    rth=get_reg(i_regmap,rs2[i]|64);
    rt=get_reg(i_regmap,r=rs2[i]);
  }
  assert(rs>=0);
  assert(rt>=0);
  if(addr<0) addr=get_reg(i_regmap,-1);
  assert(addr>=0);
  intptr_t ftable=0;
  if(type==STOREB_STUB)
    ftable=(intptr_t)writememb;
  if(type==STOREH_STUB)
    ftable=(intptr_t)writememh;
  if(type==STOREW_STUB)
    ftable=(intptr_t)writemem;
  if(type==STORED_STUB)
    ftable=(intptr_t)writememd;
  emit_writeword(rs,(intptr_t)&address);
  //emit_shrimm(rs,16,rs);
  //emit_movmem_indexedx4(ftable,rs,rs);
  if(type==STOREB_STUB)
    emit_writebyte(rt,(intptr_t)&cpu_byte);
  if(type==STOREH_STUB)
    emit_writehword(rt,(intptr_t)&cpu_hword);
  if(type==STOREW_STUB)
    emit_writeword(rt,(intptr_t)&cpu_word);
  if(type==STORED_STUB) {
    emit_writeword(rt,(intptr_t)&cpu_dword);
    emit_writeword(r?rth:rt,(intptr_t)&cpu_dword+4);
  }
  //emit_pusha();
  save_regs(reglist);
  ds=i_regs!=&regs[i];
  int real_rs=get_reg(i_regmap,rs1[i]);
  u_int cmask=ds?-1:(0x7ffff|~i_regs->wasconst);
  if(!ds) load_all_consts(regs[i].regmap_entry,regs[i].was32,regs[i].wasdirty&~(1<<addr)&(real_rs<0?-1:~(1<<real_rs))&0x7ffff,i);
  wb_dirtys(i_regs->regmap_entry,i_regs->was32,i_regs->wasdirty&cmask&~(1<<addr)&(real_rs<0?-1:~(1<<real_rs)));
  if(!ds) wb_consts(regs[i].regmap_entry,regs[i].was32,regs[i].wasdirty&~(1<<addr)&(real_rs<0?-1:~(1<<real_rs))&~0x7ffff,i);
  emit_shrimm(rs,16,1);
  int cc=get_reg(i_regmap,CCREG);
  if(cc<0) {
    emit_loadreg(CCREG,2);
  }
  emit_read_ptr(ftable,0);
  emit_addimm(cc<0?2:cc,2*stubs[n][6]+2,2);
  emit_movimm(start+stubs[n][3]*4+(((regs[i].was32>>rs1[i])&1)<<1)+ds,3);
  //emit_readword((int)&last_count,temp);
  //emit_addimm(cc,2*stubs[n][5]+2,cc);
  //emit_add(cc,temp,cc);
  //emit_writeword(cc,(int)&g_cp0_regs[CP0_COUNT_REG]);
  emit_call((intptr_t)&indirect_jump_indexed);
  //emit_callreg(rs);
  emit_readword((intptr_t)&g_cp0_regs[CP0_COUNT_REG],HOST_TEMPREG);
  emit_readword((intptr_t)&next_interupt,2);
  emit_addimm(HOST_TEMPREG,-2*stubs[n][6]-2,HOST_TEMPREG);
  emit_writeword(2,(intptr_t)&last_count);
  emit_sub(HOST_TEMPREG,2,cc<0?HOST_TEMPREG:cc);
  if(cc<0) {
    emit_storereg(CCREG,HOST_TEMPREG);
  }
  //emit_popa();
  restore_regs(reglist);
  //if((cc=get_reg(regmap,CCREG))>=0) {
  //  emit_loadreg(CCREG,cc);
  //}
  emit_jmp(stubs[n][2]); // return address
}

static void inline_writestub(int type, int i, u_int addr, signed char regmap[], int target, int adj, u_int reglist)
{
  int rs=get_reg(regmap,-1);
  int rth=get_reg(regmap,target|64);
  int rt=get_reg(regmap,target);
  assert(rs>=0);
  assert(rt>=0);
  intptr_t ftable=0;
  if(type==STOREB_STUB)
    ftable=(intptr_t)writememb;
  if(type==STOREH_STUB)
    ftable=(intptr_t)writememh;
  if(type==STOREW_STUB)
    ftable=(intptr_t)writemem;
  if(type==STORED_STUB)
    ftable=(intptr_t)writememd;
  emit_writeword(rs,(intptr_t)&address);
  //emit_shrimm(rs,16,rs);
  //emit_movmem_indexedx4(ftable,rs,rs);
  if(type==STOREB_STUB)
    emit_writebyte(rt,(intptr_t)&cpu_byte);
  if(type==STOREH_STUB)
    emit_writehword(rt,(intptr_t)&cpu_hword);
  if(type==STOREW_STUB)
    emit_writeword(rt,(intptr_t)&cpu_word);
  if(type==STORED_STUB) {
    emit_writeword(rt,(intptr_t)&cpu_dword);
    emit_writeword(target?rth:rt,(intptr_t)&cpu_dword+4);
  }
  //emit_pusha();
  save_regs(reglist);
  if((signed int)addr>=(signed int)0xC0000000) {
    // Theoretically we can have a pagefault here, if the TLB has never
    // been enabled and the address is outside the range 80000000..BFFFFFFF
    // Write out the registers so the pagefault can be handled.  This is
    // a very rare case and likely represents a bug.
    int ds=regmap!=regs[i].regmap;
    if(!ds) load_all_consts(regs[i].regmap_entry,regs[i].was32,regs[i].wasdirty,i);
    if(!ds) wb_dirtys(regs[i].regmap_entry,regs[i].was32,regs[i].wasdirty);
    else wb_dirtys(branch_regs[i-1].regmap_entry,branch_regs[i-1].was32,branch_regs[i-1].wasdirty);
  }
  //emit_shrimm(rs,16,1);
  int cc=get_reg(regmap,CCREG);
  if(cc<0) {
    emit_loadreg(CCREG,2);
  }
  //emit_movimm(ftable,0);
  emit_read_ptr(((uintptr_t *)ftable)[addr>>16],0);
  //emit_readword((int)&last_count,12);
  emit_addimm(cc<0?2:cc,CLOCK_DIVIDER*(adj+1),2);
  if((signed int)addr>=(signed int)0xC0000000) {
    // Pagefault address
    int ds=regmap!=regs[i].regmap;
    emit_movimm(start+i*4+(((regs[i].was32>>rs1[i])&1)<<1)+ds,3);
  }
  //emit_add(12,2,2);
  //emit_writeword(2,(int)&g_cp0_regs[CP0_COUNT_REG]);
  //emit_call(((u_int *)ftable)[addr>>16]);
  emit_call((intptr_t)&indirect_jump);
  emit_readword((intptr_t)&g_cp0_regs[CP0_COUNT_REG],HOST_TEMPREG);
  emit_readword((intptr_t)&next_interupt,2);
  emit_addimm(HOST_TEMPREG,-(int)CLOCK_DIVIDER*(adj+1),HOST_TEMPREG);
  emit_writeword(2,(intptr_t)&last_count);
  emit_sub(HOST_TEMPREG,2,cc<0?HOST_TEMPREG:cc);
  if(cc<0) {
    emit_storereg(CCREG,HOST_TEMPREG);
  }
  //emit_popa();
  restore_regs(reglist);
}

static void do_unalignedwritestub(int n)
{
  set_jump_target(stubs[n][1],(intptr_t)out);
  emit_breakpoint(0);
  output_w32(0xd4000001); //SVC
  emit_jmp(stubs[n][2]); // return address
}

static void printregs(int edi,int esi,int ebp,int esp,int b,int d,int c,int a)
{
  DebugMessage(M64MSG_VERBOSE, "regs: %x %x %x %x %x %x %x (%x)",a,b,c,d,ebp,esi,edi,(&edi)[-1]);
}

static void do_invstub(int n)
{
  literal_pool(20);
  u_int reglist=stubs[n][3];
  set_jump_target(stubs[n][1],(intptr_t)out);
  save_regs(reglist);
  if(stubs[n][4]!=0) emit_mov(stubs[n][4],0);
  emit_call((intptr_t)&invalidate_addr);
  restore_regs(reglist);
  emit_jmp(stubs[n][2]); // return address
}

static intptr_t do_dirty_stub(int i)
{
  assem_debug("do_dirty_stub %x",start+i*4);

  // Careful about the code output here, verify_dirty and get_bounds needs to parse it.
  if((int)start<(int)0xC0000000){
    emit_read_ptr((intptr_t)source,1);
  }else{
    assert(0);
    emit_movz_lsl16(((u_int)start>>16)&0xffff,1);
    emit_movk(((u_int)start)&0xffff,1);
  }

  emit_read_ptr((intptr_t)copy,2);

  emit_movz(slen*4,3);
  emit_movimm(start+i*4,0);
  emit_call((int)start<(int)0xC0000000?(intptr_t)&verify_code:(intptr_t)&verify_code_vm);
  intptr_t entry=(intptr_t)out;
  load_regs_entry(i);
  if(entry==(intptr_t)out) entry=instr_addr[i];
  emit_jmp(instr_addr[i]);
  return entry;
}

static void do_dirty_stub_ds(void)
{
  assert(0);
  // Careful about the code output here, verify_dirty and get_bounds needs to parse it.
  #ifdef ARMv5_ONLY
  emit_loadlp((int)start<(int)0xC0000000?(int)source:(int)start,1);
  emit_loadlp((int)copy,2);
  emit_loadlp(slen*4,3);
  #else
  emit_movw(((int)start<(int)0xC0000000?(u_int)source:(u_int)start)&0x0000FFFF,1);
  emit_movw(((u_int)copy)&0x0000FFFF,2);
  emit_movt(((int)start<(int)0xC0000000?(u_int)source:(u_int)start)&0xFFFF0000,1);
  emit_movt(((u_int)copy)&0xFFFF0000,2);
  emit_movw(slen*4,3);
  #endif
  emit_movimm(start+1,0);
  emit_call((int)&verify_code_ds);
}

static void do_cop1stub(int n)
{
  literal_pool(256);
  assem_debug("do_cop1stub %x",start+stubs[n][3]*4);
  set_jump_target(stubs[n][1],(intptr_t)out);
  int i=stubs[n][3];
  int rs=stubs[n][4];
  struct regstat *i_regs=(struct regstat *)stubs[n][5];
  int ds=stubs[n][6];
  if(!ds) {
    load_all_consts(regs[i].regmap_entry,regs[i].was32,regs[i].wasdirty,i);
    //if(i_regs!=&regs[i]) DebugMessage(M64MSG_VERBOSE, "oops: regs[i]=%x i_regs=%x",(int)&regs[i],(int)i_regs);
  }
  //else {DebugMessage(M64MSG_ERROR, "fp exception in delay slot");}
  wb_dirtys(i_regs->regmap_entry,i_regs->was32,i_regs->wasdirty);
  if(regs[i].regmap_entry[HOST_CCREG]!=CCREG) emit_loadreg(CCREG,HOST_CCREG);
  emit_movimm(start+(i-ds)*4,EAX); // Get PC
  emit_addimm(HOST_CCREG,CLOCK_DIVIDER*ccadj[i],HOST_CCREG); // CHECK: is this right?  There should probably be an extra cycle...
  emit_jmp(ds?(intptr_t)fp_exception_ds:(intptr_t)fp_exception);
}

/* TLB */

static int do_tlb_r(int s,int ar,int map,int cache,int x,int a,int shift,int c,u_int addr)
{
  assert(0);
  if(c) {
    if((signed int)addr>=(signed int)0xC0000000) {
      // address_generation already loaded the const
      emit_readword_dualindexedx4(FP,map,map);
    }
    else
      return -1; // No mapping
  }
  else {
    assert(s!=map);
    if(cache>=0) {
      // Use cached offset to memory map
      emit_addsr12(cache,s,map);
    }else{
      emit_movimm(((int)memory_map-(int)&dynarec_local)>>2,map);
      emit_addsr12(map,s,map);
    }
    // Schedule this while we wait on the load
    //if(x) emit_xorimm(s,x,ar);
    if(shift>=0) emit_shlimm(s,3,shift);
    if(~a) emit_andimm(s,a,ar);
    emit_readword_dualindexedx4(FP,map,map);
  }
  return map;
}
static int do_tlb_r_branch(int map, int c, u_int addr, intptr_t *jaddr)
{
  assert(0);
  if(!c||(signed int)addr>=(signed int)0xC0000000) {
    emit_test(map,map);
    *jaddr=(int)out;
    emit_js(0);
  }
  return map;
}

static void gen_tlb_addr_r(int ar, int map) {
  if(map>=0) {
    assem_debug("add %s,%s,%s lsl #2",regname64[ar],regname64[ar],regname64[map]);
    output_w32(0x8b000000|map<<16|2<<10|ar<<5|ar);
  }
}

static int do_tlb_w(int s,int ar,int map,int cache,int x,int c,u_int addr)
{
  assert(0);
  if(c) {
    if(addr<0x80800000||addr>=0xC0000000) {
      // address_generation already loaded the const
      emit_readword_dualindexedx4(FP,map,map);
    }
    else
      return -1; // No mapping
  }
  else {
    assert(s!=map);
    if(cache>=0) {
      // Use cached offset to memory map
      emit_addsr12(cache,s,map);
    }else{
      emit_movimm(((int)memory_map-(int)&dynarec_local)>>2,map);
      emit_addsr12(map,s,map);
    }
    // Schedule this while we wait on the load
    //if(x) emit_xorimm(s,x,ar);
    emit_readword_dualindexedx4(FP,map,map);
  }
  return map;
}
static void do_tlb_w_branch(int map, int c, u_int addr, intptr_t *jaddr)
{
  assert(0);
  if(!c||addr<0x80800000||addr>=0xC0000000) {
    emit_testimm(map,0x40000000);
    *jaddr=(int)out;
    emit_jne(0);
  }
}

static void gen_tlb_addr_w(int ar, int map) {
  if(map>=0) {
    assem_debug("add %s,%s,%s lsl #2",regname64[ar],regname64[ar],regname64[map]);
    output_w32(0x8b000000|map<<16|2<<10|ar<<5|ar);
  }
}

// This reverses the above operation
static void gen_orig_addr_w(int ar, int map) {
  if(map>=0) {
    assem_debug("sub %s,%s,%s lsl #2",regname[ar],regname[ar],regname[map]);
    output_w32(0xcb000000|map<<16|2<<10|ar<<5|ar);
  }
}

// Generate the address of the memory_map entry, relative to dynarec_local
static void generate_map_const(u_int addr,int tr) {
  assert(0);
  //DebugMessage(M64MSG_VERBOSE, "generate_map_const(%x,%s)",addr,regname[tr]);
  emit_movimm((addr>>12)+(((u_int)memory_map-(u_int)&dynarec_local)>>2),tr);
}

/* Special assem */

static void shift_assemble_arm64(int i,struct regstat *i_regs)
{
  if(rt1[i]) {
    if(opcode2[i]<=0x07) // SLLV/SRLV/SRAV
    {
      signed char s,t,shift;
      t=get_reg(i_regs->regmap,rt1[i]);
      s=get_reg(i_regs->regmap,rs1[i]);
      shift=get_reg(i_regs->regmap,rs2[i]);
      if(t>=0){
        if(rs1[i]==0)
        {
          emit_zeroreg(t);
        }
        else if(rs2[i]==0)
        {
          assert(s>=0);
          if(s!=t) emit_mov(s,t);
        }
        else
        {
          emit_andimm(shift,31,HOST_TEMPREG);
          if(opcode2[i]==4) // SLLV
          {
            emit_shl(s,HOST_TEMPREG,t);
          }
          if(opcode2[i]==6) // SRLV
          {
            emit_shr(s,HOST_TEMPREG,t);
          }
          if(opcode2[i]==7) // SRAV
          {
            emit_sar(s,HOST_TEMPREG,t);
          }
        }
      }
    } else { // DSLLV/DSRLV/DSRAV
      signed char sh,sl,th,tl,shift;
      th=get_reg(i_regs->regmap,rt1[i]|64);
      tl=get_reg(i_regs->regmap,rt1[i]);
      sh=get_reg(i_regs->regmap,rs1[i]|64);
      sl=get_reg(i_regs->regmap,rs1[i]);
      shift=get_reg(i_regs->regmap,rs2[i]);
      if(tl>=0){
        if(rs1[i]==0)
        {
          emit_zeroreg(tl);
          if(th>=0) emit_zeroreg(th);
        }
        else if(rs2[i]==0)
        {
          assert(sl>=0);
          if(sl!=tl) emit_mov(sl,tl);
          if(th>=0&&sh!=th) emit_mov(sh,th);
        }
        else
        {
          // FIXME: What if shift==tl ?
          assert(shift!=tl);
          int temp=get_reg(i_regs->regmap,-1);
          int real_th=th;
          if(th<0&&opcode2[i]!=0x14) {th=temp;} // DSLLV doesn't need a temporary register
          assert(sl>=0);
          assert(sh>=0);
          emit_andimm(shift,31,HOST_TEMPREG);
          if(opcode2[i]==0x14) // DSLLV
          {
            if(th>=0) emit_shl(sh,HOST_TEMPREG,th);
            emit_rsbimm(HOST_TEMPREG,32,HOST_TEMPREG);
            emit_orrshr(sl,HOST_TEMPREG,th);
            emit_andimm(shift,31,HOST_TEMPREG);
            emit_testimm(shift,32);
            emit_shl(sl,HOST_TEMPREG,tl);
            if(th>=0) emit_cmovne_reg(tl,th);
            emit_cmovne_imm(0,tl);
          }
          if(opcode2[i]==0x16) // DSRLV
          {
            assert(th>=0);
            emit_shr(sl,HOST_TEMPREG,tl);
            emit_rsbimm(HOST_TEMPREG,32,HOST_TEMPREG);
            emit_orrshl(sh,HOST_TEMPREG,tl);
            emit_andimm(shift,31,HOST_TEMPREG);
            emit_testimm(shift,32);
            emit_shr(sh,HOST_TEMPREG,th);
            emit_cmovne_reg(th,tl);
            if(real_th>=0) emit_cmovne_imm(0,th);
          }
          if(opcode2[i]==0x17) // DSRAV
          {
            assert(th>=0);
            emit_shr(sl,HOST_TEMPREG,tl);
            emit_rsbimm(HOST_TEMPREG,32,HOST_TEMPREG);
            if(real_th>=0) {
              assert(temp>=0);
              emit_sarimm(th,31,temp);
            }
            emit_orrshl(sh,HOST_TEMPREG,tl);
            emit_andimm(shift,31,HOST_TEMPREG);
            emit_testimm(shift,32);
            emit_sar(sh,HOST_TEMPREG,th);
            emit_cmovne_reg(th,tl);
            if(real_th>=0) emit_cmovne_reg(temp,th);
          }
        }
      }
    }
  }
}
#define shift_assemble shift_assemble_arm64

static void loadlr_assemble_arm64(int i,struct regstat *i_regs)
{
  int s,th,tl,temp,temp2,addr,map=-1,cache=-1;
  int offset;
  intptr_t jaddr=0;
  int memtarget=0;
  int c=0;
  u_int hr,reglist=0;
  th=get_reg(i_regs->regmap,rt1[i]|64);
  tl=get_reg(i_regs->regmap,rt1[i]);
  s=get_reg(i_regs->regmap,rs1[i]);
  temp=get_reg(i_regs->regmap,-1);
  temp2=get_reg(i_regs->regmap,FTEMP);
  addr=get_reg(i_regs->regmap,AGEN1+(i&1));
  assert(addr<0);
  offset=imm[i];
  for(hr=0;hr<HOST_REGS;hr++) {
    if(i_regs->regmap[hr]>=0) reglist|=1<<hr;
  }
  reglist|=1<<temp;
  if(offset||s<0||c) addr=temp2;
  else addr=s;
  if(s>=0) {
    c=(i_regs->wasconst>>s)&1;
    memtarget=((signed int)(constmap[i][s]+offset))<(signed int)0x80800000;
    if(using_tlb&&((signed int)(constmap[i][s]+offset))>=(signed int)0xC0000000) memtarget=1;
  }
  if(!using_tlb) {
    if(!c) {
      #ifdef RAM_OFFSET
      map=get_reg(i_regs->regmap,ROREG);
      if(map<0) emit_loadreg(ROREG,map=HOST_TEMPREG);
      #endif
      emit_shlimm(addr,3,temp);
      if (opcode[i]==0x22||opcode[i]==0x26) {
        emit_andimm(addr,0xFFFFFFFC,temp2); // LWL/LWR
      }else{
        emit_andimm(addr,0xFFFFFFF8,temp2); // LDL/LDR
      }
      emit_cmpimm(addr,0x800000);
      jaddr=(intptr_t)out;
      emit_jno(0);
    }
    else {
      if (opcode[i]==0x22||opcode[i]==0x26) {
        emit_movimm(((constmap[i][s]+offset)<<3)&24,temp); // LWL/LWR
      }else{
        emit_movimm(((constmap[i][s]+offset)<<3)&56,temp); // LDL/LDR
      }
    }
  }else{ // using tlb
    assert(0);
    int a;
    if(c) {
      a=-1;
    }else if (opcode[i]==0x22||opcode[i]==0x26) {
      a=0xFFFFFFFC; // LWL/LWR
    }else{
      a=0xFFFFFFF8; // LDL/LDR
    }
    map=get_reg(i_regs->regmap,TLREG);
    cache=get_reg(i_regs->regmap,MMREG); // Get cached offset to memory_map
    assert(map>=0);
    reglist&=~(1<<map);
    map=do_tlb_r(addr,temp2,map,cache,0,a,c?-1:temp,c,constmap[i][s]+offset);
    if(c) {
      if (opcode[i]==0x22||opcode[i]==0x26) {
        emit_movimm(((constmap[i][s]+offset)<<3)&24,temp); // LWL/LWR
      }else{
        emit_movimm(((constmap[i][s]+offset)<<3)&56,temp); // LDL/LDR
      }
    }
    do_tlb_r_branch(map,c,constmap[i][s]+offset,&jaddr);
  }
  if (opcode[i]==0x22||opcode[i]==0x26) { // LWL/LWR
    if(!c||memtarget) {
      //emit_readword_indexed((intptr_t)g_rdram-0x80000000,temp2,temp2);
      emit_readword_indexed_tlb(0,temp2,map,temp2);
      if(jaddr) add_stub(LOADW_STUB,jaddr,(intptr_t)out,i,temp2,(intptr_t)i_regs,ccadj[i],reglist);
    }
    else
      inline_readstub(LOADW_STUB,i,(constmap[i][s]+offset)&0xFFFFFFFC,i_regs->regmap,FTEMP,ccadj[i],reglist);
    if(rt1[i]) {
      assert(tl>=0);
      emit_andimm(temp,24,temp);
      if (opcode[i]==0x26) emit_xorimm(temp,24,temp); // LWR
      emit_movimm(-1,HOST_TEMPREG);
      if (opcode[i]==0x26) {
        emit_shr(temp2,temp,temp2);
        emit_shr(HOST_TEMPREG,temp,HOST_TEMPREG);
        emit_bic(tl,HOST_TEMPREG,tl);
        //emit_bic_lsr(tl,HOST_TEMPREG,temp,tl);
      }else{
        emit_shl(temp2,temp,temp2);
        emit_shl(HOST_TEMPREG,temp,HOST_TEMPREG);
        emit_bic(tl,HOST_TEMPREG,tl);
        //emit_bic_lsl(tl,HOST_TEMPREG,temp,tl);
      }
      emit_or(temp2,tl,tl);
    }
    //emit_storereg(rt1[i],tl); // DEBUG
  }
  if (opcode[i]==0x1A||opcode[i]==0x1B) { // LDL/LDR
    int temp2h=get_reg(i_regs->regmap,FTEMP|64);
    if(!c||memtarget) {
      //if(th>=0) emit_readword_indexed((intptr_t)g_rdram-0x80000000,temp2,temp2h);
      //emit_readword_indexed((intptr_t)g_rdram-0x7FFFFFFC,temp2,temp2);
      emit_readdword_indexed_tlb(0,temp2,map,temp2h,temp2);
      if(jaddr) add_stub(LOADD_STUB,jaddr,(intptr_t)out,i,temp2,(intptr_t)i_regs,ccadj[i],reglist);
    }
    else
      inline_readstub(LOADD_STUB,i,(constmap[i][s]+offset)&0xFFFFFFF8,i_regs->regmap,FTEMP,ccadj[i],reglist);
    if(rt1[i]) {
      assert(th>=0);
      assert(tl>=0);
      emit_testimm(temp,32);
      emit_andimm(temp,24,temp);
      assert(0);
      if (opcode[i]==0x1A) { // LDL
        emit_rsbimm(temp,32,HOST_TEMPREG);
        emit_shl(temp2h,temp,temp2h);
        emit_orrshr(temp2,HOST_TEMPREG,temp2h);
        emit_movimm(-1,HOST_TEMPREG);
        emit_shl(temp2,temp,temp2);
        emit_cmove_reg(temp2h,th);
        emit_biceq_lsl(tl,HOST_TEMPREG,temp,tl);
        emit_bicne_lsl(th,HOST_TEMPREG,temp,th);
        emit_orreq(temp2,tl,tl);
        emit_orrne(temp2,th,th);
      }
      if (opcode[i]==0x1B) { // LDR
        emit_xorimm(temp,24,temp);
        emit_rsbimm(temp,32,HOST_TEMPREG);
        emit_shr(temp2,temp,temp2);
        emit_orrshl(temp2h,HOST_TEMPREG,temp2);
        emit_movimm(-1,HOST_TEMPREG);
        emit_shr(temp2h,temp,temp2h);
        emit_cmovne_reg(temp2,tl);
        emit_bicne_lsr(th,HOST_TEMPREG,temp,th);
        emit_biceq_lsr(tl,HOST_TEMPREG,temp,tl);
        emit_orrne(temp2h,th,th);
        emit_orreq(temp2h,tl,tl);
      }
    }
  }
}
#define loadlr_assemble loadlr_assemble_arm64

static void storelr_assemble_arm64(int i,struct regstat *i_regs)
{
  int s,th,tl;
  int temp;
  int temp2;
  int offset;
  intptr_t jaddr=0;
  intptr_t jaddr2=0;
  intptr_t case1,case2,case3;
  intptr_t done0,done1,done2;
  int memtarget,c=0;
  int agr=AGEN1+(i&1);
  u_int hr,reglist=0;
  th=get_reg(i_regs->regmap,rs2[i]|64);
  tl=get_reg(i_regs->regmap,rs2[i]);
  s=get_reg(i_regs->regmap,rs1[i]);
  temp=get_reg(i_regs->regmap,agr);
  if(temp<0) temp=get_reg(i_regs->regmap,-1);
  offset=imm[i];
  if(s>=0) {
    c=(i_regs->isconst>>s)&1;
    memtarget=((signed int)(constmap[i][s]+offset))<(signed int)0x80800000;
    if(using_tlb&&((signed int)(constmap[i][s]+offset))>=(signed int)0xC0000000) memtarget=1;
  }
  assert(tl>=0);
  for(hr=0;hr<HOST_REGS;hr++) {
    if(i_regs->regmap[hr]>=0) reglist|=1<<hr;
  }
  assert(temp>=0);
  if(!using_tlb) {
    if(!c) {
      emit_cmpimm(s<0||offset?temp:s,0x800000);
      if(!offset&&s!=temp) emit_mov(s,temp);
      jaddr=(intptr_t)out;
      emit_jno(0);
    }
    else
    {
      if(!memtarget||!rs1[i]) {
        jaddr=(intptr_t)out;
        emit_jmp(0);
      }
    }
    #ifdef RAM_OFFSET
    int map=get_reg(i_regs->regmap,ROREG);
    if(map<0) emit_loadreg(ROREG,map=HOST_TEMPREG);
    gen_tlb_addr_w(temp,map);
    #else
    if((uintptr_t)g_rdram!=0x80000000) 
      emit_addimm_no_flags((uintptr_t)g_rdram-(uintptr_t)0x80000000,temp);
    #endif
  }else{ // using tlb
    assert(0);
    int map=get_reg(i_regs->regmap,TLREG);
    int cache=get_reg(i_regs->regmap,MMREG);
    assert(map>=0);
    reglist&=~(1<<map);
    map=do_tlb_w(c||s<0||offset?temp:s,temp,map,cache,0,c,constmap[i][s]+offset);
    if(!c&&!offset&&s>=0) emit_mov(s,temp);
    do_tlb_w_branch(map,c,constmap[i][s]+offset,&jaddr);
    if(!jaddr&&!memtarget) {
      jaddr=(intptr_t)out;
      emit_jmp(0);
    }
    gen_tlb_addr_w(temp,map);
  }

  if (opcode[i]==0x2C||opcode[i]==0x2D) { // SDL/SDR
    temp2=get_reg(i_regs->regmap,FTEMP);
    if(!rs2[i]) temp2=th=tl;
  }

  emit_testimm64(temp,2);
  case2=(intptr_t)out;
  emit_jne(0);
  emit_testimm64(temp,1);
  case1=(intptr_t)out;
  emit_jne(0);
  // 0
  if (opcode[i]==0x2A) { // SWL
    emit_writeword_indexed(tl,0,temp);
  }
  if (opcode[i]==0x2E) { // SWR
    emit_writebyte_indexed(tl,3,temp);
  }
  if (opcode[i]==0x2C) { // SDL
    emit_writeword_indexed(th,0,temp);
    if(rs2[i]) emit_mov(tl,temp2);
  }
  if (opcode[i]==0x2D) { // SDR
    emit_writebyte_indexed(tl,3,temp);
    if(rs2[i]) emit_shldimm(th,tl,24,temp2);
  }
  done0=(intptr_t)out;
  emit_jmp(0);
  // 1
  set_jump_target(case1,(intptr_t)out);
  if (opcode[i]==0x2A) { // SWL
    // Write 3 msb into three least significant bytes
    if(rs2[i]) emit_rorimm(tl,8,tl);
    emit_writehword_indexed(tl,-1,temp);
    if(rs2[i]) emit_rorimm(tl,16,tl);
    emit_writebyte_indexed(tl,1,temp);
    if(rs2[i]) emit_rorimm(tl,8,tl);
  }
  if (opcode[i]==0x2E) { // SWR
    // Write two lsb into two most significant bytes
    emit_writehword_indexed(tl,1,temp);
  }
  if (opcode[i]==0x2C) { // SDL
    if(rs2[i]) emit_shrdimm(tl,th,8,temp2);
    // Write 3 msb into three least significant bytes
    if(rs2[i]) emit_rorimm(th,8,th);
    emit_writehword_indexed(th,-1,temp);
    if(rs2[i]) emit_rorimm(th,16,th);
    emit_writebyte_indexed(th,1,temp);
    if(rs2[i]) emit_rorimm(th,8,th);
  }
  if (opcode[i]==0x2D) { // SDR
    if(rs2[i]) emit_shldimm(th,tl,16,temp2);
    // Write two lsb into two most significant bytes
    emit_writehword_indexed(tl,1,temp);
  }
  done1=(intptr_t)out;
  emit_jmp(0);
  // 2
  set_jump_target(case2,(intptr_t)out);
  emit_testimm64(temp,1);
  case3=(intptr_t)out;
  emit_jne(0);
  if (opcode[i]==0x2A) { // SWL
    // Write two msb into two least significant bytes
    if(rs2[i]) emit_rorimm(tl,16,tl);
    emit_writehword_indexed(tl,-2,temp);
    if(rs2[i]) emit_rorimm(tl,16,tl);
  }
  if (opcode[i]==0x2E) { // SWR
    // Write 3 lsb into three most significant bytes
    emit_writebyte_indexed(tl,-1,temp);
    if(rs2[i]) emit_rorimm(tl,8,tl);
    emit_writehword_indexed(tl,0,temp);
    if(rs2[i]) emit_rorimm(tl,24,tl);
  }
  if (opcode[i]==0x2C) { // SDL
    if(rs2[i]) emit_shrdimm(tl,th,16,temp2);
    // Write two msb into two least significant bytes
    if(rs2[i]) emit_rorimm(th,16,th);
    emit_writehword_indexed(th,-2,temp);
    if(rs2[i]) emit_rorimm(th,16,th);
  }
  if (opcode[i]==0x2D) { // SDR
    if(rs2[i]) emit_shldimm(th,tl,8,temp2);
    // Write 3 lsb into three most significant bytes
    emit_writebyte_indexed(tl,-1,temp);
    if(rs2[i]) emit_rorimm(tl,8,tl);
    emit_writehword_indexed(tl,0,temp);
    if(rs2[i]) emit_rorimm(tl,24,tl);
  }
  done2=(intptr_t)out;
  emit_jmp(0);
  // 3
  set_jump_target(case3,(intptr_t)out);
  if (opcode[i]==0x2A) { // SWL
    // Write msb into least significant byte
    if(rs2[i]) emit_rorimm(tl,24,tl);
    emit_writebyte_indexed(tl,-3,temp);
    if(rs2[i]) emit_rorimm(tl,8,tl);
  }
  if (opcode[i]==0x2E) { // SWR
    // Write entire word
    emit_writeword_indexed(tl,-3,temp);
  }
  if (opcode[i]==0x2C) { // SDL
    if(rs2[i]) emit_shrdimm(tl,th,24,temp2);
    // Write msb into least significant byte
    if(rs2[i]) emit_rorimm(th,24,th);
    emit_writebyte_indexed(th,-3,temp);
    if(rs2[i]) emit_rorimm(th,8,th);
  }
  if (opcode[i]==0x2D) { // SDR
    if(rs2[i]) emit_mov(th,temp2);
    // Write entire word
    emit_writeword_indexed(tl,-3,temp);
  }
  set_jump_target(done0,(intptr_t)out);
  set_jump_target(done1,(intptr_t)out);
  set_jump_target(done2,(intptr_t)out);
  if (opcode[i]==0x2C) { // SDL
    emit_testimm64(temp,4);
    done0=(intptr_t)out;
    emit_jne(0);
    emit_andimm64(temp,~3,temp);
    emit_writeword_indexed(temp2,4,temp);
    set_jump_target(done0,(intptr_t)out);
  }
  if (opcode[i]==0x2D) { // SDR
    emit_testimm64(temp,4);
    done0=(intptr_t)out;
    emit_jeq(0);
    emit_andimm64(temp,~3,temp);
    emit_writeword_indexed(temp2,-4,temp);
    set_jump_target(done0,(intptr_t)out);
  }
  if(!c||!memtarget)
    //TOBEDONE: Move this after invalid stub? (see store_assemble)
    add_stub(STORELR_STUB,jaddr,(intptr_t)out,0,(intptr_t)i_regs,rs2[i],ccadj[i],reglist);
  if(!using_tlb) {
    #ifdef RAM_OFFSET
    int map=get_reg(i_regs->regmap,ROREG);
    if(map<0) map=HOST_TEMPREG;
    gen_orig_addr_w(temp,map);
    #else
    emit_addimm_no_flags((uintptr_t)0x80000000-(uintptr_t)g_rdram,temp);
    #endif
    #if defined(HOST_IMM8)
    int ir=get_reg(i_regs->regmap,INVCP);
    assert(ir>=0);
    emit_cmpmem_indexedsr12_reg(ir,temp,1);
    #else
    emit_cmpmem_indexedsr12_imm((intptr_t)invalid_code,temp,1);
    #endif
    #if defined(HAVE_CONDITIONAL_CALL) && !defined(DESTRUCTIVE_SHIFT)
    emit_callne(invalidate_addr_reg[temp]);
    #else
    jaddr2=(intptr_t)out;
    emit_jne(0);
    add_stub(INVCODE_STUB,jaddr2,(intptr_t)out,reglist|(1<<HOST_CCREG),temp,0,0,0);
    #endif
  }
  /*
    emit_pusha();
    //save_regs(0x100f);
        emit_readword((intptr_t)&last_count,ECX);
        if(get_reg(i_regs->regmap,CCREG)<0)
          emit_loadreg(CCREG,HOST_CCREG);
        emit_add(HOST_CCREG,ECX,HOST_CCREG);
        emit_addimm(HOST_CCREG,2*ccadj[i],HOST_CCREG);
        emit_writeword(HOST_CCREG,(intptr_t)&g_cp0_regs[CP0_COUNT_REG]);
    emit_call((intptr_t)memdebug);
    emit_popa();
    //restore_regs(0x100f);
  */
}
#define storelr_assemble storelr_assemble_arm64

static void cop0_assemble(int i,struct regstat *i_regs)
{
  if(opcode2[i]==0) // MFC0
  {
    if(rt1[i]) {
      signed char t=get_reg(i_regs->regmap,rt1[i]);
      char copr=(source[i]>>11)&0x1f;
      if(t>=0) {
        emit_addimm64(FP,(intptr_t)&fake_pc-(intptr_t)&dynarec_local,0);
        emit_movimm((source[i]>>11)&0x1f,1);
        emit_writeword64(0,(intptr_t)&PC);
        emit_writebyte(1,(intptr_t)&(fake_pc.f.r.nrd));
        if(copr==9) {
          emit_readword((intptr_t)&last_count,ECX);
          emit_loadreg(CCREG,HOST_CCREG); // TODO: do proper reg alloc
          emit_add(HOST_CCREG,ECX,HOST_CCREG);
          emit_addimm(HOST_CCREG,CLOCK_DIVIDER*ccadj[i],HOST_CCREG);
          emit_writeword(HOST_CCREG,(intptr_t)&g_cp0_regs[CP0_COUNT_REG]);
        }
        emit_call((intptr_t)cached_interpreter_table.MFC0);
        emit_readword((intptr_t)&readmem_dword,t);
      }
    }
  }
  else if(opcode2[i]==4) // MTC0
  {
    signed char s=get_reg(i_regs->regmap,rs1[i]);
    char copr=(source[i]>>11)&0x1f;
    assert(s>=0);
    emit_writeword(s,(intptr_t)&readmem_dword);
    wb_register(rs1[i],i_regs->regmap,i_regs->dirty,i_regs->is32);
    emit_addimm64(FP,(intptr_t)&fake_pc-(intptr_t)&dynarec_local,0);
    emit_movimm((source[i]>>11)&0x1f,1);
    emit_writeword64(0,(intptr_t)&PC);
    emit_writebyte(1,(intptr_t)&(fake_pc.f.r.nrd));
    if(copr==9||copr==11||copr==12) {
      emit_readword((intptr_t)&last_count,ECX);
      emit_loadreg(CCREG,HOST_CCREG); // TODO: do proper reg alloc
      emit_add(HOST_CCREG,ECX,HOST_CCREG);
      emit_addimm(HOST_CCREG,CLOCK_DIVIDER*ccadj[i],HOST_CCREG);
      emit_writeword(HOST_CCREG,(intptr_t)&g_cp0_regs[CP0_COUNT_REG]);
    }
    // What a mess.  The status register (12) can enable interrupts,
    // so needs a special case to handle a pending interrupt.
    // The interrupt must be taken immediately, because a subsequent
    // instruction might disable interrupts again.
    if(copr==12&&!is_delayslot) {
      emit_movimm(start+i*4+4,0);
      emit_movimm(0,1);
      emit_writeword(0,(intptr_t)&pcaddr);
      emit_writeword(1,(intptr_t)&pending_exception);
    }
    //else if(copr==12&&is_delayslot) emit_call((int)MTC0_R12);
    //else
    emit_call((intptr_t)cached_interpreter_table.MTC0);
    if(copr==9||copr==11||copr==12) {
      emit_readword((intptr_t)&g_cp0_regs[CP0_COUNT_REG],HOST_CCREG);
      emit_readword((intptr_t)&next_interupt,ECX);
      emit_addimm(HOST_CCREG,-(int)CLOCK_DIVIDER*ccadj[i],HOST_CCREG);
      emit_sub(HOST_CCREG,ECX,HOST_CCREG);
      emit_writeword(ECX,(intptr_t)&last_count);
      emit_storereg(CCREG,HOST_CCREG);
    }
    if(copr==12) {
      assert(!is_delayslot);
      emit_readword((intptr_t)&pending_exception,HOST_TEMPREG);
    }
    emit_loadreg(rs1[i],s);
    if(get_reg(i_regs->regmap,rs1[i]|64)>=0)
      emit_loadreg(rs1[i]|64,get_reg(i_regs->regmap,rs1[i]|64));
    if(copr==12) {
      emit_test(HOST_TEMPREG,HOST_TEMPREG);
      emit_jeq((intptr_t)out+8);
      emit_jmp((intptr_t)&do_interrupt);
    }
    cop1_usable=0;
  }
  else
  {
    assert(opcode2[i]==0x10);
    if((source[i]&0x3f)==0x01) // TLBR
      emit_call((intptr_t)cached_interpreter_table.TLBR);
    if((source[i]&0x3f)==0x02) // TLBWI
      emit_call((intptr_t)TLBWI_new);
    if((source[i]&0x3f)==0x06) { // TLBWR
      // The TLB entry written by TLBWR is dependent on the count,
      // so update the cycle count
      emit_readword((intptr_t)&last_count,ECX);
      if(i_regs->regmap[HOST_CCREG]!=CCREG) emit_loadreg(CCREG,HOST_CCREG);
      emit_add(HOST_CCREG,ECX,HOST_CCREG);
      emit_addimm(HOST_CCREG,CLOCK_DIVIDER*ccadj[i],HOST_CCREG);
      emit_writeword(HOST_CCREG,(intptr_t)&g_cp0_regs[CP0_COUNT_REG]);
      emit_call((intptr_t)TLBWR_new);
    }
    if((source[i]&0x3f)==0x08) // TLBP
      emit_call((intptr_t)cached_interpreter_table.TLBP);
    if((source[i]&0x3f)==0x18) // ERET
    {
      int count=ccadj[i];
      if(i_regs->regmap[HOST_CCREG]!=CCREG) emit_loadreg(CCREG,HOST_CCREG);
      emit_addimm(HOST_CCREG,CLOCK_DIVIDER*count,HOST_CCREG); // TODO: Should there be an extra cycle here?
      emit_jmp((intptr_t)jump_eret);
    }
  }
}

static void cop1_assemble(int i,struct regstat *i_regs)
{
  // Check cop1 unusable
  if(!cop1_usable) {
    signed char rs=get_reg(i_regs->regmap,CSREG);
    assert(rs>=0);
    emit_testimm(rs,0x20000000);
    intptr_t jaddr=(intptr_t)out;
    emit_jeq(0);
    add_stub(FP_STUB,jaddr,(intptr_t)out,i,rs,(intptr_t)i_regs,is_delayslot,0);
    cop1_usable=1;
  }
  if (opcode2[i]==0) { // MFC1
    signed char tl=get_reg(i_regs->regmap,rt1[i]);
    if(tl>=0) {
      emit_readword((intptr_t)&reg_cop1_simple[(source[i]>>11)&0x1f],tl);
      emit_readword_indexed(0,tl,tl);
    }
  }
  else if (opcode2[i]==1) { // DMFC1
    signed char tl=get_reg(i_regs->regmap,rt1[i]);
    signed char th=get_reg(i_regs->regmap,rt1[i]|64);
    if(tl>=0) {
      emit_readword((intptr_t)&reg_cop1_double[(source[i]>>11)&0x1f],tl);
      if(th>=0) emit_readword_indexed(4,tl,th);
      emit_readword_indexed(0,tl,tl);
    }
  }
  else if (opcode2[i]==4) { // MTC1
    signed char sl=get_reg(i_regs->regmap,rs1[i]);
    signed char temp=get_reg(i_regs->regmap,-1);
    emit_readword((intptr_t)&reg_cop1_simple[(source[i]>>11)&0x1f],temp);
    emit_writeword_indexed(sl,0,temp);
  }
  else if (opcode2[i]==5) { // DMTC1
    signed char sl=get_reg(i_regs->regmap,rs1[i]);
    signed char sh=rs1[i]>0?get_reg(i_regs->regmap,rs1[i]|64):sl;
    signed char temp=get_reg(i_regs->regmap,-1);
    emit_readword((intptr_t)&reg_cop1_double[(source[i]>>11)&0x1f],temp);
    emit_writeword_indexed(sh,4,temp);
    emit_writeword_indexed(sl,0,temp);
  }
  else if (opcode2[i]==2) // CFC1
  {
    signed char tl=get_reg(i_regs->regmap,rt1[i]);
    if(tl>=0) {
      u_int copr=(source[i]>>11)&0x1f;
      if(copr==0) emit_readword((intptr_t)&FCR0,tl);
      if(copr==31) emit_readword((intptr_t)&FCR31,tl);
    }
  }
  else if (opcode2[i]==6) // CTC1
  {
    signed char sl=get_reg(i_regs->regmap,rs1[i]);
    u_int copr=(source[i]>>11)&0x1f;
    assert(sl>=0);
    if(copr==31)
    {
      emit_writeword(sl,(intptr_t)&FCR31);
      // Set the rounding mode
      //FIXME
      //char temp=get_reg(i_regs->regmap,-1);
      //emit_andimm(sl,3,temp);
      //emit_fldcw_indexed((int)&rounding_modes,temp);
    }
  }
}

static void fconv_assemble_arm64(int i,struct regstat *i_regs)
{
  assert(0);
  signed char temp=get_reg(i_regs->regmap,-1);
  assert(temp>=0);
  // Check cop1 unusable
  if(!cop1_usable) {
    signed char rs=get_reg(i_regs->regmap,CSREG);
    assert(rs>=0);
    emit_testimm(rs,0x20000000);
    int jaddr=(int)out;
    emit_jeq(0);
    add_stub(FP_STUB,jaddr,(intptr_t)out,i,rs,(intptr_t)i_regs,is_delayslot,0);
    cop1_usable=1;
  }
  
  #if (defined(__VFP_FP__) && !defined(__SOFTFP__)) 
  if(opcode2[i]==0x10&&(source[i]&0x3f)==0x0d) { // trunc_w_s
    emit_readword((int)&reg_cop1_simple[(source[i]>>11)&0x1f],temp);
    emit_flds(temp,15);
    emit_ftosizs(15,15); // float->int, truncate
    if(((source[i]>>11)&0x1f)!=((source[i]>>6)&0x1f))
      emit_readword((int)&reg_cop1_simple[(source[i]>>6)&0x1f],temp);
    emit_fsts(15,temp);
    return;
  }
  if(opcode2[i]==0x11&&(source[i]&0x3f)==0x0d) { // trunc_w_d
    emit_readword((int)&reg_cop1_double[(source[i]>>11)&0x1f],temp);
    emit_vldr(temp,7);
    emit_ftosizd(7,13); // double->int, truncate
    emit_readword((int)&reg_cop1_simple[(source[i]>>6)&0x1f],temp);
    emit_fsts(13,temp);
    return;
  }
  
  if(opcode2[i]==0x14&&(source[i]&0x3f)==0x20) { // cvt_s_w
    emit_readword((int)&reg_cop1_simple[(source[i]>>11)&0x1f],temp);
    emit_flds(temp,13);
    if(((source[i]>>11)&0x1f)!=((source[i]>>6)&0x1f))
      emit_readword((int)&reg_cop1_simple[(source[i]>>6)&0x1f],temp);
    emit_fsitos(13,15);
    emit_fsts(15,temp);
    return;
  }
  if(opcode2[i]==0x14&&(source[i]&0x3f)==0x21) { // cvt_d_w
    emit_readword((int)&reg_cop1_simple[(source[i]>>11)&0x1f],temp);
    emit_flds(temp,13);
    emit_readword((int)&reg_cop1_double[(source[i]>>6)&0x1f],temp);
    emit_fsitod(13,7);
    emit_vstr(7,temp);
    return;
  }
  
  if(opcode2[i]==0x10&&(source[i]&0x3f)==0x21) { // cvt_d_s
    emit_readword((int)&reg_cop1_simple[(source[i]>>11)&0x1f],temp);
    emit_flds(temp,13);
    emit_readword((int)&reg_cop1_double[(source[i]>>6)&0x1f],temp);
    emit_fcvtds(13,7);
    emit_vstr(7,temp);
    return;
  }
  if(opcode2[i]==0x11&&(source[i]&0x3f)==0x20) { // cvt_s_d
    emit_readword((int)&reg_cop1_double[(source[i]>>11)&0x1f],temp);
    emit_vldr(temp,7);
    emit_readword((int)&reg_cop1_simple[(source[i]>>6)&0x1f],temp);
    emit_fcvtsd(7,13);
    emit_fsts(13,temp);
    return;
  }
  #endif
  
  // C emulation code
  
  u_int hr,reglist=0;
  for(hr=0;hr<HOST_REGS;hr++) {
    if(i_regs->regmap[hr]>=0) reglist|=1<<hr;
  }
  save_regs(reglist);
  
  if(opcode2[i]==0x14&&(source[i]&0x3f)==0x20) {
    emit_readword((int)&reg_cop1_simple[(source[i]>>11)&0x1f],ARG1_REG);
    emit_readword((int)&reg_cop1_simple[(source[i]>> 6)&0x1f],ARG2_REG);
    emit_call((int)cvt_s_w);
  }
  if(opcode2[i]==0x14&&(source[i]&0x3f)==0x21) {
    emit_readword((int)&reg_cop1_simple[(source[i]>>11)&0x1f],ARG1_REG);
    emit_readword((int)&reg_cop1_double[(source[i]>> 6)&0x1f],ARG2_REG);
    emit_call((int)cvt_d_w);
  }
  if(opcode2[i]==0x15&&(source[i]&0x3f)==0x20) {
    emit_readword((int)&reg_cop1_double[(source[i]>>11)&0x1f],ARG1_REG);
    emit_readword((int)&reg_cop1_simple[(source[i]>> 6)&0x1f],ARG2_REG);
    emit_call((int)cvt_s_l);
  }
  if(opcode2[i]==0x15&&(source[i]&0x3f)==0x21) {
    emit_readword((int)&reg_cop1_double[(source[i]>>11)&0x1f],ARG1_REG);
    emit_readword((int)&reg_cop1_double[(source[i]>> 6)&0x1f],ARG2_REG);
    emit_call((int)cvt_d_l);
  }
  
  if(opcode2[i]==0x10&&(source[i]&0x3f)==0x21) {
    emit_readword((int)&reg_cop1_simple[(source[i]>>11)&0x1f],ARG1_REG);
    emit_readword((int)&reg_cop1_double[(source[i]>> 6)&0x1f],ARG2_REG);
    emit_call((int)cvt_d_s);
  }
  if(opcode2[i]==0x10&&(source[i]&0x3f)==0x24) {
    emit_readword((int)&reg_cop1_simple[(source[i]>>11)&0x1f],ARG1_REG);
    emit_readword((int)&reg_cop1_simple[(source[i]>> 6)&0x1f],ARG2_REG);
    emit_call((int)cvt_w_s);
  }
  if(opcode2[i]==0x10&&(source[i]&0x3f)==0x25) {
    emit_readword((int)&reg_cop1_simple[(source[i]>>11)&0x1f],ARG1_REG);
    emit_readword((int)&reg_cop1_double[(source[i]>> 6)&0x1f],ARG2_REG);
    emit_call((int)cvt_l_s);
  }
  
  if(opcode2[i]==0x11&&(source[i]&0x3f)==0x20) {
    emit_readword((int)&reg_cop1_double[(source[i]>>11)&0x1f],ARG1_REG);
    emit_readword((int)&reg_cop1_simple[(source[i]>> 6)&0x1f],ARG2_REG);
    emit_call((int)cvt_s_d);
  }
  if(opcode2[i]==0x11&&(source[i]&0x3f)==0x24) {
    emit_readword((int)&reg_cop1_double[(source[i]>>11)&0x1f],ARG1_REG);
    emit_readword((int)&reg_cop1_simple[(source[i]>> 6)&0x1f],ARG2_REG);
    emit_call((int)cvt_w_d);
  }
  if(opcode2[i]==0x11&&(source[i]&0x3f)==0x25) {
    emit_readword((int)&reg_cop1_double[(source[i]>>11)&0x1f],ARG1_REG);
    emit_readword((int)&reg_cop1_double[(source[i]>> 6)&0x1f],ARG2_REG);
    emit_call((int)cvt_l_d);
  }
  
  if(opcode2[i]==0x10&&(source[i]&0x3f)==0x08) {
    emit_readword((int)&reg_cop1_simple[(source[i]>>11)&0x1f],ARG1_REG);
    emit_readword((int)&reg_cop1_double[(source[i]>> 6)&0x1f],ARG2_REG);
    emit_call((int)round_l_s);
  }
  if(opcode2[i]==0x10&&(source[i]&0x3f)==0x09) {
    emit_readword((int)&reg_cop1_simple[(source[i]>>11)&0x1f],ARG1_REG);
    emit_readword((int)&reg_cop1_double[(source[i]>> 6)&0x1f],ARG2_REG);
    emit_call((int)trunc_l_s);
  }
  if(opcode2[i]==0x10&&(source[i]&0x3f)==0x0a) {
    emit_readword((int)&reg_cop1_simple[(source[i]>>11)&0x1f],ARG1_REG);
    emit_readword((int)&reg_cop1_double[(source[i]>> 6)&0x1f],ARG2_REG);
    emit_call((int)ceil_l_s);
  }
  if(opcode2[i]==0x10&&(source[i]&0x3f)==0x0b) {
    emit_readword((int)&reg_cop1_simple[(source[i]>>11)&0x1f],ARG1_REG);
    emit_readword((int)&reg_cop1_double[(source[i]>> 6)&0x1f],ARG2_REG);
    emit_call((int)floor_l_s);
  }
  if(opcode2[i]==0x10&&(source[i]&0x3f)==0x0c) {
    emit_readword((int)&reg_cop1_simple[(source[i]>>11)&0x1f],ARG1_REG);
    emit_readword((int)&reg_cop1_simple[(source[i]>> 6)&0x1f],ARG2_REG);
    emit_call((int)round_w_s);
  }
  if(opcode2[i]==0x10&&(source[i]&0x3f)==0x0d) {
    emit_readword((int)&reg_cop1_simple[(source[i]>>11)&0x1f],ARG1_REG);
    emit_readword((int)&reg_cop1_simple[(source[i]>> 6)&0x1f],ARG2_REG);
    emit_call((int)trunc_w_s);
  }
  if(opcode2[i]==0x10&&(source[i]&0x3f)==0x0e) {
    emit_readword((int)&reg_cop1_simple[(source[i]>>11)&0x1f],ARG1_REG);
    emit_readword((int)&reg_cop1_simple[(source[i]>> 6)&0x1f],ARG2_REG);
    emit_call((int)ceil_w_s);
  }
  if(opcode2[i]==0x10&&(source[i]&0x3f)==0x0f) {
    emit_readword((int)&reg_cop1_simple[(source[i]>>11)&0x1f],ARG1_REG);
    emit_readword((int)&reg_cop1_simple[(source[i]>> 6)&0x1f],ARG2_REG);
    emit_call((int)floor_w_s);
  }
  
  if(opcode2[i]==0x11&&(source[i]&0x3f)==0x08) {
    emit_readword((int)&reg_cop1_double[(source[i]>>11)&0x1f],ARG1_REG);
    emit_readword((int)&reg_cop1_double[(source[i]>> 6)&0x1f],ARG2_REG);
    emit_call((int)round_l_d);
  }
  if(opcode2[i]==0x11&&(source[i]&0x3f)==0x09) {
    emit_readword((int)&reg_cop1_double[(source[i]>>11)&0x1f],ARG1_REG);
    emit_readword((int)&reg_cop1_double[(source[i]>> 6)&0x1f],ARG2_REG);
    emit_call((int)trunc_l_d);
  }
  if(opcode2[i]==0x11&&(source[i]&0x3f)==0x0a) {
    emit_readword((int)&reg_cop1_double[(source[i]>>11)&0x1f],ARG1_REG);
    emit_readword((int)&reg_cop1_double[(source[i]>> 6)&0x1f],ARG2_REG);
    emit_call((int)ceil_l_d);
  }
  if(opcode2[i]==0x11&&(source[i]&0x3f)==0x0b) {
    emit_readword((int)&reg_cop1_double[(source[i]>>11)&0x1f],ARG1_REG);
    emit_readword((int)&reg_cop1_double[(source[i]>> 6)&0x1f],ARG2_REG);
    emit_call((int)floor_l_d);
  }
  if(opcode2[i]==0x11&&(source[i]&0x3f)==0x0c) {
    emit_readword((int)&reg_cop1_double[(source[i]>>11)&0x1f],ARG1_REG);
    emit_readword((int)&reg_cop1_simple[(source[i]>> 6)&0x1f],ARG2_REG);
    emit_call((int)round_w_d);
  }
  if(opcode2[i]==0x11&&(source[i]&0x3f)==0x0d) {
    emit_readword((int)&reg_cop1_double[(source[i]>>11)&0x1f],ARG1_REG);
    emit_readword((int)&reg_cop1_simple[(source[i]>> 6)&0x1f],ARG2_REG);
    emit_call((int)trunc_w_d);
  }
  if(opcode2[i]==0x11&&(source[i]&0x3f)==0x0e) {
    emit_readword((int)&reg_cop1_double[(source[i]>>11)&0x1f],ARG1_REG);
    emit_readword((int)&reg_cop1_simple[(source[i]>> 6)&0x1f],ARG2_REG);
    emit_call((int)ceil_w_d);
  }
  if(opcode2[i]==0x11&&(source[i]&0x3f)==0x0f) {
    emit_readword((int)&reg_cop1_double[(source[i]>>11)&0x1f],ARG1_REG);
    emit_readword((int)&reg_cop1_simple[(source[i]>> 6)&0x1f],ARG2_REG);
    emit_call((int)floor_w_d);
  }
  
  restore_regs(reglist);
}
#define fconv_assemble fconv_assemble_arm64

static void fcomp_assemble(int i,struct regstat *i_regs)
{
  assert(0);
  signed char fs=get_reg(i_regs->regmap,FSREG);
  signed char temp=get_reg(i_regs->regmap,-1);
  assert(temp>=0);
  // Check cop1 unusable
  if(!cop1_usable) {
    signed char cs=get_reg(i_regs->regmap,CSREG);
    assert(cs>=0);
    emit_testimm(cs,0x20000000);
    int jaddr=(int)out;
    emit_jeq(0);
    add_stub(FP_STUB,jaddr,(intptr_t)out,i,cs,(intptr_t)i_regs,is_delayslot,0);
    cop1_usable=1;
  }
  
  if((source[i]&0x3f)==0x30) {
    emit_andimm(fs,~0x800000,fs);
    return;
  }
  
  if((source[i]&0x3e)==0x38) {
    // sf/ngle - these should throw exceptions for NaNs
    emit_andimm(fs,~0x800000,fs);
    return;
  }
  
  #if (defined(__VFP_FP__) && !defined(__SOFTFP__)) 
  if(opcode2[i]==0x10) {
    emit_readword((int)&reg_cop1_simple[(source[i]>>11)&0x1f],temp);
    emit_readword((int)&reg_cop1_simple[(source[i]>>16)&0x1f],HOST_TEMPREG);
    emit_orimm(fs,0x800000,fs);
    emit_flds(temp,14);
    emit_flds(HOST_TEMPREG,15);
    emit_fcmps(14,15);
    emit_fmstat();
    if((source[i]&0x3f)==0x31) emit_bicvc_imm(fs,0x800000,fs); // c_un_s
    if((source[i]&0x3f)==0x32) emit_bicne_imm(fs,0x800000,fs); // c_eq_s
    if((source[i]&0x3f)==0x33) {emit_bicne_imm(fs,0x800000,fs);emit_orrvs_imm(fs,0x800000,fs);} // c_ueq_s
    if((source[i]&0x3f)==0x34) emit_biccs_imm(fs,0x800000,fs); // c_olt_s
    if((source[i]&0x3f)==0x35) {emit_biccs_imm(fs,0x800000,fs);emit_orrvs_imm(fs,0x800000,fs);} // c_ult_s 
    if((source[i]&0x3f)==0x36) emit_bichi_imm(fs,0x800000,fs); // c_ole_s
    if((source[i]&0x3f)==0x37) {emit_bichi_imm(fs,0x800000,fs);emit_orrvs_imm(fs,0x800000,fs);} // c_ule_s
    if((source[i]&0x3f)==0x3a) emit_bicne_imm(fs,0x800000,fs); // c_seq_s
    if((source[i]&0x3f)==0x3b) emit_bicne_imm(fs,0x800000,fs); // c_ngl_s
    if((source[i]&0x3f)==0x3c) emit_biccs_imm(fs,0x800000,fs); // c_lt_s
    if((source[i]&0x3f)==0x3d) emit_biccs_imm(fs,0x800000,fs); // c_nge_s
    if((source[i]&0x3f)==0x3e) emit_bichi_imm(fs,0x800000,fs); // c_le_s
    if((source[i]&0x3f)==0x3f) emit_bichi_imm(fs,0x800000,fs); // c_ngt_s
    return;
  }
  if(opcode2[i]==0x11) {
    emit_readword((int)&reg_cop1_double[(source[i]>>11)&0x1f],temp);
    emit_readword((int)&reg_cop1_double[(source[i]>>16)&0x1f],HOST_TEMPREG);
    emit_orimm(fs,0x800000,fs);
    emit_vldr(temp,6);
    emit_vldr(HOST_TEMPREG,7);
    emit_fcmpd(6,7);
    emit_fmstat();
    if((source[i]&0x3f)==0x31) emit_bicvc_imm(fs,0x800000,fs); // c_un_d
    if((source[i]&0x3f)==0x32) emit_bicne_imm(fs,0x800000,fs); // c_eq_d
    if((source[i]&0x3f)==0x33) {emit_bicne_imm(fs,0x800000,fs);emit_orrvs_imm(fs,0x800000,fs);} // c_ueq_d
    if((source[i]&0x3f)==0x34) emit_biccs_imm(fs,0x800000,fs); // c_olt_d
    if((source[i]&0x3f)==0x35) {emit_biccs_imm(fs,0x800000,fs);emit_orrvs_imm(fs,0x800000,fs);} // c_ult_d
    if((source[i]&0x3f)==0x36) emit_bichi_imm(fs,0x800000,fs); // c_ole_d
    if((source[i]&0x3f)==0x37) {emit_bichi_imm(fs,0x800000,fs);emit_orrvs_imm(fs,0x800000,fs);} // c_ule_d
    if((source[i]&0x3f)==0x3a) emit_bicne_imm(fs,0x800000,fs); // c_seq_d
    if((source[i]&0x3f)==0x3b) emit_bicne_imm(fs,0x800000,fs); // c_ngl_d
    if((source[i]&0x3f)==0x3c) emit_biccs_imm(fs,0x800000,fs); // c_lt_d
    if((source[i]&0x3f)==0x3d) emit_biccs_imm(fs,0x800000,fs); // c_nge_d
    if((source[i]&0x3f)==0x3e) emit_bichi_imm(fs,0x800000,fs); // c_le_d
    if((source[i]&0x3f)==0x3f) emit_bichi_imm(fs,0x800000,fs); // c_ngt_d
    return;
  }
  #endif
  
  // C only
  
  u_int hr,reglist=0;
  for(hr=0;hr<HOST_REGS;hr++) {
    if(i_regs->regmap[hr]>=0) reglist|=1<<hr;
  }
  reglist&=~(1<<fs);
  save_regs(reglist);
  if(opcode2[i]==0x10) {
    emit_readword((int)&reg_cop1_simple[(source[i]>>11)&0x1f],ARG1_REG);
    emit_readword((int)&reg_cop1_simple[(source[i]>>16)&0x1f],ARG2_REG);
    if((source[i]&0x3f)==0x30) emit_call((int)c_f_s);
    if((source[i]&0x3f)==0x31) emit_call((int)c_un_s);
    if((source[i]&0x3f)==0x32) emit_call((int)c_eq_s);
    if((source[i]&0x3f)==0x33) emit_call((int)c_ueq_s);
    if((source[i]&0x3f)==0x34) emit_call((int)c_olt_s);
    if((source[i]&0x3f)==0x35) emit_call((int)c_ult_s);
    if((source[i]&0x3f)==0x36) emit_call((int)c_ole_s);
    if((source[i]&0x3f)==0x37) emit_call((int)c_ule_s);
    if((source[i]&0x3f)==0x38) emit_call((int)c_sf_s);
    if((source[i]&0x3f)==0x39) emit_call((int)c_ngle_s);
    if((source[i]&0x3f)==0x3a) emit_call((int)c_seq_s);
    if((source[i]&0x3f)==0x3b) emit_call((int)c_ngl_s);
    if((source[i]&0x3f)==0x3c) emit_call((int)c_lt_s);
    if((source[i]&0x3f)==0x3d) emit_call((int)c_nge_s);
    if((source[i]&0x3f)==0x3e) emit_call((int)c_le_s);
    if((source[i]&0x3f)==0x3f) emit_call((int)c_ngt_s);
  }
  if(opcode2[i]==0x11) {
    emit_readword((int)&reg_cop1_double[(source[i]>>11)&0x1f],ARG1_REG);
    emit_readword((int)&reg_cop1_double[(source[i]>>16)&0x1f],ARG2_REG);
    if((source[i]&0x3f)==0x30) emit_call((int)c_f_d);
    if((source[i]&0x3f)==0x31) emit_call((int)c_un_d);
    if((source[i]&0x3f)==0x32) emit_call((int)c_eq_d);
    if((source[i]&0x3f)==0x33) emit_call((int)c_ueq_d);
    if((source[i]&0x3f)==0x34) emit_call((int)c_olt_d);
    if((source[i]&0x3f)==0x35) emit_call((int)c_ult_d);
    if((source[i]&0x3f)==0x36) emit_call((int)c_ole_d);
    if((source[i]&0x3f)==0x37) emit_call((int)c_ule_d);
    if((source[i]&0x3f)==0x38) emit_call((int)c_sf_d);
    if((source[i]&0x3f)==0x39) emit_call((int)c_ngle_d);
    if((source[i]&0x3f)==0x3a) emit_call((int)c_seq_d);
    if((source[i]&0x3f)==0x3b) emit_call((int)c_ngl_d);
    if((source[i]&0x3f)==0x3c) emit_call((int)c_lt_d);
    if((source[i]&0x3f)==0x3d) emit_call((int)c_nge_d);
    if((source[i]&0x3f)==0x3e) emit_call((int)c_le_d);
    if((source[i]&0x3f)==0x3f) emit_call((int)c_ngt_d);
  }
  restore_regs(reglist);
  emit_loadreg(FSREG,fs);
}

static void float_assemble(int i,struct regstat *i_regs)
{
  assert(0);
  signed char temp=get_reg(i_regs->regmap,-1);
  assert(temp>=0);
  // Check cop1 unusable
  if(!cop1_usable) {
    signed char cs=get_reg(i_regs->regmap,CSREG);
    assert(cs>=0);
    emit_testimm(cs,0x20000000);
    int jaddr=(int)out;
    emit_jeq(0);
    add_stub(FP_STUB,jaddr,(intptr_t)out,i,cs,(intptr_t)i_regs,is_delayslot,0);
    cop1_usable=1;
  }
  
  #if (defined(__VFP_FP__) && !defined(__SOFTFP__)) 
  if((source[i]&0x3f)==6) // mov
  {
    if(((source[i]>>11)&0x1f)!=((source[i]>>6)&0x1f)) {
      if(opcode2[i]==0x10) {
        emit_readword((int)&reg_cop1_simple[(source[i]>>11)&0x1f],temp);
        emit_readword((int)&reg_cop1_simple[(source[i]>>6)&0x1f],HOST_TEMPREG);
        emit_readword_indexed(0,temp,temp);
        emit_writeword_indexed(temp,0,HOST_TEMPREG);
      }
      if(opcode2[i]==0x11) {
        emit_readword((int)&reg_cop1_double[(source[i]>>11)&0x1f],temp);
        emit_readword((int)&reg_cop1_double[(source[i]>>6)&0x1f],HOST_TEMPREG);
        emit_vldr(temp,7);
        emit_vstr(7,HOST_TEMPREG);
      }
    }
    return;
  }
  
  if((source[i]&0x3f)>3)
  {
    if(opcode2[i]==0x10) {
      emit_readword((int)&reg_cop1_simple[(source[i]>>11)&0x1f],temp);
      emit_flds(temp,15);
      if(((source[i]>>11)&0x1f)!=((source[i]>>6)&0x1f)) {
        emit_readword((int)&reg_cop1_simple[(source[i]>>6)&0x1f],temp);
      }
      if((source[i]&0x3f)==4) // sqrt
        emit_fsqrts(15,15);
      if((source[i]&0x3f)==5) // abs
        emit_fabss(15,15);
      if((source[i]&0x3f)==7) // neg
        emit_fnegs(15,15);
      emit_fsts(15,temp);
    }
    if(opcode2[i]==0x11) {
      emit_readword((int)&reg_cop1_double[(source[i]>>11)&0x1f],temp);
      emit_vldr(temp,7);
      if(((source[i]>>11)&0x1f)!=((source[i]>>6)&0x1f)) {
        emit_readword((int)&reg_cop1_double[(source[i]>>6)&0x1f],temp);
      }
      if((source[i]&0x3f)==4) // sqrt
        emit_fsqrtd(7,7);
      if((source[i]&0x3f)==5) // abs
        emit_fabsd(7,7);
      if((source[i]&0x3f)==7) // neg
        emit_fnegd(7,7);
      emit_vstr(7,temp);
    }
    return;
  }
  if((source[i]&0x3f)<4)
  {
    if(opcode2[i]==0x10) {
      emit_readword((int)&reg_cop1_simple[(source[i]>>11)&0x1f],temp);
    }
    if(opcode2[i]==0x11) {
      emit_readword((int)&reg_cop1_double[(source[i]>>11)&0x1f],temp);
    }
    if(((source[i]>>11)&0x1f)!=((source[i]>>16)&0x1f)) {
      if(opcode2[i]==0x10) {
        emit_readword((int)&reg_cop1_simple[(source[i]>>16)&0x1f],HOST_TEMPREG);
        emit_flds(temp,15);
        emit_flds(HOST_TEMPREG,13);
        if(((source[i]>>11)&0x1f)!=((source[i]>>6)&0x1f)) {
          if(((source[i]>>16)&0x1f)!=((source[i]>>6)&0x1f)) {
            emit_readword((int)&reg_cop1_simple[(source[i]>>6)&0x1f],temp);
          }
        }
        if((source[i]&0x3f)==0) emit_fadds(15,13,15);
        if((source[i]&0x3f)==1) emit_fsubs(15,13,15);
        if((source[i]&0x3f)==2) emit_fmuls(15,13,15);
        if((source[i]&0x3f)==3) emit_fdivs(15,13,15);
        if(((source[i]>>16)&0x1f)==((source[i]>>6)&0x1f)) {
          emit_fsts(15,HOST_TEMPREG);
        }else{
          emit_fsts(15,temp);
        }
      }
      else if(opcode2[i]==0x11) {
        emit_readword((int)&reg_cop1_double[(source[i]>>16)&0x1f],HOST_TEMPREG);
        emit_vldr(temp,7);
        emit_vldr(HOST_TEMPREG,6);
        if(((source[i]>>11)&0x1f)!=((source[i]>>6)&0x1f)) {
          if(((source[i]>>16)&0x1f)!=((source[i]>>6)&0x1f)) {
            emit_readword((int)&reg_cop1_double[(source[i]>>6)&0x1f],temp);
          }
        }
        if((source[i]&0x3f)==0) emit_faddd(7,6,7);
        if((source[i]&0x3f)==1) emit_fsubd(7,6,7);
        if((source[i]&0x3f)==2) emit_fmuld(7,6,7);
        if((source[i]&0x3f)==3) emit_fdivd(7,6,7);
        if(((source[i]>>16)&0x1f)==((source[i]>>6)&0x1f)) {
          emit_vstr(7,HOST_TEMPREG);
        }else{
          emit_vstr(7,temp);
        }
      }
    }
    else {
      if(opcode2[i]==0x10) {
        emit_flds(temp,15);
        if(((source[i]>>11)&0x1f)!=((source[i]>>6)&0x1f)) {
          emit_readword((int)&reg_cop1_simple[(source[i]>>6)&0x1f],temp);
        }
        if((source[i]&0x3f)==0) emit_fadds(15,15,15);
        if((source[i]&0x3f)==1) emit_fsubs(15,15,15);
        if((source[i]&0x3f)==2) emit_fmuls(15,15,15);
        if((source[i]&0x3f)==3) emit_fdivs(15,15,15);
        emit_fsts(15,temp);
      }
      else if(opcode2[i]==0x11) {
        emit_vldr(temp,7);
        if(((source[i]>>11)&0x1f)!=((source[i]>>6)&0x1f)) {
          emit_readword((int)&reg_cop1_double[(source[i]>>6)&0x1f],temp);
        }
        if((source[i]&0x3f)==0) emit_faddd(7,7,7);
        if((source[i]&0x3f)==1) emit_fsubd(7,7,7);
        if((source[i]&0x3f)==2) emit_fmuld(7,7,7);
        if((source[i]&0x3f)==3) emit_fdivd(7,7,7);
        emit_vstr(7,temp);
      }
    }
    return;
  }
  #endif
  
  u_int hr,reglist=0;
  for(hr=0;hr<HOST_REGS;hr++) {
    if(i_regs->regmap[hr]>=0) reglist|=1<<hr;
  }
  if(opcode2[i]==0x10) { // Single precision
    save_regs(reglist);
    emit_readword((int)&reg_cop1_simple[(source[i]>>11)&0x1f],ARG1_REG);
    if((source[i]&0x3f)<4) {
      emit_readword((int)&reg_cop1_simple[(source[i]>>16)&0x1f],ARG2_REG);
      emit_readword((int)&reg_cop1_simple[(source[i]>> 6)&0x1f],ARG3_REG);
    }else{
      emit_readword((int)&reg_cop1_simple[(source[i]>> 6)&0x1f],ARG2_REG);
    }
    switch(source[i]&0x3f)
    {
      case 0x00: emit_call((int)add_s);break;
      case 0x01: emit_call((int)sub_s);break;
      case 0x02: emit_call((int)mul_s);break;
      case 0x03: emit_call((int)div_s);break;
      case 0x04: emit_call((int)sqrt_s);break;
      case 0x05: emit_call((int)abs_s);break;
      case 0x06: emit_call((int)mov_s);break;
      case 0x07: emit_call((int)neg_s);break;
    }
    restore_regs(reglist);
  }
  if(opcode2[i]==0x11) { // Double precision
    save_regs(reglist);
    emit_readword((int)&reg_cop1_double[(source[i]>>11)&0x1f],ARG1_REG);
    if((source[i]&0x3f)<4) {
      emit_readword((int)&reg_cop1_double[(source[i]>>16)&0x1f],ARG2_REG);
      emit_readword((int)&reg_cop1_double[(source[i]>> 6)&0x1f],ARG3_REG);
    }else{
      emit_readword((int)&reg_cop1_double[(source[i]>> 6)&0x1f],ARG2_REG);
    }
    switch(source[i]&0x3f)
    {
      case 0x00: emit_call((int)add_d);break;
      case 0x01: emit_call((int)sub_d);break;
      case 0x02: emit_call((int)mul_d);break;
      case 0x03: emit_call((int)div_d);break;
      case 0x04: emit_call((int)sqrt_d);break;
      case 0x05: emit_call((int)abs_d);break;
      case 0x06: emit_call((int)mov_d);break;
      case 0x07: emit_call((int)neg_d);break;
    }
    restore_regs(reglist);
  }
}

void multdiv_alloc_arm64(struct regstat *current,int i)
{
  //  case 0x18: MULT
  //  case 0x19: MULTU
  //  case 0x1A: DIV
  //  case 0x1B: DIVU
  //  case 0x1C: DMULT
  //  case 0x1D: DMULTU
  //  case 0x1E: DDIV
  //  case 0x1F: DDIVU
  clear_const(current,rs1[i]);
  clear_const(current,rs2[i]);
  if(rs1[i]&&rs2[i])
  {
    if((opcode2[i]&4)==0) // 32-bit
    {
      current->u&=~(1LL<<HIREG);
      current->u&=~(1LL<<LOREG);
      alloc_reg(current,i,HIREG);
      alloc_reg(current,i,LOREG);
      alloc_reg(current,i,rs1[i]);
      alloc_reg(current,i,rs2[i]);
      current->is32|=1LL<<HIREG;
      current->is32|=1LL<<LOREG;
      dirty_reg(current,HIREG);
      dirty_reg(current,LOREG);
    }
    else // 64-bit
    {
      current->u&=~(1LL<<HIREG);
      current->u&=~(1LL<<LOREG);
      current->uu&=~(1LL<<HIREG);
      current->uu&=~(1LL<<LOREG);
      alloc_reg64(current,i,HIREG);
      alloc_reg64(current,i,LOREG);
      alloc_reg64(current,i,rs1[i]);
      alloc_reg64(current,i,rs2[i]);
      current->is32&=~(1LL<<HIREG);
      current->is32&=~(1LL<<LOREG);
      dirty_reg(current,HIREG);
      dirty_reg(current,LOREG);
    }
  }
  else
  {
    // Multiply by zero is zero.
    // MIPS does not have a divide by zero exception.
    // The result is undefined, we return zero.
    alloc_reg(current,i,HIREG);
    alloc_reg(current,i,LOREG);
    current->is32|=1LL<<HIREG;
    current->is32|=1LL<<LOREG;
    dirty_reg(current,HIREG);
    dirty_reg(current,LOREG);
  }
}
#define multdiv_alloc multdiv_alloc_arm64

static void multdiv_assemble_arm64(int i,struct regstat *i_regs)
{
  //  case 0x18: MULT
  //  case 0x19: MULTU
  //  case 0x1A: DIV
  //  case 0x1B: DIVU
  //  case 0x1C: DMULT
  //  case 0x1D: DMULTU
  //  case 0x1E: DDIV
  //  case 0x1F: DDIVU
  if(rs1[i]&&rs2[i])
  {
    if((opcode2[i]&4)==0) // 32-bit
    {
      if(opcode2[i]==0x18) // MULT
      {
        assert(0);
        signed char m1=get_reg(i_regs->regmap,rs1[i]);
        signed char m2=get_reg(i_regs->regmap,rs2[i]);
        signed char high=get_reg(i_regs->regmap,HIREG);
        signed char low=get_reg(i_regs->regmap,LOREG);
        assert(m1>=0);
        assert(m2>=0);
        assert(high>=0);
        assert(low>=0);
        emit_smull(m1,m2,high,low);
      }
      if(opcode2[i]==0x19) // MULTU
      {
        signed char m1=get_reg(i_regs->regmap,rs1[i]);
        signed char m2=get_reg(i_regs->regmap,rs2[i]);
        signed char high=get_reg(i_regs->regmap,HIREG);
        signed char low=get_reg(i_regs->regmap,LOREG);
        assert(m1>=0);
        assert(m2>=0);
        assert(high>=0);
        assert(low>=0);
        emit_umull(m1,m2,HOST_TEMPREG);
        emit_mov(HOST_TEMPREG,low);
        emit_shrimm64(HOST_TEMPREG,32,high);
      }
      if(opcode2[i]==0x1A) // DIV
      {
        assert(0);
        signed char d1=get_reg(i_regs->regmap,rs1[i]); // dividend
        signed char d2=get_reg(i_regs->regmap,rs2[i]); // divisor
        assert(d1>=0);
        assert(d2>=0);
        signed char quotient=get_reg(i_regs->regmap,LOREG);
        signed char remainder=get_reg(i_regs->regmap,HIREG);
        assert(quotient>=0);
        assert(remainder>=0);

        //if(arm_cpu_features.IDIVa)
        if(1)
        {
          emit_test(d2,d2);
          emit_jeq((int)out+16); // Division by zero
          emit_sdiv(d1,d2,quotient);
          emit_mul(quotient,d2,remainder);
          emit_sub(d1,remainder,remainder);
        }
        else
        {
          emit_movs(d1,remainder);
          emit_negmi(remainder,remainder);
          emit_movs(d2,HOST_TEMPREG);
          emit_jeq((int)out+52); // Division by zero
          emit_negmi(HOST_TEMPREG,HOST_TEMPREG);
          emit_clz(HOST_TEMPREG,quotient);
          emit_shl(HOST_TEMPREG,quotient,HOST_TEMPREG);
          emit_orimm(quotient,1<<31,quotient);
          emit_shr(quotient,quotient,quotient);
          emit_cmp(remainder,HOST_TEMPREG);
          emit_subcs(remainder,HOST_TEMPREG,remainder);
          emit_adcs(quotient,quotient,quotient);
          emit_shrimm(HOST_TEMPREG,1,HOST_TEMPREG);
          emit_jcc((int)out-16); // -4
          emit_teq(d1,d2);
          emit_negmi(quotient,quotient);
          emit_test(d1,d1);
          emit_negmi(remainder,remainder);
        }
      }
      if(opcode2[i]==0x1B) // DIVU
      {
        assert(0);
        signed char d1=get_reg(i_regs->regmap,rs1[i]); // dividend
        signed char d2=get_reg(i_regs->regmap,rs2[i]); // divisor
        assert(d1>=0);
        assert(d2>=0);
        signed char quotient=get_reg(i_regs->regmap,LOREG);
        signed char remainder=get_reg(i_regs->regmap,HIREG);
        assert(quotient>=0);
        assert(remainder>=0);
        emit_test(d2,d2);

        //if(arm_cpu_features.IDIVa)
        if(1)
        {
          emit_jeq((int)out+16); // Division by zero
          emit_udiv(d1,d2,quotient);
          emit_mul(quotient,d2,remainder);
          emit_sub(d1,remainder,remainder);
        }
        else
        {
          emit_jeq((int)out+44); // Division by zero
          emit_clz(d2,HOST_TEMPREG);
          emit_movimm(1<<31,quotient);
          emit_shl(d2,HOST_TEMPREG,d2);
          emit_mov(d1,remainder);
          emit_shr(quotient,HOST_TEMPREG,quotient);
          emit_cmp(remainder,d2);
          emit_subcs(remainder,d2,remainder);
          emit_adcs(quotient,quotient,quotient);
          emit_shrcc_imm(d2,1,d2);
          emit_jcc((int)out-16); // -4
        }
      }
    }
    else // 64-bit
    {
      if(opcode2[i]==0x1C) // DMULT
      {
        assert(0);
        signed char m1h=get_reg(i_regs->regmap,rs1[i]|64);
        signed char m1l=get_reg(i_regs->regmap,rs1[i]);
        signed char m2h=get_reg(i_regs->regmap,rs2[i]|64);
        signed char m2l=get_reg(i_regs->regmap,rs2[i]);
        assert(m1h>=0);
        assert(m2h>=0);
        assert(m1l>=0);
        assert(m2l>=0);
        signed char rh=get_reg(i_regs->regmap,HIREG|64);
        signed char rl=get_reg(i_regs->regmap,HIREG);
        assert(rh>=0);
        assert(rl>=0);

        /*emit_umull(m1l,m2l,rh,rl);
        emit_storereg(LOREG,rl);
        emit_mov(rh,rl);
        emit_zeroreg(rh);
        emit_smlal(m1l,m2h,rh,rl);
        emit_mov(rh,HOST_TEMPREG);
        emit_testimm(m1l,0x80000000);
        emit_addne(HOST_TEMPREG,m2h,HOST_TEMPREG);
        emit_zeroreg(rh);
        emit_smlal(m1h,m2l,rh,rl);
        emit_testimm(m2l,0x80000000);
        emit_addne(rh,m1h,rh);
        emit_storereg(LOREG|64,rl);
        emit_sarimm(HOST_TEMPREG,31,rl);
        emit_adds(HOST_TEMPREG,rh,HOST_TEMPREG);
        emit_addsarimm(rl,rh,rh,31);
        emit_mov(HOST_TEMPREG,rl);
        emit_smlal(m1h,m2h,rh,rl);*/
      }
      if(opcode2[i]==0x1D) // DMULTU
      {
        signed char m1h=get_reg(i_regs->regmap,rs1[i]|64);
        signed char m1l=get_reg(i_regs->regmap,rs1[i]);
        signed char m2h=get_reg(i_regs->regmap,rs2[i]|64);
        signed char m2l=get_reg(i_regs->regmap,rs2[i]);
        assert(m1h>=0);
        assert(m2h>=0);
        assert(m1l>=0);
        assert(m2l>=0);
        signed char hih=get_reg(i_regs->regmap,HIREG|64);
        signed char hil=get_reg(i_regs->regmap,HIREG);
        signed char loh=get_reg(i_regs->regmap,LOREG|64);
        signed char lol=get_reg(i_regs->regmap,LOREG);
        assert(hih>=0);
        assert(hil>=0);
        assert(loh>=0);
        assert(lol>=0);
        emit_mov(m1l,lol);
        emit_orrshl64(m1h,32,lol);
        emit_mov(m2l,loh);
        emit_orrshl64(m2h,32,loh);
        emit_mul64(lol,loh,hil);
        emit_umulh(lol,loh,hih);
        emit_mov(hil,lol);
        emit_shrimm64(hil,32,loh);
        emit_mov(hih,hil);
        emit_shrimm64(hih,32,hih);
      }
      if(opcode2[i]==0x1E) // DDIV
      {
        assert(0);
        signed char d1h=get_reg(i_regs->regmap,rs1[i]|64);
        signed char d1l=get_reg(i_regs->regmap,rs1[i]);
        signed char d2h=get_reg(i_regs->regmap,rs2[i]|64);
        signed char d2l=get_reg(i_regs->regmap,rs2[i]);
        assert(d1h>=0);
        assert(d2h>=0);
        assert(d1l>=0);
        assert(d2l>=0);
        save_regs(0x7ffff);
        if(d1l!=0) emit_mov(d1l,0);
        if(d1h==0) emit_readword((int)&dynarec_local,1);
        else if(d1h>1) emit_mov(d1h,1);
        if(d2l<2) emit_readword((int)&dynarec_local+d2l*4,2);
        else if(d2l>2) emit_mov(d2l,2);
        if(d2h<3) emit_readword((int)&dynarec_local+d2h*4,3);
        else if(d2h>3) emit_mov(d2h,3);
        emit_call((int)&div64);
        restore_regs(0x7ffff);
        signed char hih=get_reg(i_regs->regmap,HIREG|64);
        signed char hil=get_reg(i_regs->regmap,HIREG);
        signed char loh=get_reg(i_regs->regmap,LOREG|64);
        signed char lol=get_reg(i_regs->regmap,LOREG);
        if(hih>=0) emit_loadreg(HIREG|64,hih);
        if(hil>=0) emit_loadreg(HIREG,hil);
        if(loh>=0) emit_loadreg(LOREG|64,loh);
        if(lol>=0) emit_loadreg(LOREG,lol);
      }
      if(opcode2[i]==0x1F) // DDIVU
      {
        assert(0);
      //u_int hr,reglist=0;
      //for(hr=0;hr<HOST_REGS;hr++) {
      //  if(i_regs->regmap[hr]>=0 && (i_regs->regmap[hr]&62)!=HIREG) reglist|=1<<hr;
      //}
        signed char d1h=get_reg(i_regs->regmap,rs1[i]|64);
        signed char d1l=get_reg(i_regs->regmap,rs1[i]);
        signed char d2h=get_reg(i_regs->regmap,rs2[i]|64);
        signed char d2l=get_reg(i_regs->regmap,rs2[i]);
        assert(d1h>=0);
        assert(d2h>=0);
        assert(d1l>=0);
        assert(d2l>=0);
        save_regs(0x7ffff);
        if(d1l!=0) emit_mov(d1l,0);
        if(d1h==0) emit_readword((int)&dynarec_local,1);
        else if(d1h>1) emit_mov(d1h,1);
        if(d2l<2) emit_readword((int)&dynarec_local+d2l*4,2);
        else if(d2l>2) emit_mov(d2l,2);
        if(d2h<3) emit_readword((int)&dynarec_local+d2h*4,3);
        else if(d2h>3) emit_mov(d2h,3);
        emit_call((int)&divu64);
        restore_regs(0x7ffff);
        signed char hih=get_reg(i_regs->regmap,HIREG|64);
        signed char hil=get_reg(i_regs->regmap,HIREG);
        signed char loh=get_reg(i_regs->regmap,LOREG|64);
        signed char lol=get_reg(i_regs->regmap,LOREG);
        if(hih>=0) emit_loadreg(HIREG|64,hih);
        if(hil>=0) emit_loadreg(HIREG,hil);
        if(loh>=0) emit_loadreg(LOREG|64,loh);
        if(lol>=0) emit_loadreg(LOREG,lol);
      }
    }
  }
  else
  {
    // Multiply by zero is zero.
    // MIPS does not have a divide by zero exception.
    // The result is undefined, we return zero.
    signed char hr=get_reg(i_regs->regmap,HIREG);
    signed char lr=get_reg(i_regs->regmap,LOREG);
    if(hr>=0) emit_zeroreg(hr);
    if(lr>=0) emit_zeroreg(lr);
  }
}
#define multdiv_assemble multdiv_assemble_arm64

static void do_preload_rhash(int r) {
  // Don't need this for ARM64.  On x86, this puts the value 0xf8 into the
  // register. On ARM64 the hash can be done with a single instruction (below)
}

static void do_preload_rhtbl(int ht) {
  emit_addimm64(FP,(intptr_t)&mini_ht-(intptr_t)&dynarec_local,ht);
}

static void do_rhash(int rs,int rh) {
  emit_andimm(rs,0xf8,rh);
  emit_shlimm(rh,1,rh);
}

static void do_miniht_load(int ht,int rh) {
  assem_debug("add %s,%s,%s",regname64[ht],regname64[ht],regname64[rh]);
  output_w32(0x8b000000|rh<<16|ht<<5|ht);
  assem_debug("ldr %s,[%s]",regname[rh],regname64[ht]);
  output_w32(0xb9400000|ht<<5|rh);
}

static void do_miniht_jump(int rs,int rh,int ht) {
  emit_cmp(rh,rs);
  #ifdef CORTEX_A8_BRANCH_PREDICTION_HACK
  emit_jeq((intptr_t)out+12);
  emit_mov(rs,7);
  emit_jmp(jump_vaddr_reg[7]);
  #else
  emit_jeq((intptr_t)out+8);
  emit_jmp(jump_vaddr_reg[rs]);
  #endif
  assem_debug("ldr %s,[%s,#8]",regname64[ht],regname64[ht]);
  output_w32(0xf9400000|(8>>3)<<10|ht<<5|ht);
  emit_jmpreg(ht);
}

static void do_miniht_insert(u_int return_address,int rt,int temp) {
  emit_movz_lsl16((return_address>>16)&0xffff,rt);
  emit_movk(return_address&0xffff,rt);
  add_to_linker((intptr_t)out,return_address,1);
  emit_adr((intptr_t)out,temp);
  emit_writeword64(temp,(intptr_t)&mini_ht[(return_address&0xFF)>>3][1]);
  emit_writeword(rt,(intptr_t)&mini_ht[(return_address&0xFF)>>3][0]);
}

// Sign-extend to 64 bits and write out upper half of a register
// This is useful where we have a 32-bit value in a register, and want to
// keep it in a 32-bit register, but can't guarantee that it won't be read
// as a 64-bit value later.
static void wb_sx(signed char pre[],signed char entry[],uint64_t dirty,uint64_t is32_pre,uint64_t is32,uint64_t u,uint64_t uu)
{
  if(is32_pre==is32) return;
  int hr,tr;
  for(hr=0;hr<HOST_REGS;hr++) {
    if(hr!=EXCLUDE_REG) {
      //if(pre[hr]==entry[hr]) {
        if((tr=pre[hr])>=0) {
          if((dirty>>hr)&1) {
            if( ((is32_pre&~is32&~uu)>>tr)&1 ) {
              emit_sarimm(hr,31,HOST_TEMPREG);
              emit_storereg(tr|64,HOST_TEMPREG);
            }
          }
        }
      //}
    }
  }
}

static void wb_valid(signed char pre[],signed char entry[],u_int dirty_pre,u_int dirty,uint64_t is32_pre,uint64_t u,uint64_t uu)
{
  //if(dirty_pre==dirty) return;
  int hr,tr;
  for(hr=0;hr<HOST_REGS;hr++) {
    if(hr!=EXCLUDE_REG) {
      tr=pre[hr];
      if(((~u)>>(tr&63))&1) {
        if(tr>0) {
          if(((dirty_pre&~dirty)>>hr)&1) {
            if(tr>0&&tr<36) {
              emit_storereg(tr,hr);
              if( ((is32_pre&~uu)>>tr)&1 ) {
                emit_sarimm(hr,31,HOST_TEMPREG);
                emit_storereg(tr|64,HOST_TEMPREG);
              }
            }
            else if(tr>=64) {
              emit_storereg(tr,hr);
            }
          }
        }
      }
    }
  }
}


/* using strd could possibly help but you'd have to allocate registers in pairs
static void wb_invalidate_arm64(signed char pre[],signed char entry[],uint64_t dirty,uint64_t is32,uint64_t u,uint64_t uu)
{
  int hr;
  int wrote=-1;
  for(hr=HOST_REGS-1;hr>=0;hr--) {
    if(hr!=EXCLUDE_REG) {
      if(pre[hr]!=entry[hr]) {
        if(pre[hr]>=0) {
          if((dirty>>hr)&1) {
            if(get_reg(entry,pre[hr])<0) {
              if(pre[hr]<64) {
                if(!((u>>pre[hr])&1)) {
                  if(hr<10&&(~hr&1)&&(pre[hr+1]<0||wrote==hr+1)) {
                    if( ((is32>>pre[hr])&1) && !((uu>>pre[hr])&1) ) {
                      emit_sarimm(hr,31,hr+1);
                      emit_strdreg(pre[hr],hr);
                    }
                    else
                      emit_storereg(pre[hr],hr);
                  }else{
                    emit_storereg(pre[hr],hr);
                    if( ((is32>>pre[hr])&1) && !((uu>>pre[hr])&1) ) {
                      emit_sarimm(hr,31,hr);
                      emit_storereg(pre[hr]|64,hr);
                    }
                  }
                }
              }else{
                if(!((uu>>(pre[hr]&63))&1) && !((is32>>(pre[hr]&63))&1)) {
                  emit_storereg(pre[hr],hr);
                }
              }
              wrote=hr;
            }
          }
        }
      }
    }
  }
  for(hr=0;hr<HOST_REGS;hr++) {
    if(hr!=EXCLUDE_REG) {
      if(pre[hr]!=entry[hr]) {
        if(pre[hr]>=0) {
          int nr;
          if((nr=get_reg(entry,pre[hr]))>=0) {
            emit_mov(hr,nr);
          }
        }
      }
    }
  }
}
#define wb_invalidate wb_invalidate_arm64
*/

// Clearing the cache is rather slow on ARM Linux, so mark the areas
// that need to be cleared, and then only clear these areas once.
static void do_clear_cache(void)
{
  int i,j;
  for (i=0;i<(1<<(TARGET_SIZE_2-17));i++)
  {
    u_int bitmap=needs_clear_cache[i];
    if(bitmap) {
      u_int start,end;
      for(j=0;j<32;j++) 
      {
        if(bitmap&(1<<j)) {
          start=BASE_ADDR+i*131072+j*4096;
          end=start+4095;
          j++;
          while(j<32) {
            if(bitmap&(1<<j)) {
              end+=4096;
              j++;
            }else{
              __clear_cache((void *)start,(void *)end);
              //cacheflush((void *)start,(void *)end,0);
              break;
            }
          }
        }
      }
      needs_clear_cache[i]=0;
    }
  }
}

// CPU-architecture-specific initialization
static void arch_init(void) {
  rounding_modes[0]=0x0<<22; // round
  rounding_modes[1]=0x3<<22; // trunc
  rounding_modes[2]=0x1<<22; // ceil
  rounding_modes[3]=0x2<<22; // floor

  jump_table_symbols[15] = (intptr_t) cached_interpreter_table.MFC0;
  jump_table_symbols[16] = (intptr_t) cached_interpreter_table.MTC0;
  jump_table_symbols[17] = (intptr_t) cached_interpreter_table.TLBR;
  jump_table_symbols[18] = (intptr_t) cached_interpreter_table.TLBP;

  #ifdef RAM_OFFSET
  ram_offset=((intptr_t)g_rdram-(intptr_t)0x80000000)>>2;
  #endif
}
