#---------------------------------------------------------------------
# Debug notification hook test
#
# This script start the executable and steps through the first five
# instructions. Each instruction is disassembled after execution.
#
# Original Author: Gergely Erdelyi <gergely.erdelyi@d-dome.net>
#
# Maintained By: IDAPython Team
#
#---------------------------------------------------------------------
from idaapi import *
import keypatch

patcher=keypatch.Keypatch_Asm()

fun_offset=0x102A0 #函数地址

class MyDbgHook(DBG_Hooks):
    """ Own debug hook class that implementd the callback functions """

    def dbg_process_start(self, pid, tid, ea, name, base, size):
        print("Process started, pid=%d tid=%d name=%s" % (pid, tid, name))
        self.dbg_process_attach(pid, tid, ea, name, base, size)
 
    def dbg_process_exit(self, pid, tid, ea, code):#调试退出时执行
        print("Process exited pid=%d tid=%d ea=0x%x code=%d" % (pid, tid, ea, code))
        for ea in self.related_dict:
            if len(self.related_dict[ea])==1:
                if idc.print_insn_mnem(ea).startswith('B'):
                    disasm='B'+' '+hex(self.related_dict[ea].pop())
                    patcher.patch_code(ea,disasm,patcher.syntax,True,False)
                else:
                    disasm='B'+' '+hex(self.related_dict[ea].pop())
                    patcher.patch_code(idc.next_head(ea),disasm,patcher.syntax,True,False)
            else:
                print(ea,self.related_dict[ea])#该真实块有两个后继真实块,要手动patch
                
 
    def dbg_process_attach(self, pid, tid, ea, name, base, size):
        print("Process attach pid=%d tid=%d ea=0x%x name=%s base=%x size=%x" % (pid, tid, ea, name, base, size))
        self.pre_block=None
        self.related_dict=dict()
        self.block_addr_dict=dict()
        so_base=idaapi.get_imagebase()
        self.f_blocks = idaapi.FlowChart(idaapi.get_func(so_base+fun_offset), flags=idaapi.FC_PREDS)
        for block in self.f_blocks:
            start=block.start_ea
            end=idc.prev_head(block.end_ea)
            # 排除所有的控制块
            if  (end==start) or\
                (idc.print_insn_mnem(start)=='LDR' and idc.print_insn_mnem(idc.next_head(start)).startswith('B')) or \
                (idc.print_insn_mnem(start)=='LDR' and idc.print_insn_mnem(idc.next_head(start))=='CMP' and idc.print_insn_mnem(idc.next_head(idc.next_head(start)))=='MOV' and idc.print_insn_mnem(idc.next_head(idc.next_head(idc.next_head(start)))).startswith('B')) or\
                (idc.print_insn_mnem(start)=='CMP' and idc.print_insn_mnem(idc.next_head(start))=='MOV' and idc.print_insn_mnem(idc.next_head(idc.next_head(start))).startswith('B')) or \
                (idc.print_insn_mnem(start)=='MOV' and idc.print_insn_mnem(idc.next_head(start))=='CMP' and idc.print_insn_mnem(idc.next_head(idc.next_head(start))).startswith('B')) or \
                (idc.print_insn_mnem(start)=='LDR' and idc.print_insn_mnem(idc.next_head(start))=='CMP' and idc.print_insn_mnem(idc.next_head(idc.next_head(start))).startswith('B')) or \
                (idc.print_insn_mnem(start)=='CMP' and idc.print_insn_mnem(idc.next_head(start)).startswith('B')) or \
                (idc.print_insn_mnem(start)=='LDR' and idc.print_insn_mnem(idc.next_head(start))=='CMP' and idc.print_insn_mnem(idc.next_head(idc.next_head(start)))=='MOV'\
                and idc.print_insn_mnem(idc.next_head(idc.next_head(idc.next_head(start)))).startswith('LDR')  \
                and idc.print_insn_mnem(idc.next_head(idc.next_head(idc.next_head(idc.next_head(start))))).startswith('B')
                ) or\
                (idc.print_insn_mnem(start)=='LDR' and idc.print_insn_mnem(idc.next_head(start))=='CMP' and idc.print_insn_mnem(idc.next_head(idc.next_head(start)))=='LDR'\
                and idc.print_insn_mnem(idc.next_head(idc.next_head(idc.next_head(start)))).startswith('B') 
                ):
                continue
            add_bpt(end,0,BPT_SOFT)
            while start<block.end_ea:   #对POP下断点 相当于x86的retn
                if idc.print_insn_mnem(start).startswith('POP'):
                    add_bpt(start,0,BPT_SOFT)
                    break
                start=idc.next_head(start)
                
                
    def dbg_bpt(self, tid, ea):
        print ("Break point at 0x%x pid=%d" % (ea, tid))
        if not self.block_addr_dict:
            so_base=idaapi.get_imagebase()
            blocks=idaapi.FlowChart(idaapi.get_func(so_base+fun_offset), flags=idaapi.FC_PREDS)
            for block in blocks:
                start=block.start_ea
                end=idc.prev_head(block.end_ea)
                self.block_addr_dict[end]=start #把每个cfg图的结尾的开头对应

        if not self.pre_block==None:#self.pre_block是上个真实块的结尾地址
            if self.pre_block in self.related_dict:#说明该真实块有两个后继真实块
                sub_set=self.related_dict[self.pre_block]
                sub_set.add(self.block_addr_dict[ea])
            else:
                # 不存在
                sub_set=set()
                sub_set.add(self.block_addr_dict[ea])
                self.related_dict.update({self.pre_block:sub_set})

        self.pre_block=ea
        if idc.print_insn_mnem(ea).startswith('POP'):
            #调试结束
            return 0
        else:
            idaapi.continue_process()
        return 0
 
 
# Remove an existing debug hook
try:
    if debughook:
        print("Removing previous hook ...")
        debughook.unhook()
except:
    pass
 
# Install the debug hook
debughook = MyDbgHook()
debughook.hook()
debughook.steps = 0
 
# Stop at the entry point
ep = get_inf_attr(INF_START_IP)
request_run_to(ep)
 
# Step one instruction
request_step_over()
 
# Start debugging
run_requests()