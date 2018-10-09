from idaapi import *
import struct

NONE_REG = 0xff

class CustomProcessor(processor_t):
    id = 0x8000 + 0x666
    flag = PR_ADJSEGS | PRN_HEX
    cnbits = 8
    dnbits = 8
    author = "Cih2001"
    psnames = ["cpr"]
    plnames = ["CustomProcessor"]
    segreg_size = 0
    instruc_start = 0
    assembler = {
        "flag": AS_NCHRE | ASH_HEXF0 | ASD_DECF0 | ASO_OCTF0 | ASB_BINF0 | AS_NOTAB,
        "uflag": 0,
        "name": "CustomProcessor",
        "origin": ".org",
        "end": ".end",
        "cmnt": ";",
        "ascsep": '"',
        "accsep": "'",
        "esccodes": "\"'",
        "a_ascii": ".ascii",
        "a_byte": "db",
        "a_word": "dw",
        "a_bss": "dfs %s",
        "a_seg": "seg",
        "a_curip": "PC",
        "a_public": "",
        "a_weak": "",
        "a_extrn": ".extern",
        "a_comdef": "",
        "a_align": ".align",
        "lbrace": "(",
        "rbrace": ")",
        "a_mod": "%",
        "a_band": "&",
        "a_bor": "|",
        "a_xor": "^",
        "a_bnot": "~",
        "a_shl": "<<",
        "a_shr": ">>",
        "a_sizeof_fmt": "size %s",
    }

    reg_names = regNames = ["rip", "rax" , "rbx", "rcx", "rdx", "rsi" ,"rdi" ,"rsp", "rbp", "r8", "r9", "r10", "r11", "r12" ,"r13" ,"r14" ,"r15",
        "eax", "ebx", "ecx", "edx", "esi" ,"edi" ,"esp", "ebp", "r8d", "r9d", "r10d", "r11d", "r12d" ,"r13d" ,"r14d" ,"r15d",
        "ah", "al", "CS", "DS"]

    # Importing instructions
    import CustomProcInstructionSet.Instructions
    instruction_class_list = [(cls) for name, cls in CustomProcInstructionSet.Instructions.__dict__.items() if name.startswith("Instruction")]
    
    instruc = []
    for c in instruction_class_list:
        instruc.append({'name': c.name , 'feature': c.feature })
        
    instruc_end = len(instruc)

    
    def __init__(self):
        processor_t.__init__(self)
        self._init_instructions()
        self._init_registers()

    def _init_instructions(self):
        self.instructions = {}
        for idx, ins in enumerate(self.instruction_class_list):
            self.instructions[idx] = ins

    def _init_registers(self):
        self.reg_ids = {}
        for i, reg in enumerate(self.reg_names):
            self.reg_ids[reg] = i
        self.reg_first_sreg = self.reg_code_sreg = self.reg_ids["CS"]
        self.reg_last_sreg = self.reg_data_sreg = self.reg_ids["DS"]


    def notify_ana(self, insn):
        ea = insn.ea
        opcode = get_full_byte(ea)
        for idx, cls in self.instructions.items():
            if cls.opcode == opcode:
                insn.itype = idx
                insn.size = self.instructions[idx].size
                self.instructions[idx].emulate(insn)
                return insn.size
        return False
        
    def notify_emu(self, insn):
        ft = insn.get_canon_feature()
        a = insn[0].addr
        # TODO: Add memory references
        if ft & CF_JUMP:
            # TODO:
            # It's just a workaround for handling unconditional jumps, but it is against OCP.
            # Correct way of implementing it is to check a flag in insn_t structure that is used for this purpose.
            insn.add_cref(a, 0, fl_JN)
            if not insn.get_canon_mnem() in ["jmp", "vm_jmp"]:
                insn.add_cref(insn.ea + insn.size, 0, fl_F)

        elif not ft & CF_STOP and not ft & CF_JUMP:
            insn.add_cref(insn.ea + insn.size, 0, fl_F)
        return True

    def notify_out_operand(self, outctx, op):
        if op.type == o_imm:
            outctx.out_value(op, OOFW_IMM)
        elif op.type == o_displ:
            outctx.out_printf("[")
            outctx.out_register(self.reg_names[op.reg])
            outctx.out_printf(" + ")
            if op.value != NONE_REG :
                outctx.out_register(self.reg_names[op.value])
                outctx.out_printf(" + ")
            outctx.out_long(op.addr, 16)
            outctx.out_printf("]")
        elif op.type == o_reg:
            outctx.out_register(self.reg_names[op.reg])
        elif op.type in [o_near, o_mem]:
            ok = outctx.out_name_expr(op, op.addr, BADADDR)
            if not ok:
                outctx.out_tagon(COLOR_ERROR)
                outctx.out_long(op.addr, 16)
                outctx.out_tagoff(COLOR_ERROR)
        elif op.type == o_idpspec0:
            # This is a platform specific operator type, where random number of registers can be summed up. 
            if op.dtyp == dt_byte:
                outctx.out_printf("byte ptr [")
            elif op.dtyp == dt_word:
                outctx.out_printf("word ptr [")
            elif op.dtyp == dt_dword:
                outctx.out_printf("dword ptr [")
            else:
                outctx.out_printf("[")

            outctx.out_register(self.reg_names[op.specflag1])
            outctx.out_printf(" + ")
            if op.specflag2 != NONE_REG :
                outctx.out_register(self.reg_names[op.specflag2])
                outctx.out_printf(" + ")
            if op.specflag3 != NONE_REG :
                outctx.out_register(self.reg_names[op.specflag3])
                outctx.out_printf(" + ")
            if op.specflag4 != NONE_REG :
                outctx.out_register(self.reg_names[op.specflag4])
                outctx.out_printf(" + ")
            outctx.out_long(op.value, 16)
            outctx.out_printf("]")
        return True

    def notify_out_insn(self,outctx):
        insn=outctx.insn
        ft = insn.get_canon_feature()
        outctx.out_mnem()
        if ft & CF_USE1:
            outctx.out_one_operand(0)
        if ft & CF_USE2:
            outctx.out_printf(", ")
            outctx.out_one_operand(1)
        outctx.flush_outbuf()

def PROCESSOR_ENTRY():
    return CustomProcessor()