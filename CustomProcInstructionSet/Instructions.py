from idaapi import *
from Registers import *

NAME_PREFIX = "vm_"

signed_word = lambda a: a if a <= 32767 else a-65536

def _set_op_near(insn, dtyp, addr):
    insn.type = o_near
    insn.dtyp = dtyp
    insn.addr = addr

def _set_op_mem(insn, dtyp, value):
    insn.type = o_mem
    insn.dtyp = dtyp
    insn.addr = value

def _set_op_imm(insn, dtyp, value):
    insn.type = o_imm
    insn.dtyp = dtyp
    insn.value = value

def _set_op_reg(insn, reg):
    insn.type = o_reg
    insn.reg = reg

def _set_op_displ(insn, dtyp, reg, phrase, addr):
    insn.type = o_displ
    insn.dtyp = dtyp
    insn.reg = reg
    insn.value = phrase
    insn.addr = addr

def _set_op_idpspec0(insn, dtyp, value, specflag1 = NONE_REG, specflag2 = NONE_REG, specflag3 = NONE_REG, specflag4 = NONE_REG):
    insn.type = o_idpspec0
    insn.dtyp = dtyp
    insn.value = value
    insn.specflag1 = specflag1
    insn.specflag2 = specflag2
    insn.specflag3 = specflag3
    insn.specflag4 = specflag4


class Instruction1:
    size = 1
    name = NAME_PREFIX + "ret"
    feature = 0
    opcode = 0x1

    @staticmethod
    def emulate(insn):
        return

class Instruction2:
    size = 3
    name = NAME_PREFIX + "mov"
    feature = CF_USE1 | CF_USE2 | CF_CHG1
    opcode = 0x2

    @staticmethod
    def emulate(insn):
        ea = insn.ea
        a = get_byte(ea+1)
        b = get_byte(ea+2)

        _set_op_reg(insn[0], GetReg32IndexFromOpcode(b))
        _set_op_reg(insn[1], GetReg32IndexFromOpcode(a))

        return

class Instruction17:
    size = 5
    name = NAME_PREFIX + "mov"
    feature = CF_USE1 | CF_USE2 | CF_CHG1
    opcode = 0x17

    @staticmethod
    def emulate(insn):
        ea = insn.ea
        a = get_dword(ea+1)

        _set_op_displ(insn[0], dt_dword, GetRegIndexFromName("rsp"), NONE_REG, a)
        _set_op_reg(insn[1], GetRegIndexFromName("al"))

        return

class Instruction19:
    size = 6
    name = NAME_PREFIX + "mov"
    feature = CF_USE1 | CF_USE2 | CF_CHG1
    opcode = 0x19

    @staticmethod
    def emulate(insn):
        ea = insn.ea
        a = get_byte(ea+1)
        b = get_dword(ea+2)

        _set_op_reg(insn[0], GetReg32IndexFromOpcode(a))
        _set_op_displ(insn[1], dt_dword, GetRegIndexFromName("rsp"), NONE_REG, b)

        return

class Instruction1A:
    size = 6
    name = NAME_PREFIX + "mov"
    feature = CF_USE1 | CF_USE2 | CF_CHG1
    opcode = 0x1A

    @staticmethod
    def emulate(insn):
        ea = insn.ea
        a = get_byte(ea+1)
        b = get_dword(ea+2)

        _set_op_reg(insn[0], GetReg64IndexFromOpcode(a))
        _set_op_displ(insn[1], dt_dword, GetRegIndexFromName("rsp"), NONE_REG, b)

        return

class Instruction1B:
    size = 5
    name = NAME_PREFIX + "mov"
    feature = CF_USE1 | CF_USE2 | CF_CHG1
    opcode = 0x1B

    @staticmethod
    def emulate(insn):
        ea = insn.ea
        a = get_dword(ea+1)

        _set_op_reg(insn[0], GetRegIndexFromName("al"))
        _set_op_displ(insn[1], dt_dword, GetRegIndexFromName("rsp"), NONE_REG, a)

        return

class Instruction1C:
    size = 6
    name = NAME_PREFIX + "movzx"
    feature = CF_USE1 | CF_USE2 | CF_CHG1
    opcode = 0x1C

    @staticmethod
    def emulate(insn):
        ea = insn.ea
        a = get_byte(ea+1)
        
        idx = 2
        src_regs=[GetRegIndexFromName("rsp")]
        while GetReg64IndexFromOpcode(get_byte(ea+idx)) != NONE_REG:
            src_regs.append(GetReg64IndexFromOpcode(get_byte(ea+idx)))
            idx += 1
        if len(src_regs) > 4:
            # Altough VM spec does not limit the number of registers, we know that only one register is used.
            # We support sum of up to 4 registers by a kind of hacky method. However, it's just a temporary workaround and should be fixed asap.
            return False

        b = get_dword(ea + idx)

        insn.size = idx + 4

        _set_op_reg(insn[0], GetReg32IndexFromOpcode(a))
        _set_op_idpspec0(insn[1], dt_byte, b, *src_regs)

        return

class Instruction1D:
    size = 6
    name = NAME_PREFIX + "movsxd"
    feature = CF_USE1 | CF_USE2 | CF_CHG1
    opcode = 0x1D

    @staticmethod
    def emulate(insn):
        ea = insn.ea
        a = get_byte(ea+1)
        
        idx = 2
        src_regs=[GetRegIndexFromName("rsp")]
        while GetReg64IndexFromOpcode(get_byte(ea+idx)) != NONE_REG:
            src_regs.append(GetReg64IndexFromOpcode(get_byte(ea+idx)))
            idx += 1
        if len(src_regs) > 4:
            # Altough VM spec does not limit the number of registers, we know that only one register is used.
            # We support sum of up to 4 registers by a kind of hacky method. However, it's just a temporary workaround and should be fixed asap.
            return False

        b = get_dword(ea + idx)

        insn.size = idx + 4

        _set_op_reg(insn[0], GetReg64IndexFromOpcode(a))
        _set_op_idpspec0(insn[1], dt_dword, b, *src_regs)

        return

class Instruction1E:
    size = 6
    name = NAME_PREFIX + "movsx"
    feature = CF_USE1 | CF_USE2 | CF_CHG1
    opcode = 0x1E

    @staticmethod
    def emulate(insn):
        ea = insn.ea
        a = get_byte(ea+1)
        
        idx = 2
        src_regs=[GetRegIndexFromName("rsp")]
        while GetReg64IndexFromOpcode(get_byte(ea+idx)) != NONE_REG:
            src_regs.append(GetReg64IndexFromOpcode(get_byte(ea+idx)))
            idx += 1
        if len(src_regs) > 4:
            # Altough VM spec does not limit the number of registers, we know that only one register is used.
            # We support sum of up to 4 registers by a kind of hacky method. However, it's just a temporary workaround and should be fixed asap.
            return False

        b = get_dword(ea + idx)

        insn.size = idx + 4

        _set_op_reg(insn[0], GetReg32IndexFromOpcode(a))
        _set_op_idpspec0(insn[1], dt_byte, b, *src_regs)

        return

class Instruction1F:
    size = 6
    name = NAME_PREFIX + "movsx"
    feature = CF_USE1 | CF_USE2 | CF_CHG1
    opcode = 0x1F

    @staticmethod
    def emulate(insn):
        ea = insn.ea
        a = get_byte(ea+1)
        
        idx = 2
        src_regs=[]
        while GetReg64IndexFromOpcode(get_byte(ea+idx)) != NONE_REG:
            src_regs.append(GetReg64IndexFromOpcode(get_byte(ea+idx)))
            idx += 1
        if len(src_regs) > 4:
            # Altough VM spec does not limit the number of registers, we know that only one register is used.
            # We support sum of up to 4 registers by a kind of hacky method. However, it's just a temporary workaround and should be fixed asap.
            return False

        b = get_dword(ea + idx)

        insn.size = idx + 4

        _set_op_reg(insn[0], GetReg32IndexFromOpcode(a))
        _set_op_idpspec0(insn[1], dt_byte, b, *src_regs)

        return

class Instruction40:
    size = 3
    name = NAME_PREFIX + "cmp"
    feature = CF_USE1 | CF_USE2
    opcode = 0x40

    @staticmethod
    def emulate(insn):
        ea = insn.ea
        a = get_byte(ea+1)
        b = get_byte(ea+2)

        _set_op_reg(insn[0], GetReg32IndexFromOpcode(a))
        _set_op_reg(insn[1], GetReg32IndexFromOpcode(b))

        return

class Instruction41:
    size = 6
    name = NAME_PREFIX + "cmp"
    feature = CF_USE1 | CF_USE2
    opcode = 0x41

    @staticmethod
    def emulate(insn):
        ea = insn.ea
        a = get_byte(ea+1)
        b = get_dword(ea+2)

        _set_op_reg(insn[0], GetReg32IndexFromOpcode(a))
        _set_op_imm(insn[1], dt_dword, b)

        return

class Instruction42:
    size = 9
    name = NAME_PREFIX + "cmp"
    feature = CF_USE1 | CF_USE2
    opcode = 0x42

    @staticmethod
    def emulate(insn):
        ea = insn.ea
        a = get_dword(ea+1)
        b = get_dword(ea+5)

        _set_op_displ(insn[0], dt_dword, GetRegIndexFromName("rsp"), NONE_REG, a)
        _set_op_imm(insn[1], dt_dword, b)

        return


def emulate_jumps(insn):
    ea = insn.ea
    a = get_word(ea+1)
    des = signed_word((insn.ea + a) & 0xffff)
    _set_op_near(insn[0], dt_word, des)
    return

class Instruction50:
    size = 3
    name = NAME_PREFIX + "jmp"
    feature = CF_USE1 | CF_JUMP
    opcode = 0x50

    @staticmethod
    def emulate(insn):
        emulate_jumps(insn)

class Instruction51:
    size = 3
    name = NAME_PREFIX + "jnz"
    feature = CF_USE1 | CF_JUMP
    opcode = 0x51

    @staticmethod
    def emulate(insn):
        emulate_jumps(insn)

class Instruction52:
    size = 3
    name = NAME_PREFIX + "jz"
    feature = CF_USE1 | CF_JUMP
    opcode = 0x52

    @staticmethod
    def emulate(insn):
        emulate_jumps(insn)

class Instruction53:
    size = 3
    name = NAME_PREFIX + "jbe"
    feature = CF_USE1 | CF_JUMP
    opcode = 0x53

    @staticmethod
    def emulate(insn):
        emulate_jumps(insn)

class Instruction54:
    size = 3
    name = NAME_PREFIX + "jge"
    feature = CF_USE1 | CF_JUMP
    opcode = 0x54

    @staticmethod
    def emulate(insn):
        emulate_jumps(insn)

class InstructionC0:
    size = 6
    name = NAME_PREFIX + "xor"
    feature = CF_USE1 | CF_USE2 | CF_CHG1
    opcode = 0xC0

    @staticmethod
    def emulate(insn):
        ea = insn.ea
        a = get_byte(ea+1)
        b = get_dword(ea+2)

        _set_op_reg(insn[0], GetReg32IndexFromOpcode(a))
        _set_op_imm(insn[1], dt_dword, b)

        return

class InstructionC1:
    size = 6
    name = NAME_PREFIX + "add"
    feature = CF_USE1 | CF_USE2 | CF_CHG1
    opcode = 0xC1

    @staticmethod
    def emulate(insn):
        ea = insn.ea
        a = get_byte(ea+1)
        b = get_dword(ea+2)

        _set_op_reg(insn[0], GetReg64IndexFromOpcode(a))
        _set_op_imm(insn[1], dt_dword, b)

        return

class InstructionC3:
    size = 6
    name = NAME_PREFIX + "sub"
    feature = CF_USE1 | CF_USE2 | CF_CHG1
    opcode = 0xC3

    @staticmethod
    def emulate(insn):
        ea = insn.ea
        a = get_byte(ea+1)
        b = get_dword(ea+2)

        _set_op_reg(insn[0], GetReg64IndexFromOpcode(a))
        _set_op_imm(insn[1], dt_dword, b)

        return

class InstructionC8:
    size = 6
    name = NAME_PREFIX + "mov"
    feature = CF_USE1 | CF_USE2 | CF_CHG1
    opcode = 0xC8

    @staticmethod
    def emulate(insn):
        ea = insn.ea
        a = get_byte(ea+1)
        b = get_dword(ea+2)

        _set_op_displ(insn[0], dt_dword, GetRegIndexFromName("rsp"), NONE_REG, b)
        _set_op_reg(insn[1], GetReg64IndexFromOpcode(a))

        return

class InstructionC9:
    size = 13
    name = NAME_PREFIX + "mov"
    feature = CF_USE1 | CF_USE2 | CF_CHG1
    opcode = 0xC9

    @staticmethod
    def emulate(insn):
        ea = insn.ea
        a = get_dword(ea+1)
        b = get_qword(ea+5)

        _set_op_displ(insn[0], dt_dword, GetRegIndexFromName("rsp"), NONE_REG, a)
        _set_op_imm(insn[1], dt_qword, b)

        return

class InstructionD1:
    size = 6
    name = NAME_PREFIX + "add"
    feature = CF_USE1 | CF_USE2 | CF_CHG1
    opcode = 0xD1

    @staticmethod
    def emulate(insn):
        ea = insn.ea
        a = get_byte(ea+1)
        b = get_dword(ea+2)

        _set_op_reg(insn[0], GetReg32IndexFromOpcode(a))
        _set_op_imm(insn[1], dt_dword, b)

        return

class InstructionD2:
    size = 3
    name = NAME_PREFIX + "add"
    feature = CF_USE1 | CF_USE2 | CF_CHG1
    opcode = 0xD2

    @staticmethod
    def emulate(insn):
        ea = insn.ea
        a = get_byte(ea+1)
        b = get_byte(ea+2)

        _set_op_reg(insn[0], GetReg32IndexFromOpcode(b))
        _set_op_reg(insn[1], GetReg32IndexFromOpcode(a))

        return

class InstructionD5:
    size = 3
    name = NAME_PREFIX + "xor"
    feature = CF_USE1 | CF_USE2 | CF_CHG1
    opcode = 0xD5

    @staticmethod
    def emulate(insn):
        ea = insn.ea
        a = get_byte(ea+1)
        b = get_byte(ea+2)

        _set_op_reg(insn[0], GetReg32IndexFromOpcode(a))
        _set_op_reg(insn[1], GetReg32IndexFromOpcode(b))

        return

class InstructionD8:
    size = 6
    name = NAME_PREFIX + "mov"
    feature = CF_USE1 | CF_USE2 | CF_CHG1
    opcode = 0xD8

    @staticmethod
    def emulate(insn):
        ea = insn.ea
        a = get_byte(ea+1)
        b = get_dword(ea+5)

        _set_op_displ(insn[0], dt_dword, GetRegIndexFromName("rsp"), NONE_REG, b)
        _set_op_reg(insn[1], GetReg32IndexFromOpcode(a))

        return