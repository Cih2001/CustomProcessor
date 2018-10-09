from idaapi import *

NONE_REG = 0xff

registers_opcode = [
	{"index" : 0,  "opcode" : 0xF4, "name" : "rip"},
	{"index" : 1,  "opcode" : 0xEE, "name" : "rax"},
	{"index" : 2,  "opcode" : 0xEF, "name" : "rbx"},
	{"index" : 3,  "opcode" : 0xF0, "name" : "rcx"},
	{"index" : 4,  "opcode" : 0xF1, "name" : "rdx"},
	{"index" : 5,  "opcode" : 0xF2, "name" : "rsi"},
	{"index" : 6,  "opcode" : 0xF3, "name" : "rdi"},
	{"index" : 7,  "opcode" : 0xF5, "name" : "rsp"},
	{"index" : 8,  "opcode" : 0xF6, "name" : "rbp"},
	{"index" : 9,  "opcode" : 0xF7, "name" : "r8"}, 
	{"index" : 10, "opcode" : 0xF8, "name" : "r9"}, 
	{"index" : 11, "opcode" : 0xF9, "name" : "r10"}, 
	{"index" : 12, "opcode" : 0xFA, "name" : "r11"}, 
	{"index" : 13, "opcode" : 0xFB, "name" : "r12"}, 
	{"index" : 14, "opcode" : 0xFC, "name" : "r13"}, 
	{"index" : 15, "opcode" : 0xFD, "name" : "r14"}, 
	{"index" : 16, "opcode" : 0xFE, "name" : "r15"},
    {"index" : 17, "name" : "eax"},
	{"index" : 18, "name" : "ebx"},
	{"index" : 19, "name" : "ecx"},
	{"index" : 20, "name" : "edx"},
	{"index" : 21, "name" : "esi"},
	{"index" : 22, "name" : "edi"},
	{"index" : 23, "name" : "esp"},
	{"index" : 24, "name" : "ebp"},
	{"index" : 25, "name" : "r8d"}, 
	{"index" : 26, "name" : "r9d"}, 
	{"index" : 27, "name" : "r10d"}, 
	{"index" : 28, "name" : "r11d"}, 
	{"index" : 29, "name" : "r12d"}, 
	{"index" : 30, "name" : "r13d"}, 
	{"index" : 31, "name" : "r14d"}, 
	{"index" : 32, "name" : "r15d"},
    {"index" : 33, "name" : "ah"},
    {"index" : 34, "name" : "al"},
	{"index" : 35, "name" : "CS"},
	{"index" : 36, "name" : "DS"},
]


def GetReg64IndexFromOpcode(opcode):
    for reg in registers_opcode:
        if "opcode" in reg and reg["opcode"] == opcode:
            return reg["index"]
    return NONE_REG

def GetReg32IndexFromOpcode(opcode):
    for reg in registers_opcode:
        if "opcode" in reg and reg["opcode"] == opcode + 9:
            return reg["index"] + 0x10
    return NONE_REG

def GetRegIndexFromName(name):
    for reg in registers_opcode:
        if reg["name"] == name:
            return reg["index"]
    return NONE_REG