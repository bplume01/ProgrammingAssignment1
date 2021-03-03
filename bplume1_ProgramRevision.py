#bplume1
#recursion
#Python 2.7.18
import argparse
import binascii
import traceback
import logging
import sys
from struct import unpack
import string
import os
import ntpath

logging.basicConfig()
log = logging.getLogger('disasm')
log.setLevel(logging.ERROR)     # enable CRITICAL and ERROR messages by default

parser = argparse.ArgumentParser()
parser.add_argument("-i", "--input", help="Input file", dest="file")
args = parser.parse_args()

filename = args.file
byte = ""
disassembly = {}
machine = {}
call_stack = []
offset_labels = []

Registers = [
	'eax',
	'ecx',
	'edx',
	'ebx',
	'esp',
	'ebp',
	'esi',
	'edi']

RegisterEncodings = {
	'000':'eax',
	'001':'ecx',
	'010':'edx',
	'011':'ebx',
	'100':'esp',
	'101':'ebp',
	'110':'esi',
	'111':'edi'}

encodedOperands = {
	'40':'inc eax',
	'41':'inc ecx',
	'42':'inc edx',
	'43':'inc ebx',
	'44':'inc esp',
	'45':'inc ebp',
	'46':'inc esi',
	'47':'inc edi',
	'48':'dec eax',
	'49':'dec ecx',
	'4a':'dec edx',
	'4b':'dec ebx',
	'4c':'dec esp',
	'4d':'dec ebp',
	'4e':'dec esi',
	'4f':'dec edi',
	'58':'pop eax',
	'59':'pop ecx',
	'5a':'pop edx',
	'5b':'pop ebx',
	'5c':'pop esp',
	'5d':'pop ebp',
	'5e':'pop esi',
	'5f':'pop edi',
	'50':'push eax',
	'51':'push ecx',
	'52':'push edx',
	'53':'push ebx',
	'54':'push esp',
	'55':'push ebp',
	'56':'push esi',
	'57':'push edi',
	'b8':'mov eax',
	'b9':'mov ecx',
	'ba':'mov edx',
	'bb':'mov ebx',
	'bc':'mov esp',
	'bd':'mov ebp',
	'be':'mov esi',
	'bf':'mov edi',}

bswapLookup = {
	'c8':'bswap eax',
	'c9':'bswap ecx',
	'ca':'bswap edx',
	'cb':'bswap ebx',
	'cc':'bswap esp',
	'cd':'bswap ebp',
	'ce':'bswap esi',
	'cf':'bswap edi',}

encodedSIB = {
        '00':'eax+eax',
        '01':'ecx+eax',
        '02':'edx+eax',
        '03':'ebx+eax',
        '04':'esp+eax',
        '05':'*+eax',
        '06':'esi+eax',
        '07':'edi+eax',
        '08':'eax+ecx',
        '09':'ecx+ecx',
        '0a':'edx+ecx',
        '0b':'ebx+ecx',
        '0c':'esp+ecx',
        '0d':'*+ecx',
        '0e':'esi+ecx',
        '0f':'edi+ecx',
        '10':'eax+edx',
        '11':'ecx+edx',
        '12':'edx+edx',
        '13':'ebx+edx',
        '14':'esp+edx',
        '15':'*+edx',
        '16':'esi+edx',
        '17':'edi+edx',
        '18':'eax+ebx',
        '19':'ecx+ebx',
        '1a':'edx+ebx',
        '1b':'ebx+ebx',
        '1c':'esp+ebx',
        '1d':'*+ebx',
        '1e':'esi+ebx',
        '1f':'edi+ebx',
        '20':'eax',
        '21':'ecx',
        '22':'edx',
        '23':'ebx',
        '24':'esp',
        '25':'*',
        '26':'esi',
        '27':'edi',
        '28':'eax+ebp',
        '29':'ecx+ebp',
        '2a':'edx+ebp',
        '2b':'ebx+ebp',
        '2c':'esp+ebp',
        '2d':'*+ebp',
        '2e':'esi+ebp',
        '2f':'edi+ebp',
        '30':'eax+esi',
        '31':'ecx+esi',
        '32':'edx+esi',
        '33':'ebx+esi',
        '34':'esp+esi',
        '35':'*+esi',
        '36':'esi+esi',
        '37':'edi+esi',
        '38':'eax+edi',
        '39':'ecx+edi',
        '3a':'edx+edi',
        '3b':'ebx+edi',
        '3c':'esp+edi',
        '3d':'*+edi',
        '3e':'esi+edi',
        '3f':'edi+edi',
        '40':'eax+eax*2',
        '41':'ecx+eax*2',
        '42':'edx+eax*2',
        '43':'ebx+eax*2',
        '44':'esp+eax*2',
        '45':'*+eax*2',
        '46':'esi+eax*2',
        '47':'edi+eax*2',
        '48':'eax+ecx*2',
        '49':'ecx+ecx*2',
        '4a':'edx+ecx*2',
        '4b':'ebx+ecx*2',
        '4c':'esp+ecx*2',
        '4d':'*+ecx*2',
        '4e':'esi+ecx*2',
        '4f':'edi+ecx*2',
        '50':'eax+edx*2',
        '51':'ecx+edx*2',
        '52':'edx+edx*2',
        '53':'ebx+edx*2',
        '54':'esp+edx*2',
        '55':'*+edx*2',
        '56':'esi+edx*2',
        '57':'edi+edx*2',
        '58':'eax+ebx*2',
        '59':'ecx+ebx*2',
        '5a':'edx+ebx*2',
        '5b':'ebx+ebx*2',
        '5c':'esp+ebx*2',
        '5d':'*+ebx*2',
        '5e':'esi+ebx*2',
        '5f':'edi+ebx*2',
        '60':'eax',
        '61':'ecx',
        '62':'edx',
        '63':'ebx',
        '64':'esp',
        '65':'*',
        '66':'esi',
        '67':'edi',
        '68':'eax+ebp*2',
        '69':'ecx+ebp*2',
        '6a':'edx+ebp*2',
        '6b':'ebx+ebp*2',
        '6c':'esp+ebp*2',
        '6d':'*+ebp*2',
        '6e':'esi+ebp*2',
        '6f':'edi+ebp*2',
        '70':'eax+esi*2',
        '71':'ecx+esi*2',
        '72':'edx+esi*2',
        '73':'ebx+esi*2',
        '74':'esp+esi*2',
        '75':'*+esi*2',
        '76':'esi+esi*2',
        '77':'edi+esi*2',
        '78':'eax+edi*2',
        '79':'ecx+edi*2',
        '7a':'edx+edi*2',
        '7b':'ebx+edi*2',
        '7c':'esp+edi*2',
        '7d':'*+edi*2',
        '7e':'esi+edi*2',
        '7f':'edi+edi*2',
        '80':'eax+eax*4',
        '81':'ecx+eax*4',
        '82':'edx+eax*4',
        '83':'ebx+eax*4',
        '84':'esp+eax*4',
        '85':'*+eax*4',
        '86':'esi+eax*4',
        '87':'edi+eax*4',
        '88':'eax+ecx*4',
        '89':'ecx+ecx*4',
        '8a':'edx+ecx*4',
        '8b':'ebx+ecx*4',
        '8c':'esp+ecx*4',
        '8d':'*+ecx*4',
        '8e':'esi+ecx*4',
        '8f':'edi+ecx*4',
        '90':'eax+edx*4',
        '91':'ecx+edx*4',
        '92':'edx+edx*4',
        '93':'ebx+edx*4',
        '94':'esp+edx*4',
        '95':'*+edx*4',
        '96':'esi+edx*4',
        '97':'edi+edx*4',
        '98':'eax+ebx*4',
        '99':'ecx+ebx*4',
        '9a':'edx+ebx*4',
        '9b':'ebx+ebx*4',
        '9c':'esp+ebx*4',
        '9d':'*+ebx*4',
        '9e':'esi+ebx*4',
        '9f':'edi+ebx*4',
        'a0':'eax',
        'a1':'ecx',
        'a2':'edx',
        'a3':'ebx',
        'a4':'esp',
        'a5':'*',
        'a6':'esi',
        'a7':'edi',
        'a8':'eax+ebp*4',
        'a9':'ecx+ebp*4',
        'aa':'edx+ebp*4',
        'ab':'ebx+ebp*4',
        'ac':'esp+ebp*4',
        'ad':'*+ebp*4',
        'ae':'esi+ebp*4',
        'af':'edi+ebp*4',
        'b0':'eax+esi*4',
        'b1':'ecx+esi*4',
        'b2':'edx+esi*4',
        'b3':'ebx+esi*4',
        'b4':'esp+esi*4',
        'b5':'*+esi*4',
        'b6':'esi+esi*4',
        'b7':'edi+esi*4',
        'b8':'eax+edi*4',
        'b9':'ecx+edi*4',
        'ba':'edx+edi*4',
        'bb':'ebx+edi*4',
        'bc':'esp+edi*4',
        'bd':'*+edi*4',
        'be':'esi+edi*4',
        'bf':'edi+edi*4',
}

def dec2bin(x): # convert decimal to binary
	return "".join(map(lambda y:str((x>>y)&1), range(8-1, -1, -1)))

def hexToSigned8(h): # sign the hex
	return int(h, 16) if int(h,16) < int('0x80', 16) else (-int('0xff', 16)+int(h,16)-1)

def hexToSigned32(h): # sign the hex
	return int(h, 16) if int(h,16) < int('0x80000000', 16) else (-int('0xffffffff', 16)+int(h,16)-1)

def print_dword(dword): # print the dword properly
	return ' '.join(a+b for a,b in zip(dword[::2], dword[1::2]))

def parseModRM(mod, rm, eip, f, machine): # important to parse the ModRM; Addressing Mode -- Register or Opcode Extension / Register or Memory -- keep track of EIP in the stack -- file -- machine code buffer
	if mod == "00":
		if rm == "100":
			return "[" + RegisterEncodings[rm] + "]"
		elif rm == "101":
			dword = f.read(4)
			machine.bytes = machine.bytes + " " + print_dword(binascii.hexlify(dword))
			disp32 = str(hex(unpack('<L', dword)[0]))
			eip.addr += 4
			return "["  + disp32 + "]"
		else:
			return "[" + RegisterEncodings[rm] + "]"
	elif mod == "01":
		if rm == "100":
			disp8 = binascii.hexlify(f.read(1))
			machine.bytes = machine.bytes + " " + disp8
			eip.addr += 1
			return "[" + RegisterEncodings[rm] + "+0x" + disp8 + "]"
		else: 
			disp8 = binascii.hexlify(f.read(1))
			machine.bytes = machine.bytes + " " + disp8
			eip.addr += 1
			return "[" + RegisterEncodings[rm] + "+0x" + disp8 + "]"
	elif mod == "10":
		if rm == "100":
			dword = f.read(4)
			machine.bytes = machine.bytes + " " + print_dword(binascii.hexlify(dword))
			disp32 = str(hex(unpack('<L', dword)[0]))
			eip.addr += 4
			return "[" + RegisterEncodings[rm] + "+0x" + disp32 + "]"
		else:
			dword = f.read(4)
			machine.bytes = machine.bytes + " " + print_dword(binascii.hexlify(dword))
			disp32 = str(hex(unpack('<L', dword)[0]))
			eip.addr += 4
			return "[" + RegisterEncodings[rm] + "+0x" + disp32 + "]"
	elif mod == "11":
		return RegisterEncodings[rm]
	else:
		raise Exception("Invalid Encoding")
	
def parseSIB(mod, rm, eip, f, machine, sib):
	if mod == "00":
		if rm == "100":
                        sib = binascii.hexlify(f.read(1))
                        eip.addr +=1
			return "[" + encodedSIB[sib] + "]"
	elif mod == "01":
		if rm == "100":
                        sib = binascii.hexlify(f.read(1))
			disp8 = binascii.hexlify(f.read(1))
			eip.addr += 2
			machine.bytes = machine.bytes + " " + sib + " " + disp8
			return "[" + encodedSIB[sib] + "+0x" + disp8 + "]"
	elif mod == "10":
		if rm == "100":
			dword = f.read(4)
			sib = binascii.hexlify(f.read(1))
			machine.bytes = machine.bytes + " " + sib + " " + print_dword(binascii.hexlify(dword))
			disp32 = str(hex(unpack('<L', dword)[0]))
			eip.addr += 5
			return "[" + encodedSIB[sib] + "+0x" + disp32 + "]"
	
def call_next(f, eip, op, offset):
	if eip.addr in call_stack:
		handle_ret(f, eip, op)
		return
	call_stack.append(eip.addr)
	eip.addr = offset
	f.seek(offset)
	
def jmp_next(f, eip, op, offset):
	if mode == "recursive":
		eip.addr = offset
		f.seek(offset)
		
def handle_ret(f, eip, op):
	if not call_stack:
		global byte
		byte = ""
		return
	else:
		eip.addr = call_stack.pop()
		f.seek(eip.addr)
		
class EIP(object):
	addr = 0
	jump_addr = 0
	
class MachineCode(object): 
	bytes = ""

def ambiguous(f, eip, op):
	if op == "0f":
		byte_two = binascii.hexlify(f.read(1))
		if byte_two in bswapLookup:
			eip.addr +=2
			return {"machine":machine.bytes, "assembly":bswapLookup[byte_two]}
		elif byte_two == "84":
			f.seek(-1,1)
			return jz(f, eip, op)
		elif byte_two == "85":
			f.seek(-1,1)
			return jnz(f, eip, op)
		elif byte_two == "af":
			f.seek(-1,1)
			return imul(f, eip, op)
		elif byte_two == "b7":
			byte_three = binascii.hexlify(f.read(1))
			eip.addr += 3
			if byte_three == "c8":
				return {"machine":"0f b7 c8", "assembly":"movzx ecx, ax"}
			else:
				raise Exception("Error: movzx mnemonic")
		else:
			raise Exception("Unsupported Opcode")
	elif op == "83" or op == "81":
		byte_two = binascii.hexlify(f.read(1))
		binary_string = dec2bin(int(byte_two, 16))
		reg = binary_string[2:5]
		f.seek(-1,1)
		if reg == "000":
			return add(f, eip, op)
		elif reg == "100":
			return andX(f, eip, op)
		elif reg == "111":
			return cmpX(f, eip, op)
		elif reg == "001":
			return orX(f, eip, op)
		elif reg == "011":
			return sbb(f, eip, op)
		elif reg == "110":
			return xor(f, eip, op)
		else:
			raise Exception("Unsupported Opcode")
	elif op == "f2":
		byte_two = binascii.hexlify(f.read(1))
		eip.addr += 2
		if byte_two == "a7":
			return {"machine":"f2 a7", "assembly":"repne cmps DWORD PTR ds:[esi], DWORD PTR es:[edi]"}
		else:
			raise Exception("Error: repne cmpsd mnemonic")
	elif op == "f3":
		byte_two = binascii.hexlify(f.read(1))
		byte_three = binascii.hexlify(f.read(1))
		eip.addr += 3
		if byte_two == "0f" and byte_three == "b8":
			modrm = binascii.hexlify(f.read(1))
			machine.bytes = machine.bytes +  " " + modrm
			eip.addr += 1
			binary_string = dec2bin(int(modrm, 16))
			mod = binary_string[0:2]
			reg = binary_string[2:5]
			rm = binary_string[5:]
			parsedmod = parseModRM(mod, rm, eip, f, machine)
			if rm == "100":
                                rm = binary_string[5:8]
                                sib = binary_string[8:]
                                parsedsib = parseSIB(mod, rm, eip, f, machine, sib)
                                return {"machine":"f3 0f b8" + modrm, "assembly":"popcnt " + RegisterEncodings[reg] + ", " + parsedsib}
			return {"machine":"f3 0f b8" + modrm, "assembly":"popcnt " + RegisterEncodings[reg] + ", " + parsedmod}
		else:
			raise Exception("Error: popcnt mnemonic")
	elif op == "f7":
		byte_two = binascii.hexlify(f.read(1))
		binary_string = dec2bin(int(byte_two, 16))
		reg = binary_string[2:5]
		f.seek(-1,1)
		if reg == "000":
			return test(f, eip, op)
		elif reg == "010":
			return notX(f, eip, op)
		elif reg == "011":
			return neg(f, eip, op)
		elif reg == "100":
			return mul(f, eip, op)
		elif reg == "101":
			return imul(f, eip, op)
		elif reg == "111":
			return idiv(f, eip, op)
		else:
			raise Exception("Unsupported Opcode")
	elif op == "fe":
		byte_two = binascii.hexlify(f.read(1))
		binary_string = dec2bin(int(byte_two, 16))
		reg = binary_string[2:5]
		f.seek(-1,1)
		if reg == "000" or reg == "001":
			return incANDdec(f, eip, op)
		else:
			raise Exception("Unsupported Opcode")
	elif op == "ff":
		byte_two = binascii.hexlify(f.read(1))
		binary_string = dec2bin(int(byte_two, 16))
		reg = binary_string[2:5]
		f.seek(-1,1)
		if reg == "000" or reg == "001":
			return incANDdec(f, eip, op)
		elif reg == "100" or reg == "101":
			return jmp(f, eip, op)
		elif reg == "010" or reg == "011":
			return call(f, eip, op)
		elif reg == "110":
			return push(f, eip, op)
		else:
			raise Exception("Unsupported Opcode")
	else:
		raise Exception("Unsupported Opcode")

def add(f, eip, op):
	machine = MachineCode()
	machine.bytes = op
	eip.addr += 1
	if op == "01" or op == "03":
		modrm = binascii.hexlify(f.read(1))
		machine.bytes = machine.bytes +  " " + modrm
		eip.addr += 1
		binary_string = dec2bin(int(modrm, 16))
		mod = binary_string[0:2]
		reg = binary_string[2:5]
		rm = binary_string[5:]
		parsedmod = parseModRM(mod, rm, eip, f, machine)
		if op == "01":
                        if rm == "100":
                                rm = binary_string[5:8]
                                sib = binary_string[8:]
                                parsedsib = parseSIB(mod, rm, eip, f, machine, sib)
                                return {"machine":machine.bytes, "assembly":"and " + parsedsib + ", " + RegisterEncodings[reg]}
			return {"machine":machine.bytes, "assembly":"add " + parsedmod + ", " + RegisterEncodings[reg]}
		else:
                        if rm == "100":
                                rm = binary_string[5:8]
                                sib = binary_string[8:]
                                parsedsib = parseSIB(mod, rm, eip, f, machine, sib)
                                return {"machine":machine.bytes, "assembly":"and " + RegisterEncodings[reg] + ", " + parsedsib}
			return {"machine":machine.bytes, "assembly":"add " + RegisterEncodings[reg] + ", " + parsedmod}
	elif op == "81" or op == "83":
		modrm = binascii.hexlify(f.read(1))
		machine.bytes = machine.bytes + " " + modrm
		eip.addr += 1
		binary_string = dec2bin(int(modrm, 16))
		mod = binary_string[0:2]
		rm = binary_string[5:]
		parsedmod = parseModRM(mod, rm, eip, f, machine)
		if op == "81":
			dword = f.read(4)
			imm32 = str(hex(unpack('<L', dword)[0]))
			machine.bytes = machine.bytes + " " + print_dword(binascii.hexlify(dword))
			eip.addr += 4
			if rm == "100":
                                rm = binary_string[5:8]
                                sib = binary_string[8:]
                                parsedsib = parseSIB(mod, rm, eip, f, machine, sib)
                                return {"machine":machine.bytes, "assembly":"and " + pasedsib + ", 0x" + imm32}
			return {"machine":machine.bytes, "assembly": "add " + parsedmod + ", 0x" + imm32}
		else:
			byte = f.read(1)
			imm8 = binascii.hexlify(byte)
			machine.bytes = machine.bytes + " " + binascii.hexlify(byte)
			eip.addr += 1
			if rm == "100":
                                rm = binary_string[5:8]
                                sib = binary_string[8:]
                                parsedsib = parseSIB(mod, rm, eip, f, machine, sib)
                                return {"machine":machine.bytes, "assembly":"and " + parsedsib + ", 0x" + imm8}
			return {"machine":machine.bytes, "assembly":"add " + parsedmod + ", 0x" + imm8}
	elif op == "05":
		dword = f.read(4)
		imm32 = str(hex(unpack('<L', dword)[0]))
		machine.bytes = machine.bytes + " " + print_dword(binascii.hexlify(dword))
		eip.addr += 4
		return {"machine":machine.bytes, "assembly":"add eax, 0x" + imm32}	
	else:
		raise Exception("Error: add mnemonic")
	
def andX(f, eip, op): # and is reserved by Py
	machine = MachineCode()
	machine.bytes = op
	eip.addr += 1 
	if op == "21" or op == "23":
		modrm = binascii.hexlify(f.read(1))
		machine.bytes = machine.bytes +  " " + modrm
		eip.addr += 1 
		binary_string = dec2bin(int(modrm, 16))
		mod = binary_string[0:2]
		reg = binary_string[2:5]
		rm = binary_string[5:]
		parsedmod = parseModRM(mod, rm, eip, f, machine)
		if op == "21":
                        if rm == "100":
                                rm = binary_string[5:8]
                                sib = binary_string[8:]
                                parsedsib = parseSIB(mod, rm, eip, f, machine, sib)
                                return {"machine":machine.bytes, "assembly":"and " + parsedsib + ", " + RegisterEncodings[reg]}
			return {"machine":machine.bytes, "assembly":"and " + parsedmod + ", " + RegisterEncodings[reg]}
		else:
                        if rm == "100":
                                rm = binary_string[5:8]
                                sib = binary_string[8:]
                                parsedsib = parseSIB(mod, rm, eip, f, machine, sib)
                                return {"machine":machine.bytes, "assembly":"and " + RegisterEncodings[reg] + ", " + parsedsib}
			return {"machine":machine.bytes, "assembly":"and " + RegisterEncodings[reg] + ", " + parsedmod}
	elif op == "81" or op == "83":
		modrm = binascii.hexlify(f.read(1))
		machine.bytes = machine.bytes + " " + modrm
		eip.addr += 1 
		binary_string = dec2bin(int(modrm, 16))
		mod = binary_string[0:2]
		rm = binary_string[5:]
		parsedmod = parseModRM(mod, rm, eip, f, machine)
		if op == "81":
			dword = f.read(4)
			imm32 = str(hex(unpack('<L', dword)[0]))
			machine.bytes = machine.bytes + " " + print_dword(binascii.hexlify(dword))
			eip.addr += 4
			if rm == "100":
                                rm = binary_string[5:8]
                                sib = binary_string[8:]
                                parsedsib = parseSIB(mod, rm, eip, f, machine, sib)
                                return {"machine":machine.bytes, "assembly":"and " + parsedsib + ", 0x" + imm32}
			return {"machine":machine.bytes, "assembly": "and " + parsedmod + ", 0x" + imm32}
		else: 
			byte = f.read(1)
			imm8 = binascii.hexlify(byte)
			machine.bytes = machine.bytes + " " + binascii.hexlify(byte)
			eip.addr += 1
			if rm == "100":
                                rm = binary_string[5:8]
                                sib = binary_string[8:]
                                parsedsib = parseSIB(mod, rm, eip, f, machine, sib)
                                return {"machine":machine.bytes, "assembly":"and " + parsedsib + ", 0x" + imm8}
			return {"machine":machine.bytes, "assembly":"and " + parsedmod + ", 0x" + imm8}
	elif op == "25": 
		dword = f.read(4)
		imm32 = str(hex(unpack('<L', dword)[0]))
		machine.bytes = machine.bytes + " " + print_dword(binascii.hexlify(dword))
		eip.addr += 4 
		return {"machine":machine.bytes, "assembly":"and eax, 0x" + imm32}	
	else:
		raise Exception("Error: and mnemonic")
	
def call(f, eip, op):
	machine = MachineCode()
	machine.bytes = op
	eip.addr += 1 
	if op == "ff": 
		modrm = binascii.hexlify(f.read(1))
		machine.bytes = machine.bytes + " " + modrm
		eip.addr += 1 
		binary_string = dec2bin(int(modrm, 16))
		mod = binary_string[0:2]
		rm = binary_string[5:]
		parsedmod = parseModRM(mod, rm, eip, f, machine)
		if rm == "100":
                                rm = binary_string[5:8]
                                sib = binary_string[8:]
                                parsedsib = parseSIB(mod, rm, eip, f, machine, sib)
                                return {"machine":machine.bytes, "assembly":"call " + parsedsib}
		return {"machine":machine.bytes, "assembly":"call " + parsedmod}
	elif op == "e8": 
		dword = f.read(4)
		offset = hex(unpack('<L', dword)[0])
		machine.bytes = machine.bytes + " " + print_dword(binascii.hexlify(dword))
		eip.addr += 4 
		signed = hexToSigned32(offset)
		ret = {"machine":machine.bytes, "assembly":"call offset_" + '{:x}'.format(eip.addr + signed) + "h"}
		offset_labels.append(str(hex(eip.addr + signed)))
		if signed != 0:
			call_next(f, eip, op, eip.addr + signed)
		return ret
	else:
		raise Exception("Error: call mnemonic")
	
def cmpX(f, eip, op): # cmp is reserved by Py
	machine = MachineCode()
	machine.bytes = op
	eip.addr += 1 
	if op == "39" or op == "3b":
		modrm = binascii.hexlify(f.read(1))
		machine.bytes = machine.bytes + " " + modrm
		binary_string = dec2bin(int(modrm, 16))
		eip.addr += 1 
		mod = binary_string[0:2]
		reg = binary_string[2:5]
		rm = binary_string[5:]
		parsedmod = parseModRM(mod, rm, eip, f, machine)
		if op == "39":
                        if rm == "100":
                                rm = binary_string[5:8]
                                sib = binary_string[8:]
                                parsedsib = parseSIB(mod, rm, eip, f, machine, sib)
                                return {"machine":machine.bytes, "assembly":"cmp " + parsedsib + ", " + RegisterEncodings[reg]}
			return {"machine":machine.bytes, "assembly":"cmp " + parsedmod + ", " +  RegisterEncodings[reg]}
		else:
                        if rm == "100":
                                rm = binary_string[5:8]
                                sib = binary_string[8:]
                                parsedsib = parseSIB(mod, rm, eip, f, machine, sib)
                                return {"machine":machine.bytes, "assembly":"cmp " + RegisterEncodings[reg] + ", " + parsedsib}
			return {"machine":machine.bytes, "assembly":"cmp " + RegisterEncodings[reg] + ", " +  parsedmod}
	elif op == "81" or op == "83":
		modrm = binascii.hexlify(f.read(1))
		machine.bytes = machine.bytes + " " + modrm
		binary_string = dec2bin(int(modrm, 16))
		eip.addr += 1 
		mod = binary_string[0:2]
		rm = binary_string[5:]
		parsedmod = parseModRM(mod, rm, eip, f, machine)
		if op == "81":
			dword = f.read(4)
			imm32 = str(hex(unpack('<L', dword)[0]))
			eip.addr += 4 
			machine.bytes = machine.bytes + " " + print_dword(binascii.hexlify(dword))
			if rm == "100":
                                rm = binary_string[5:8]
                                sib = binary_string[8:]
                                parsedsib = parseSIB(mod, rm, eip, f, machine, sib)
                                return {"machine":machine.bytes, "assembly":"cmp " + parsedsib + ", " + imm32}
			return {"machine":machine.bytes, "assembly":"cmp" + parsedmod  + ", " + imm32}
		else:
			byte = f.read(1)
			imm8 = binascii.hexlify(byte)
			machine.bytes = machine.bytes + " " + binascii.hexlify(byte)
			eip.addr += 1
			if rm == "100":
                                rm = binary_string[5:8]
                                sib = binary_string[8:]
                                parsedsib = parseSIB(mod, rm, eip, f, machine, sib)
                                return {"machine":machine.bytes, "assembly":"cmp " + parsedsib + ", 0x" + imm8}
			return {"machine":machine.bytes, "assembly":"cmp " + parsedmod  + ", 0x" + imm8}
	elif op == "3d":
		dword = f.read(4)
		imm32 = str(hex(unpack('<L', dword)[0]))
		machine.bytes = machine.bytes + " " + print_dword(binascii.hexlify(dword))
		eip.addr += 4 
		return {"machine":machine.bytes, "assembly":"cmp eax, 0x" + imm32}
	else:	
		raise Exception("Error: cmp mnemonic")
	
def incANDdec(f, eip, op): # dec and inc function similarly
	machine = MachineCode()
	machine.bytes = op
	eip.addr +=1 
	if op in encodedOperands:
		return {"machine":machine.bytes, "assembly":encodedOperands[op]}
	elif op == "ff":
		modrm = binascii.hexlify(f.read(1))
		eip.addr += 1 
		machine.bytes = machine.bytes + " " + modrm
		binary_string = dec2bin(int(modrm, 16))
		mod = binary_string[0:2]
		reg = binary_string[2:5]
		rm = binary_string[5:]
		parsedmod = parseModRM(mod, rm, eip, f, machine)
		if reg == "000":
                        if rm == "100":
                                rm = binary_string[5:8]
                                sib = binary_string[8:]
                                parsedsib = parseSIB(mod, rm, eip, f, machine, sib)
                                return {"machine":machine.bytes, "assembly":"inc " + parsedsib}
			return {"machine":machine.bytes, "assembly":"inc " + parsedmod}
		else:
                        if rm == "100":
                                rm = binary_string[5:8]
                                sib = binary_string[8:]
                                parsedsib = parseSIB(mod, rm, eip, f, machine, sib)
                                return {"machine":machine.bytes, "assembly":"dec " + parsedsib}
			return {"machine":machine.bytes, "assembly":"dec " + parsedmod}
	else:
		raise Exception("Error: inc/dec mnemonic")
	
def idiv(f, eip, op):
	machine = MachineCode()
	machine.bytes = op
	eip.addr += 1 
	if op == "f7":
		modrm = binascii.hexlify(f.read(1))
		machine.bytes = machine.bytes +  " " + modrm
		eip.addr += 1 
		binary_string = dec2bin(int(modrm, 16))
		mod = binary_string[0:2]
		rm = binary_string[5:]
		parsedmod = parseModRM(mod, rm, eip, f, machine)
		if rm == "100":
                                rm = binary_string[5:8]
                                sib = binary_string[8:]
                                parsedsib = parseSIB(mod, rm, eip, f, machine, sib)
                                return {"machine":machine.bytes, "assembly":"idiv " + parsedsib}
		return {"machine":machine.bytes, "assembly":"idiv " + parsedmod}
	else:
		raise Exception("Error: idiv mnemonic")
	
def imul(f, eip, op):
	machine = MachineCode()
	machine.bytes = op
	eip.addr += 1 
	if op == "0f":
		byte_two = binascii.hexlify(f.read(1))
		machine.bytes = machine.bytes +  " " + byte_two
		eip.addr += 1 
		modrm = binascii.hexlify(f.read(1))
		machine.bytes = machine.bytes +  " " + modrm
		eip.addr += 1 
		binary_string = dec2bin(int(modrm, 16))
		mod = binary_string[0:2]
		reg = binary_string[2:5]
		rm = binary_string[5:]
		parsedmod = parseModRM(mod, rm, eip, f, machine)
		if rm == "100":
                                rm = binary_string[5:8]
                                sib = binary_string[8:]
                                parsedsib = parseSIB(mod, rm, eip, f, machine, sib)
                                return {"machine":machine.bytes, "assembly":"imul " + RegisterEncodings[reg] + ", " + parsedsib}
		return {"machine":machine.bytes, "assembly":"imul " + RegisterEncodings[reg] + ", " + parsedmod}
	elif op == "6b" or op == "69": 
		modrm = binascii.hexlify(f.read(1))
		machine.bytes = machine.bytes + " " + modrm
		eip.addr += 1 
		binary_string = dec2bin(int(modrm, 16))
		mod = binary_string[0:2]
		reg = binary_string[2:5]
		rm = binary_string[5:]
		parsedmod = parseModRM(mod, rm, eip, f, machine)
		if op == "69":
			dword = f.read(4)
			imm32 = str(hex(unpack('<L', dword)[0]))
			machine.bytes = machine.bytes + " " + print_dword(binascii.hexlify(dword))
			eip.addr += 4
			if rm == "100":
                                rm = binary_string[5:8]
                                sib = binary_string[8:]
                                parsedsib = parseSIB(mod, rm, eip, f, machine, sib)
                                return {"machine":machine.bytes, "assembly":"imul " + RegisterEncodings[reg] + ", " + parsedsib + ", 0x" + imm32}
			return {"machine":machine.bytes, "assembly": "imul " + RegisterEncodings[reg] + ", " + parsedmod + ", 0x" + imm32}
		else:
			byte = f.read(1)
			imm8 = binascii.hexlify(byte)
			machine.bytes = machine.bytes + " " + binascii.hexlify(byte)
			eip.addr += 1
			if rm == "100":
                                rm = binary_string[5:8]
                                sib = binary_string[8:]
                                parsedsib = parseSIB(mod, rm, eip, f, machine, sib)
                                return {"machine":machine.bytes, "assembly":"imul " + RegisterEncodings[reg] + ", " + parsedsib + ", 0x" + imm8}
			return {"machine":machine.bytes, "assembly":"imul " + RegisterEncodings[reg] + ", " + parsedmod + ", 0x" + imm8}
	elif op == "f7":
		modrm = binascii.hexlify(f.read(1))
		machine.bytes = machine.bytes + " " + modrm
		eip.addr += 1 
		binary_string = dec2bin(int(modrm, 16))
		mod = binary_string[0:2]
		rm = binary_string[5:]
		parsedmod = parseModRM(mod, rm, eip, f, machine)
		if rm == "100":
                                rm = binary_string[5:8]
                                sib = binary_string[8:]
                                parsedsib = parseSIB(mod, rm, eip, f, machine, sib)
                                return {"machine":machine.bytes, "assembly":"imul eax " + parsedsib}
		return {"machine":machine.bytes, "assembly":"imul eax, " + parsedmod}	
	else:
		raise Exception("Error: imul mnemonic")
	
def jmp(f, eip, op):
	machine = MachineCode()
	machine.bytes = op
	eip.addr += 1 
	if op == "ff":
		modrm = binascii.hexlify(f.read(1))
		machine.bytes = machine.bytes + " " + modrm
		eip.addr += 1 
		binary_string = dec2bin(int(modrm, 16))
		mod = binary_string[0:2]
		rm = binary_string[5:]
		parsedmod = parseModRM(mod, rm, eip, f, machine)
		if rm == "100":
                                rm = binary_string[5:8]
                                sib = binary_string[8:]
                                parsedsib = parseSIB(mod, rm, eip, f, machine, sib)
                                return {"machine":machine.bytes, "assembly":"jmp " + parsedsib}
		return {"machine":machine.bytes, "assembly":"jmp " + parsedmod}
	elif op == "e9": 
		dword = f.read(4)
		offset = hex(unpack('<L', dword)[0])
		eip.addr += 4
		machine.bytes = machine.bytes + " " + print_dword(binascii.hexlify(dword))
		signed = hexToSigned32(offset)
		rel32 = '{:x}'.format(eip.addr + signed)
		offset_labels.append(str(hex(eip.addr + signed)))
		jmp_next(f, eip, op, eip.addr + signed)
		return {"machine":machine.bytes, "assembly":"jmp offset_" + rel32 + "h"}
	elif op == "eb": 
		rel8 = binascii.hexlify(f.read(1))
		machine.bytes = machine.bytes + " " + rel8
		signed = hexToSigned8(rel8)
		eip.addr += 1
		rel8 = '{:x}'.format(eip.addr + signed)
		offset_labels.append(str(hex(eip.addr + signed)))
		jmp_next(f, eip, op,eip.addr + signed)
		return {"machine":machine.bytes, "assembly":"jmp offset_" + rel8 + "h"}
	else:
		raise Exception("Error: jmp mnemonic")
	
def jz(f, eip, op):
	machine = MachineCode()
	machine.bytes = op
	eip.addr += 1 
	if op == "74":
		rel8 = binascii.hexlify(f.read(1))
		machine.bytes = machine.bytes + " " + rel8
		signed = hexToSigned8(rel8)
		eip.addr += 1
		rel8 = '{:x}'.format(eip.addr + signed)
		offset_labels.append(str(hex(eip.addr + signed)))
		call_next(f, eip, op,eip.addr + signed)
		return {"machine":machine.bytes, "assembly":"jz offset_" + rel8 + "h"}
	elif op == "0f":
		byte_two = binascii.hexlify(f.read(1))
		machine.bytes = machine.bytes +  " " + byte_two
		eip.addr += 1 
		dword = f.read(4)
		offset = hex(unpack('<L', dword)[0])
		machine.bytes = machine.bytes + " " + print_dword(binascii.hexlify(dword))
		eip.addr += 4 
		signed = hexToSigned32(offset)
		rel32 = '{:x}'.format(eip.addr + signed)
		offset_labels.append(str(hex(eip.addr + signed)))
		call_next(f, eip, op, eip.addr + signed)
		return {"machine":machine.bytes, "assembly":"jz offset_" + rel32 + "h"}
	else:
		raise Exception("Error: jz mnemonic")
	
def jnz(f, eip, op):
	machine = MachineCode()
	machine.bytes = op
	eip.addr += 1 
	if op == "75":
		rel8 = binascii.hexlify(f.read(1))
		machine.bytes = machine.bytes + " " + rel8
		signed = hexToSigned8(rel8)
		eip.addr += 1
		rel8 = '{:x}'.format(eip.addr + signed)
		offset_labels.append(str(hex(eip.addr + signed)))
		call_next(f, eip, op,eip.addr + signed)
		return {"machine":machine.bytes, "assembly":"jnz offset_" + rel8 + "h"}
	elif op == "0f":
		byte_two = binascii.hexlify(f.read(1))
		machine.bytes = machine.bytes +  " " + byte_two
		eip.addr += 1 
		dword = f.read(4)
		offset = hex(unpack('<L', dword)[0])
		machine.bytes = machine.bytes + " " + print_dword(binascii.hexlify(dword))
		eip.addr += 4
		signed = hexToSigned32(offset)
		rel32 = '{:x}'.format(eip.addr + signed)
		offset_labels.append(str(hex(eip.addr + signed)))
		call_next(f, eip, op, eip.addr + signed)
		return {"machine":machine.bytes, "assembly":"jnz offset_" + rel32 + "h"}
	else:
		raise Exception("Error: jnz mnemonic")
	
def lea(f, eip, op):
	machine = MachineCode()
	machine.bytes = op
	eip.addr += 1 
	if op == "8d":
		modrm = binascii.hexlify(f.read(1))
		machine.bytes = machine.bytes + " " + modrm
		eip.addr += 1 
		binary_string = dec2bin(int(modrm, 16))
		mod = binary_string[0:2]
		reg = binary_string[2:5]
		rm = binary_string[5:]
		if rm == "100":
                        rm = binary_string[5:8]
                        sib = binary_string[8:]
                        parsedsib = parseSIB(mod, rm, eip, f, machine, sib)
                        return {"machine":machine.bytes, "assembly":"lea " + RegisterEncodings[reg] + ", " + parsedsib}
		parsedmod = parseModRM(mod, rm, eip, f, machine)
		return {"machine":machine.bytes, "assembly":"lea " + RegisterEncodings[reg] + ", " + parsedmod}
	else:
		raise Exception("Error: lea mnemonic")
	
def mov(f, eip, op):
	machine = MachineCode()
	machine.bytes = op
	eip.addr += 1 
	if op == "89" or op == '8b': 
		modrm = binascii.hexlify(f.read(1))
		machine.bytes = machine.bytes + " " + modrm
		eip.addr += 1 
		binary_string = dec2bin(int(modrm, 16))
		mod = binary_string[0:2]
		reg = binary_string[2:5]
		rm = binary_string[5:]	
		parsedmod = parseModRM(mod, rm, eip, f, machine)
		if op == '89':
                        if rm == "100":
                                rm = binary_string[5:8]
                                sib = binary_string[8:]
                                parsedsib = parseSIB(mod, rm, eip, f, machine, sib)
                                return {"machine":machine.bytes, "assembly":"mov " + parsedsib + ", " + RegisterEncodings[reg]}
			return {"machine":machine.bytes, "assembly":"mov " + parsedmod + ", " + RegisterEncodings[reg]}
		elif op == "8b":
                        if rm == "100":
                                rm = binary_string[5:8]
                                sib = binary_string[8:]
                                parsedsib = parseSIB(mod, rm, eip, f, machine, sib)
                                return {"machine":machine.bytes, "assembly":"mov " + RegisterEncodings[reg] + ", " + parsedsib}
			return {"machine":machine.bytes, "assembly":"mov " + RegisterEncodings[reg]+ ", " +  parsedmod}
	elif op == "c7":
		modrm = binascii.hexlify(f.read(1))
		machine.bytes = machine.bytes + " " + modrm
		eip.addr += 1 
		binary_string = dec2bin(int(modrm, 16))
		mod = binary_string[0:2]
		rm = binary_string[5:]		
		parsedmod = parseModRM(mod, rm, eip, f, machine)
		dword = f.read(4)
		machine.bytes = machine.bytes + " " + print_dword(binascii.hexlify(dword))
		imm32 = str(hex(unpack('<L', dword)[0]))
		eip.addr += 4
		if rm == "100":
                                rm = binary_string[5:8]
                                sib = binary_string[8:]
                                parsedsib = parseSIB(mod, rm, eip, f, machine, sib)
                                return {"machine":machine.bytes, "assembly":"mov " + parsedsib + ", 0x" + imm32}
		return {"machine":machine.bytes, "assembly":"mov " + parsedmod + ", 0x" + imm32}
	elif op in encodedOperands:
		dword = f.read(4)
		machine.bytes = machine.bytes + " " + print_dword(binascii.hexlify(dword))
		imm32 = str(hex(unpack('<L', dword)[0]))
		eip.addr += 4
		return {"machine":machine.bytes, "assembly": encodedOperands[op] + ", 0x" + imm32}
	else:
		raise Exception("Error: mov mnemonic")
	
def movs(f, eip, op):
	machine = MachineCode()
	machine.bytes = op
	eip.addr += 1 
	if op == "a4":
		return {"machine":machine.bytes, "assembly": "movs BYTE PTR es:[edi], BYTE PTR ds:[esi]"}
	elif op == "a5":
		return {"machine":machine.bytes, "assembly": "movs DWORD PTR es:[edi], DWORD PTR ds:[esi]"}
	else:
		raise Exception("Error: movsb/movsd mnemonic")
	
def mul(f, eip, op):
	machine = MachineCode()
	machine.bytes = op
	eip.addr += 1 
	if op == "f7":
		modrm = binascii.hexlify(f.read(1))
		machine.bytes = machine.bytes + " " + modrm
		eip.addr += 1 
		binary_string = dec2bin(int(modrm, 16))
		mod = binary_string[0:2]
		rm = binary_string[5:]
		parsedmod = parseModRM(mod, rm, eip, f, machine)
		if rm == "100":
                                rm = binary_string[5:8]
                                sib = binary_string[8:]
                                parsedsib = parseSIB(mod, rm, eip, f, machine, sib)
                                return {"machine":machine.bytes, "assembly":"mul " + parsedsib}
		return {"machine":machine.bytes, "assembly":"mul " + parsedmod}
	else:
		raise Exception("Error: mul mnemonic")
	
def neg(f, eip, op):
	machine = MachineCode()
	machine.bytes = op
	eip.addr += 1 
	if op == "f7":
		modrm = binascii.hexlify(f.read(1))
		machine.bytes = machine.bytes + " " + modrm
		eip.addr += 1 
		binary_string = dec2bin(int(modrm, 16))
		mod = binary_string[0:2]
		rm = binary_string[5:]
		parsedmod = parseModRM(mod, rm, eip, f, machine)
		if rm == "100":
                                rm = binary_string[5:8]
                                sib = binary_string[8:]
                                parsedsib = parseSIB(mod, rm, eip, f, machine, sib)
                                return {"machine":machine.bytes, "assembly":"neg " + parsedsib}
		return {"machine":machine.bytes, "assembly":"neg " + parsedmod}
	else:
		raise Exception("Error: neg mnemonic")
	
def nop(f, eip, op):
	machine = MachineCode()
	machine.bytes = op
	eip.addr += 1 
	if op == "90":
		return {"machine":machine.bytes, "assembly":"nop"}
	elif op == "1f":
		modrm = binascii.hexlify(f.read(1))
		machine.bytes = machine.bytes + " " + modrm
		eip.addr += 1 
		binary_string = dec2bin(int(modrm, 16))
		mod = binary_string[0:2]
		rm = binary_string[5:]
		parsedmod = parseModRM(mod, rm, eip, f, machine)
		if rm == "100":
                                rm = binary_string[5:8]
                                sib = binary_string[8:]
                                parsedsib = parseSIB(mod, rm, eip, f, machine, sib)
                                return {"machine":machine.bytes, "assembly":"nop " + parsedsib}
		return {"machine":machine.bytes, "assembly":"nop " + parsedmod}
	else:
		raise Exception("Error: neg mnemonic")
	
def notX(f, eip, op): # not is reserved by Py
	machine = MachineCode()
	machine.bytes = op
	eip.addr += 1 
	if op == "f7":
		modrm = binascii.hexlify(f.read(1))
		machine.bytes = machine.bytes + " " + modrm
		eip.addr += 1 
		binary_string = dec2bin(int(modrm, 16))
		mod = binary_string[0:2]
		rm = binary_string[5:]
		parsedmod = parseModRM(mod, rm, eip, f, machine)
		if rm == "100":
                                rm = binary_string[5:8]
                                sib = binary_string[8:]
                                parsedsib = parseSIB(mod, rm, eip, f, machine, sib)
                                return {"machine":machine.bytes, "assembly":"not " + parsedsib}
		return {"machine":machine.bytes, "assembly":"not " + parsedmod}
	else:
		raise Exception("Error: not mnemonic")
	
def orX(f, eip, op): # or is reserved by Py
	machine = MachineCode()
	machine.bytes = op
	eip.addr += 1 
	if op == "09" or op == "0b":
		modrm = binascii.hexlify(f.read(1))
		machine.bytes = machine.bytes +  " " + modrm
		eip.addr += 1 
		binary_string = dec2bin(int(modrm, 16))
		mod = binary_string[0:2]
		reg = binary_string[2:5]
		rm = binary_string[5:]
		parsedmod = parseModRM(mod, rm, eip, f, machine)
		if op == "09":
                        if rm == "100":
                                rm = binary_string[5:8]
                                sib = binary_string[8:]
                                parsedsib = parseSIB(mod, rm, eip, f, machine, sib)
                                return {"machine":machine.bytes, "assembly":"or " + parsedsib + ", " + RegisterEncodings[reg]}
			return {"machine":machine.bytes, "assembly":"or " + parsedmod + ", " + RegisterEncodings[reg]}
		else:
                        if rm == "100":
                                rm = binary_string[5:8]
                                sib = binary_string[8:]
                                parsedsib = parseSIB(mod, rm, eip, f, machine, sib)
                                return {"machine":machine.bytes, "assembly":"or " + RegisterEncodings[reg] + ", " + parsedsib}
			return {"machine":machine.bytes, "assembly":"or " + RegisterEncodings[reg] + ", " + parsedmod}
	elif op == "81" or op == "83":
		modrm = binascii.hexlify(f.read(1))
		machine.bytes = machine.bytes + " " + modrm
		eip.addr += 1 
		binary_string = dec2bin(int(modrm, 16))
		mod = binary_string[0:2]
		rm = binary_string[5:]
		parsedmod = parseModRM(mod, rm, eip, f, machine)
		if op == "81":
			dword = f.read(4)
			imm32 = str(hex(unpack('<L', dword)[0]))
			machine.bytes = machine.bytes + " " + print_dword(binascii.hexlify(dword))
			eip.addr += 4
			if rm == "100":
                                rm = binary_string[5:8]
                                sib = binary_string[8:]
                                parsedsib = parseSIB(mod, rm, eip, f, machine, sib)
                                return {"machine":machine.bytes, "assembly":"or " + parsedsib + ", 0x" + imm32}
			return {"machine":machine.bytes, "assembly": "or " + parsedmod + ", 0x" + imm32}
		else:
			byte = f.read(1)
			imm8 = binascii.hexlify(byte)
			machine.bytes = machine.bytes + " " + binascii.hexlify(byte)
			eip.addr += 1
			if rm == "100":
                                rm = binary_string[5:8]
                                sib = binary_string[8:]
                                parsedsib = parseSIB(mod, rm, eip, f, machine, sib)
                                return {"machine":machine.bytes, "assembly":"or " + parsedsib + ", 0x" + imm8}
			return {"machine":machine.bytes, "assembly":"or " + parsedmod + ", 0x" + imm8}
	elif op == "0d":
		dword = f.read(4)
		imm32 = str(hex(unpack('<L', dword)[0]))
		machine.bytes = machine.bytes + " " + print_dword(binascii.hexlify(dword))
		eip.addr += 4 
		return {"machine":machine.bytes, "assembly":"or eax, 0x" + imm32}	
	else:
		raise Exception("Error: or mnemonic")
	
def pop(f, eip, op):
	machine = MachineCode()
	machine.bytes = op
	if op in encodedOperands:
		eip.addr += 1 
		return {"machine":machine.bytes, "assembly":encodedOperands[op]}
	elif op == "8f":
		modrm = binascii.hexlify(f.read(1))
		machine.bytes = machine.bytes + " " + modrm
		eip.addr += 1 
		binary_string = dec2bin(int(modrm, 16))
		mod = binary_string[0:2]
		rm = binary_string[5:]
		parsedmod = parseModRM(mod, rm, eip, f, machine)
		if rm == "100":
                                rm = binary_string[5:8]
                                sib = binary_string[8:]
                                parsedsib = parseSIB(mod, rm, eip, f, machine, sib)
                                return {"machine":machine.bytes, "assembly":"pop " + parsedsib}
		return {"machine":machine.bytes, "assembly":"pop " + parsedmod}
	else:
		raise Exception("Error: pop mnemonic")
	
def push(f, eip, op):
	machine = MachineCode()
	machine.bytes = op
	eip.addr += 1 
	if op in encodedOperands:
		return {"machine":machine.bytes, "assembly":encodedOperands[op]}
	elif op == "68":
		dword = f.read(4)
		machine.bytes = machine.bytes + " " + print_dword(binascii.hexlify(dword))
		imm32 = str(hex(unpack('<L', dword)[0]))
		eip.addr += 4 
		return {"machine":machine.bytes, "assembly":"push 0x" + imm32}
	elif op == "6a":
		byte = f.read(1)
		imm8 = binascii.hexlify(byte)
		machine.bytes = machine.bytes + " " + binascii.hexlify(byte)
		eip.addr += 1 
		return {"machine":machine.bytes, "assembly":"push 0x" + imm8}
	elif op == "ff":
		modrm = binascii.hexlify(f.read(1))
		machine.bytes = machine.bytes + " " + modrm
		eip.addr += 1 
		binary_string = dec2bin(int(modrm, 16))
		mod = binary_string[0:2]
		rm = binary_string[5:]
		parsedmod = parseModRM(mod, rm, eip, f, machine)
		if rm == "100":
                                rm = binary_string[5:8]
                                sib = binary_string[8:]
                                parsedsib = parseSIB(mod, rm, eip, f, machine, sib)
                                return {"machine":machine.bytes, "assembly":"push 0x" + parsedsib}
		return {"machine":machine.bytes, "assembly":"push 0x" + parsedmod}
	else:
		raise Exception("Error: push mnemonic")
	
def ret(f, eip, op):
	machine = MachineCode()
	machine.bytes = op
	eip.addr += 1 
	if op == "c3":
		handle_ret(f, eip, op)
		return {"machine":op, "assembly":"retn"}
	elif op == "cb":
		handle_ret(f, eip, op)
		return {"machine":op, "assembly":"retf"}
	elif op == "c2":
		word = f.read(2)
		machine.bytes = machine.bytes + " " + print_dword(binascii.hexlify(word))
		imm16 = str(hex(unpack('<h', word)[0]))
		eip.addr +=2
		handle_ret(f, eip, op)
		return {"machine":machine.bytes, "assembly":"retn " + imm16}
	elif op == "ca":
		word = f.read(2)
		machine.bytes = machine.bytes + " " + print_dword(binascii.hexlify(word))
		imm16 = str(hex(unpack('<h', word)[0]))
		eip.addr +=2
		handle_ret(f, eip, op)
		return {"machine":machine.bytes, "assembly":"retf " + imm16}
	else:
		raise Exception("Error: retn/retf mnemonic")
	
def shift(f, eip, op): 
# consists of shr, shl, sal, and sar
# sal and shl are roughly the same because
# they both shift the bits in the destination operand towards the more significant bit locations
	machine = MachineCode()
	machine.bytes = op
	eip.addr += 1 
	if op == "d1": 
		modrm = binascii.hexlify(f.read(1))
		machine.bytes = machine.bytes + " " + modrm
		eip.addr += 1 
		binary_string = dec2bin(int(modrm, 16))
		mod = binary_string[0:2]
		reg = binary_string[2:5]
		rm = binary_string[5:]
		parsedmod = parseModRM(mod, rm, eip, f, machine)
		if reg == "101":
                        if rm == "100":
                                rm = binary_string[5:8]
                                sib = binary_string[8:]
                                parsedsib = parseSIB(mod, rm, eip, f, machine, sib)
                                return {"machine":machine.bytes, "assembly":"sar " + parsedsib + ", 1"}
			return {"machine":machine.bytes, "assembly":"shr " + parsedmod + ", 1"}
		elif reg == "100":
                        if rm == "100":
                                rm = binary_string[5:8]
                                sib = binary_string[8:]
                                parsedsib = parseSIB(mod, rm, eip, f, machine, sib)
                                return {"machine":machine.bytes, "assembly":"sar " + parsedsib + ", 1"}
			return {"machine":machine.bytes, "assembly":"shl " + parsedmod + ", 1"}
		elif reg == "111":
                        if rm == "100":
                                rm = binary_string[5:8]
                                sib = binary_string[8:]
                                parsedsib = parseSIB(mod, rm, eip, f, machine, sib)
                                return {"machine":machine.bytes, "assembly":"sar " + parsedsib + ", 1"}
			return {"machine":machine.bytes, "assembly":"sar " + parsedmod + ", 1"}
		else:
			raise Exception("Unsupported shr/shl/sal/sar mnemonic")
	else:
		raise Exception("Error: shr/shl/sal/sar mnemonic")
	
def sbb(f, eip, op):
	machine = MachineCode()
	machine.bytes = op
	eip.addr += 1
	if op == "19" or op == "1b":
		modrm = binascii.hexlify(f.read(1))
		machine.bytes = machine.bytes +  " " + modrm
		eip.addr += 1
		binary_string = dec2bin(int(modrm, 16))
		mod = binary_string[0:2]
		reg = binary_string[2:5]
		rm = binary_string[5:]	
		parsedmod = parseModRM(mod, rm, eip, f, machine)
		if op == "19":
                        if rm == "100":
                                rm = binary_string[5:8]
                                sib = binary_string[8:]
                                parsedsib = parseSIB(mod, rm, eip, f, machine, sib)
                                return {"machine":machine.bytes, "assembly":"sbb " + parsedsib + ", " + RegisterEncodings[reg]}
			return {"machine":machine.bytes, "assembly":"sbb " + parsedmod + ", " + RegisterEncodings[reg]}
		else:
                        if rm == "100":
                                rm = binary_string[5:8]
                                sib = binary_string[8:]
                                parsedsib = parseSIB(mod, rm, eip, f, machine, sib)
                                return {"machine":machine.bytes, "assembly":"sbb " + RegisterEncodings[reg] + ", " + parsedsib}
			return {"machine":machine.bytes, "assembly":"sbb " + RegisterEncodings[reg] + ", " + parsedmod}
	elif op == "81" or op == "83":
		modrm = binascii.hexlify(f.read(1))
		machine.bytes = machine.bytes + " " + modrm
		eip.addr += 1
		binary_string = dec2bin(int(modrm, 16))
		mod = binary_string[0:2]
		rm = binary_string[5:]
		parsedmod = parseModRM(mod, rm, eip, f, machine)
		if op == "81":
			dword = f.read(4)
			imm32 = str(hex(unpack('<L', dword)[0]))
			machine.bytes = machine.bytes + " " + print_dword(binascii.hexlify(dword))
			eip.addr += 4
			if rm == "100":
                                rm = binary_string[5:8]
                                sib = binary_string[8:]
                                parsedsib = parseSIB(mod, rm, eip, f, machine, sib)
                                return {"machine":machine.bytes, "assembly":"sbb " + parsedsib + ", 0x" + imm32}
			return {"machine":machine.bytes, "assembly": "sbb " + parsedmod + ", 0x" + imm32}
		else:
			byte = f.read(1)
			imm8 = binascii.hexlify(byte)
			machine.bytes = machine.bytes + " " + binascii.hexlify(byte)
			eip.addr += 1
			if rm == "100":
                                rm = binary_string[5:8]
                                sib = binary_string[8:]
                                parsedsib = parseSIB(mod, rm, eip, f, machine, sib)
                                return {"machine":machine.bytes, "assembly":"sbb " + parsedsib + ", 0x" + imm8}
			return {"machine":machine.bytes, "assembly":"sbb " + parsedmod + ", 0x" + imm8}
	elif op == "1d":
		dword = f.read(4)
		imm32 = str(hex(unpack('<L', dword)[0]))
		machine.bytes = machine.bytes + " " + print_dword(binascii.hexlify(dword))
		eip.addr += 4 
		return {"machine":machine.bytes, "assembly":"sbb eax, 0x" + imm32}	
	else:
		raise Exception("Error: sbb mnemonic")
	
def test(f, eip, op):
	machine = MachineCode()
	machine.bytes = op
	eip.addr += 1 
	if op == "a9":
		dword = f.read(4)
		imm32 = str(hex(unpack('<L', dword)[0]))
		machine.bytes = machine.bytes + " " + print_dword(binascii.hexlify(dword))
		eip.addr += 4 
		return {"machine":machine.bytes, "assembly":"test eax, 0x" + imm32}
	elif op == "f7":
		modrm = binascii.hexlify(f.read(1))
		eip.addr += 1 
		machine.bytes = machine.bytes + " " + modrm
		binary_string = dec2bin(int(modrm, 16))
		mod = binary_string[0:2]
		rm = binary_string[5:]
		parsedmod = parseModRM(mod, rm, eip, f, machine)
		dword = f.read(4)
		eip.addr += 4 
		imm32 = str(hex(unpack('<L', dword)[0]))
		machine.bytes = machine.bytes + " " + print_dword(binascii.hexlify(dword))
		if rm == "100":
                        rm = binary_string[5:8]
                        sib = binary_string[8:]
                        parsedsib = parseSIB(mod, rm, eip, f, machine, sib)
                        return {"machine":machine.bytes, "assembly":"test " + parsedsib + ", 0x" + imm32}
		return {"machine":machine.bytes, "assembly":"test " + parsedmod  + ", 0x" + imm32}
	elif op == "85":
		modrm = binascii.hexlify(f.read(1))
		eip.addr += 1 
		machine.bytes = machine.bytes + " " + modrm
		binary_string = dec2bin(int(modrm, 16))
		mod = binary_string[0:2]
		reg = binary_string[2:5]
		rm = binary_string[5:]
		if rm == "100":
                                rm = binary_string[5:8]
                                sib = binary_string[8:]
                                parsedsib = parseSIB(mod, rm, eip, f, machine, sib)
                                return {"machine":machine.bytes, "assembly":"test " + parsedsib + ", " + RegisterEncodings[reg]}
		parsedmod = parseModRM(mod, rm, eip, f, machine)
		return {"machine":machine.bytes, "assembly":"test " + parsedmod + ", " +  RegisterEncodings[reg]}
	else:	
		raise Exception("Error: test mnemonic")
	
def xor(f, eip, op):
	machine = MachineCode()
	machine.bytes = op
	eip.addr += 1 
	if op == "35":
		dword = f.read(4)
		machine.bytes = machine.bytes + " " + print_dword(binascii.hexlify(dword))
		imm32 = str(hex(unpack('<L', dword)[0]))
		eip.addr += 4
		return {"machine":machine.bytes, "assembly":"xor eax, 0x" + imm32}
	elif op == "31" or op == "33":
		modrm = binascii.hexlify(f.read(1))
		machine.bytes = machine.bytes + " " + modrm
		eip.addr += 1 
		binary_string = dec2bin(int(modrm, 16))
		mod = binary_string[0:2]
		reg = binary_string[2:5]
		rm = binary_string[5:]
		parsedmod = parseModRM(mod, rm, eip, f, machine)
		if op == "31":
                        if rm == "100":
                                rm = binary_string[5:8]
                                sib = binary_string[8:]
                                parsedsib = parseSIB(mod, rm, eip, f, machine, sib)
                                return {"machine":machine.bytes, "assembly":"xor " + parsedsib + ", " + RegisterEncodings[reg]}
			return {"machine":machine.bytes, "assembly":"xor " + parsedmod + ", " + RegisterEncodings[reg]}
		else:
                        if rm == "100":
                                rm = binary_string[5:8]
                                sib = binary_string[8:]
                                parsedsib = parseSIB(mod, rm, eip, f, machine, sib)
                                return {"machine":machine.bytes, "assembly":"xor " + RegisterEncodings[reg] + ", " + parsedsib}
			return {"machine":machine.bytes, "assembly":"xor " + RegisterEncodings[reg] + ", " + parsedmod}
	elif op == "81" or op == "83":
		modrm = binascii.hexlify(f.read(1))
		eip.addr += 1 
		binary_string = dec2bin(int(modrm, 16))
		mod = binary_string[0:2]
		rm = binary_string[5:]
		parsedmod = parseModRM(mod, rm, eip, f, machine)
		if op == "81":
			dword = f.read(4)
			machine.bytes = machine.bytes + " " + print_dword(binascii.hexlify(dword))
			imm32 = str(hex(unpack('<L', dword)[0]))
			eip.addr += 4
                        if rm == "100":
                                rm = binary_string[5:8]
                                sib = binary_string[8:]
                                parsedsib = parseSIB(mod, rm, eip, f, machine, sib)
                                return {"machine":machine.bytes, "assembly":"xor 0x " + parsedsib + ", " + imm32}
			return {"machine":machine.bytes, "assembly":"xor 0x" + parsedmod + ", " + imm32}
		elif op == "83":
			byte = f.read(1)
			imm8 = binascii.hexlify(byte)
			machine.bytes = machine.bytes + " " + binascii.hexlify(byte)
			eip.addr += 1
			if rm == "100":
                                rm = binary_string[5:8]
                                sib = binary_string[8:]
                                parsedsib = parseSIB(mod, rm, eip, f, machine, sib)
                                return {"machine":machine.bytes, "assembly":"xor 0x " + parsedsib + ", " + imm8}
			return {"machine":machine.bytes, "assembly":"xor 0x" + parsedmod + ", " + imm8}
	else:
		raise Exception("Error: xor mnemonic")
	
# Determine which opcode function to call based on the first byte
opcodeLookupTable = {
	'01': add,
	'03': add,
	'05': add,
	'09': orX,
	'0b': orX,
	'0d': orX,
	'0f': ambiguous,
	'19': sbb,
	'1b': sbb,
	'1d': sbb,
	'1f': nop,
	'21': andX,
	'23': andX,
	'25': andX,
	'31': xor,
	'33': xor,
	'35': xor,
	'39': cmpX,
	'3b': cmpX,
	'3d': cmpX,
	'40': incANDdec,
	'41': incANDdec,
	'42': incANDdec,
	'43': incANDdec,
	'44': incANDdec,
	'45': incANDdec,
	'46': incANDdec,
	'47': incANDdec,
	'48': incANDdec,
	'49': incANDdec,
	'4a': incANDdec,
	'4b': incANDdec,
	'4c': incANDdec,
	'4d': incANDdec,
	'4e': incANDdec,
	'4f': incANDdec,
	'50': push,
	'51': push,
	'52': push,
	'53': push,
	'54': push,
	'55': push,
	'56': push,
	'57': push,
	'58': pop,
	'59': pop,
	'5a': pop,
	'5b': pop,
	'5c': pop,
	'5d': pop,
	'5e': pop,
	'5f': pop,
	'68': push,
	'6a': push,
	'6b': imul,
	'69': imul,
	'74': jz,
	'75': jnz,
	'81': ambiguous,
	'83': ambiguous,
	'85': test,
	'89': mov,
	'8b': mov,
	'8d': lea,
	'8f': pop,
	'90': nop,
 	'a4': movs,
	'a5': movs,
	'af': imul,
	'a9': test,
	'b8': mov,
	'b9': mov,
	'ba': mov,
	'bb': mov,
	'bc': mov,
	'bd': mov,
	'be': mov,
	'bf': mov,
	'c2': ret,
	'c3': ret,
	'c7': mov,
	'ca': ret,
	'cb': ret,
	'd1': shift,
	'e8': call,
	'e9': jmp,
	'eb': jmp,
	'f2': ambiguous,
	'f3': ambiguous,
	'f7': ambiguous,
	'fe': ambiguous,
	'ff': ambiguous,}

def main():
	# read the file as a hex
	try:
		f = open(filename, "rb")
		print "File: " + ntpath.basename(filename) + "\n"
		try:
			start = 0
			f.seek(-1, 2)
			end = f.tell()
			f.seek(0, 0)
			eip = EIP()
			output_buffer = ""
			error_buffer = ""
			global byte
			try:
				byte = f.read(1)
				while byte != "":
					byte_string = binascii.hexlify(byte)
					if byte_string in opcodeLookupTable:
						loc = str(hex(eip.addr))
						instr = opcodeLookupTable[byte_string](f, eip, byte_string)
						disassembly[loc] = instr["assembly"]
						machine[loc] = instr["machine"]
					elif byte_string == "00":
						eip.addr += 1
					else:
						print "Unknown opcode: " + byte_string + " at: " + str(hex(eip.addr)) + ".  Continuing."
						eip.addr += 1
					if byte != "":
						byte = f.read(1)
			except:
				# display errors at end
				error_buffer += "Error: " + str(sys.exc_info()[1]) + "\n\n"
				error_buffer += traceback.format_exc() + "\n\n"
			for instr in range(start,end): 
				try:
					output_buffer += '{0:>4s}:\t{1:30s} {2:4s}\n'.format(str(hex(instr)) , machine[str(hex(instr))], disassembly[str(hex(instr))])
				except:
					continue	
		finally:
			line_output = output_buffer.split('\n')
			for line in line_output:
				offset = line[:4]
				if offset in offset_labels:
					print "\noffset_" + '{:x}'.format(int(offset, 16)) + "h:"
				print line
			f.close()
			# print errors
			print "\n"
			print "There were the errors found during disassembly:\n"
			print error_buffer
	except:
		print "Error: Invalid file"
main()
