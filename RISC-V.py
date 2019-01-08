# --------------------------------------------------------
# David Demicco
# RISC-V processor module for IDA-PRO
# using information from DEVA's ida-riscv and the example in idapro
#
# this module is losely based on DEVA's ida-RISC-V.py implentation and the exmaple msp430.py in /procs/

# -----------------------------------------------------------
# this section is from the msp430.py provided with idapro 
import sys
import copy

from ida_bytes import *
from ida_ua import *
from ida_idp import *
from ida_auto import *
from ida_nalt import *
from ida_funcs import *
from ida_lines import *
from ida_problems import *
from ida_offset import *
from ida_segment import *
from ida_name import *
from ida_netnode import *
from ida_xref import *
from ida_idaapi import *
import ida_frame
import idc


# values for insn_t.auxpref
AUX_SIGNED = 1


# extract bitfield occupying bits high..low from val (inclusive, start from 0)
def BITS(val, high, low):
  return (val>>low)&((1<<(high-low+1))-1)

# extract one bit
def BIT(val, bit):
  return (val>>bit) & 1

# sign extend b low bits in x
# from "Bit Twiddling Hacks"
def SIGNEXT(x, b):
  m = 1 << (b - 1)
  x = x & ((1 << b) - 1)
  return (x ^ m) - m
#----------------------------------------------------------

class riscv_processor_t(processor_t):
	id = 0x8921 #arbitrary number above 8000
	
	#processor features
	flag = PRN_HEX | PRN_HEX | PR_RNAMESOK | PR_NO_SEGMOVE | PR_USE32 | PR_DEFSEG32

	# code segment byte size
	cnbits = 8; 

	# non code segment byte size
	dnbits = 8; 

	psnames = ['riscv']
	plnames = ['RISCV']

  
  	segreg_size = 0


	# codestart = ?
	# Array of 'return' instruction opcodes (optional)
    	retcodes = ['\x82\x80']   # 8082: ret


	#instruction array...
	instruc = [
		{ 'name': '', 'feature': 0},
		
		#unknown RISCV instruction
			{ 'name': 'UKN', 'feature' : 0, 'cmt': "Unable to resolve instruction"},
			{ 'name': 'UKN_c', 'feature' : 0, 'cmt': "Unable to resolve compressed instruction"},

		

		#base Integer instructions RV32I
			#loads
			{ 'name': 'lb', 'feature': CF_CHG1 | CF_USE2, 'cmt': "Load Byte from base+offset to rd"},		#I
			{ 'name': 'lh', 'feature': CF_CHG1 | CF_USE2, 'cmt': "Load Halfword from rs1+offset to rd"},		#I
			{ 'name': 'lw', 'feature': CF_CHG1 | CF_USE2, 'cmt': "Load Word from rs1+offset to rd"},		#I
			{ 'name': 'lwu', 'feature': CF_CHG1 | CF_USE2, 'cmt': "Load Word ubsugbed from rs1+offset to rd"},	#I
			{ 'name': 'lbu', 'feature': CF_CHG1 | CF_USE2, 'cmt': "Load Byte unsigned from rs1+offset to rd"}, 	#I
			{ 'name': 'lhu', 'feature': CF_CHG1 | CF_USE2, 'cmt': "Load HalfWord Unsigned from rs1+offset to rd"}, 	#I
			{ 'name': 'ld', 'feature': CF_CHG1 | CF_USE2, 'cmt': "Load double word from base+offset to rd"},	#I	
					


			#Stores
			{ 'name': 'sb', 'feature': CF_USE1 | CF_USE2, 'cmt': "Store Byte from rs2 to rs1+offset"},	 	#S
			{ 'name': 'sh', 'feature': CF_USE1 | CF_USE2, 'cmt': "Store HalfWord from rs2 to rs1+offset"},		#S
			{ 'name': 'sw', 'feature': CF_USE1 | CF_USE2, 'cmt': "Store Word from rs2 to rs1+offset"},	 	#S
			{ 'name': 'sd', 'feature': CF_USE1 | CF_USE2, 'cmt': "Store dword from rs2 to rs1+offset"},		#S
			{ 'name': 'sq', 'feature': CF_USE1 | CF_USE2, 'cmt': "Store qWord from rs2 to rs1+offset"},		#S

			#Shifts
 	
			{ 'name': 'slli', 'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': "store rs1 >> imm in rd"},				#I
	
			#Immidates 
			{ 'name': 'addi', 'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': "store rs1 + imm in rd"},		     		#I
			{ 'name': 'addiw', 'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': "store rs1 + imm in rd"},		     		#I
			{ 'name': 'slti', 'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': "writes 1 to rd if rs1 < imm, else writes 1"}, 	#I
			{ 'name': 'sltiu', 'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': "writes 1 to rd if rs1 < imm, else writes 1, unsigned compare"},
			{ 'name' :'xori', 'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': "store rsi XOR imm in rd"},
			{ 'name' :'ori', 'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': "store rsi | imm in rd"},
			{ 'name' :'andi', 'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': "store rsi & imm in rd"},
			{ 'name' :'slli', 'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': "store rsi << imm in rd"},
			{ 'name' :'srli', 'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': "store rsi >> imm in rd"},
			{ 'name' :'srai', 'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': "store rsi >> imm in rd, copying the MSB"},


			{ 'name' :'lb', 'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': "loads the a byte from rs1(offset) into rd"},		#I
			{ 'name' :'lbu', 'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': "loads a byte from rs1(offset) zero extended into rd"},		#I
			{ 'name' :'ld', 'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': "loads a doubleword from rs1(offset) into rd"},		#I
			{ 'name' :'lh', 'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': "loads a halfword from rs1(offset) into rd"},		#I
			{ 'name' :'lhu', 'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': "loads a halfword from rs1(offset) into rd, zero extended"},		#I
			{ 'name': 'ecall', 'feature': 0, 'cmt': "enviormental call"},								#I
			{ 'name': 'ebrake', 'feature': 0, 'cmt': "enviormental call"},								#I
			{ 'name': 'fence', 'feature': CF_USE1 | CF_USE2,  'cmt': "Fence (pred, succ)"},	
			{ 'name': 'fence_i', 'feature': 0, 'cmt': "Fence instruction stream"},	
			
			{ 'name': 'jalr', 'feature': CF_CHG1 | CF_USE2 | CF_CALL, 'cmt': "Jump and link register"},				#I
			{ 'name': 'jal', 'feature': CF_CHG1 | CF_USE2 | CF_CALL, 'cmt': "Jump and link"},					#J	

			#R types
			{ 'name': 'sll', 'feature': CF_CHG1 |  CF_USE2 | CF_USE3, 'cmt': "store rs1 << rs2 in rd"},				#R
			{ 'name': 'srl', 'feature': CF_CHG1 |  CF_USE2 | CF_USE3, 'cmt': "store rs1 >> rs2 in rd"},				#R
			{ 'name': 'sra', 'feature': CF_CHG1 |  CF_USE2 | CF_USE3, 'cmt': "store rs1 >> rs2 in rd"},				#R
			{ 'name': 'sllw', 'feature': CF_CHG1 |  CF_USE2 | CF_USE3, 'cmt': "store rs1 << rs2 in rd"},				#R
			{ 'name': 'srlw', 'feature': CF_CHG1 |  CF_USE2 | CF_USE3, 'cmt': "store rs1 >> rs2 in rd"},				#R
			{ 'name': 'sraw', 'feature': CF_CHG1 |  CF_USE2 | CF_USE3, 'cmt': "store rs1 >> rs2 in rd"},				#R
			{ 'name': 'add', 'feature': CF_CHG1 |  CF_USE2 | CF_USE3, 'cmt': "store rs1 + rs2 in rd"},				#R
			{ 'name': 'sub', 'feature': CF_CHG1 |  CF_USE2 | CF_USE3, 'cmt': "store rs1 - rs2 in rd"},				#R
			{ 'name': 'addw', 'feature': CF_CHG1 |  CF_USE2 | CF_USE3, 'cmt': "store rs1 + rs2 in rd"},				#R
			{ 'name': 'subw', 'feature': CF_CHG1 |  CF_USE2 | CF_USE3, 'cmt': "store rs1 - rs2 in rd"},				#R
			{ 'name': 'xor', 'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': "store rs1 ^ rs2 in rd"},				#R 
			{ 'name': 'or', 'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': "store rs1 | rs2 in rd"},				#R 
			{ 'name': 'and', 'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': "store rs1 & rs2 in rd"},				#R
			
			#U types
			{ 'name': 'lui', 'feature': CF_CHG1 | CF_USE2,  'cmt': "writes the signext immedait, left shifted by 12 to rd"},	#U 
			{ 'name': 'auipc', 'feature': CF_CHG1 | CF_USE2,  'cmt': "writes the signext imedate + pc to rd"},			#U 
			#Branches
			{ 'name': 'beq', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': "branch if rs1 and rs2 are equal"},		 	#SB
			{ 'name': 'bne', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': "branch if rs1 and rs2 are not equal"},			#SB
			{ 'name': 'blt', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': "branch if rs1 < rs2"},					#SB
			{ 'name': 'bge', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': "branch if rs1 >= rs2"},				#SB
			{ 'name': 'bltu', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': "branch if rs1 < rs2 unsigned"},			#SB
			{ 'name': 'bgeu', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': "branch if rs1 >= rs2 unsigned"},			#SB
			
			##psuedo instructions
			{ 'name': 'ret', 'feature': CF_STOP, 'cmt': 'emulated return function?'}	
	
	]

	instruc_start = 0
	instruc_end = len(instruc) + 1
	
	#alignment code, optional but i think this will work?
	real_width = (0, 7, 15, 19)

	#taken from 0xDeva's file
	assembler = {
		"flag": ASH_HEXF0 | ASD_DECF0 | ASO_OCTF5 | ASB_BINF0 | AS_N2CHR,
		"uflag": 0,
		"name": "RISC-V asm",
		"origin": ".org",
		"end": ".end",
		"cmnt": ";",
		"ascsep": '"',
		"accsep": "'",
		"esccodes": "\"'",
		"a_ascii": ".ascii",
		"a_byte": ".byte",
		"a_word": ".word",
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

#--------------------------------------------------------------------------------
# optional callbacks

#--------------------------------------------------------------------------------
# manditory callbacks

	def handle_operand(self, insn, op, isRead):
		optype = op.type
		itype = insn.itype
		if optype == o_imm:  		
			if itype in [self.itype_jal]:
				if insn.Op1.reg != 0:  #jal and jalr with a register of zero are not function calls, but jumps
					insn.add_cref(op.value, op.offb, fl_CN); #this is a call
				else: 
					insn.add_cref(op.value, op.offb, fl_JN);
		if optype == o_near:
			insn.add_cref(op.addr, op.offb, fl_JN);
		return 1

	def notify_emu(self, insn):
		"""
		Emulate instruction, create cross-references, plan to analyze
		subsequent instructions, modify flags etc. Upon entrance to this function
		all information about the instruction is in 'insn' structure.
		If zero is returned, the kernel will delete the instruction.
		"""
		features = insn.get_canon_feature()
		if features & CF_USE1:
			self.handle_operand(insn, insn.Op1, 1) 
		if features & CF_CHG1:
			self.handle_operand(insn, insn.Op1, 0)
		if features & CF_USE2:
			self.handle_operand(insn, insn.Op2, 1) 
		if features & CF_CHG2:
			self.handle_operand(insn, insn.Op2, 0) 
		if features & CF_USE3:
			self.handle_operand(insn, insn.Op3, 1) 
		if features & CF_CHG3:
			self.handle_operand(insn, insn.Op3, 0) 
		

		if (features & CF_STOP == 0): add_cref(insn.ea, insn.ea + insn.size, fl_F)

		return 1

	def notify_out_operand(self, ctx, op):
		"""
		Generate text representation of an instructon operand.
		This function shouldn't change the database, flags or anything else.
		All these actions should be performed only by the emu() function.
		This function uses out_...() functions from ua.hpp to generate the operand text
		Returns: 1-ok, 0-operand is hidden.
		"""
		optype = op.type


		if optype == o_reg:
            		ctx.out_register(self.reg_names[op.reg])
		if optype == o_imm:
			ctx.out_value(op, OOFW_IMM | OOF_SIGNED)
		if optype == o_near:
			ctx.out_name_expr(op, op.addr, BADADDR)
		if optype == o_displ:
			ctx.out_value(op, OOF_ADDR | OOFW_16 | OOF_SIGNED ) 
			ctx.out_symbol('(')
			ctx.out_register(self.reg_names[op.reg])
			ctx.out_symbol(')')
		if optype == o_phrase:
            		ctx.out_register(self.reg_names[op.reg])

		return 1

	def notify_out_insn(self, ctx):
		"""
		Generate text representation of an instruction in 'ctx.insn' structure.
		This function shouldn't change the database, flags or anything else.
		All these actions should be performed only by emu() function.
		Returns: nothing
		"""
		## for now we just have unknown, and  unknown does not care about registers
		if (ctx.insn.size == 2):
			ctx.out_line("c.", COLOR_INSN)
    		ctx.out_mnemonic()
		


		#this is from the mps430 example
		if (ctx.insn.Op1.type != o_void):
			ctx.out_one_operand(0)

		# output the rest of operands separated by commas
		for i in xrange(1, 3):
			if (ctx.insn[i].type == o_void):
			        break
			ctx.out_symbol(',')
			ctx.out_char(' ')
			ctx.out_one_operand(i)

		ctx.set_gen_cmt()
		ctx.flush_outbuf()
		return 1

	def is_I_type(self, op):
		if op == 0b0010011: #athrimitic immediates
			return True
		if op == 0b0001111: # some kind of fence thing?
			return True
		if op == 0b1110011: # control and system operations
			return True
		if op == 0b0000011: # loads 
			return True
		if op == 0b1100111: # jalr 
			return True
		else:
			return False
	
	def is_J_type(self, op):
		if op == 0b1101111: #jal
			return True
		else:
			return False

	def is_S_type(self, op):
		if op == 0b0100011: 
			return True
		else:
			return False

	def is_SB_type(self, op):
		if op == 0b1100011:
			return True
		else:
			return False
			
	def is_U_type(self, op):
		if (op == 0b0010111) or (op == 0b0110111):
			return True
		else:
			return False
	
	def is_R_type(self, op):
		if (op == 0b0111011) or (op == 0b0110011):
			return True
		else:
			return False
	
	def decode_R_type(self, insn, w):
		op = BITS(w, 6, 0)
		funct7 = BITS(w, 31, 25)
		rs2 = BITS(w, 24,20)
		rs1 = BITS(w, 19, 15)
		funct3 = BITS(w, 14, 12)
		rd = BITS(w, 11,7)
		insn.Op1.type = o_reg
		insn.Op1.reg = rd
		insn.Op2.type = o_reg
		insn.Op2.reg = rs1
		insn.Op3.type = o_reg
		insn.Op3.reg = rs2
		if op == 0b0110011: #32 bit R opcodes 
			if funct7 == 0b0000000: 
				if funct3 == 0b000: insn.itype = self.itype_add
				if funct3 == 0b001: insn.itype = self.itype_sll
				if funct3 == 0b110: insn.itype = self.itype_or
				if funct3 == 0b101: insn.itype = self.itype_srl
				if funct3 == 0b111: insn.itype = self.itype_and
				if funct3 == 0b100: insn.itype = self.itype_xor
			if funct7 == 0b0100000: 
				if funct3 == 0b000: insn.itype = self.itype_sub
				if funct3 == 0b101: insn.itype = self.itype_sra
		elif op == 0b0111011: #64 bit
			if funct7 == 0b0000000:
				if funct3 == 0b000: insn.itype = self.itype_addw
				if funct3 == 0b001: insn.itype = self.itype_sllw
				if funct3 == 0b101: insn.itype = self.itype_srlw
			if funct7 == 0b0100000: 
				if funct3 == 0b000: insn.itype = self.itype_subw
				if funct3 == 0b101: insn.itype = self.itype_sraw			
	def decode_U_type(self, insn, w):
		imm = SIGNEXT((BITS(w, 31, 12) << 12), 32)
		rd = BITS(w, 11, 7) 
		op = BITS(w, 6, 0)
		insn.Op1.type = o_reg
		insn.Op2.type = o_imm
		insn.Op1.reg = rd
		insn.Op2.value = imm
		if op == 0b0010111: insn.itype =self.itype_auipc
		if op == 0b0110111: insn.itype = self.itype_lui
		

	def decode_S_type(self, insn, w):
		rs2 = BITS(w, 24, 20)
		rs1 = BITS(w, 19, 15)
		func3 = BITS(w, 14, 12)
		insn.Op1.type = o_displ;
		insn.Op1.addr = (BITS(w,31, 25) << 5) + BITS(w, 11,7)
		insn.Op1.reg = rs1; 
		insn.Op2.type = o_phrase;
		insn.Op2.reg = rs2;
		if (func3 == 0b000): insn.itype = self.itype_sb
		if (func3 == 0b011): insn.itype = self.itype_sd
		if (func3 == 0b001): insn.itype = self.itype_sh
		if (func3 == 0b010): insn.itype = self.itype_sw


	def decode_SB_type(self, insn, w):
		rs2 = BITS(w, 24, 20)
		rs1 = BITS(w, 19, 15)
		func3 = BITS(w, 14, 12)
		imm = SIGNEXT( (BIT(w,31) << 12) + (BITS(w, 30,25) << 5) + (BITS(w, 11, 8) << 1) + (BIT(w,  7) << 11) , 13) 
		insn.Op1.type = o_reg
		insn.Op2.type = o_reg
		insn.Op1.reg = rs1
		insn.Op2.reg = rs2
		insn.Op3.type = o_near
		insn.Op3.addr = insn.ea + imm
		if (func3 == 0b000): insn.itype = self.itype_beq
		if (func3 == 0b001): insn.itype = self.itype_bne
		if (func3 == 0b100): insn.itype = self.itype_blt
		if (func3 == 0b101): insn.itype = self.itype_bge
		if (func3 == 0b110): insn.itype = self.itype_bltu
		if (func3 == 0b111): insn.itype = self.itype_bgeu

	def decode_J_type(self, insn, w):
		op = BITS(w, 6, 0)
		rd = BITS(w, 11, 7)
		if (rd == 0):
			rd = 1	 #if rd is ommitted, x1 is assumed
		if (op == 0b1101111):
			insn.itype = self.itype_jal
			insn.Op1.type = o_reg
			insn.Op1.reg = rd
			insn.Op2.type = o_imm
							
			insn.Op2.value = insn.ea + SIGNEXT( (BIT(w,31) << 20) + (BITS(w, 30,21) << 1) + (BIT(w, 20) << 11) + (BITS(w,  19, 12) << 12) , 20) 
			insn.Op2.dtype = dt_dword


	def decode_I_type(self, insn, w):
		op = BITS(w, 6, 0)
		func3 = BITS(w, 14, 12)
		rd = BITS(w, 11, 7)
		rs1 = BITS(w, 19, 15)
		offset = BITS(w, 31, 20)
		insn.Op1.type = o_reg
		insn.Op1.reg = rd
		insn.Op2.type = o_reg
		insn.Op2.reg = rs1
		insn.Op3.type = o_imm
		insn.Op3.value = SIGNEXT(BITS(w, 31,20), 12)
		insn.Op3.dtype = dt_word
		shamt = BITS(w, 24, 20) 
				
		if op == 0b0010011: #athrimitic immediates
			if func3 == 0b000: # addi
				insn.itype = self.itype_addi
			elif func3 == 0b010: # slti
				insn.itype = self.itype_slti
			elif func3 == 0b011: # sltiu
				insn.itype = self.itype_sltiu
			elif func3 == 0b100: # xori
				insn.itype = self.itype_xori
			elif func3 == 0b110: # ori
				insn.itype = self.itype_ori
			elif func3 == 0b111: # andi
				insn.itype = self.itype_andi
			elif func3 == 0b001: # slli				#TODO add sanity checking to these shift values
				insn.itype = self.itype_slli
				insn.Op3.value = shamt
			elif (func3 == 0b101): # shift right and shift arthaimatic right
				if (BIT(w, 30)): #srai
					insn.itype = self.itype_srai
					insn.Op3.value = shamt
				else:		 #srli
					insn.itype = self.itype_srli
					insn.Op3.value = shamt
		if op == 0b0011011: #athrimitic immediates word sized
			if func3 == 0b000: # addiw
				insn.itype = self.itype_addiw
		if op == 0b0001111: # some kind of fence thing?
			if (BITS(w, 27, 7) == 0):
				insn.itype = self.itype_fence
				insn.Op3 = o_void
				insn.Op1.type = o_imm
				insn.Op1.value = BITS(w, 27, 24)
				insn.Op2.type = o_imm
				insn.Op2.value = BITS(w, 27, 24)
			elif (BITS(w, 31, 7) == 32):
				insn.itype = self.itype_fence_i
			 	insn.Op1.type = o_void
				insn.Op2.type = o_void
				insn.Op3.type = o_void


		if op == 0b1110011: # control and system operations
			if (BITS(w, 31, 7) == 0): # ecall			
				insn.itype = self.itype_ecall
				insn.Op1.type = o_void
				insn.Op2.type = o_void
				insn.Op3.type = o_void
			elif (insn.Op3.value == 1) and (BITS(w, 19, 7) == 0): #ebreak
				insn.itype = self.itype_ebreak
				insn.Op1.type = o_void
				insn.Op2.type = o_void
				insn.Op3.type = o_void
		if op == 0b0000011: # loads 
			insn.Op2.type = o_displ
			insn.Op2.addr = SIGNEXT(offset, 12) 
			insn.Op3.type = o_void
			if (func3 == 0b000): #lb
				insn.itype = self.itype_lb

			elif (func3 == 0b100): #lbu
				insn.itype = self.itype_lbu
		
			elif (func3 == 0b011): #ld
				insn.itype = self.itype_ld

			elif (func3 ==0b001): #lh
				insn.itype = self.itype_lh

			elif (func3 == 0b101): #lhu
				insn.itype = self.itype_lhu

			elif (func3 == 0b010): #lw
				insn.itype = self.itype_lw

			elif (func3 == 0b110): #lwu
				insn.itype = self.itype_lwu
			else : insn.itype = self.itype_UKN

		if op == 0b1100111: # jalr 

			insn.itype = self.itype_jalr
			insn.Op2.type = o_displ
			insn.Op2.addr = BITS(w, 31,20)
			insn.Op2.addr = SIGNEXT(insn.Op2.addr, 12)
			insn.Op3.type = o_void
					

	def decode_compressed_format(self, insn, w): 
	## couldnt figure out a better way to handle the compressed instructions- there all pretty unique with a few exceptions
		op = BITS(w, 1, 0)
		reg = BITS(w, 11, 7) 
		funct4 = BITS(w, 15, 12)
		funct3 = BITS(w, 15, 13)
		funct6 = BITS(w, 15, 10)
		bits62 = BITS(w, 6,2)
		bits65 = BITS(w, 6,5)
		
		if op == 0:
			if funct3 == 000: #c.addi4spn
				insn.itype = self.itype_addi
				insn.Op1.type = o_reg
				insn.Op1.reg = BITS(w, 4, 2) + 8 
				insn.Op2.type = o_reg
				insn.Op2.reg = 2
				insn.Op3.type = o_imm
				insn.Op3.value = (BITS(w, 10, 7) << 6) +  (BITS(w, 12, 11) << 4) + (BIT(w,6) << 2) + (BIT(w,5) << 3)
				insn.Op3.dtype = dt_word
			elif funct3 == 0b011: #c.ld
				insn.itype = self.itype_ld
				insn.Op1.type = o_reg
				insn.Op1.reg = BITS(w, 4, 2) + 8
				insn.Op2.type = o_displ
				insn.Op2.reg = BITS(w, 9, 7) + 8
				insn.Op2.addr = (BITS(w, 6, 5) << 6) + (BITS(w, 12, 10) << 3)		
			elif funct3 == 0b111: #c.sd
				insn.itype = self.itype_sd
				insn.Op1.type = o_displ;
				insn.Op1.addr = (BITS(w,12, 10) << 3) + (BITS(w, 6,5) << 6)
				insn.Op1.reg = BITS(w, 9, 7) + 8 
				insn.Op2.type = o_phrase;
				insn.Op2.reg = BITS(w, 4, 2) + 8 ;	
			else:
				insn.itype = self.itype_UKN

		elif op == 1:
			if funct3 == 000: #c.addi 
				insn.itype = self.itype_addi
				insn.Op1.type = o_reg
				insn.Op1.reg = reg
				insn.Op2.type = o_reg
				insn.Op2.reg = reg
				insn.Op3.type = o_imm
				insn.Op3.value = SIGNEXT((BIT(w, 12) << 5) + BITS(w, 6,2) , 6)
				insn.Op3.dtype = dt_byte

			if funct3 == 0b001: #c.addiw 
				insn.itype = self.itype_addiw
				insn.Op1.type = o_reg
				insn.Op1.reg = reg
				insn.Op2.type = o_reg
				insn.Op2.reg = reg
				insn.Op3.type = o_imm
				insn.Op3.value = SIGNEXT((BIT(w, 12) << 5) + BITS(w, 6,2) , 6)
				insn.Op3.dtype = dt_byte

			elif funct3 == 0b010: #c.li
				insn.itype = self.itype_addi
				insn.Op1.type = o_reg
				insn.Op1.reg = reg
				insn.Op2.type = o_reg
				insn.Op2.reg = 0 #zero register
				insn.Op3.type = o_imm
				insn.Op3.value = SIGNEXT((BIT(w, 12) << 5) + BITS(w, 6,2) , 6)
				insn.Op3.dtype = dt_byte
				
			elif (funct3 == 0b011) and (reg == 0b00010): #c.addi16sp
				insn.itype = self.itype_addi
				insn.Op1.type = o_reg
				insn.Op1.reg = 2
				insn.Op2.type = o_reg
				insn.Op2.reg = 2
				insn.Op3.type = o_imm
				insn.Op3.value = (BIT(w, 12) << 9) + (BIT(w, 6) << 4) + (BIT(w, 5) << 6) + (BITS(w, 4, 3) << 7) + (BIT(w, 2) << 5)
				insn.Op3.dtype = dt_word

			elif funct3 == 0b011: #c.lui				#TODO figure out correct way to output this (IE, before or after the shift) 
				insn.itype = self.itype_lui
				insn.Op1.type = o_reg
				insn.Op1.reg = reg
				insn.Op2.type = o_imm
				insn.Op2.dtype = dt_word
				insn.Op2.value = SIGNEXT((BIT(w, 12) << 5) + (BITS(w, 6, 2)), 6) 
			elif funct3 == 0b100: #c.andi
				insn.itype = self.itype_andi
				insn.Op1.type = o_reg
				insn.Op1.reg = BITS(w, 9, 7) + 8
				insn.Op2.type = o_reg
				insn.Op2.reg = BITS(w, 9, 7) + 8
				insn.Op3.type = o_imm
				insn.Op3.value = SIGNEXT((BIT(w, 12) << 5) + BITS(w, 6, 2), 6) 


			elif funct3 == 0b101: #c.j 
				insn.itype = self.itype_jal
				insn.Op1.type = o_reg
				insn.Op1.reg = 0
				insn.Op2.type = o_imm
				insn.Op2.value = insn.ea + SIGNEXT( (BIT(w,12) << 11) + (BIT(w, 11) << 4) + (BITS(w, 10, 9) << 8) + (BIT(w,  8) << 10)   + (BIT(w,  7) << 6)  + (BIT(w,  6) << 7)
+ (BIT(w,  6) << 7) + (BITS(w, 5, 3) << 1) + (BIT(w,2) << 5) , 12)
				insn.Op2.dtype = dt_dword

			elif funct3 == 0b110: #c.beqz
				insn.itype = self.itype_beq
				insn.Op1.type = o_reg
				insn.Op1.reg = BITS(w, 9, 7) + 8
				insn.Op2.type = o_reg
				insn.Op2.reg = 0			
				insn.Op3.type = o_near
				insn.Op3.addr = insn.ea + SIGNEXT( (BIT(w, 12) << 8) + (BITS(w, 11, 10) << 3) + (BITS(w, 6, 5) << 6) + (BITS(w, 4, 3) << 1) + (BIT(w, 2) << 5), 9)

			elif funct3 == 0b111: #c.bnez
				insn.itype = self.itype_bne
				insn.Op1.type = o_reg
				insn.Op1.reg = BITS(w, 9, 7) + 8
				insn.Op2.type = o_reg
				insn.Op2.reg = 0
				insn.Op3.type = o_near
				insn.Op3.addr = insn.ea + SIGNEXT( (BIT(w, 12) << 8) + (BITS(w, 11, 10) << 3) + (BITS(w, 6, 5) << 6) + (BITS(w, 4, 3) << 1) + (BIT(w, 2) << 5), 9)
				
			elif funct6 == 0b100011 and bits65 == 00: #c.sub
				insn.itype = self.itype_sub
				insn.Op1.type = o_reg
				insn.Op1.reg = BITS(w, 9, 7) + 8
				insn.Op2.type = o_reg
				insn.Op2.reg = BITS(w, 9, 7) + 8
				insn.Op3.type = o_reg
				insn.Op3.reg = BITS(w, 4, 2) + 8

			else:
				insn.itype = self.itype_UKN
		elif op == 2:
			if funct3 == 0b111: # c.sdsp 
				insn.itype = self.itype_sd
				insn.Op1.type = o_displ
				insn.Op1.addr = (BITS(w, 12, 10) << 3) + (BITS(w, 9, 7) << 6)
				#insn.Op1.value = BITS(w, 12, 10) << 3 
				insn.Op1.reg = 2 #sp
				insn.Op2.type = o_reg
				insn.Op2.reg = BITS(w, 6, 2)

			elif (funct3 == 0b011):  #c.ldsp
				insn.itype = self.itype_ld
				insn.Op1.type = o_reg
				insn.Op1.reg = reg
				insn.Op2.type = o_displ
				insn.Op2.reg = 2 #sp 
				insn.Op2.addr = (BIT(w, 12) << 5) + (BITS(w, 6, 5) << 3) + (BITS(w, 4,2) << 6)	
				
			elif (funct3 == 0b000):  #c.slli
				insn.itype = self.itype_slli
				insn.Op1.type = o_reg
				insn.Op1.reg = reg
				insn.Op2.type = o_reg
				insn.Op2.reg = reg
				insn.Op3.type = o_imm
				insn.Op3.value = (BIT(w, 12) << 5) + (BITS(w, 6, 2))
						
			elif (funct4 == 0b1001) and (bits62 == 0): #c.jalr
				insn.itype = self.itype_jalr
				insn.Op1.type = o_reg
				insn.Op1.reg = 1
				insn.Op2.type = o_displ
				insn.Op2.reg = reg

				insn.Op2.addr = 0
			elif (funct4 == 0b1001): #c.add
				insn.itype = self.itype_add
				insn.Op1.type = o_reg
				insn.Op1.reg = reg
				insn.Op2.type = o_reg
				insn.Op2.reg = reg
				insn.Op3.type = o_reg
				insn.Op3.reg = bits62
			elif (funct4 == 0b1000) and (bits62 == 0): #c.jr
				if (reg == 1): 
					insn.itype = self.itype_ret
					insn.Op1.type = o_void
					insn.Op2.type = o_void
				else:
					insn.itype = self.itype_jalr
					insn.Op1.type = o_reg
					insn.Op1.reg = 0
					insn.Op2.type = o_displ
					insn.Op2.reg = reg
					insn.Op2.addr = 0

				
			elif (funct4 == 0b1000) and (bits62 != 0): #c.mv
				insn.itype = self.itype_addi
				insn.Op1.type = o_reg
				insn.Op1.reg = reg
				insn.Op2.type = o_reg
				insn.Op2.reg = 0
				insn.Op3.type = o_reg
				insn.Op3.reg = bits62
				insn.Op3.dtype = dt_byte
							
			else:
				insn.itype = self.itype_UKN
		else:
			insn.itype = self.itype_UKN
		
			 

	def notify_ana(self, insn):
		"""
		Decodes an instruction into 'insn'.
		Returns: insn.size (=the size of the decoded instruction) or zero
		"""
		unknown = True		
		w = insn.get_next_dword()
		
		if BITS(w, 1, 0) != 0b00011:
			insn.size = 2
			self.decode_compressed_format(insn, w)
			#insn.itype = self.itype_UKN_c
			#unknown = False
			#this is not a compressed instruction 
		#make a switch statment or if/else chang of the different formats
		elif self.is_I_type(BITS(w, 6, 0)):
			self.decode_I_type(insn, w)
		elif self.is_J_type(BITS(w, 6, 0)):
			self.decode_J_type(insn, w)
		elif self.is_SB_type(BITS(w, 6, 0)):
			self.decode_SB_type(insn, w)	
		elif self.is_S_type(BITS(w, 6, 0)):
			self.decode_S_type(insn, w)	
		elif self.is_U_type(BITS(w, 6, 0)):
			self.decode_U_type(insn, w)
		elif self.is_R_type(BITS(w, 6, 0)):
			self.decode_R_type(insn, w)		
		else:
			insn.itype = self.itype_UKN
		return insn.size


	#section copied from msp430.py
	def init_instructions(self):
		Instructions = []
		i = 0
		for x in self.instruc:
		    if x['name'] != '':
		        setattr(self, 'itype_' + x['name'], i)
		    else:
		        setattr(self, 'itype_null', i)
		    i += 1

		# icode of the last instruction + 1
		self.instruc_end = len(self.instruc) + 1

		# Icode of return instruction. It is ok to give any of possible return
		# instructions
		# self.icode_return = self.itype_reti
	#endcopy

	def init_registers(self):
		"""This function parses the register table and creates corresponding ireg_XXX constants"""
		self.reg_names = [
		#	ABI			Reg  	 Discription	
			"zero", 		#x0 - 	zero
			"ra",  			#x1 - 	return address
			"sp",   		#x2 - 	stack pointer
			"gp", 			#x3 - 	Global pointer
			"tp", 			#x4 - 	thread pointer
			"t0", "t1", "t2",	#x5-7	Temporary registers
			"s0", "s1",		#x8-9	Saved registers
			"a0", "a1",		#x10-11	Function arguments/return values
			"a2", "a3", "a4", "a5",
			"a6", "a7",		#x12-17	Function arguments
			"s2", "s3", "s4", "s5",
			"s6", "s7", "s8", "s9",
			"s10", "s11",		#x18-27	Saved registers
			"t3", "t4", "t5", "t6",	#x28-31	Temporary registers
			# Fake segment registers
			"CS", "DS"		
		]
	#section copied from msp430.py
		# Create the ireg_XXXX constants
		for i in xrange(len(self.reg_names)):
		    setattr(self, 'ireg_' + self.reg_names[i], i)

		# Segment register information (use virtual CS and DS registers if your
		# processor doesn't have segment registers):
		self.reg_first_sreg = self.ireg_CS
		self.reg_last_sreg  = self.ireg_DS

		# number of CS register
		self.reg_code_sreg = self.ireg_CS

		# number of DS register
		self.reg_data_sreg = self.ireg_DS
	#endcopy



	def __init__(self):
		processor_t.__init__(self)
		self.init_instructions()
		self.init_registers()

# ----------------------------------------------------------------------
# Every processor module script must provide this function.
# It should return a new instance of a class derived from processor_t

def PROCESSOR_ENTRY():
	return riscv_processor_t()

