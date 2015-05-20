import elt


import idaapi 
import idautils
import idc

late_import = ['xref', 'stack', 'idb', 'flags']


# TODO : real name for 'constructors' get_func and get_block

     
           
class IDACodeElt(elt.IDANamedSizedElt):
    """ 
        A code element:
        It may be defined or not
    """
    # size = 0 #?
    
    @property
    def is_defined(self):
        return False
     
    def _gen_code_xto(self, ignore_normal_flow):
        for x in idautils.XrefsTo(self.addr, ignore_normal_flow):
            yield xref.CodeXref(x) 
       
    # Yes : code can jump to undefined code (packer/ import / etc)
    # So undefined instruction will have rjump
    @property
    def rjump(self): # find a better name ?
        """ reverse jump : all instr that jump on the first instruction of this code element (call included) """
        return [x for x in self._gen_code_xto(True) if x.is_code and not x.is_nflow]
       
       
class IDADefinedCodeElt(IDACodeElt):
    """
        Abstract class just to have a common denominator between
            - Defined Instr
            - Blocks
            - Functions
    """
    
    @property
    def is_defined(self):
        return True

class IDAFunction(IDADefinedCodeElt):
    """Represent an IDA sub"""
    # Constructors
    @classmethod
    def get_func(cls, addr):
        func_t = idaapi.get_func(addr)
        if func_t is None:
            raise ValueError("{0} get_func failed (not the addr in a function".format(cls.__name__))
        return cls(func_t.startEA)
        
    #all getter
    @classmethod
    def get_all(cls):
        return [cls(addr) for addr in idautils.Functions()]

    # Functions        
    def __init__(self, addr):
        self.func_t = idaapi.get_func(addr)
        if self.func_t is None:
            raise ValueError("{0} get_func failed (not the addr of a function".format(self.__class__.__name__))
        if self.func_t.startEA != addr:
            raise ValueError("Call {0}(addr) where addr is not the beginning of a function: use {0}.get_func instead".format(self.__class__.__name__))
        super(IDAFunction, self).__init__(addr, self.func_t.endEA)      
   
    @property
    def Blocks(self):
        "Blocks in the function"
        return [IDABlock(basic_block) for basic_block in idaapi.FlowChart(idaapi.get_func(self.addr), flags=idaapi.FC_PREDS)]
          
    @property             
    def Instrs(self):
        "Instructions in the function"
        return [IDAInstr(i) for i in idautils.FuncItems(self.addr)]
                
    @property
    def stack(self):
        "Stack of the function"
        return stack.IDAStack(idc.GetFrame(self.addr), self)
     
    @property
    def flags(self):
        "Flags of the function"
        return flags.FunctionFlags(idc.GetFunctionFlags(self.addr))
        
    @property
    def type(self):
        "Type of the function (calling convention and arguments)"
        return idc.GetType(self.addr)
     
    @property
    def arguments(self):
        t = self.type
        begin = t.find("(")
        end = t.find(")")
        raw_args = t[begin + 1: end - 1]
        if not raw_args:
            return []
        return [arg.split() for arg in raw_args.split(",")]
        
     
    # Do "commentable interface ?"
    def get_comment(self, repeteable=True):
        return idc.GetFunctionCmt(self.addr, repeteable)
        
    def set_comment(self, comment, repeteable=True):
        return idc.SetFunctionCmt(self.addr, comment, repeteable)
                   

class IDABlock(IDADefinedCodeElt):
    """Represent a basic bloc of code"""
    #Constructors
    @classmethod
    def get_block(cls, addr):
        "Get all the blocks for function at address 'addr'"
        f = IDAFunction.get_func(addr) # TODO: handle error
        return [b for b in f.Blocks if addr in b][0]
        
    #all getter
    @classmethod
    def get_all(cls):
        "Get all blocks of all functions in IDB"
        return [b for f in IDAFunction.get_all() for b in f.Blocks]
        
    def __init__(self, basic_block):
        super(IDABlock, self).__init__(basic_block.startEA, basic_block.endEA)
        self.basic_block = basic_block
    
    @property    
    def Instrs(self):
        "Instructions in the block"
        return [IDAInstr(addr, self) for addr in  idautils.Heads(self.addr, self.endADDR)]
    
    @property
    def Succs(self):
        "List of blocks succeeding of the current block"
        return [IDABlock(basic_block) for basic_block in self.basic_block.succs()]
        
    @property
    def Preds(self):
        "List of blocks preceding of the current block"
        return [IDABlock(basic_block) for basic_block in self.basic_block.preds()]
    
    @property    
    def is_noret(self):
        "is True if block is NOT a ret block (have successor)"
        return idaapi.is_noret_block(self.basic_block.type)
    
    @property
    def is_ret(self):
        "is True if block is a ret block (no successor)"
        return idaapi.is_ret_block(self.basic_block.type)
    
    # Duplicate code from IDAInstr, missing one abstraction ? (IDAFuncElt ? for member potentially in a function ?)
    @property
    def func(self):
        "Return the function the block is member of"
        try:
            return IDAFunction.get_func(self.addr)
        except ValueError:
            return None 

# TODO: use DecodeInstruction and insn_t ? <- yep, later for instr in instr


        
class IDAUndefInstr(IDACodeElt):
    """ Undefined instruction:
        Accessible by code flow but code cannot be know with static informations.
        - Can be rewriting code, unpacking, ...
    """
        
    def __init__(self, addr):
        super(IDAUndefInstr, self).__init__(addr, addr) # Size = 0     
        self.mnemo = ""
        self.operands = []
     
    property_ret_none = property(lambda self: None)
    # auto lookup for import ? IDAImportInstr ?
    func = property_ret_none 
    block = property_ret_none
    next = property_ret_none
    prev = property_ret_none
    jump = property_ret_none
    switch = property(lambda self: [])
    data = property_ret_none
    is_flow  = property(lambda self: False)
    
    
class IDAImportInstr(IDAUndefInstr):
    """
        Instruction in imported function:
        This instruction is not part of the current module.
        Example: jump into kernel32 import.
    """
    def __init__(self, addr, imp):
        super(IDAImportInstr, self).__init__(addr)
        self.imp = imp

    @property
    def func(self):
        return self.imp
        
    @classmethod
    def from_import(cls, imp):
        return cls(imp.addr, imp)

        
class IDAInstr(IDADefinedCodeElt):
    """Represent an instruction"""
    def __init__(self, addr, block=None):
        end_addr  = idc.NextHead(addr)
        super(IDAInstr, self).__init__(addr, end_addr)
        
        # Check (is_code | GetMnem) ? to prevent implicit disassembly ?  
        
        #Get Operand may disass unknow Bytes so put it before GetMnem (do we need to accept this behaviour ?)
        self.mnemo = idc.GetMnem(addr)
        if self.mnemo == "":
            raise ValueError("address <{0}> is not an instruction".format(hex(self.addr)))
        self._block = block
        self.operands = [IDAOperand(self, i) for i in range(idaapi.UA_MAXOP) if not IDAOperand(self, i).is_void]
        
    #Any better way to do this ?
    @classmethod
    def get_all(cls):
        "Return all instructions in the IDB"
        return [IDAInstr(ea) for ea in idautils.Heads() if elt.IDAElt(ea).is_code]
        
            
    @property
    def completeinstr(self):
        "Complete disassembly of the instruction"
        return idc.GetDisasm(self.addr)
        
        
    @property        
    def func(self):
        "Return the function the instruction is member of"
        try:
            return IDAFunction.get_func(self.addr)
        except ValueError:
            return None
          
    @property        
    def block(self):
        "Return the block the instruction is member of"
        if self._block is not None:
            return self._block
        return IDABlock.get_block(self.addr)
        

    def _gen_code_xfrom(self, ignore_normal_flow):
        for x in idautils.XrefsFrom(self.addr, ignore_normal_flow):
            yield xref.CodeXref(x)
            
        
    @property
    def next(self):
        "Return the next instruction in normal execution flow"
        normal_next = [x for x in self._gen_code_xfrom(False) if x.is_code and x.is_nflow]
        if len(normal_next) > 1:
            raise ValueError("Instruction {0} has more that one normal flow xrefFrom".format(self))
        if not normal_next:
            return None
        return normal_next[0]
    
    @property    
    def prev(self):
        "Return the previous instruction in normal execution flow if any else None"
        if not self.has_flow_prev:
            return None
        return IDAInstr(idc.PrevHead(self.addr))
         
    def _get_instr_jumps(self): # might be remove : redundancy
        return [x for x in self._gen_code_xfrom(True) if x.is_code and not x.is_nflow]
        
    @property
    def jump(self):
        "return the CodeXref of a jump instruction else None"
        jump_next = self._get_instr_jumps()
        if len(jump_next) != 1:
            # This is not a simple call / jmp
            # THIS IS A SWITCH (see switch property)
            return None
        return jump_next[0]
     
    @property
    def switch(self):
        "return the list of CodeXref of a switch instruction else None"
        jump_next = self._get_instr_jumps()
        if len(jump_next) <= 1:
            return None
        return jump_next
    
        
    # Todo : rename
    # Todo: handle data to stack variable :D (can be multiple for struct on stack...)
    @property
    def data(self):
        "return DataXref of the instruction if any else None"
        datas = [xref.CodeToDataXref(x) for x in idautils.XrefsFrom(self.addr, False) if not x.iscode]
        if len(datas) > 1:
            # HAHA:  IDA have some fun ideas: "and     [ebp+ms_exc.registration.TryLevel], 0" will have XrefFrom on "registration" and "TryLevel" struct members.. (but not on ms_exc)
            # We really don't want those to be here: filter them
            # They will be available when we have stack_var xref (with already implemented struct definition)
            all_members = [m.addr for s in idb.current.Structs for m in s.members]
            datas = [d for d in datas if d.to.addr not in all_members]
        if len(datas) > 1:
            raise ValueError("Instruction {0} has more that one data xrefFrom (after members filtering)".format(self))
        if not datas:
            return None
        return datas[0]
        
        
    @property
    def is_flow(self):
        """return True if instruction 'Exec flow from prev instruction'
        idc.py:
        FF_FLOW  = idaapi.FF_FLOW  # Exec flow from prev instruction?
         """
        return idc.isFlow(self.flags)
        
    has_flow_prev = is_flow
         
    def __IDA_repr__(self):
        return "{" + self.completeinstr + "}"
        
class IDAOperand(elt.IDAElt):
    # o_void     #  No Operand                           ----------
    # o_reg      #  General Register (al,ax,es,ds...)    reg
    # o_mem      #  Direct Memory Reference  (DATA)      addr
    # o_phrase   #  Memory Ref [Base Reg + Index Reg]    phrase
    # o_displ    #  Memory Reg [Base Reg + Index Reg + Displacement] phrase+addr
    # o_imm      #  Immediate Value                      value
    # o_far      #  Immediate Far Address  (CODE)        addr
    # o_near     #  Immediate Near Address (CODE)        addr
    
    op_type_name =  { idc.o_void : "void",
                    idc.o_reg    : "reg",
                    idc.o_mem    : "mem",
                    idc.o_phrase : "phrase",
                    idc.o_displ  : "displ",
                    idc.o_imm    : "imm",
                    idc.o_far    : "far",
                    idc.o_near   : "near"}
    
    

    def __init__(self, instruction, op_number):
        super(IDAOperand, self).__init__(instruction.addr)
        self.instruction = instruction
        self.op_number = op_number
   
    @property
    def str(self):
        "The string representation of the operand"
        return idc.GetOpnd(self.addr , self.op_number)
        
    @property
    def type(self):
        "The type of the operand"
        return idc.GetOpType(self.addr , self.op_number)
        
    @property
    def value(self):
        "The type of the operand"
        return idc.GetOperandValue(self.addr , self.op_number)
     
    @property
    def is_void(self):
        return self.type == idc.o_void 
     
    @property
    def is_reg(self):
        return self.type == idc.o_reg
        
    @property
    def is_mem(self):
        return self.type == idc.o_mem    

    @property
    def is_imm(self):
        return self.type == idc.o_imm  
        
    @property
    def is_phrase(self):
        return self.type == idc.o_phrase
        
    @property
    def is_far(self):
        return self.type == idc.o_far
        
    @property
    def is_near(self):
        return self.type == idc.o_near
        
    def __IDA_repr__(self):
        return "<{0}>(nb={1}|type={3})>".format(self.str, self.op_number, self.instruction.completeinstr, self.op_type_name.get(self.type, "unknow"))
        


        
