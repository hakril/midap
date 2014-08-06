import elt


import idaapi 
import idautils
import idc

late_import = ['xref']

#Other import are at the end:
#import xref

# reload(MIDAP); MIDAP.reload(); g = MIDAP.functions.MFunctions(); x = next(g) ; gg = iter(x) ; y = next(gg); y = next(gg)

# reload(MIDAP); MIDAP.reload(); g = MIDAP.functions.MFunctions(); f = MIDAP.fhere(); i = MIDAP.ihere()


# TODO : real name for constructor get_func and get_block
# TODO : real name for MFunctions



class IDAFunction(elt.IDANamedSizedElt):

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
        return [IDABlock(basic_block) for basic_block in idaapi.FlowChart(idaapi.get_func(self.addr), flags=idaapi.FC_PREDS)]
     
    # use FuncItems ?     
    @property             
    def Instrs(self):
        return [i for b in self.Blocks for i in b.Instrs]   
     
    # Do "commentable interface ?"
    def get_comment(self, repeteable=True):
        return idc.GetFunctionCmt(self.addr, repeteable)
        
    def set_comment(self, comment, repeteable=True):
        return idc.SetFunctionCmt(self.addr, comment, repeteable)
        

class IDABlock(elt.IDANamedSizedElt):

      #Constructors
    @classmethod
    def get_block(cls, addr):
        f = get_func(addr) # TODO: handle error
        return [b for b in f.Blocks if addr in b][0]
        
    #all getter
    @classmethod
    def get_all(cls):
        return [b for f in IDAFunction.get_all() for b in f.Blocks]
        
    def __init__(self, basic_block):
        super(IDABlock, self).__init__(basic_block.startEA, basic_block.endEA)
        self.basic_block = basic_block
    
    @property    
    def Instrs(self):
        return [IDAInstr(addr, self) for addr in  idautils.Heads(self.addr, self.endADDR)]
    
    @property
    def Succs(self):
        return [IDABlock(basic_block) for basic_block in self.basic_block.succs()]
        
    @property
    def Preds(self):
        return [IDABlock(basic_block) for basic_block in self.basic_block.preds()]
    
    @property    
    def is_noret(self):
        return idaapi.is_noret_block(self.basic_block.type)
    
    @property
    def is_ret(self):
        return idaapi.is_ret_block(self.basic_block.type)
    
    # Duplicate cod from IDAInstr, missing one abstraction ? (IDAFuncElt ? for member potentially in a function ?)
    @property
    def func(self):
        try:
            return IDAFunction.get_func(self.addr)
        except ValueError:
            return None 

# TODO: use DecodeInstruction and insn_t ?
class IDAInstr(elt.IDASizedElt):
    def __init__(self, addr, block=None):
        end_addr  = idc.NextHead(addr)
        super(IDAInstr, self).__init__(addr, end_addr)
        self.mnemo = idc.GetMnem(addr)
        self.operands = [idc.GetOpnd(addr , i) for i in range(idaapi.UA_MAXOP) if idc.GetOpnd(addr , i) is not ""]
        self.completeinstr = "{0} {1}".format(self.mnemo, ",".join(self.operands))
        self._block = block
        
    #all getter
    @classmethod
    def get_all(cls):
        return [i for b in IDABlock.get_all() for i in b.Instrs]
        
    @property        
    def func(self):
        try:
            return IDAFunction.get_func(self.addr)
        except ValueError:
            return None
          
    @property        
    def block(self):
        if self._block is not None:
            return self._block
        return IDABlock.get_block(self.addr)
        

    def _gen_code_xfrom(self, ignore_normal_flow):
        for x in idautils.XrefsFrom(self.addr, ignore_normal_flow):
            yield xref.CodeXref(x)
        
    @property
    def next(self):
        normal_next = [x for x in self._gen_code_xfrom(False) if x.is_code and x.is_nflow]
        if len(normal_next) > 1:
            raise ValueError("Instruction {0} has more that one normal flow xrefFrom".format(self))
        if not normal_next:
            return None
        return normal_next[0]
    
    @property
    def jump(self):
        jump_next = [x for x in self._gen_code_xfrom(True) if x.is_code and not x.is_nflow]
        if len(jump_next) > 1:
            raise ValueError("Instruction {0} has more that one jump flow xrefFrom".format(self))
        if not jump_next:
            return None
        return jump_next[0]
    
        
    #Todo : rename
    @property
    def data(self):
        datas = [xref.CodeToDataXref(x) for x in idautils.XrefsFrom(self.addr, False) if not x.iscode]
        if len(datas) > 1:
            raise ValueError("Instruction {0} has more that one data xrefFrom".format(self))
        if not datas:
            return None
        return datas[0]
        
    def set_comment(self, comment, repeteable=True):
        if repeteable:
            idc.MakeRptCmt(self.addr, comment)
        else:
            return idc.MakeComm(self.addr, comment)
        
    def get_comment(self, repeteable=True):
        return idc.CommentEx(self.addr, repeteable)
         
    def __IDA_repr__(self):
        return self.completeinstr
        

               