import idc

late_import = ['elt', 'code', 'data', 'idb']



# Testing code: not sure its really usefull..
# RealHierarchy ..


# xref to stack / to real data (Named)

class Xref(object):

    def __init__(self, xref):
        self.xref = xref
            
    @property
    def frm(self):
        return elt.IDANamedElt(self.xref.frm)

    @property   
    def to(self):
        return elt.IDANamedElt(self.xref.to)
            
    @property    
    def type(self):
        return self.xref.type 
        
    @property
    def is_code(self):
        return self.xref.iscode
     
    @property
    def is_user(self):
        return self.xref.user
           
    def __repr__(self):
        return "<{0} <{1} to {2}>>".format(self.__class__.__name__, hex(self.xref.frm), hex(self.xref.to))
        
        
    def guess_xref_type(self):
        for subcls in Xref.__subclasses__() + DataXref.__subclasses__(): # cleaner way ? ...
            if subcls.match(self):
                return subcls(self.xref)
        type_str = lambda(b): "Code" if b else "Data"
        raise NotImplementedError("Xref From <{0}> To <{1}> not implem :(".format(type_str(self.frm.is_code), type_str(self.to.is_code)))
    
    @staticmethod
    def match(xref):
        return False
        

        
class CodeXref(Xref): #name it CodeToCode ?
    """ Code to Code xref """

    @property
    def frm(self):
        return code.IDAInstr(self.xref.frm)

    @property   
    def to(self):
        # This is a code xref where to is not code: import or undefined
        # If someone found another case: tell me please !
        dst = elt.IDAElt(self.xref.to)
        if not dst.is_code:
            if dst in idb.current.imports:
                return code.IDAImportInstr(self.xref.to, idb.current.imports[dst])
            else:
                return code.IDAUndefInstr(self.xref.to)
        return code.IDAInstr(self.xref.to)

    @property
    def is_call(self):
        return (self.xref.type & 0x1f) in [idc.fl_CF, idc.fl_CN]
        
    @property
    def is_jump(self):
        return (self.xref.type & 0x1f) in [idc.fl_JF, idc.fl_JN]
    
    @property
    def is_nflow(self): # name it 'is_flow' ?
        return (self.xref.type & 0x1f) ==  idc.fl_F
        
    @staticmethod
    def match(xref):
        return  xref.frm.is_code and xref.to.is_code
        
class DataXref(Xref):
    """ Data to Data xref """
 
    def __init__(self, xref):
        super(DataXref, self).__init__(xref)
        if (self.xref.type & 0x1f) in (idc.dr_I,):
            print("DEBUG strange xref with dr_I")
            
    @property
    def to(self):
        return data.Data.new_data_by_type(self.xref.to)
                        
    @property
    def is_offset(self):
        return (self.xref.type & 0x1f) == idc.dr_O
 
    @property
    def is_write(self):
        return (self.xref.type & 0x1f) == idc.dr_W
        
    @property
    def is_read(self):
        return (self.xref.type & 0x1f) == idc.dr_R
    
    @property
    def is_text(self): # name it 'is_flow' ?
        return (self.xref.type & 0x1f) == idc.dr_T
        
    @staticmethod
    def match(xref):
        return not xref.frm.is_code and not xref.to.is_code
    
    
class CodeToDataXref(DataXref):
    """ Code to Data xref """
    @property
    def frm(self):
        return code.IDAInstr(self.xref.frm)


    @staticmethod
    def match(xref):
        return xref.frm.is_code and not xref.to.is_code
        
        
class DataToCodeXref(DataXref):
    """ Data to Code xref """
    @property
    def to(self):
        return code.IDAInstr(self.xref.to)


    @staticmethod
    def match(xref):
        return not xref.frm.is_code and xref.to.is_code

        
