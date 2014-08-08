import idc

late_import = ['elt', 'functions', 'data', 'idb']



# Testing code: not sure its really usefull..
# If really usefull: rewrite this horrible code :D
# RealHierarchy ..

#Xref to IAT: to code but not really

# from / to : instruction ? if code


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

        
class CodeXref(Xref):
    """ Code to Code xref """

    @property
    def frm(self):
        return functions.IDAInstr(self.xref.frm)

    @property   
    def to(self):
        # This is a code xref dans to is not code: import
        # If someone found another case: tell me please !
        dst = elt.IDAElt(self.xref.to)
        if not dst.is_code:
            if dst in idb.current.imports:
                return functions.IDAImportInstr(self.xref.to, idb.current.imports[dst])
            else:
                return functions.IDAUndefInstr(self.xref.to)
        return functions.IDAInstr(self.xref.to)

    @property
    def is_call(self):
        return (self.xref.type & 0x1f) in [idc.fl_CF, idc.fl_CN]
        
    @property
    def is_jump(self):
        return (self.xref.type & 0x1f) in [idc.fl_JF, idc.fl_JN]
    
    @property
    def is_nflow(self): # name it 'is_flow' ?
        return (self.xref.type & 0x1f) ==  idc.fl_F 
        
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
    
    
class CodeToDataXref(DataXref):
    """ Code to Data xref """
    @property
    def frm(self):
        return functions.IDAInstr(self.xref.frm)
        
