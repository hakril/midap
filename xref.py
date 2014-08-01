import elt

# Testing code: not sure its really usefull..

# from / to : instruction ? if code

class Xref(object):
    def __init__(self, xref):
        self.xref = xref
     
    @property
    def frm(self):
        return self.xref.frm
        
    @property   
    def to(self):
        return self.xref.to
        
    @property    
    def type(self):
        return self.xref.type 
        
    @property
    def iscode(self):
        return self.xref.iscode
     
    @property
    def isuser(self):
        return self.xref.user
           
    def __repr__(self):
        return "<{0} <{1} to {2}>>".format(self.__class__.__name__, hex(self.frm), hex(self.to))
        

class CodeXref(Xref):
      
    @property
    def is_call(self):
        return (self.xref.type & 0x1f) in [idc.fl_CF, idc.fl_CN]
        
    @property
    def is_jump(self):
        return (self.xref.type & 0x1f) in [idc.fl_JF, idc.fl_JN]
    
    @property
    def is_normal(self):
        return (self.xref.type & 0x1f) ==  idc.fl_F 