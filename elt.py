import idc
import idautils

late_import = ['xref', 'data']


class IDAElt(object):
    def __init__(self, addr, *args):
        self._addr  = addr
        
    def get_addr(self):
        return self._addr
        
    addr = property(get_addr, None, None, 'ea of the object')
    
    @classmethod
    def get_all(cls):
        return [cls(x) for x in idautils.Heads()]
    
    #property ?
    def goto(self):
        idc.Jump(self.addr)
        
    def __int__(self):
        return self.addr
        
    def __repr__(self):
        return "<{cls} {ida_repr} <at {addr}>>".format(
                cls=self.__class__.__name__,
                ida_repr=self.__IDA_repr__(),
                addr=hex(self.addr))
        
    def __IDA_repr__(self):
        return ""
    
    @property    
    def xfrom(self):
        """ List of all XrefsFrom the element """
        return [xref.Xref(x) for x in idautils.XrefsFrom(self.addr, False)]
        
    @property   
    def xto(self):
        """ List of all XrefsTo the element """
        return [xref.Xref(x) for x in idautils.XrefsTo(self.addr, False)]
        
    @property
    def flags(self):
        return idc.GetFlags(self.addr)
        
    # do LineA and LineB ? for comments ?
    
    # Flags
      
    @property
    def is_code(self):
        return idc.isCode(self.flags)
   
    @property
    def is_data(self):
        return idc.isData(self.flags)
    
    @property    
    def is_unknow(self):
        return idc.isUnknown(self.flags)
        
    @property
    def is_head(self):
        return idc.isHead(self.flags)
       
    @property
    def is_tail(self):
        return idc.isTail(self.flags)
        
    # useful ? here ?
    @property     
    def is_var(self):
        return idc.isVar(self.flags)
      
    @property
    def has_extra_comment(self):
        """ 
            Does this address has extra prev ou next line comments ?
             - see LineA and LineB
        """
        return idc.isExtra(self.flags)
        
    @property
    def has_ref(self):
        return idc.isRef(self.flags) 
        
    @property
    def has_value(self):
        return idc.hasValue(self.flags) 
        
    # comments: properties ? for normal and repeteable ?
    def set_comment(self, comment, repeteable=True):
        if repeteable:
            idc.MakeRptCmt(self.addr, comment)
        else:
            return idc.MakeComm(self.addr, comment)
        
    def get_comment(self, repeteable=True):
        return idc.CommentEx(self.addr, repeteable)
     

class IDANamedElt(IDAElt):
    """ Real base class : looks like everything can have a name """
    def __init__(self, addr, *args):
        super(IDANamedElt, self).__init__(addr)
        
    def get_name(self):
        return idc.Name(self.addr)
        
    def set_name(self, name):
        return idc.MakeName(self.addr, name)
       
    name = property(get_name, set_name, None, 'Name default property')
    
    def __IDA_repr__(self):
        if self.name is not "":
            return self.name
        return   "{no name}"
      
    # Do not use the Has*Name from idc because these have no sens
    @property
    def has_user_name(self):
        return bool(self.flags & idc.FF_NAME)
        
    @property    
    def has_dummy_name(self):
        return bool(self.flags & idc.FF_LABL)
        
    @property  
    def has_name(self):
        return bool(self.flags & idc.FF_ANYNAME)

        
class IDASizedElt(IDAElt):
    # always use NextHead to get endaddr ? or ItemEnd ? or ItemSize ?
    # endAddr should be private ? think so
    def __init__(self, addr, endaddr=None, nb_elt=None):
        """ endaddr: first addr not part of the element """
        if endaddr is None:
            endaddr = idc.ItemEnd(addr)
        super(IDASizedElt, self).__init__(addr, endaddr, nb_elt)
        self.endADDR = endaddr
        self.size = endaddr - addr
        if nb_elt is None:
            nb_elt = self.size
        self.nb_elt = nb_elt
        
    def __contains__(self, value):
        return self.addr <= value < self.endADDR
        
    def patch(self, patch, fill_nop=True):
        print("PATCH ASKED at <{0}| size {1}> with {2}".format(self.addr, self.size, patch))
        nop = 0x90 #<- need to adapt to other platform
        if self.size < len(patch):
            raise ValueError("Patch if too big for {0}".format(self)) 
        if self.size != len(patch) and not fill_nop:
            pass
            # raise Value("Patch is too small for {0} and no fill_patch (better idea than raise ?)".format(self))
            # Not patching other bytes seems cool ?
        
        full_patch = list(patch) + [nop] * (self.size - len(patch))
        for addr, byte in zip(range(self.addr, self.addr + self.size), full_patch):
            if idc.Byte(addr) == byte:
                print("NOPATCH BYTE : SAME VALUE")
                continue
            if not idc.PatchByte(addr, byte):
                print("PATCH addr {0} with byte {1} failed".format(hex(addr), hex(byte)))
                
    def replace(self, value):
        return self.patch([value] * self.size)
     
    @property
    def bytes(self):
        return [data.ByteData(addr) for addr in range(self.addr, self.addr + self.size)]
        
        
        
class IDANamedSizedElt(IDASizedElt, IDANamedElt):
    pass