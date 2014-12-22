import idc
import idautils
import itertools

late_import = ['xref', 'data', 'cast']


class IDAElt(object):
    def __init__(self, addr, *args):
        self._addr  = addr
        
    def get_addr(self):
        return self._addr
        
    addr = property(get_addr, None, None, 'effective address of the object')
    
    def get_color(self):
        return idc.GetColor(self.addr, idc.CIC_ITEM)
        
    color = property(get_color, None, None, 'Color of the current item')
    
    @classmethod
    def get_all(cls):
        return [cls(x) for x in idautils.Heads()]
    
    @property
    def goto(self):
        """Jump to the address of the object"""
        idc.Jump(self.addr)
        # chaining stuff
        return self
        
    def __int__(self):
        return self.addr
        
    def __repr__(self):
        addr_hex = hex(self.addr)
        if addr_hex.endswith("L"):
            addr_hex = addr_hex[:-1]
        return "<{cls} {ida_repr} <at {addr}>>".format(
                cls=self.__class__.__name__,
                ida_repr=self.__IDA_repr__(),
                addr=addr_hex)
        
    def __IDA_repr__(self):
        return ""
    
    @property    
    def xfrom(self):
        """ List of all XrefsFrom the element """
        return [xref.Xref(x).guess_xref_type() for x in idautils.XrefsFrom(self.addr, False)]
        
    @property   
    def xto(self):
        """ List of all XrefsTo the element """
        return [xref.Xref(x).guess_xref_type() for x in idautils.XrefsTo(self.addr, False)]
        
    @property
    def flags(self):
        """ Return the Flags of the object """
        return idc.GetFlags(self.addr)
		
    def read(self, size):
		return idc.GetManyBytes(self.addr, size, False)
        
    # do LineA and LineB ? for comments ?
         
    @property
    def is_code(self):
        """Return True if current object is code """
        return idc.isCode(self.flags)
   
    @property
    def is_data(self):
        """Return True if current object is data """
        return idc.isData(self.flags)
    
    @property    
    def is_unknow(self):
        """Return True if current object type is unknow """
        return idc.isUnknown(self.flags)
        
    @property
    def is_head(self):
        """Return True if current object is the Head of an IDB
            (The beginning of a line)
        """
        return idc.isHead(self.flags)
       
    @property
    def is_tail(self):
        """ TODO : what is a tail finally ? """
        return idc.isTail(self.flags)
        
    # useful ? here ?
    @property     
    def is_var(self):
        """ TODO : what is `idc.isVar` finally ? """
        return idc.isVar(self.flags)
      
    @property
    def has_extra_comment(self):
        """ 
            Does this address has extra prev or next line comments ?
             - see LineA and LineB
        """
        return idc.isExtra(self.flags)
        
    @property
    def has_ref(self):
        """Return True if object has some xref (from or to) """
        return idc.isRef(self.flags) 
        
    @property
    def has_value(self):
        """Return True if object has a defined value
            (no interrogation mark in IDA)
        """
        return idc.hasValue(self.flags) 
        
    # comments: properties ? for normal and repeteable ?...
    def set_comment(self, comment, repeteable=True):
        """ set a comment for object (repeatable not )"""
        if repeteable:
            idc.MakeRptCmt(self.addr, comment)
        else:
            return idc.MakeComm(self.addr, comment)
        
    def get_comment(self, repeteable=True):
        """ get comment for object (repeatable not )"""
        return idc.CommentEx(self.addr, repeteable)
     

class IDANamedElt(IDAElt):
    """ Real base class : looks like everything can have a name """
    def __init__(self, addr, *args):
        super(IDANamedElt, self).__init__(addr)
        
    def get_name(self):
        return idc.Name(self.addr) or ""
        
    # if already named auto-add prefix like _0 ? (seems good for automation)    
    def set_name(self, name):
        if idc.MakeName(self.addr, name):
            return
        # Fail : autoname
        counter = itertools.count()
        
        for i in counter:
            if idc.MakeName(self.addr, name + "_{0}".format(i)):
                return True
        raise ValueError("Out of infinite loop")
       
    name = property(get_name, set_name, None, 'name of the object')
    
    def __IDA_repr__(self):
        if self.name is not "":
            return self.name
        return   "{no name}"
      
    # Do not use the Has*Name from idc because these have no sens
    @property
    def has_user_name(self):
        """return True if object's name have been defined by the user"""
        return bool(self.flags & idc.FF_NAME)
        
    @property    
    def has_dummy_name(self):
        """return True if object's name is auto-defined by IDA"""
        return bool(self.flags & idc.FF_LABL)
        
    @property  
    def has_name(self):
        """return True if object has a name"""
        return bool(self.flags & idc.FF_ANYNAME)

        
class IDASizedElt(IDAElt):
    # always use NextHead to get endaddr ? or ItemEnd ? or ItemSize ?
    # endAddr should be private ? think so
    def __init__(self, addr, endaddr=None):
        """ endaddr: first addr not part of the element """
        if endaddr is None:
            endaddr = idc.ItemEnd(addr)
        super(IDASizedElt, self).__init__(addr)
        self.endADDR = endaddr
        self.size = endaddr - addr
        
    def __contains__(self, value):
        return self.addr <= value < self.endADDR
        
    def patch(self, patch, fill_nop=True):
        """ change the content of object by `patch`
                if fill_nop is True and size(patch) < size(object): add some 0x90
        """
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
        """Patch integrality of object with value given in parameter"""
        return self.patch([value] * self.size)
     
    @property
    def bytes(self):
        """Return list of bytes of the current object"""
        return [data.ByteData(addr) for addr in range(self.addr, self.addr + self.size)]
	
    @property
    def str(self):
		return "".join([chr(b.value) for b in self.bytes])
     
    @property
    def heads(self):
        return [cast.data_or_code_cast(IDAElt(addr)) for addr in idautils.Heads(self.addr, self.endADDR)]
        
        
        
class IDANamedSizedElt(IDASizedElt, IDANamedElt):
    pass
