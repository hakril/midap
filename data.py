import elt

import idc
import idautils

late_import = ['struct']

# TODO : handle array ? // See if data size match data type ? Data.is_dword and Data.size = 400 -> 100 dword array ?

# __new__ that return the matching subclass ?
class Data(elt.IDANamedSizedElt):

    size = -1
    match = staticmethod(lambda *args : False)
    # addr -> bool
    # staticmethod
    _get_value_func = None

    def value(self):
        """ 
            [property] [get | set]
            The value of the Data object.
            DataByte.value = 0x42 will patch the byte at DataByte.addr
        """
        if self._get_value_func is None:
            raise ValueError("Cannot access value of {0}".format(self))
        if not self.has_value:
            return None
        return self._get_value_func(self.addr)
        
    def set_value(self, value, litte_endian=True):
        # TODO: ask endianness to IDB
        initial_value = value
        bytes = []
        if self._get_value_func is None:
            raise ValueError("Cannot access value of {0}".format(self))
        for i in range(self.size):
            bytes.append(value & 255)
            value = value >> 8
        if value != 0:
            raise ValueError("value {0} is too big for {1}".format(hex(initial_value), self.__class__.__name__))
        if not litte_endian:
            bytes.reverse()
        self.patch(bytes, False)
        
    value = property(value, set_value, None)
        

    @classmethod
    def get_all(cls):
        return [Data.new_data_by_type(ea) for ea in idautils.Heads() if elt.IDAElt(ea).is_data]    
        
    def __init__(self, addr, endaddr=None):
        if endaddr is None and self.__class__.size != -1:
            endaddr = addr + self.__class__.size
        super(Data, self).__init__(addr, endaddr)
    
    #Should all this be in IDAelt ?
    
    @property
    def is_byte(self):
        return idc.isByte(self.flags)

    @property
    def is_word(self):
        return idc.isWord(self.flags)
      
    @property
    def is_dword(self):
        return idc.isDwrd(self.flags)
        
    @property
    def is_qword(self):
        return idc.isQwrd(self.flags)
    
    @property
    def is_oword(self):
        return idc.isOwrd(self.flags)
        
    @property
    def is_tbyte(self):
        return idc.isTbyt(self.flags)
        
    @property    
    def is_float(self):
        return idc.isFloat(self.flags)
        
    @property    
    def is_double(self):
        return idc.isDouble(self.flags)
         
    @property   
    def is_packreal(self):
        return idc.isPackReal(self.flags)
        
    @property    
    def is_ascii(self):
        return idc.isASCII(self.flags)
     
    @property
    def is_align(self):
        return idc.isAlign(self.flags)
    
    @property    
    def is_struct(self):
        return idc.isStruct(self.flags)
        
    @property
    def is_offset(self):
        return idc.isOff0(self.flags)
        
    @property
    def is_xref(self):
        return idc.isOff0(self.flags) and self.xfrom
     
    # As xfrom if is_offset or is_struct
    @property
    def to(self):
        if not self.is_xref:
            raise ValueError("call 'to' on non-offset data")
        return self.xfrom[0].to
        
    
    
    def __IDA_repr__(self):
        if self._get_value_func is None:
            return self.name
        if not self.has_value:
            ret =  self.name + " " + "{no_value}"
        else:
            ret = self.name + " " + hex(self.value)
        if self.is_offset:
            ret += " (offset)"
        return ret
        
    @classmethod
    def new_data_by_size(cls, addr, size):
        for subcls in cls.__subclasses__():
            if subcls.size == size:
                return subcls(addr)
        return UnknowData(addr)
    
    @classmethod    
    #Name new_data ? (most general use)
    def new_data_by_type(cls, addr):
        data = Data(addr)
        for subcls in cls.__subclasses__():
            if subcls.match(data):
                return subcls(addr)
        return UnknowData(addr)
        
 
class UnknowData(Data):
    pass
        
class ByteData(Data):
    size = 1
    _get_value_func = staticmethod(idc.Byte)
    match = staticmethod(Data.is_byte.fget)
    
class ASCIIByteData(ByteData):
    def __IDA_repr__(self):
        c = chr(self.value) if self.value != 0 else "\\x00"
        return "{0} ({1})".format(hex(self.value), c)
               
    def __init__(self, addr):
        super(ASCIIByteData, self).__init__(addr, addr + 1)
     
    @property
    def str(self):
        return chr(self.value)
    
class WordData(Data):
    size = 2
    _get_value_func = staticmethod(idc.Word)
    match = staticmethod(Data.is_word.fget)
    
class DwordData(Data):
    size = 4
    _get_value_func = staticmethod(idc.Dword)
    match = staticmethod(Data.is_dword.fget)
    
    
class QwordData(Data):
    size = 8
    _get_value_func = staticmethod(idc.Qword)
    match = staticmethod(Data.is_qword.fget)
  
# TODO : being able to create String from sub string ?
class ASCIIData(Data): # auto MakeStr if is_ASCII ?
    """ 
        An IDA string:
            ASCIIData.size = size of the item encoded.
            len(ASCIIData.str) = size of the decoded string.
    """
    max_char_displayed = 20
    match = staticmethod(Data.is_ascii.fget)
    
    
    # Find better string definition
    type_value = ["ASCSTR_C", "ASCSTR_PASCAL", "ASCSTR_LEN2", "ASCSTR_UNICODE", "ASCSTR_LEN4", "ASCSTR_ULEN2", "ASCSTR_ULEN4"]
    
    def __init__(self, addr, auto_str=False): 
        # Not an error: we need to bypass the 'general' Data constructor | is that still the case ? with new Data constructor
        super(ASCIIData, self).__init__(addr)
        if self.type == -1 or self.type is None: # Is not a string yet
            if auto_str or Data(addr).is_ascii: # if is_ascii MakeString will juste add a name.
                is_str = self._try_all_type_string(addr)
                print(self.type)
            # TODO : handle if MakeStr failed
                if not is_str:
                    raise ValueError("Cannot make string at addr {0}".format(hex(addr)))
            else:
                raise ValueError("no string at addr {0}, use {0}(addr, auto_str=True) for automatic conversion".format(addr, self.__class__.__name__))
        

    def _try_all_type_string(self, addr_to_stringify):
        old_INF_STRTYPE = idc.GetLongPrm(idc.INF_STRTYPE)
        for i in range(len(self.type_value)):
            idc.SetLongPrm(idc.INF_STRTYPE, i)
            if idc.MakeStr(addr_to_stringify, idc.BADADDR):
                idc.SetLongPrm(idc.INF_STRTYPE, old_INF_STRTYPE)
                return True
        idc.SetLongPrm(idc.INF_STRTYPE, old_INF_STRTYPE)
        return False
        
    @property
    def str(self):
        """ The actual decoded python string """
        print("CALL WITH {0} | {1}".format(self.addr, self.type))
        return idc.GetString(self.addr, -1, self.type)
    
    @property
    def type(self): # TODO: export idc enum ?
        """ The type of the string """
        return idc.GetStringType(self.addr)
    
    @classmethod
    def type_to_str(cls, type):
        if not 0 <= type < len(cls.type_value):
            raise ValueError("Unknow String Type : {0}".format(type))
        return cls.type_value[type]
        
    def __IDA_repr__(self):
        s = self.str
        if len(s) > self.max_char_displayed:
            s = s[:self.max_char_displayed] + "..."
        return '{0} "{1}"'.format(self.type_to_str(self.type), s)
        
    def __getitem__(self, index):
        b = self.bytes[index]
        return ASCIIByteData(b.addr)
        
    def __contains__(self, str):
        return str in self.str
        
    def __len__(self):
        return len(self.bytes)
        
    @property    
    def bytes(self):
        return [ASCIIByteData(addr) for addr in range(self.addr, self.addr + self.size)]
    
    @property
    def is_cstr(self):
        return self.type == idc.ASCSTR_C
        
    @property
    def is_unicode(self):
        return self.type == idc.ASCSTR_UNICODE
           
    @property
    def is_pascal(self):
        return self.type == idc.ASCSTR_PASCAL
        
    @property
    def is_len2(self):
        return self.type == idc.ASCSTR_LEN2

    @property
    def is_len4(self):
        return self.type == idc.ASCSTR_LEN4
        
    @property
    def is_ulen2(self):
        return self.type == idc.ASCSTR_ULEN2
        
    @property
    def is_ulen4(self):
        return self.type == idc.ASCSTR_ULEN4
