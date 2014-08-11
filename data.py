import elt

import idc

late_import = ['struct']

# why not: automatic subclassing :)
class Data(elt.IDANamedSizedElt):

    # size == 0 doesn't make sens: need automatic subclassing :D
    size = 0
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
        return self._get_value_func(self.addr)
        
    def set_value(self, value, litte_endian=True):
        # TODO: ask endianness to IDB
        initial_value = value
        bytes = []
        for i in range(self.size):
            bytes.append(value & 255)
            value = value >> 8
        if value != 0:
            raise ValueError("value {0} is too big for {1}".format(hex(initial_value), self.__class__.__name__))
        if not litte_endian:
            bytes.reverse()
        self.patch(bytes, False)
        
    value = property(value, set_value, None)
        

    def __init__(self, addr, endaddr=None):
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
         
    def __IDA_repr__(self):
        if self._get_value_func is None:
            return ""
        return hex(self.value)
        
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
    size = 0
        
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
    
class ASCIIData(Data):
    """ 
        An IDA string:
            ASCIIData.size = size of the item encoded.
            len(ASCIIData.str) = size of the decoded string.
    """
    match = staticmethod(Data.is_ascii.fget)
    
    # Find better string definition
    type_value = ["ASCSTR_C", "ASCSTR_PASCAL", "ASCSTR_LEN2", "ASCSTR_UNICODE", "ASCSTR_LEN4", "ASCSTR_ULEN2", "ASCSTR_ULEN4"]
    
    def __init__(self, addr): 
        # Not an error: we need to bypass the 'general' Data constructor
        super(Data, self).__init__(addr)
        
    @property
    def str(self):
        """ The actual decoded python string """
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
        if len(s) > 10:
            s = s[:10] + "..."
        return '{0} "{1}"'.format(self.type_to_str(self.type), s)
        
    def __getitem__(self, index):
        b = self.bytes[index]
        return ASCIIByteData(b.addr)
        
 

    