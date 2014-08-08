import elt

import idc

# why not: automatic subclassing :)
class Data(elt.IDANamedSizedElt):

    # size == 0 doesn't make sens: need automatic subclassing :D
    size = 0
    match = (lambda *args : False)
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
        

    def __init__(self, addr):
        super(Data, self).__init__(addr, addr + self.size)
    
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
        
    def __IDA_repr__(self):
        if self._get_value_func is None:
            return ""
        return hex(self.value)
        
  #  @property
  #  def next(self):
  #      return Data.new_data_by_type(

    @classmethod
    def new_data_by_size(cls, addr, size):
        for subcls in cls.__subclasses__():
            if subcls.size == size:
                return subcls(addr)
        raise ValueError("Don't know how to handle size = {0}".format(size))
    
    @classmethod    
    #Name new_data ? (most general use)
    def new_data_by_type(cls, addr):
        data = Data(addr)
        for subcls in cls.__subclasses__():
            if subcls.match(data):
                return subcls(addr)
        raise ValueError("Don't know how to handle addr = {0}".format(hex(addr)))
        
        
        
class ByteData(Data):
    size = 1
    _get_value_func = staticmethod(idc.Byte)
    match = staticmethod(Data.is_byte.fget)
    
class WordData(Data):
    size = 2
    _get_value_func = staticmethod(idc.Word)
    match = staticmethod(Data.is_word.fget)
    
class DwordData(Data):
    size = 4
    _get_value_func = staticmethod(idc.Dword)
    match = staticmethod(Data.is_dword.fget)
    
    
class DwordData(Data):
    size = 8
    _get_value_func = staticmethod(idc.Qword)
    match = staticmethod(Data.is_qword.fget)
    
        
    