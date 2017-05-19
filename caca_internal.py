import sys
import platform
import ctypes

def is_valid_python():
    if not sys.version.startswith("2.7.6"):
        return False
    return platform.architecture()[0].startswith('32')
    
# def get_type_dict(type):
#     DICT_OFFSET = 33 * 4
#     l = []
#     dict_addr = ctypes.c_uint.from_address(id(type) + DICT_OFFSET).value
#     ctypes.pythonapi.PyList_Append(id(l), dict_addr)
#     return l[0]
#     
# 
# long_int_goto = property(lambda self: Jump(self))
# 
# 
# get_type_dict(int)['goto'] = long_int_goto
# get_type_dict(long)['goto'] = long_int_goto


import ctypes

def my_own_long_hex(self):
    hex(self)
    return "SUCE"
    
my_repr = ctypes.CFUNCTYPE(ctypes.py_object, ctypes.c_uint)(my_own_int_repr)
my_repr_c_callback = ctypes.c_ulong.from_address(id(my_repr._objects['0']) + 3 * ctypes.sizeof(ctypes.c_void_p)).value



def xchg_repr_hex(type):
    import ctypes
    type_id = id(type)

    as_nb = ctypes.c_uint.from_address(type_id + 0xc + (4 * (8 + 1))).value
    to_hex = ctypes.c_uint.from_address(as_nb + (4 * 22)).value
    to_dec = ctypes.c_uint.from_address(type_id + 0xc + (4 * (8))).value
    # Change type.__repr__ and type.__str__ by type.__hex__
    #ctypes.c_uint.from_address(type_id + 0xc + (4 * (8))).value = my_repr_c_callback  # __repr__
    #ctypes.c_uint.from_address(type_id + 0xc + (4 * (8 + 6))).value = my_repr_c_callback #__str__
    
    ctypes.c_uint.from_address(type_id + 0xc + (4 * (8))).value = to_hex  # __repr__
    ctypes.c_uint.from_address(type_id + 0xc + (4 * (8 + 6))).value = to_hex #__str__
    
    # Change type.__hex__ by old type.__str__
    #ctypes.c_uint.from_address(as_nb + (4 * 22)).value = to_dec
  
def int_hex():
    xchg_repr_hex(int)
    xchg_repr_hex(long)
    
def update_long_hex():
    import ctypes
    type_id = id(long)
    as_nb = ctypes.c_uint.from_address(type_id + 0xc + (4 * (8 + 1))).value
    to_hex = ctypes.c_uint.from_address(as_nb + (4 * 22)).value
    original_hex = ctypes.CFUNCTYPE(ctypes.py_object, ctypes.c_uint)(to_hex)
    def my_new_hex(self):
        return original_hex(self).strip("L")
    my_repr = ctypes.CFUNCTYPE(ctypes.py_object, ctypes.c_uint)(my_new_hex)
    my_repr_c_callback = ctypes.c_ulong.from_address(id(my_repr._objects['0']) + 3 * ctypes.sizeof(ctypes.c_void_p)).value
    update_long_hex.keep_alive = [my_repr]
    ctypes.c_uint.from_address(as_nb + (4 * 22)).value = my_repr_c_callback
    
    


