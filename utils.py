import idc
import idautils
import midap

def xchg_repr_hex(type):
    import ctypes
    type_id = id(type)

    as_nb = ctypes.c_uint.from_address(type_id + 0xc + (4 * (8 + 1))).value
    to_hex = ctypes.c_uint.from_address(as_nb + (4 * 22)).value
    to_dec = ctypes.c_uint.from_address(type_id + 0xc + (4 * (8))).value
    # Change type.__repr__ and type.__str__ by type.__hex__
    ctypes.c_uint.from_address(type_id + 0xc + (4 * (8))).value = to_hex  # __repr__
    ctypes.c_uint.from_address(type_id + 0xc + (4 * (8 + 6))).value = to_hex #__str__
    # Change type.__hex__ by old type.__str__
    ctypes.c_uint.from_address(as_nb + (4 * 22)).value = to_dec
  
def int_hex():
    xchg_repr_hex(int)
    xchg_repr_hex(long)
    
    
def assemble_at(addr, code):
    code_to_assemble = code.split(";")
    res, assembled_code = idautils.Assemble(addr, code_to_assemble)
    if not res:
        raise ValueError("Impossible to assemble <{0}> at <{1}>".format(code, hex(addr)))
    full_assembled_code = "".join(assembled_code)
    return midap.Buffer(addr, len(code)).patch([ord(x) for x in full_assembled_code])
    
def resolve(value):
    try:
        return int(value)
    except ValueError:
        pass
        
    res = idc.LocByName(value)
    if res == idc.BADADDR and "+" in value:
        name, offset = value.split("+")
        res = idc.LocByName(name)
        if res != idc.BADADDR:
            try:
                res += int(offset, 0)
            except ValueError:
                res = idc.BADADDR
    if res == idc.BADADDR:        
        raise ValueError("Unable to resolve <{0}>".format(value))
    return res
    
        
    
    