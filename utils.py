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