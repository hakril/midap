import sys

import idc
import idaapi
import idautils

import elt
import code
import xref
import ida_import
import idb
import data
import idastruct
import stack
import flags
import cast
import segment
from utils import resolve, int_hex

all_submodules_name = ['elt', 'code', 'xref', 'ida_import', 'idb', 'data', 'idastruct', 'stack', 'flags', 'cast', 'segment']


def get_full_submodule_name(name):
    return "{0}{1}".format(__name__ + "." if __name__ not in ["__main__", "__init__"] else "", name)

all_submodules = [get_full_submodule_name(sub) for sub  in all_submodules_name]


# TODO: stack
#offset = idaapi.get_fileregion_offset(ea)
#ea = idaapi.get_fileregion_ea(offset)

def reload():
    for submodule_name in all_submodules:
        mod = sys.modules[submodule_name]
        __builtins__['reload'](mod)
    fixup_late_import()
    return sys.modules[__name__]


#: this is really horrible
# but fun to code, and I don't know how else to do right now
def fixup_late_import():
    for submodule_name in all_submodules:
        mod = sys.modules[submodule_name]
        try:
            late_import = mod.late_import
        except AttributeError:
            continue
        for late_name, late_mod in [(late, sys.modules[get_full_submodule_name(late)]) for late in late_import]:
            setattr(mod, late_name,  late_mod)


# Put type dispatch functions elsewhere
def ihere(addr=None):
    "Typed here(): return current :class:`midap.code.IDAInstr`"
    elt = ehere(addr)
    return cast.code_cast(elt)

def bhere(addr=None):
    "Typed here(): return current :class:`midap.code.IDABlock`"
    f = fhere(addr)
    if addr is None:
        addr = idc.here()
    return [b for b in f.Blocks if addr in b][0]

def fhere(addr=None):
    "Typed here(): return current :class:`midap.code.IDAFunction`"
    if addr is None:
        addr = idc.here()
    return code.IDAFunction.get_func(addr)

def dhere(addr=None):
    "Typed here(): return current Data"
    if addr is None:
        addr = idc.here()
    return data.Data.new_data_by_type(addr)

def shere(addr=None):
    "Typed here(): return current :class:`midap.segment.IDASegment`"
    if addr is None:
        addr = idc.here()
    return segment.IDASegment(addr)

def ehere(addr=None):
    "low typed here(): return current :class:`midap.elt.IDAElt` for basic operation"
    if addr is None:
        addr = idc.here()
    return data.elt.IDAElt(addr)

def here(addr=None):
    """ Guess typed here(): return what seems more apropiate
        May return IDAData or IDAInstr
    """
    elt = ehere(addr)
    return cast.data_or_code_cast(elt)

def where(addr=None):
    # idc.GetFuncOffset exist but might return something like MySub:loc_FFFFFFFFFC4948A2
    # And the loc_whatever might change if we rebase the IDB
    # So this function return "name+offset"
    if addr is None:
        addr = idc.here()
    f = fhere(addr)
    offset = hex(addr - f.addr)
    if offset[-1] == "L":
        offset = offset[:-1]
    return "{0}+{1}".format(f.name, offset)


def Buffer(addr, size):
    return elt.IDASizedElt(addr, addr + size)

# TODO : move this elsewhere

def find_all_bin(str):
    start_addr = 0
    res = []
    while start_addr != idc.BADADDR:
        addr = idc.FindBinary(start_addr + 1, idc.SEARCH_DOWN, str, 16)
        if addr == idc.BADADDR:
            break
        yield here(addr)
        start_addr = addr
    return



def dlist(s):
    s = s.lower()
    elts = dir(idc) + dir(idaapi) + dir(idautils)
    return [x for x in elts if s in x.lower()]

fixup_late_import()


def select():
    return idb.Selection()

# Handle auto reload

self_mod = sys.modules[__name__]
if hasattr(self_mod, "__is_imported"):
        # reload
        self_mod.reload()

self = idb.current
__is_imported = True
