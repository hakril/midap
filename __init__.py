import sys

import idc
import idaapi

import elt
import functions
import xref
import ida_import
import idb
import data
import struct
import stack
import flags
import cast
import segment

all_submodules_name = ['elt', 'functions', 'xref', 'ida_import', 'idb', 'data', 'struct', 'stack', 'flags', 'cast', 'segment']


def get_full_submodule_name(name):
    return "{0}.{1}".format(__name__ if __name__ != "__main__" else "", name)

all_submodules = [get_full_submodule_name(sub) for sub  in all_submodules_name]


# TODO: stack

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
    "Typed here(): return current Instruction"
    elt = ehere(addr)
    return cast.code_cast(elt)

def bhere(addr=None):
    "Typed here(): return current Block"
    f = fhere(addr)
    addr = idc.here()
    return [b for b in f.Blocks if addr in b][0]

def fhere(addr=None):
    "Typed here(): return current Function"
    if addr is None:
        addr = idc.here()
    return functions.IDAFunction.get_func(addr)
    
def dhere(addr=None):
    "Typed here(): return current Data"
    if addr is None:
        addr = idc.here()
    return data.Data.new_data_by_type(addr)
    
def ehere(addr=None):
    "low typed here(): return current IDAElt for badic operations"
    if addr is None:
        addr = idc.here()
    return data.elt.IDAElt(addr)
    
def here(addr=None):
    """ Guess typed here(): return what seems more apropiate
        May return IDAData or IDAInstr
    """
    elt = ehere(addr)
    return cast.data_or_code_cast(elt)


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

 
fixup_late_import()
self = idb.current

def select():
    return idb.Selection()
    
    
# Handle auto reload

self_mod = sys.modules[__name__]
if hasattr(self_mod, "__is_imported"):
        # reload
        self_mod.reload()    
    
__is_imported = True
