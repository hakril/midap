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

all_submodules_name = ['elt', 'functions', 'xref', 'ida_import', 'idb', 'data', 'struct', 'stack', 'flags']


def get_full_submodule_name(name):
    return "{0}.{1}".format(__name__ if __name__ != "__main__" else "", name)

all_submodules = [get_full_submodule_name(sub) for sub  in all_submodules_name]


#TODO : You know what for problem with kernel32.dll

# TODO: segments
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
    
    

def ihere():
    "Typed here(): return current Instruction"
    elt = ehere()
    if elt.is_code:
        return functions.IDAInstr(elt.addr)
    elif elt in self.imports:
        return functions.IDAImportInstr.from_import(self.imports[elt])
    # Return UndefInstr ?
    raise ValueError("Current position <{0}> is not code nor an import".format(hex(elt.addr)))
    
    return functions.IDAInstr(idc.here())

def bhere():
    "Typed here(): return current Block"
    f = fhere()
    addr = idc.here()
    return [b for b in f.Blocks if addr in b][0]

def fhere():
    "Typed here(): return current Function"
    return functions.IDAFunction.get_func(idc.here())
    
def dhere():
    "Typed here(): return current Data"
    return data.Data.new_data_by_type(idc.here())
    
def ehere():
    "low typed here(): return current IDAElt for badic operations"
    return data.elt.IDAElt(idc.here())
    
def here():
    """ Guess typed here(): return what seems more apropiate
        May return IDAData or IDAInstr
    """
    elt = ehere()
    if elt.is_code:
        return ihere()
    if elt in self.imports:
        return self.imports[elt]
    return dhere()


     

fixup_late_import()

self = idb.current
