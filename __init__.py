import sys

import idc
import idaapi

import elt
import functions
import xref
import ida_import
import idb

all_submodules_name = ['elt', 'functions', 'xref', 'ida_import', 'idb']


def get_full_submodule_name(name):
    return "{0}.{1}".format(__name__ if __name__ != "__main__" else "", name)

all_submodules = [get_full_submodule_name(sub) for sub  in all_submodules_name]


#TODO : You know what for problem with kernel32.dll

#TODO data.py -> Bytes / Word / Dword / String / cstr


# helper : reload(MIDAP); MIDAP.reload(); g = MIDAP.functions.MFunctions(); f = MIDAP.fhere(); i = MIDAP.ihere()

# TODO: structures ?
# Entry point: list(Entries())


#TODO : CLEAR ON RELOAD

def reload():
    for submodule_name in all_submodules:
        mod = sys.modules[submodule_name]
        __builtins__['reload'](mod)
    fixup_late_import()

        
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
    
    
# TODO: find a real name    
def ihere():
    "Typed here(): return current Instruction"
    return functions.IDAInstr(idc.here())

def bhere():
    "Typed here(): return current Block"
    f = fhere()
    addr = idc.here()
    return [b for b in f.Blocks if addr in b][0]

def fhere():
    "Typed here(): return current Function"
    return functions.IDAFunction.get_func(idc.here())


     

fixup_late_import()

self = idb.IDB()
