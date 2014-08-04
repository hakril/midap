import elt
import xref
import functions
import ida_import


import idc
import sys

#TODO : You know what for problem with kernel32.dll

#TODO data.py


# helper : reload(MIDAP); MIDAP.reload(); g = MIDAP.functions.MFunctions(); f = MIDAP.fhere(); i = MIDAP.ihere()

# TODO: structures ?
# Entry point: list(Entries())

def reload():
    __builtins__['reload'](elt)
    __builtins__['reload'](functions)
    __builtins__['reload'](xref)
    __builtins__['reload'](ida_import)


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

#Put this somewhere else
class IDB(object):
    @property
    def Functions(self):
        "Return all functions in IDB"
        return functions.IDAFunction.get_all()
    
idb = IDB()