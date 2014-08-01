import elt
import functions
import xref

import idc
import sys

#TODO : You know what for problem with kernel32.dll


# helper : reload(MIDAP); MIDAP.reload(); g = MIDAP.functions.MFunctions(); f = MIDAP.fhere(); i = MIDAP.ihere()

# TODO: structures ?
# Entry point: list(Entries())

def reload():
    __builtins__['reload'](elt)
    __builtins__['reload'](functions)
    __builtins__['reload'](xref)


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