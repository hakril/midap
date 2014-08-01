import elt
import functions
import xref

import idc


# TODO: structures ?

# Entry point: list(Entries())


# TODO : here instr
# TODO : here func



def reload():
    __builtins__['reload'](elt)
    __builtins__['reload'](functions)
    __builtins__['reload'](xref)
    
    
# TODO: find a real name    
def ihere():
    return functions.IDAInstr(idc.here())
    
def fhere():
    return functions.IDAFunction.get_func(idc.here())
    
def bhere():
    f = fhere()
    addr = idc.here()
    return [b for b in f.Blocks if addr in b][0]
 
#TODO remove
def clean_globals():
    import idautils
    import idc
    import idaapi
    for i in dir(idc) + dir(idaapi) + dir(idautils):
        try:
            del globals()[i]
        except:
            pass