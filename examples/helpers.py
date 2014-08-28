# Examples code

import MIDAP

def list_function_import(f=None):
    """ Return the list of import used in function f
        Oneliner is:
            [i.jump.to.func for i in f.Instrs if i.jump and i.jump.to in MIDAP.self.imports]
    """
    if f is None:
        f = MIDAP.fhere() # current function
    res = []
    for instr in f.Instrs: # iter over each instruction of the function
        # instr.jump is and Xref if the instruction do a (jump / call) else None
        # 'instr.jump.to in MIDAP.self.imports' check that the jump destination is in the import list
        if instr.jump and instr.jump.to in MIDAP.self.imports:
            # instr.jump.to.func is the import itself
            # instr.jump.to is an 'ImportInstr' (an instruction that code is not known because the code is in another module)
            res.append(instr.jump.to.func)
    return res
    