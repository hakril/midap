late_import = ['code', 'data', 'idb']


def code_cast(elt):
    if elt.is_code:
        return code.IDAInstr(elt.addr)
    elif elt.addr in idb.current.imports:
        return code.IDAImportInstr.from_import(idb.current.imports[elt])
    # Return UndefInstr ?
    raise ValueError("Current position <{0}> is not code nor an import".format(hex(elt.addr)))

def data_cast(elt):
    return data.Data.new_data_by_type(elt.addr)
    
def data_or_code_cast(elt):
    try:
        return code_cast(elt)
    except ValueError:
        return data_cast(elt)
    