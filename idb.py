import idaapi 
import ida_import
 
late_import = ['functions']
 
 #Put this somewhere else
class IDB(object):
    current = None
    
    def __new__(cls, *args, **kwargs):
        if IDB.current is not None:
            return IDB.current
        idb = super(IDB, cls).__new__(cls, *args, **kwargs)
        IDB.current = idb
        return idb

    def __init__(self):
        # Already exist: no more init
        if hasattr(self, 'init'):
            return
        filetype = idaapi.get_file_type_name()
        if "PE" in filetype:
            self.format = "PE"
        elif "ELF" in filetype:
            self.format = "ELF"
        else:
            raise ValueError("Unknow format <{0}>".format(filetype))
        self.imports = ida_import.IDAImportList()
        self.exports = ida_import.IDAExportList()
        self.init = True
        
        
        
        
    @property
    def is_pe(self):
        return self.format == "PE"
        
    @property
    def is_elf(self):
        return self.format == "ELF"

    @property
    def Functions(self):
        "Return all functions in IDB"
        return functions.IDAFunction.get_all()
        

current = IDB()