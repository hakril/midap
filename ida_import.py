import functools
import idaapi

import elt


class IDAImport(elt.IDANamedElt):
    all = {}

    def __init__(self, module_name, addr, name, ord):
        #name is ignored and will be accessed using the property of IDANamedElt
        super(IDAImport, self).__init__(addr)
        self.module_name = module_name
        self.ord = ord
    
    @classmethod
    def new_import(cls, module_name, ea, name, ord):
        cls.all[ea] = IDAImport(module_name, ea, name, ord)
        return True
        
    #TODO: repr with ordinal and name
    
    def __IDA_repr__(self):
        descr = "ord={0}".format(self.ord)
        if self.name is not "":
            descr = "name={0}".format(self.name)  
        return "{0}({2}, module={1})".format(self.__class__.__name__, self.module_name, descr)
        
    
    
# strongly inspired by ex_imports.py in IDAPython examples
nimps = idaapi.get_import_module_qty()
for i in xrange(0, nimps):
    name = idaapi.get_import_module_name(i)
    if not name:
        print "Failed to get import module name for #%d" % i
        continue
    idaapi.enum_import_names(i, functools.partial(IDAImport.new_import, name))


