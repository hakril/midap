import functools
import collections

import idaapi
import idautils

import elt
import code


# TODO : merge both code
       

class IDAExport(elt.IDANamedElt):
    entry_point = None
     
    def __init__(self, addr, ord, name):
        super(IDAExport, self).__init__(addr)
        self.export_name = name
        self.ord = ord
        self._func = None
        
    # Overwrite the  IDANamedElt by a read-only name
    @property
    def name(self):
        return self.export_name
      
    @property
    def func(self):
        "DAT FUNCTION"
        if self._func is not None:
            return self._func
        self._func = code.IDAFunction(self.addr)
        return self._func
        
    
class IDAExportList(object):
    def __init__(self):
        self.exports_by_addr = collections.defaultdict(list)
        self.exports_by_name = {}
        self.export_by_ordinal = {}
        for index, ordinal, addr, name in idautils.Entries():
           x = IDAExport(addr, ordinal, name)
           self.exports_by_addr[addr].append(x)
           self.exports_by_name[name] = x
           self.export_by_ordinal[ordinal] = x
           #Entry point : doesnt works for ELF..
           # TODO: find real entry point method
           if  addr == ordinal:
               self.entry_point = x
        # disable default dict at this point to prevent error
        self.exports_by_addr.default_factory = None
     
    def __contains__(self, value):
        if isinstance(value, basestring):
            return value in self.exports_by_name
        return int(value) in self.exports_by_addr
        
    def __getitem__(self, value):
        if isinstance(value, basestring):
            return self.get_by_name(value)
        return self.get_by_addr(value)
        
    def get_by_name(self, name):
        return self.exports_by_name[name]
     
    def get_by_addr(self, addr):
        return self.exports_by_addr[int(addr)]    
        
    @property
    def get_all(self):
        return list(self.exports_by_name.values())
        
    def __iter__(self):
        return iter(self.get_all)
        
    def by_ord(self, ord):
        return self.export_by_ordinal[ord]
        

class IDAImport(code.IDACodeElt): # CodeElt to do rjump on import

    def __init__(self, module_name, addr, name, ord):
        #name is ignored and will be accessed using the property of IDANamedElt
        super(IDAImport, self).__init__(addr)
        #module_name might be empty (ELF)
        self.module = module_name
        self.ord = ord
       
    def __IDA_repr__(self):
        descr = "ord={0}".format(self.ord)
        if self.name is not "":
            descr = "name={0}".format(self.name)
        module = ", module={0}".format(self.module) if self.module else ""
        return "({1}{2})".format(self.__class__.__name__,descr, module)
        
class IDAImportList(object):
    # Really need import by name ?
    def __init__(self):
        #strongly inspired by ex_imports.py in IDAPython examples
        self.imports_by_name = {}
        self.imports_by_addr = {}
        nimps = idaapi.get_import_module_qty()
        for i in xrange(0, nimps):
            name = idaapi.get_import_module_name(i)
            idaapi.enum_import_names(i, functools.partial(self._add_import, name))
            
    def _add_import(self, module_name, ea, name, ord):
        imp = IDAImport(module_name, ea, name, ord)
        self.imports_by_name[name] = imp
        self.imports_by_addr[ea] = imp
        return True
        
    def __contains__(self, value):
        if isinstance(value, basestring):
            return value in self.imports_by_name
        return int(value) in self.imports_by_addr
              
    def __getitem__(self, value):
        if isinstance(value, basestring):
            return self.get_by_name(value)
        return self.get_by_addr(value)
        
    def get_by_name(self, name):
        return self.imports_by_name[name]
     
    def get_by_addr(self, addr):
        return self.imports_by_addr[int(addr)]    
        
    @property
    def get_all(self):
        return list(self.imports_by_name.values())
        
    def __iter__(self):
        return iter(self.get_all)
        
        



