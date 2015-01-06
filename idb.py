import idaapi 
import idautils
import idc

import ida_import
import elt


late_import = ['functions', 'data', 'struct', 'segment']
 
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
        # TODO: Use (FT_PE | FT_ELF) instead
        if hasattr(self, 'init'):
            return
        filetype = idaapi.get_file_type_name()
        # This code is really dumb..
        if "PE" in filetype:
            self.format = "PE"
        elif "ELF" in filetype:
            self.format = "ELF"
        elif "Binary file" == filetype:
            self.format = "Binary file"
        else:
            self.format = "Unknow"
        self.imports = ida_import.IDAImportList()
        self.exports = ida_import.IDAExportList()
        self.init = True
        
             
    @property
    def main(self):
        "Return the main function of the IDB"
        main_addr = idc.GetLongPrm(idc.INF_MAIN)
        if main_addr == idc.BADADDR:
            return None
        return functions.IDAFunction(main_addr)
             
    @property
    def is_pe(self): #  You can do better than that..
        return self.format == "PE"
        
    @property
    def is_elf(self): #  You can do better than that..
        return self.format == "ELF"

    @property
    def Functions(self):
        "all functions in IDB"
        return functions.IDAFunction.get_all()
        
    @property
    def Instrs(self):
        "all instructions in IDB"
        return functions.IDAInstr.get_all()
     
    @property
    def Data(self):
        "all datas in IDB"
        return data.Data.get_all()
        
    @property
    def Segments(self):
        "dict {name : segment} of all segments in IDB"
        return {s.name : s for s in [segment.IDASegment(seg) for seg in idautils.Segments()]}
        
    @property
    def Strings(self): # This will create new strings: put a name to it
        "All strings in IDB"
        return self.get_strings()
    
    @staticmethod
    def get_strings(min_len=5, display_only_existing_strings=False, debug=False):
        strs = idautils.Strings()
        #Do we export the other Strings.setup parameters ?
        strs.setup(0xffffffff, minlen=min_len, display_only_existing_strings=display_only_existing_strings)
        res = []
        fails = []
        for s in strs:
            try:
                 res.append(data.ASCIIData(s.ea, True))
            except ValueError as e:
                if (s.ea < res[-1].addr + len(data.ASCIIData(res[-1].addr))):
                    print("Pass substring")
                    continue
                print("String list error : {0}".format(e))
                fails.append(s.ea)
                raise
        if debug:
            return res, fails
        return res #auto str construction ?
      
    @property
    def Structs(self):
        "All structs definitions in the IDB"
        return [struct.StructDef(s[1]) for s in idautils.Structs()]
        
    def rebase_delta(self, delta, flags=idc.MSF_FIXONCE):
        return idc.rebase_program(delta, flags)
        
    def rebase_fix(self, addr, flags=idc.MSF_FIXONCE):
        delta = addr - idc.MinEA()
        return self.rebase_delta(delta, flags)   
        
class Selection(elt.IDASizedElt):
	def __init__(self):
		start, end = idc.SelStart(), idc.SelEnd()
		if start == idc.BADADDR:
			raise ValueError("No selection")
		super(Selection, self).__init__(start, end)
		
	def __repr__(self):
		return "<{0} <from {1} to {2}>>".format(self.__class__.__name__, hex(self.addr), hex(self.endADDR))
 
current = IDB()