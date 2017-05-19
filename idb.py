import idaapi
import idautils
import idc

import ida_import
import elt


late_import = ['code', 'data', 'idastruct', 'segment']

class IDB(object):
    """Represent the current IDB
    
    This class allows to work on the totality of the code/data of the IDB.
    """ 

    current = None

    def __new__(cls, *args, **kwargs):
        if IDB.current is not None:
            return IDB.current
        idb = super(IDB, cls).__new__(cls, *args, **kwargs)
        IDB.current = idb
        return idb

    def __init__(self):
        # Already exist: no more init
        pass
        
    @property
    def imports(self):
        """The imports of the IDB 
        
        "type: :class:`midap.ida_import.IDAImportList`"""
        return ida_import.IDAImportList()
        
    @property
    def export(self):
        """The imports of the IDB
        
            :type: :class:`midap.ida_import.IDAExportList`
        """
        return ida_import.IDAExportList()
        
    @property
    def main(self):
        "Return the main function of the IDB"
        main_addr = idc.GetLongPrm(idc.INF_MAIN)
        if main_addr == idc.BADADDR:
            return None
        return code.IDAFunction(main_addr)

    @property
    def Functions(self):
        """All functions in IDB
        
        :type: [:class:`midap.code.IDAFunction`]"""
        return code.IDAFunction.get_all()

    @property
    def Instrs(self):
        """All instructions in IDB
        
        :type: [:class:`midap.code.IDAInstr`]"""
        return code.IDAInstr.get_all()

    @property
    def Datas(self):
        """All datas in IDB
        
            :type: see DataType (TODO)"""
        return data.Data.get_all()

    @property
    def Segments(self):
        """dict of all segments in the IDB
        
        :type: dict{str : :class:`midap.segments.IDASegment`}"""
        return {s.name : s for s in [segment.IDASegment(seg) for seg in idautils.Segments()]}

    @property
    def Strings(self): # This will create new strings: put a name to it
        """All strings in IDB
        
            :type: [:class:`midap.data.ASCIIData`]"""
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
        """All structures definitions in the IDB
        
        :type: [:class:`midap.struct.StructDef`]"""
        return [idastruct.StructDef(s[1]) for s in idautils.Structs()]

    @property
    def imagebase(self):
        """The base image of the IDB
        
        :type: int"""
        return idaapi.get_imagebase()

    def rebase_delta(self, delta, flags=idc.MSF_FIXONCE):
        """Rebase the IDB to +delta"""
        return idc.rebase_program(delta, flags)

    def rebase_fix(self, addr, flags=idc.MSF_FIXONCE):
        """Rebase the IDB at address `addr`"""
        delta = addr - self.imagebase
        return self.rebase_delta(delta, flags)


class Selection(elt.IDASizedElt):
    """Represent the cursor selection
    
    Can be read / patched / ... (see base class)"""
    def __init__(self):
        start, end = idc.SelStart(), idc.SelEnd()
        if start == idc.BADADDR:
            raise ValueError("No selection")
        super(Selection, self).__init__(start, end)

    def __repr__(self):
        return "<{0} <from {1} to {2}>>".format(self.__class__.__name__, hex(self.addr), hex(self.endADDR))

current = IDB()