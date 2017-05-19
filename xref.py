import idc

late_import = ['elt', 'code', 'data', 'idb']



# Testing code: not sure its really usefull..
# RealHierarchy ..


# xref to stack / to real data (Named)

class Xref(object):
    """Mother class of all Xrefs"""
    def __init__(self, xref):
        self.xref = xref

    @property
    def frm(self):
        """source of the Xref
        
        :type: :class:`midap.elt.IDANamedElt`
        type may change in subclasses"""
        return elt.IDANamedElt(self.xref.frm)

    @property
    def to(self):
        """destination of the Xref
        
        :type: :class:`midap.elt.IDANamedElt`
        type may change in subclasses"""
        return elt.IDANamedElt(self.xref.to)

    @property
    def type(self):
        "type of the xref"
        return self.xref.type

    @property
    def is_code(self):
        "True if xref is a code Xref"
        return self.xref.iscode

    @property
    def is_user(self):
        "true if xref is user defined"
        return self.xref.user

    def __repr__(self):
        return "<{0} <{1} to {2}>>".format(self.__class__.__name__, hex(self.xref.frm), hex(self.xref.to))


    def guess_xref_type(self):
        for subcls in Xref.__subclasses__() + DataXref.__subclasses__(): # cleaner way ? ...
            if subcls.match(self):
                return subcls(self.xref)
        type_str = lambda(b): "Code" if b else "Data"
        raise NotImplementedError("Xref From <{0}> To <{1}> not implem :(".format(type_str(self.frm.is_code), type_str(self.to.is_code)))

    @staticmethod
    def match(xref):
        return False



class CodeXref(Xref): #name it CodeToCode ?
    """ Code to Code xref """

    @property
    def frm(self):
        """source of the Xref
        
        :type: :class:`midap.code.IDAInstr`"""
        return code.IDAInstr(self.xref.frm)

    @property
    def to(self):
        # This is a code xref where to is not code: import or undefined
        # If someone found another case: tell me please !
        """Destination of the Xref
        
        :type: :class:`midap.code.IDAInstr` | :class:`midap.code.IDAImportInstr` | :class:`midap.code.IDAUndefInstr`"""
        dst = elt.IDAElt(self.xref.to)
        if not dst.is_code:
            if dst in idb.current.imports:
                return code.IDAImportInstr(self.xref.to, idb.current.imports[dst])
            else:
                return code.IDAUndefInstr(self.xref.to)
        return code.IDAInstr(self.xref.to)

    @property
    def is_call(self):
        """True if Xref is a call"""
        return (self.xref.type & 0x1f) in [idc.fl_CF, idc.fl_CN]

    @property
    def is_jump(self):
        """True if Xref is a jump"""
        return (self.xref.type & 0x1f) in [idc.fl_JF, idc.fl_JN]

    @property
    def is_nflow(self): # name it 'is_flow' ?
        """True if Xref is normal execution flow"""
        return (self.xref.type & 0x1f) ==  idc.fl_F

    @staticmethod
    def match(xref):
        return  xref.frm.is_code and xref.to.is_code

class DataXref(Xref):
    """ Data to Data xref """

    def __init__(self, xref):
        super(DataXref, self).__init__(xref)
        if (self.xref.type & 0x1f) in (idc.dr_I,):
            print("DEBUG strange xref with dr_I")

    @property
    def to(self):
        """source of the Xref
        
        :type: :class:`midap.data.Data`"""
        return data.Data.new_data_by_type(self.xref.to)

    @property
    def is_offset(self):
        """True if Xref is an offset"""
        return (self.xref.type & 0x1f) == idc.dr_O

    @property
    def is_write(self):
        """True if Xref is a write"""
        return (self.xref.type & 0x1f) == idc.dr_W

    @property
    def is_read(self):
        """True if Xref is a read"""
        return (self.xref.type & 0x1f) == idc.dr_R

    @property
    def is_text(self):
        """True if xref is text (idaapi.dr_T  # Text (names in manual operands))"""
        return (self.xref.type & 0x1f) == idc.dr_T

    @staticmethod
    def match(xref):
        return not xref.frm.is_code and not xref.to.is_code


class CodeToDataXref(DataXref):
    """ Code to Data xref """
    @property
    def frm(self):
        """source of the Xref
        
        :type: :class:`midap.code.IDAInstr`"""
        return code.IDAInstr(self.xref.frm)
        return code.IDAInstr(self.xref.frm)

    @staticmethod
    def match(xref):
        return xref.frm.is_code and not xref.to.is_code


class DataToCodeXref(DataXref):
    """ Data to Code xref """
    @property
    def to(self):
        """destination of the Xref
        
        :type: :class:`midap.code.IDAInstr`"""
        return code.IDAInstr(self.xref.to)

    @staticmethod
    def match(xref):
        return not xref.frm.is_code and xref.to.is_code


