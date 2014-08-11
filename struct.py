import elt
import data

import idc

# RETHINKS THIS SHIT
# global idea is good, but need to put nested struct inside

class DataDefinition(data.Data):
    """ Abstract data for definition:
            size is retrieved differently
            Allow to have access to is_struct and co in MemberDefinition
    """
            
    def __init__(self, addr):
        elt.IDAElt.__init__(self, addr)
        
    __IDA_repr__ = elt.IDANamedElt.__IDA_repr__

    
    
class StructDef(DataDefinition):

    @staticmethod
    def all_ids():
        return [idc.GetStrucId(i) for i in range(idc.GetStrucQty())]
        
    def __init__(self, sid):
        # Get sid by xrefsfrom struct variables
        self.sid = sid
        # Make sid like the addr of StructDef ?
        super(StructDef, self).__init__(sid)
     
    @property
    def size(self):
        return idc.GetStrucSize(self.sid)
     
    def get_name(self):
        return idc.GetStrucName(self.sid)
        
    def set_name(self, value):
        return idc.SetStrucName(self.sid, value)
        
    name = property(get_name, set_name, None, "Name of the structure")
        
    @property
    def nb_member(self):
        return idc.GetMemberQty(self.sid)
        
    @property # autoflat structs ? return StructDef when struct ?
    def members(self):
        # Try for returning StructDef in members // better ideas ? 
        return [StructMemberDef(self, offset) for offset in self._get_members_offset()]
   
    @property
    def flat_members(self):
        res = []
        for m in self.members:
            if not m.is_struct:
                res.append(m)
            else:
                res.extend(m.definition.flat_members)
        return res
            
     
    @property     
    def is_union(self):
        return idc.IsUnion(self.sid)
        
    def set_comment(self, comment, repeteable=True):
            return idc.SetStrucComment(self.sid, comment, repeteable)
        
    def get_comment(self, repeteable=True):
        return idc.GetStrucComment(self.sid, repeteable)
        
    def _get_members_offset(self):
        off = idc.GetFirstMember(self.sid)
        for i in range(self.nb_member):
            yield off
            off = idc.GetStrucNextOff(self.sid, off)
"""            
class SubStrucDef(StructDef):
    def __init__(self, sid, parents_structs):
        super(SubStrucDef, self).__init__(sid)
        self.parents_structs = parents_structs
        
    def __IDA_repr__(self):
        return ".".join([s.name for s in self.parents_structs] + [self.name])
"""
   

   
class StructMemberDef(DataDefinition):
    def __init__(self, struct, offset):
        # member id : no idea of its usage ...
        self.mid = idc.GetMemberId(struct.sid, offset)
        self.struct = struct
        self.offset = offset
        super(StructMemberDef, self).__init__(self.mid)
        
    def get_name(self):
        return idc.GetMemberName(self.struct.sid, self.offset)
        
    def set_name(self, value):
        return idc.SetMemberName(self.struct.sid, self.offset, value)
        
    name = property(get_name, set_name, None, "Name of the member")
     
    @property     
    def size(self):
        return idc.GetMemberSize(self.struct.sid, self.offset)
        
    @property
    def flags(self):
        return idc.GetMemberFlag(self.struct.sid, self.offset)
        
    @property
    def definition(self):
        if not self.is_struct:
            return None # raise ?
        xfrom = self.xfrom
        if len(xfrom) != 1:
            raise ValueError("Unexpected {0} xrefsfrom in {1}".format(len(xfrom), self)) 
        return StructDef(xfrom[0].to.addr)
        
    def set_comment(self, value, repeteable=True):
        return idc.SetMemberComment(self.struct.sid, self.offset, value, repeteable)
        
    def get_comment(self, repeteable=True):
        return idc.GetMemberComment(self.struct.sid, self.offset, repeteable)
        
    def __IDA_repr__(self):
        return ".".join([self.struct.name, self.name])
        

        
        
#TODO: StructData -> mapping of a variable StructDef on data
# is there a better way than manually by 'parsing' the StructDef.flat_members
  
# generating struct memberdata based on Data subclasses
 
  
class StructData(data.Data):
    def __init__(self, addr):
        idaelt = elt.IDAElt(addr)
        struct_ids = StructDef.all_ids()
        structs = [xref.to.addr for xref in idaelt.xfrom if xref.to.addr in struct_ids]
        if not structs:
            raise ValueError("Coul not find xref to struct definition for addr {0}".format(hex(addr)))
        if len(structs) > 1:
            raise ValueError("multiple xref to struct definition for addr {0} (WHAT DO I DO ?)".format(hex(addr)))
        self.struct = StructDef(structs[0])
        super(StructData, self).__init__(addr, addr + self.struct.size)
        
    
    def members(self):
        for member in self.struct.members:
            
    
    def new_data_by_member_type(cls, addr):
        data = Data(addr)
        for subcls in cls.__subclasses__():
            if subcls.match(data):
                return subcls(addr)
        return UnknowData(addr)
            