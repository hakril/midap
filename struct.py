import elt
import data

import idc

# Definitions

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
        self.root = self
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
        return [MemberDef(self, offset) for offset in self._get_members_offset()]
  
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
            
                       
class SubStrucDef(StructDef):
    """ offset : global offset of the sub struct into root struct """
    def __init__(self, sid, parents_structs, base_offset):
        super(SubStrucDef, self).__init__(sid)
        self.parents_structs = parents_structs
        self.offset = base_offset
        self.root = parents_structs[-1].root
        
    def __IDA_repr__(self):
        return ".".join([s.name for s in self.parents_structs]) + " {0}".format(self.name)
      
    @property # autoflat structs ? return StructDef when struct ?
    def members(self):
        # Try for returning StructDef in members // better ideas ? 
        return [SubMemberDef(self, offset) for offset in self._get_members_offset()]

        
      
class MemberDef(DataDefinition):
    def __init__(self, struct, struct_offset):
        # member id : no idea of its usage ...
        self.mid = idc.GetMemberId(struct.sid, struct_offset)
        self.parent = struct
        self.struct_offset = struct_offset
        self.offset = struct_offset
        self.root = struct.root
        super(MemberDef, self).__init__(self.mid)
       
    def get_name(self):
        return idc.GetMemberName(self.parent.sid, self.struct_offset)
        
    def set_name(self, value):
        return idc.SetMemberName(self.parent.sid, self.struct_offset, value)
        
    name = property(get_name, set_name, None, "Name of the member")
    
    @property
    def full_name(self):
        return ".".join([self.parent.name, self.name])
   
    @property
    def path_name(self):
        return self.name
     
    @property     
    def size(self):
        return idc.GetMemberSize(self.parent.sid, self.struct_offset)
        
    @property
    def flags(self):
        return idc.GetMemberFlag(self.parent.sid, self.struct_offset)
        
    @property
    def definition(self):
        if not self.is_struct:
            return None # raise ?
        xfrom = self.xfrom
        if len(xfrom) != 1:
            raise ValueError("Unexpected {0} xrefsfrom in {1}".format(len(xfrom), self)) 
        return SubStrucDef(xfrom[0].to.addr, [self.parent, self] , self.struct_offset)
        
    def set_comment(self, value, repeteable=True):
        return idc.SetMemberComment(self.parent.sid, self.struct_offset, value, repeteable)
        
    def get_comment(self, repeteable=True):
        return idc.GetMemberComment(self.parent.sid, self.struct_offset, repeteable)
        
    def __IDA_repr__(self):
        return self.full_name
        
   

class SubMemberDef(MemberDef):
    """ offset : offset in the root struct
        struct_offset = offset in sur SubStructDef
    """
    
    def __init__(self, parent_struct, struct_offset):
        super(SubMemberDef, self).__init__(parent_struct, struct_offset)
        self.offset = parent_struct.offset + struct_offset
     
    @property
    def full_name(self):
        return ".".join([s.name for s in self.parent.parents_structs]) + ".{0}".format(self.name)
     
    @property
    def path_name(self):
        return ".".join([s.name for s in self.parent.parents_structs[1:]]) + ".{0}".format(self.name)
       

# Struct data
       
class StructData(data.Data):
    match = staticmethod(data.Data.is_struct.fget)

    def __init__(self, addr):
        idaelt = elt.IDAElt(addr)
        struct_ids = StructDef.all_ids()
        structs = [xref.to.addr for xref in idaelt.xfrom if xref.to.addr in struct_ids]
        if not structs:
            raise ValueError("Coul not find xref to struct definition for addr {0}".format(hex(addr)))
        if len(structs) > 1:
            raise ValueError("multiple xref to struct definition for addr {0} (WHAT DO I DO ?)".format(hex(addr)))
        self.definition = StructDef(structs[0])
        super(StructData, self).__init__(addr, addr + self.definition.size)
       
    @property
    def members(self):
        return [self.new_data_by_member_type(member) for member in self.definition.flat_members]
                         
    def new_data_by_member_type(self, member): 
        for subcls in data.Data.__subclasses__():
            if subcls.match(member):
                return self.new_data_member(subcls)(self.addr + member.offset, member)
        return self.new_data_member(UnknowData)(self.addr + member.offset, member)
        
    def new_data_member(self_struct, cls):
        class MemberData(cls):
            def __init__(self, addr, member):
                super(MemberData, self).__init__(addr)
                self.definition = member
                self.parent = self_struct

            @property    
            def name(self):
                """ name of a MemberData is name of the struct + path_name of the member definition """
                return self.parent.name + "." + self.definition.path_name
                
            def __IDA_repr__(self):
                return self.name  + " " + super(MemberData, self).__IDA_repr__()
            
        MemberData.__name__ = "Member" + cls.__name__
        return MemberData
        

            
    
         