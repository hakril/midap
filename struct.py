import elt
import data

import idc

# Definitions

# Todo fix offseterror in multiple cascade struct (see stack stuff)


# TODO : rename definition because it describe two things:
    # - the definition of a datastruct / datamember
    # - the passage from datamembers to StructDef
    
    # or ? double deref when needed ? because this is the same !
    
    # to_struct? for:
    
#Python>MIDAP.dhere().definition.members[-1]
#<MemberDef _EH4_SCOPETABLE.ScopeRecord <at 0xff0004e1L>>
#Python>MIDAP.dhere().definition.members[-1].to_struct
#<SubStrucDef _EH4_SCOPETABLE.ScopeRecord _EH4_SCOPETABLE_RECORD <at 0xff0004ddL>>


#use struct_t and member_t ?

# DOCUMENT THE SHIT OUT OF THIS :D

class DataDefinition(data.Data):
    """ Abstract data for definition:
            size is retrieved differently
            Allow to have access to is_struct and co in MemberDefinition
    """
            
    def __init__(self, addr):
        elt.IDAElt.__init__(self, addr)
        
    __IDA_repr__ = elt.IDANamedElt.__IDA_repr__

    
class StructDef(DataDefinition):
    """ Definition of a structure """
    @staticmethod
    def all_ids():
        return [idc.GetStrucId(i) for i in range(idc.GetStrucQty())]
        
    def __init__(self, sid):
        # Get sid by xrefsfrom struct variables
        self.sid = sid
        self.root = self
        self._offset = 0 
        # offset is always 0 as StructDef is a root struct (not a SubStructDef)
        # Make sid like the addr of StructDef ?
        super(StructDef, self).__init__(sid)
     
    @property
    def size(self):
        return idc.GetStrucSize(self.sid)
     
    def get_name(self):
        return idc.GetStrucName(self.sid) or "{no name}"
        
    def set_name(self, value):
        return idc.SetStrucName(self.sid, value)
        
    name = property(get_name, set_name, None, "Name of the structure")
      
    @property
    def offset(self):
        """ offset of the sub-struct into its root structure.
            Is always 0 for StructDef
        """
        return self._offset
      
    @property
    def nb_member(self):
        return idc.GetMemberQty(self.sid)
        
    @property # autoflat structs ? return StructDef when struct ? also see with stackFrame
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
                res.extend(m.to_struct.flat_members)
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
            
    # Hack by implementing is struct? a struct def is a struct..
    # But it's not a struct data (so no)
            
                       
class SubStrucDef(StructDef):
    """ A structure definition that is part of another struct definition
        Example:      
            struct root{
                int a
                struct other x
                }
        root->x is a SubStructDef of 'other'
    """
    def __init__(self, sid, parents_structs, base_offset):
        super(SubStrucDef, self).__init__(sid)
        self.parents_structs = parents_structs
        self._offset = base_offset
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
        self._offset = struct_offset
        self.root = struct.root
        super(MemberDef, self).__init__(self.mid)
       
    def get_name(self):
        return idc.GetMemberName(self.parent.sid, self.struct_offset) or "{no_name}"
        
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
    def offset(self):
        return self._offset
        
    @property
    def to_struct(self):
        if not self.is_struct:
            return None # raise ?
        xfrom = self.xfrom
        if len(xfrom) != 1:
            raise ValueError("Unexpected {0} xrefsfrom in {1}".format(len(xfrom), self)) 
        return SubStrucDef(xfrom[0].to.addr, [self.parent, self] , self.offset) # self.offset so submembers propagate their offset
        
    def set_comment(self, value, repeteable=True):
        return idc.SetMemberComment(self.parent.sid, self.struct_offset, value, repeteable)
        
    def get_comment(self, repeteable=True):
        return idc.GetMemberComment(self.parent.sid, self.struct_offset, repeteable)
        
    def __IDA_repr__(self):
        return self.full_name
        
   

class SubMemberDef(MemberDef):
    """ offset : offset in the root struct
        struct_offset = offset in the SubStructDef
    """
    
    def __init__(self, parent_struct, struct_offset):
        super(SubMemberDef, self).__init__(parent_struct, struct_offset)
        self._offset = parent_struct.offset + struct_offset
     
    @property
    def full_name(self):
        return ".".join([s.name for s in self.parent.parents_structs]) + ".{0}".format(self.name)
     
    @property
    def path_name(self):
        return ".".join([s.name for s in self.parent.parents_structs[1:]]) + ".{0}".format(self.name)
       

# Struct data

# Rewrite it for better SubStruct Data.. (hidden or not)
       
class StructData(data.Data):
    match = staticmethod(data.Data.is_struct.fget)

    def __init__(self, addr, parent_struct=None):
        self.definition = self.get_struct_definition(addr)
        self.parent_struct = None
        super(StructData, self).__init__(addr, addr + self.definition.size)

       
    def get_struct_definition(self, addr):
        """ might be called before object initialization: use addr not self.addr """
        struct_ids = StructDef.all_ids()
        structs = [xref.to.addr for xref in elt.IDAElt(addr).xfrom if xref.to.addr in struct_ids]
        if not structs:
            raise ValueError("Coul not find xref to struct definition for addr {0}".format(hex(addr)))
        if len(structs) > 1:
            raise ValueError("multiple xref to struct definition for addr {0} (WHAT DO I DO ?)".format(hex(addr)))
        return StructDef(structs[0])
       
    @property
    def members(self):
        real_def = self.definition
        if isinstance(self.definition, MemberDef): # Where are a sub Struct data so a Member that is a struct
            real_def = self.definition.to_struct
            print("AUTO_DEREF")
        return [self.new_data_by_member_type(member) for member in real_def.members]
        
    @property
    def flat_members(self):
        real_def = self.definition
        if isinstance(self.definition, MemberDef): # Where are a sub Struct data so a Member that is a struct
            real_def = self.definition.to_struct
        return [self.new_data_by_member_type(member) for member in real_def.flat_members]
                         
    def new_data_by_member_type(self, member):
        for subcls in data.Data.__subclasses__():
            if subcls.match(member):
                return self.new_data_member(subcls)(self.addr + member.offset, member)
        return self.new_data_member(UnknowData)(self.addr + member.offset, member)
    #Class should handle struct in struct nicely !
    # rethink this shit :(
    def new_data_member(self_struct, cls):
        class MemberData(cls):
            def __init__(self, addr, member):
                self.definition = member
                self.parent = self_struct
                super(MemberData, self).__init__(addr)

            @property    
            def name(self):
                """ name of a MemberData is name of the struct + path_name of the member definition """
                return self.parent.name + "." + self.definition.path_name
                
            def __IDA_repr__(self):
                return super(MemberData, self).__IDA_repr__()
                
            def get_struct_definition(self, addr):
                """ Hack method for StructData because definition is given by the member paremeter of __init__"""
                return self.definition
             
            # what is the best way to write describe this? 
            is_byte = property(lambda self: self.definition.is_byte)
            is_word = property(lambda self: self.definition.is_word)
            is_dword = property(lambda self: self.definition.is_dword)
            is_qword = property(lambda self: self.definition.is_qword)
            is_oword = property(lambda self: self.definition.is_oword)
            is_float = property(lambda self: self.definition.is_float)
            is_double = property(lambda self: self.definition.is_double)
            is_packreal = property(lambda self: self.definition.is_packreal)
            is_ascii = property(lambda self: self.definition.is_ascii)
            is_align = property(lambda self: self.definition.is_align)
            is_struct = property(lambda self: self.definition.is_struct)
            
            

        MemberData.__name__ = "Member" + cls.__name__
        return MemberData

         