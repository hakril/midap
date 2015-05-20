import idastruct
import idc

# Important:
# Some function doesnt have a ebp used for access
# in this case : use of r as 0 offset !



#-0000003C var_3C          db ?
#-0000003B                 db ? ; undefined
#-0000003A                 db ? ; undefined
#-00000039                 db ? ; undefined
#-00000038                 db ? ; undefined
#-00000037                 db ? ; undefined
#-00000036                 db ? ; undefined
#-00000035                 db ? ; undefined
#-00000034 var_34          dd ?

# Make var_3c an array ? because there is probleme beetwen stack.nb_member and number of values returned by GetStrucNextOff

# tmp response: do no return field without a name :D

# <MemberDef $ F40F9CA.{no_name} <at -0x1>>
# also handle that in struct also ?


# TODO: stack var xref ? HOWTO ? get_stkvar and iter over every args ?

# Use function flags

class IDAStack(idastruct.StructDef): # IDAStrackFrame ?
    def __init__(self, addr, func):
        super(IDAStack, self).__init__(addr)
        self.func = func
        self.func_addr = func.addr
        
    @property
    def locals_size(self):
        return idc.GetFrameLvarSize(self.func_addr)
    
    @property
    def saved_regs_size(self):
        return idc.GetFrameRegsSize(self.func_addr)
        
    @property    
    def cleaned_size(self):
        return idc.GetFrameSize(self.func_addr)
        
    @property   
    def args_size(self):
        return self.size - self.cleaned_size
    
    @property
    def args(self):
        return [m for m in self.members if m.offset >= (self.size - self.args_size)]
        
    @property
    def locals(self):
        return [m for m in self.members if m.offset < self.locals_size]
      
    @property
    def saved_regs(self): # looks like " s" and " r" canot be renamed: use it ? :D
        return [m for m in self.members if self.locals_size <= m.offset < self.locals_size + self.saved_regs_size]
    
    @property
    def members(self): # see exemple in begin of file: GetStrucNextOff might return offset that are not named members
    # Also: stack has a last members with size None: hide it.
        return [idastruct.MemberDef(self, offset) for offset in self._get_members_offset() if idastruct.MemberDef(self, offset).size is not None]
        
        
    def _get_members_offset(self):
        off = idc.GetFirstMember(self.sid)
        while off != idc.BADADDR:
            yield off
            off = idc.GetStrucNextOff(self.sid, off)


    
