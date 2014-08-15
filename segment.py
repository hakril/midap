import elt

import idc
import idaapi

class IDASegment(elt.IDANamedSizedElt):
    # Segment from any addr ?
    def __init__(self, addr):
        start = idc.SegStart(addr)
        end = idc.SegEnd(addr)
        super(IDASegment, self).__init__(start, end)
        
    
            
    def get_name(self):
        return idc.SegName(self.addr)
        
    def set_name(self, value):
        return idc.RenameSeg(self.addr, value)
        
    name = property(get_name, set_name, None, "Name of the segment")
    
    def get_class(self):
        seg = idaapi.getseg(self.addr)
        if not seg:
            return None
        return idaapi.get_segm_class()
        
    def set_class(self, value):
        
        return idc.SetSegClass(self.addr, value)
        
    sclass = property(get_class, set_class, "class of the segment")
    
    
    def get_type(self):
        seg = idaapi.getseg(self.addr)
        if not seg:
            return None
        return seg.type
        
    def set_type(self, value):
        return idc.SetSegmentType(self.addr, value)
        
       
    type = property(get_type, set_type, "type of the segment")
        
        
    