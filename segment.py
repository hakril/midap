import elt

import idc
import idaapi

class IDASegment(elt.IDANamedSizedElt):
    # Segment from any addr ? : yep
    def __init__(self, addr):
        start = idc.SegStart(addr)
        end = idc.SegEnd(addr)
        # TODO: when implementing segment relocation: be carrefull with self.addr going out of the new segment
        super(IDASegment, self).__init__(start, end)
     
    @property     
    def start(self):
        return idc.SegStart(self.addr)
    
    @property
    def end(self):     
         return idc.SegEnd(addr)
         
    # make start and end descriptor writable to move segment ? (seems dangerous)     
    def set_bound(self, startea=None, endea= None, flags=SEGMOD_KEEP):
        """
        Change segment boundaries

        @param ea: any address in the segment
        @param startea: new start address of the segment
        @param endea: new end address of the segment
        @param flags: combination of SEGMOD_... flags

        @return: boolean success
        """
        if startea is None:
            startea = self.start
        if endea is None:
            endea = self.end
        return idc.SetSegBounds(self.start, startea, endea, flags)
        
         
    def SetSegBounds(ea, startea, endea, flags):
        """
        Change segment boundaries

        @param ea: any address in the segment
        @param startea: new start address of the segment
        @param endea: new end address of the segment
        @param flags: combination of SEGMOD_... flags

        @return: boolean success
        """
        return idaapi.set_segm_start(ea, startea, flags) & \
               idaapi.set_segm_end(ea, endea, flags)
         
               
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
    
    
    def get_addressing(self):
        seg = idaapi.getseg(self.start)
        return seg.bitness
        
    def set_addressing(self, value):
        return idc.SetSegAddressing(selt.start, value)
        
    addressing_doc = """addressing bitness of the segment\n0: 16bit\n1: 32bit\n2: 64bit"""
        
    addressing = property(get_addressing, set_addressing, None, addressing_doc)
    
    
    def move(to, flags):
        """
        Move the segment to a new address
        This function moves all information to the new address
        It fixes up address sensitive information in the kernel
        The total effect is equal to reloading the segment to the target address

        @param ea: any address within the segment to move
        @param to: new segment start address
        @param flags: combination MFS_... constants
        
        @returns: MOVE_SEGM_... error code
        
        MSF_SILENT  # don't display a "please wait" box on the screen
        MSF_NOFIX  # don't call the loader to fix relocations
        MSF_LDKEEP  # keep the loader in the memory (optimization)
        MSF_FIXONCE    # valid for rebase_program(): call loader only once

        MOVE_SEGM_OK        # all ok
        MOVE_SEGM_PARAM     # The specified segment does not exist
        MOVE_SEGM_ROOM      # Not enough free room at the target address
        MOVE_SEGM_IDP       # IDP module forbids moving the segment
        MOVE_SEGM_CHUNK     # Too many chunks are defined, can't move
        MOVE_SEGM_LOADER    # The segment has been moved but the loader complained
        MOVE_SEGM_ODD       # Can't move segments by an odd number of bytes

        """
        return idc.MoveSegm(self.start, to, flags)

    