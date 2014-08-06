import idc
import idautils

late_import = ['xref']


class IDAElt(object):
    def __init__(self, addr, *args):
        self._addr  = addr
        
    def get_addr(self):
        return self._addr
        
    addr = property(get_addr, None, None, 'ea of the object')
    
    #property ?
    def goto(self):
        idc.Jump(self.addr)
        
    def __int__(self):
        return self.addr
        
    def __repr__(self):
        return "<{0}>".format(self.__IDA_repr__() + " <at {0}>".format(hex(self.addr)))
        
    def __IDA_repr__(self):
        return self.__class__.__name__
    
    @property    
    def xfrom(self):
        return [xref.Xref(x) for x in idautils.XrefsFrom(self.addr, False)]
        
    @property   
    def xto(self):
        return [xref.Xref(x) for x in idautils.XrefsTo(self.addr, False)]
        
    #Create data xref ?
         

class IDANamedElt(IDAElt):
    """ Real base class : looks like everything can have a name """
    def __init__(self, addr, *args):
        super(IDANamedElt, self).__init__(addr)
        
    def get_name(self):
        return idc.Name(self.addr)
        
    def set_name(self, name):
        return idc.MakeName(self.addr, name)
       
    name = property(get_name, set_name, None, 'Name default property')
    
    def __IDA_repr__(self):
        if self.name is not "":
            return self.__class__.__name__ + " " +  self.name
        return super(IDANamedElt, self).__IDA_repr__()

        
class IDASizedElt(IDAElt):
    def __init__(self, addr, endaddr, nb_elt=None):
        """ endaddr: first addr not part of the element """
        super(IDASizedElt, self).__init__(addr, endaddr, nb_elt)
        self.endADDR = endaddr
        self.size = endaddr - addr
        if nb_elt is None:
            nb_elt = self.size
        self.nb_elt = nb_elt
        
    def __contains__(self, value):
        return self.addr <= value < self.endADDR
        
        
class IDANamedSizedElt(IDASizedElt, IDANamedElt):
    pass