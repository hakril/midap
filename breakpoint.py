import idc
import idaapi

# Vient d'un projet perso
# Le code est potentiellement trouvable sur internet a mon nom.


all_breakpoint = {}

class BreakPoint(object):
    BP_TYPE = idc.BPT_DEFAULT
    BP_SIZE = 0

    def __init__(self, addr, size=None):
        if size is None:
            size = self.BP_SIZE
        self.addr = addr
        if idc.CheckBpt(self.addr) != idc.BPTCK_NONE:
            raise ValueError("There is already a breakpoint at {0}".format(hex(self.addr)))
        if not idc.AddBptEx(addr, size, self.BP_TYPE):
            raise ValueError("Failed to create breakpoint at {0}".format(hex(self.addr)))
        self._set_elang("Python")
        self._set_condition("return breakpoint.all_breakpoint[{0}].trigger()".format(self.addr))
        all_breakpoint[self.addr] = self

    def _set_condition(self, cond):
        return idc.SetBptCnd(self.addr, cond)

    def _set_elang(self, elang):
        bpt = idaapi.bpt_t()
        if not idaapi.get_bpt(self.addr, bpt):
            return False
        bpt.elang = elang
        return idaapi.update_bpt(bpt)

    def delete(self):
        if all_breakpoint[self.addr] is self:
            del all_breakpoint[self.addr]
            idc.DelBpt(self.addr)

    @property
    def condition(self):
        return idc.GetBptAttr(self.addr, idc.BPTATTR_COND)

    @property
    def elang(self):
        bpt = idaapi.bpt_t()
        if not idaapi.get_bpt(self.addr, bpt):
            return False
        return bpt.elang
        
    @property
    def state(self):
        return idc.CheckBpt(self.addr)
        
    @property
    def is_enabled(self):
        return self.state in [idc.BPTCK_YES, idc.BPTCK_ACT]
            
    def enable(self):
        if self.is_enabled:
            raise ValueError("{0} already enabled".format(self))
        return idc.EnableBpt(self.addr, True)
        
    def disable(self):
        if not self.is_enabled:
            raise ValueError("{0} is not enabled".format(self))
        return idc.EnableBpt(self.addr, False)    

    def trigger(self):
        return True

class HardwareExecBreakPoint(BreakPoint):
    BP_TYPE = idc.BPT_EXEC
    BP_SIZE = 1

def wait_for_breakpoint():
    while True:
        x = idc.GetDebuggerEvent(idc.WFNE_SUSP | idc.WFNE_CONT, -1)
        if x == idc.DBG_TIMEOUT:
            return x
        bp_addr = idc.GetEventEa()
        if bp_addr not in all_breakpoint:
            print "Ignore event at {0}".format(hex(bp_addr))
            continue
        return all_breakpoint[bp_addr]
        
def remove_all_breakpoint():
    for i in range(idc.GetBptQty()):
        idc.DelBpt(idc.GetBptEA(i))
    all_breakpoint.clear()





