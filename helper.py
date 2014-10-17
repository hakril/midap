import re

import idc
import idaapi
import idautils

def dlist(s):
	elts = dir(idc) + dir(idaapi) + dir(idautils)
	return [x for x in elts if s in x]