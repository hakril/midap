__author__ = 'clement'
import idaapi

# Test module to see if autogenerated flags recognition
# based on IDC.py constants definition is doable and usable


class AutoFlagGeneration(type):
    def __new__(meta, name, bases, attributes):
        if "__doc__" not in attributes:
            raise ValueError("class with AUtoFlag meta has no __doc__")
        doc = attributes['__doc__']
        raw_flags = meta.parse_doc(doc)
        attributes['raw_flags'] = raw_flags
        new_cls = type.__new__(meta, name, bases, attributes)
        return new_cls

    @classmethod
    def parse_doc(meta, doc):
        flags = []
        for line in doc.split("\n"):
            if "=" in line:
                name, other = line.split("=", 1)
                name = name.strip()
                value , doc = other.split("#", 1)
                value = eval(value.strip())
                flags.append([name, value, doc])
            elif "#" in line:
                if not flags:
                    raise ValueError("__doc__ of cls begin with only doc line")
                doc = line.split("#", 1)[1]
                flags[-1][2] = flags[-1][2] + doc
        return flags

    def __getitem__(cls, item):
        for name, value, doc in cls.raw_flags:
            if item == name:
                return cls(value)
        raise AttributeError("class <{0}> has no flag named {1}".format(cls.__name__, item))





class AutoFlagGenerated(int):
    ""
    __metaclass__ = AutoFlagGeneration

    def __init__(self, x):
        self.flags = []
        self.values = []
        tot = 0
        for name, value, doc in self.raw_flags:
            if value & x:
                tot += value
                self.flags.append(name)
                self.values.append(value)
        if tot != x:
            raise ValueError("Value {0} is not a sum of {1}".format(x, self.__class__.__name__))

    def __repr__(self):
        return "<{0} {2}({1})>".format(self.__class__.__name__, "|".join(self.flags), int(self))

    def __contains__(self, item):
        if isinstance(item, basestring):
            return item in self.flags
        return item in self.values


    __str__ = __repr__


# Try on flag enumeration

class FunctionFlags(AutoFlagGenerated):
    """FUNC_NORET         = idaapi.FUNC_NORET      # function doesn't return
    FUNC_FAR           = idaapi.FUNC_FAR           # far function
    FUNC_LIB           = idaapi.FUNC_LIB           # library function
    FUNC_STATIC        = idaapi.FUNC_STATICDEF     # static function
    FUNC_FRAME         = idaapi.FUNC_FRAME         # function uses frame pointer (BP)
    FUNC_USERFAR       = idaapi.FUNC_USERFAR       # user has specified far-ness
                                                   # of the function
    FUNC_HIDDEN        = idaapi.FUNC_HIDDEN        # a hidden function
    FUNC_THUNK         = idaapi.FUNC_THUNK         # thunk (jump) function
    FUNC_BOTTOMBP      = idaapi.FUNC_BOTTOMBP      # BP points to the bottom of the stack frame
    FUNC_NORET_PENDING = idaapi.FUNC_NORET_PENDING # Function 'non-return' analysis
                                                   # must be performed. This flag is
                                                   # verified upon func_does_return()
    FUNC_SP_READY      = idaapi.FUNC_SP_READY      # SP-analysis has been performed
                                                   # If this flag is on, the stack
                                                   # change points should not be not
                                                   # modified anymore. Currently this
                                                   # analysis is performed only for PC
    FUNC_PURGED_OK     = idaapi.FUNC_PURGED_OK     # 'argsize' field has been validated.
                                                   # If this bit is clear and 'argsize'
                                                   # is 0, then we do not known the real
                                                   # number of bytes removed from
                                                   # the stack. This bit is handled
                                                   # by the processor module.
    FUNC_TAIL          = idaapi.FUNC_TAIL          # This is a function tail.
                                                   # Other bits must be clear
                                                   # (except FUNC_HIDDEN)
    """
