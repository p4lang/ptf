from bf_pktpy.library.fields import EnumField


class XShortEnumField(EnumField):
    def __init__(self, name, default_value, types=None):
        super(XShortEnumField, self).__init__(name, default_value, size=16, types=types)
