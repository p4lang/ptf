from bf_pktpy.library.fields import EnumField


class BitEnumField(EnumField):
    def __init__(self, name, default_value, size=1, types=None):
        super(BitEnumField, self).__init__(name, default_value, size, types)
