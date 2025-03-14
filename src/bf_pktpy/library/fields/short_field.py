from bf_pktpy.library.fields.bit_field import BitField


class ShortField(BitField):
    def __init__(self, name, default_value):
        super(ShortField, self).__init__(name, default_value, size=16)
