from bf_pktpy.library.fields.bit_field import BitField


class ThreeBytesField(BitField):
    def __init__(self, name, default_value):
        super(ThreeBytesField, self).__init__(name, default_value, size=24)
