from bf_pktpy.library.fields.bit_field import BitField


class ByteField(BitField):
    def __init__(self, name, default_value):
        super(ByteField, self).__init__(name, default_value, size=8)
