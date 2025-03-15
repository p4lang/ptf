from bf_pktpy.library.fields.bit_field import BitField


class IntField(BitField):
    def __init__(self, name, default_value):
        super(IntField, self).__init__(name, default_value, size=32)
