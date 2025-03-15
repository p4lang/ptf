from bf_pktpy.library.fields.x_bit_field import XBitField


class XShortField(XBitField):
    def __init__(self, name, default_value):
        super(XShortField, self).__init__(name, default_value, size=16)
