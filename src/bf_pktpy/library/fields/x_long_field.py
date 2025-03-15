from bf_pktpy.library.fields.x_bit_field import XBitField


class XLongField(XBitField):
    def __init__(self, name, default_value):
        super(XLongField, self).__init__(name, default_value, size=64)
