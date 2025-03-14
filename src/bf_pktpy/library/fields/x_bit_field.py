from bf_pktpy.library.fields.bit_field import BitField


# noinspection PyPropertyAccess
class XBitField(BitField):
    def __init__(self, name, default_value, size=1):
        super(XBitField, self).__init__(name, default_value, size)

    def __repr__(self):
        return "{}(name={}, default_value={}, length={})".format(
            type(self).__name__,
            self.name,
            self.default_value
            if self.default_value is None
            else hex(self.default_value),
            self.size,
        )
