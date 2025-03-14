from bf_pktpy.library.fields.mac_field import MACField


class DestMACField(MACField):
    def __init__(self, name, default_value="ff:ff:ff:ff:ff:ff"):
        super(DestMACField, self).__init__(name, default_value)
