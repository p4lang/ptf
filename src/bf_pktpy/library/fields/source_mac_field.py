from bf_pktpy.library.helpers.mac import get_src_mac_address
from bf_pktpy.library.fields.mac_field import MACField


class SourceMACField(MACField):
    def __init__(self, name, default_value=None):
        if default_value is None:
            default_value = get_src_mac_address()
        super(SourceMACField, self).__init__(name, default_value)
