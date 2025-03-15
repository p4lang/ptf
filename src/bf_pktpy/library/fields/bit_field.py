import math

import six

from bf_pktpy.library.fields.field import Field


# noinspection PyPropertyAccess,PyAttributeOutsideInit
class BitField(Field):
    def __init__(self, name, default_value, size=1):
        super(BitField, self).__init__(name, default_value, size)

    def from_internal(self, raw_value):
        return super(BitField, self).from_internal(raw_value)

    def validate(self, new_value):
        if new_value is None:
            return True

        if isinstance(new_value, six.binary_type):
            new_value = int.from_bytes(new_value, "big")
        return isinstance(new_value, six.integer_types) and (
            0 <= new_value <= math.pow(2, self.size) - 1
        )

    def to_internal(self, new_value):
        if isinstance(new_value, six.binary_type):
            return int.from_bytes(new_value, "big")
        return int(new_value) if new_value is not None else 0
