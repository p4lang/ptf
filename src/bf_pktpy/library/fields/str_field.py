import binascii
import math
import six

from bf_pktpy.library.fields import Field


# noinspection PyPropertyAccess,PyAttributeOutsideInit
class StrField(Field):
    def __init__(self, name, default_value):
        super(StrField, self).__init__(
            name, default_value, size=lambda value: len(value) * 8 if value else 0
        )

    @Field.size.setter
    def size(self, new_size):
        if callable(new_size):
            self._size = new_size
            return
        default_value_len = (
            len(self.default_value) if self._default_value is not None else 0
        )
        if new_size is None:
            self._size = default_value_len * 8
        elif isinstance(new_size, six.integer_types):
            self._size = (
                default_value_len * 8 if new_size < default_value_len else new_size * 8
            )
        else:
            raise TypeError(
                "StrField size should be long or int, not: {}".format(
                    type(new_size).__name__
                )
            )

    def value2bin(self, value):
        return six.ensure_binary(value)

    def value2hex(self, value):
        return binascii.hexlify(value)

    def from_internal(self, raw_value):
        return raw_value if raw_value else b""

    def validate(self, new_value):
        return super(StrField, self).validate(new_value)

    def to_internal(self, new_value):
        if not new_value:
            return b""
        if isinstance(new_value, six.integer_types):
            val_size = self._get_size_of_int_val(new_value)
            return new_value.to_bytes(val_size, byteorder="big")
        return self.value2bin(new_value)

    def _get_size_of_int_val(self, new_value):
        return math.ceil(math.log(new_value, 256)) if new_value > 1 else 1
