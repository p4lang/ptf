import functools
import math
import six

from bf_pktpy.library.fields.field import Field
from bf_pktpy.library.fields.flag_value import FlagValue


# noinspection PyPropertyAccess
class FlagsField(Field):
    """FlagsField adds another property: `flags` which can store flag information.

    Provided flags should be in one of two supported variants:

    Example (list):
        >>> from bf_pktpy.all import Packet
        >>> class FlagsPacket(Packet):
            fields_desc = [FlagsField("list_flags", 0, 3, ["foo", "bar", "baz"])]
        >>> FlagsPacket(list_flags=3).list_flags
        'foo+bar'

    Example (str):
        >>> from bf_pktpy.all import Packet
        >>> class FlagsPacket(Packet):
            fields_desc = [FlagsField("list_flags", 5, 4, "BASE")]
        >>> FlagsPacket(list_flags=3).list_flags
        'BA'

    """

    def __init__(self, name, default_value, size, flags):
        if not isinstance(flags, (str, list)):
            raise TypeError(
                "Flags provided: %s are not of type str or list" % str(flags)
            )
        super(FlagsField, self).__init__(name, default_value, size)
        self.flags = flags

    def to_internal(self, new_value):
        if not new_value:
            return 0

        if isinstance(new_value, six.integer_types):
            return new_value

        if isinstance(new_value, FlagValue):
            return new_value.value

        new_flags = new_value.split("+") if isinstance(self.flags, list) else new_value
        return functools.reduce(
            lambda x, y: x + y, (1 << self.flags.index(flag) for flag in new_flags)
        )

    def validate(self, new_value):
        if new_value is None or (
            isinstance(new_value, six.integer_types)
            and (0 <= new_value <= math.pow(2, self.size) - 1)
        ):
            return True

        if not isinstance(new_value, (str, list)):
            return False

        new_flags = new_value.split("+") if isinstance(self.flags, list) else new_value
        return all(flag in self.flags for flag in set(new_flags))

    def from_internal(self, raw_value):
        return FlagValue(raw_value, self.flags)
