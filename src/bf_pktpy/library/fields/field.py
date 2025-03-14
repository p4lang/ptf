import abc
from abc import ABCMeta
import math
from operator import attrgetter


# noinspection PyPropertyAccess,PyAttributeOutsideInit
class Field(object):
    """Abstract class for defining validation field.

    In order to define a field, one needs to implement 3 methods:\n
    * `from_internal`\n
    * `to_internal`\n
    * `validate`\n

    There is also an option to implement `post_build` method in order to invoke some
    operations after the packet which defines field of that type is created.

    As a default, one can give a strict value, or provide a function to
    invoke when field is asked for its default value. The signature of this function
    should be (it can be lambda function):

    def <function_name>(packet: Packet) -> Any
    """

    __metaclass__ = ABCMeta

    def __init__(self, name, default_value, size):
        self._name = ""
        self._default_value = None
        self._size = 0

        self.name = name
        self.size = size
        self.default_value = default_value

    def __str__(self):
        return self.__repr__()

    def __repr__(self):
        return "{}(name={}, default_value={}, length={})".format(
            type(self).__name__,
            self.name,
            self._default_value.__name__
            if callable(self._default_value)
            else self.default_value,
            self.size,
        )

    name = property(attrgetter("_name"))

    @name.setter
    def name(self, new_name):
        if isinstance(new_name, str):
            self._name = new_name
        else:
            raise TypeError("Value %s is not a string" % new_name)

    @property
    def default_value(self):
        if self._default_value is None or callable(self._default_value):
            return None
        return self.from_internal(self._default_value)

    @default_value.setter
    def default_value(self, new_value):
        if new_value is None or callable(new_value):
            self._default_value = new_value
            return
        if not self.validate(new_value):
            raise TypeError(
                "Value %s is not valid for field of type %s" % (new_value, self.name)
            )
        self._default_value = self.to_internal(new_value)

    size = property(attrgetter("_size"))

    @size.setter
    def size(self, new_size):
        if (isinstance(new_size, int) and new_size > 0) or callable(new_size):
            self._size = new_size
        else:
            raise TypeError("Given size %s is not a valid positive int" % new_size)

    def value2bin(self, value):
        return bin(value)[2:].zfill(self.size)

    def defaultvalue2bin(self):
        return self.value2bin(self.default_value)

    def value2hex(self, value):
        if value is None:
            value = 0
        return hex(value)[2:].zfill(int(math.ceil(self.size / 4.0)))

    def defaultvalue2hex(self):
        return self.value2hex(self.default_value)

    def post_build(self, pkt):
        """An option to perform some actions after the given packet is created.

        :param pkt: a packet object
        :type pkt: bf_pktpy.library.specs.packet.Packet
        """
        pass

    @abc.abstractmethod
    def from_internal(self, raw_value):
        """Returns value transformed from its raw representation (usually int).

        :param raw_value: internal representation of value of the field
        :type raw_value: Any
        :return: transformed value of the field in its normal representation
        :rtype: Any
        """
        return raw_value

    @abc.abstractmethod
    def to_internal(self, new_value):
        """Returns internal representation of value of the field (usually int).

        :param new_value: value of the field in its normal representation
        :type new_value: Any
        :return: internal representation of value of the field
        :rtype: Any
        """
        return int(new_value)

    @abc.abstractmethod
    def validate(self, new_value):
        """Validates new_value against rules defined in the field.

        :param new_value: value of the field in its normal representation
        :type new_value: Any
        :return: validation result
        :rtype: bool
        """
        return True
