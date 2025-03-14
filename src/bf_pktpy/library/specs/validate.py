#!/usr/bin/env python


# Copyright (c) 2021 Intel Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

###############################################################################
""" Enforce module to validate instance variables """
import ipaddress
import re
import six

from bf_pktpy.library.specs.constant import MAC_PATTERN


# =============================================================================
def is_hex(value):
    """Check if value is hex"""
    try:
        int(str(value), 16)
        return True
    except ValueError:
        return False


def remove_unicode(value):
    """
    Remove unicode and return a unicode-free string
    :param value: string or unicode string
    :return: unicode-free string
    """

    #  TODO temporary fix for compatibility
    if isinstance(value, six.string_types):
        return six.ensure_str(value)
    return value


class ToBeOneOfThese:
    """Descriptor to validate supported value"""

    def __init__(self, itemlist, default=None):
        self.default = default
        self.itemlist = [each for each in itemlist]
        self.data = {}

    def __get__(self, instance, owner):
        return self.data.get(instance, self.default)

    def __set__(self, instance, value):
        if isinstance(value, str) and not value:
            self.data[instance] = ""
            return
        if value not in self.itemlist:
            print("-ERROR- Value %r is not supported" % value)
            return
        self.data[instance] = value


class ToBeIntegerInRange:
    """Descriptor to validate in-range value"""

    def __init__(self, min_val, max_val, default=0):
        self.default = default
        self.min_val = min_val
        self.max_val = max_val
        self.data = {}

    def __get__(self, instance, owner):
        return self.data.get(instance, self.default)

    def __set__(self, instance, value):
        if isinstance(value, int):
            if self.min_val <= value <= self.max_val:
                self.data[instance] = value
                return
        print("-ERROR- Value must be between %d and %d" % (self.min_val, self.max_val))


class ToBeBitField(ToBeIntegerInRange):
    def __init__(self, bit_count, default=0):
        ToBeIntegerInRange.__init__(self, 0, 2**bit_count - 1, default)


class ToBeByteField(ToBeBitField):
    def __init__(self, default=0):
        ToBeBitField.__init__(self, 8, default)


class ToBeShortField(ToBeBitField):
    def __init__(self, default=0):
        ToBeBitField.__init__(self, 16, default)


class ToBeIntegerField(ToBeBitField):
    def __init__(self, default=0):
        ToBeBitField.__init__(self, 32, default)


class ToBeLongField(ToBeBitField):
    def __init__(self, default=0):
        ToBeBitField.__init__(self, 64, default)


class ToBeStringInRange:
    """Descriptor to validate in-range value"""

    def __init__(self, min_val, max_val, default=0):
        self.default = default
        self.min_val = min_val
        self.max_val = max_val
        self.data = {}

    def __get__(self, instance, owner):
        return self.data.get(instance, self.default)

    def __set__(self, instance, value):
        if isinstance(value, str) and not value:
            self.data[instance] = ""
            return
        if isinstance(value, (int, str)):
            try:
                int(str(value), 16)
                if self.min_val <= eval(str(value)) <= self.max_val:
                    self.data[instance] = str(eval(str(value)))
                    return
            except ValueError:
                pass
        print("-ERROR- Value must be between %d and %d" % (self.min_val, self.max_val))


class ToBeListOfIntegerInRange:
    """Descriptor to validate in-range value"""

    def __init__(self, min_val, max_val, default=None):
        self.default = default or [64]
        self.min_val = min_val
        self.max_val = max_val
        self.data = {}

    def __get__(self, instance, owner):
        return self.data.get(instance, self.default)

    def __set__(self, instance, values):
        if isinstance(values, (tuple, list)):
            for value in values:
                if not isinstance(value, int):
                    print("-ERROR- Value must be integer")
                    return
                if not self.min_val <= value <= self.max_val:
                    print(
                        "-ERROR- Value must be between %d and %d"
                        % (self.min_val, self.max_val)
                    )
                    return
                self.data[instance] = values
            return
        print("-ERROR- Value must be of type 'list'")


class ToBeNonEmptyString:
    """Descriptor to validate non-empty value"""

    def __init__(self, default=""):
        self.default = default
        self.data = {}

    def __get__(self, instance, owner):
        return self.data.get(instance, self.default)

    def __set__(self, instance, value):
        if isinstance(value, str):
            if value:
                self.data[instance] = value
                return
        print("-ERROR- Value cannot be an empty string")


class ToBeBinaryString:
    """Descriptor to validate binary string value"""

    def __init__(self, default=""):
        self.default = default
        self.data = {}

    def __get__(self, instance, owner):
        return self.data.get(instance, self.default)

    def __set__(self, instance, value):
        if isinstance(value, str):
            if value:
                temp = value.replace("0", "").replace("1", "")
                if len(temp):
                    print("-ERROR- Value must be in binary format")
                    return
                self.data[instance] = value
                return
            else:
                self.data[instance] = ""
                return
        print("-ERROR- Value cannot be an empty string")


class ToBeValidMacAddress:
    """Descriptor to validate a valid mac address"""

    def __init__(self, default="00:00:00:00:00:00"):
        self.default = default
        self.check_mac = re.compile(MAC_PATTERN, re.I)
        self.data = {}

    def __get__(self, instance, owner):
        return self.data.get(instance, self.default)

    def __set__(self, instance, value):
        #  TODO temporary fix for compatibility
        if type(value).__name__ in ("int", "long"):
            hex_bytes = [
                "{}{}".format(a, b)
                for a, b in zip(*[iter("{:012x}".format(value))] * 2)
            ]
            self.data[instance] = ":".join(hex_bytes)
            return

        if isinstance(value, str) and not value:
            self.data[instance] = self.default
            return
        if "-" in value:
            value = value.replace("-", ":")
        elif is_hex(value) and len(value) == 14:
            value = value[2:]
            value = ":".join(["%s" % (value[i : i + 2]) for i in range(0, 12, 2)])
        elif re.findall(r"[\._-]", value):
            value = re.sub(r"[\._-]", "", value)
            value = ":".join(["%s" % (value[i : i + 2]) for i in range(0, 12, 2)])
        if not self.check_mac.match(value):
            print("-ERROR- Mac address is not valid")
            return
        self.data[instance] = value.upper()


class ToBeValidIPv4Address:
    """Descriptor to validate a valid ip address"""

    def __init__(self, default="0.0.0.0"):
        self.default = default
        self.data = {}

    def __get__(self, instance, owner):
        return self.data.get(instance, self.default)

    def __set__(self, instance, value):
        if isinstance(value, str) and not value:
            self.data[instance] = self.default
            return
        if isinstance(value, (int, str)):
            try:
                value = str(ipaddress.IPv4Address(value))
                self.data[instance] = value
                return
            except ValueError:
                if is_hex(value) and (0 <= eval(str(value)) < pow(2, 32)):
                    self.data[instance] = str(eval(str(value)))
                    return
        print("-ERROR- Value must be a valid IPv4 Address")


class ToBeValidIPv6Address:
    """Descriptor to validate a valid ipv6 address"""

    def __init__(self, default=""):
        self.default = default
        self.data = {}

    def __get__(self, instance, owner):
        return self.data.get(instance, self.default)

    def __set__(self, instance, value):
        if isinstance(value, str) and not value:
            self.data[instance] = ""
            return
        if isinstance(value, (int, str)):
            try:
                ipaddress.IPv6Address(value)
                self.data[instance] = value
                return
            except ValueError:
                if is_hex(value) and (0 <= eval(str(value)) < pow(2, 128)):
                    self.data[instance] = hex(eval(str(value)))
                    return
        print("-ERROR- Value must be a valid IPv6 Address")


class ToBeValidListOfIPv6Addresses:
    """Descriptor to validate a list of valid ipv6 addresses"""

    def __init__(self, default=None):
        self.default = default or []
        self.data = {}

    def __get__(self, instance, owner):
        return self.data.get(instance, self.default)

    def __set__(self, instance, values):
        if isinstance(values, (tuple, list)):
            for i in range(len(values)):
                value = values[i]
                if isinstance(value, str) and not value:
                    print("-ERROR- Each value in list must be str or int")
                    return
                if isinstance(value, (int, str)):
                    try:
                        ipaddress.IPv6Address(value)
                    except ValueError:
                        if is_hex(value) and (0 <= eval(str(value)) < pow(2, 128)):
                            values[i] = hex(eval(str(value)))
                            continue
                        print("-ERROR- Value from list must be a valid IPv6 " "address")
                        return
            self.data[instance] = values
            return
        print("-ERROR- Value must be of type 'list'")


# =============================================================================
