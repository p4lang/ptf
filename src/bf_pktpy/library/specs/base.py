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
""" Base class """
import abc
import binascii
from collections import OrderedDict
import copy
from functools import wraps
import pprint
import six

from bf_pktpy.library.helpers.bin import to_bin
from bf_pktpy.library.specs.pretty import pretty, docnote, footnote, todict

# =============================================================================

_INSTANCES = {}


def singleton(cls):
    """Singleton"""

    @wraps(cls)
    def get_instance(*args, **kwargs):
        instance = _INSTANCES.get(cls, None)
        if not instance:
            instance = cls(*args, **kwargs)
            _INSTANCES[cls] = instance
        return instance

    return get_instance


def get_instance(child, parent, case=None):
    """Get acceptable value"""
    if child == case:
        return child
    if isinstance(child, dict):
        child = parent(**child)
    if not isinstance(child, parent):
        raise ValueError("Value must be an instance of " + parent.__name__)
    return child


def set_instance(this, value):
    """Set acceptable value"""
    if isinstance(value, dict):
        for key, val in value.items():
            if hasattr(this, key):
                setattr(this, key, val)
    else:
        raise ValueError("Unsupported value :", value)


class Base:
    """Base: foundation base class to inheritance"""

    _ETYPES = {
        "0800": "IPv4",
        "86dd": "IPv6",
        "8100": "Dot1Q",
        "0806": "ARP",
        "8035": "RARP",
        "8847": "MPLS Ucast",
        "8848": "MPLS Mcast",
        "88a8": "Dot1AD",
        "88CC": "LLDP",
        "9100": "Vlan Double tag",
        "8914": "FCoE",
    }
    name = "Base"

    def __init__(self, **kwargs):
        self._body = None
        self.sniffed_on = None  # interface name
        self._member_mask = None
        self.underlayer = None

        self._lock = {}  # lock mechanism

    def recalculate_hex(self):
        """
        Force a recalculation of hex
        :return: None
        """
        self.hex()

    @abc.abstractmethod
    def _members(self):
        return

    def __repr__(self):
        member_key = [x for x in self.members.keys()][0]
        payload = []
        if self._body is not None:
            payload.append(repr(self._body))
        return "<{}  {} |{}>".format(
            self.name,
            " ".join(["{}={}".format(x[0], x[1]) for x in self.members[member_key]]),
            " ".join(payload),
        )

    def __index__(self):
        return 0

    @staticmethod
    def _prepare_kwargs(kwargs):
        for k, v in six.iteritems(kwargs.copy()):
            if v is None:
                del kwargs[k]
            if isinstance(v, six.string_types):
                kwargs[k] = six.ensure_str(v)

    def _all_members(self):
        members = self.members
        inner = self.body
        while inner:
            if not isinstance(inner, Base):
                members.update({"packet_payload": inner})
                break
            name = next(member_name for member_name in inner.members.keys())
            if name in members:
                ct = sum([1 for each in members if name + "_" in each])
                new_name = name + "_" + str(ct + 1)
                new_inner = {new_name: inner.members.pop(name)}
                members.update(new_inner)
            else:
                members.update(inner.members)
            if not inner.body:
                break
            inner = inner.body
        return members

    def is_lock(self, key, default_value=None):
        return self._lock.get(key, default_value)

    def lock(self, key, value=True):
        self._lock[key] = value

    def lock_all(self):
        for k, _ in self._lock.items():
            self._lock[k] = True

    def unlock_all(self):
        for k, _ in self._lock.items():
            self._lock[k] = False

    def show(self):
        members = self._all_members()
        return pprint.pformat(todict(members), indent=4)

    def setfieldval(self, field_name, new_val):
        if not hasattr(self, field_name):
            raise ValueError("%s is not a field of %s" % (field_name, self.name))
        setattr(self, field_name, new_val)

    def __contains__(self, item):
        return self.get(item) is not False

    def __getitem__(self, key):
        # TODO This is hack for temporary work with bf-switch tests
        if key == "Ethernet":
            key = "Ether"
        current = self

        if isinstance(key, int):
            current = self.getlayer(key)
            if current is None:
                raise IndexError("Layer [%s] not found" % key)
            return current

        if isinstance(key, slice):
            name = key.start.__name__
            idx = key.stop
            count = 1
            while count <= idx:
                if current.name == name:
                    if count == idx:
                        return current
                    count += 1
                current = current.body
                if not hasattr(current, "name"):
                    break
            raise IndexError("Could not find header of type '%s' in frame" % key)

        if isinstance(key, type) and issubclass(key, Base):
            name = key.name
        elif isinstance(key, str):
            name = key
        else:
            name = key.__name__

        while current is not None:
            if current.name == name:
                return current
            current = current._body
            if not hasattr(current, "name"):
                break
        raise IndexError("Could not find header of type '%s' in frame" % key)

    def __str__(self):
        """ptf's bytes compatibility"""
        if six.PY2:
            return self.pack()
        return str(self.pack())

    def __bytes__(self):
        return self.pack()

    def __call__(self):
        return todict(self.members)

    def __div__(self, other):
        return self.__truediv__(other)

    def __truediv__(self, body):
        if isinstance(body, (Base, six.binary_type, six.string_types)):
            result = self.copy()
            body_copy = body.copy() if hasattr(body, "copy") else body
            result._add_layer(body_copy)
            result.post_build()
            return result
        else:
            raise ValueError("Unsupported value type: %s" % type(body))

    def __len__(self):
        """ptf's len compatibility"""
        return len(self.bin()) // 8

    def _add_layer(self, body_copy):
        if self.body is not None:
            self.body._add_layer(body_copy)
        else:
            if isinstance(body_copy, (six.binary_type, six.string_types)):
                self._body = self._create_raw_packet(six.ensure_binary(body_copy))
                if self.name == "IPv6ExtHdrRouting":
                    self.nh = 59
            elif body_copy.__class__.__name__ == "Raw":
                self._body = body_copy
            else:
                self._combine(body_copy)

            if self.body is not None:
                self.body.underlayer = self

    def _create_raw_packet(self, str_payload):
        import importlib

        mod = importlib.import_module("bf_pktpy.library.specs.templates.raw")
        raw_pkt_class = getattr(mod, "Raw")
        return raw_pkt_class(load=str_payload)

    def _combine(self, body_copy):
        """
        Method to overload by all child headers if specific bindings need to be
        defined
        """
        self._body = body_copy
        return self

    @staticmethod
    def calculate_hdr(members):
        """
        Calculate the header size, base on the information
        stored in the members
        """
        if members is None:
            return 0
        for _, member in members.items():
            return int(sum([field[2] for field in member]) / 8)

    @property
    def hdr_len(self):
        """
        Return information about header size, base on information
        stored at the members method
        """
        return self.calculate_hdr(self._members())

    @property
    def total_len(self):
        """
        Return a total length of frame from position on which
        is called to the end (all packets on the right)
        """
        if self._body is None:
            return self.hdr_len
        if isinstance(self._body, (six.binary_type, six.string_types)):
            return self.hdr_len + len(self._body)
        if hasattr(self._body, "total_len"):
            return self.hdr_len + self._body.total_len
        return self.hdr_len

    @property
    def payload(self):
        """
        Return a payload -- _body
        """
        return self._body

    @payload.setter
    def payload(self, value):
        """
        Try to set new value for payload
        """
        self._body = value

    @payload.deleter
    def payload(self):
        """
        Remove payload
        """
        self._body = None

    def remove_payload(self):
        self._body = None

    def get(self, layer, return_value=False):
        try:
            return self.__getitem__(layer)
        except IndexError:
            return return_value

    def get_last(self):
        """Return the last protocol on the stack"""
        current = self
        while current.body is not None and hasattr(current.body, "name"):
            current = current.body
        return current

    def getlayer(self, layer_number):
        if layer_number < 0:
            return None

        current = self
        i = 0
        while (
            current.body is not None
            and hasattr(current.body, "name")
            and layer_number > i
        ):
            i += 1
            current = current.body

        if layer_number > i:
            return None
        return current

    def haslayer(self, layer_name):
        if not isinstance(layer_name, str):
            layer_name = layer_name.__name__

        try:
            _ = self[layer_name]
            return True
        except IndexError:
            return False

    def args_details(self):
        members = self._members()
        det = []
        if members is None:
            return det

        # members should return only one child
        for x in list(members.values())[0]:
            det.append((x[0], x[2]))  # (name, width)
        return det

    def info(self, option="yaml"):
        """to yaml or json"""
        members = self._all_members()
        pretty(members, option)

    def bin(self, header=False, field=None, **fields_to_override):
        """To binary

        Args:
            header          (bool): convert header to bin only
            field            (str): field name
        Returns:
            str: string of binary
        Examples:
            | binary = self.bin()
            |
        """
        binary = ""

        _, props = tuple(six.iteritems(self._members(**fields_to_override)))[0]
        for name, value, size in props:
            if field and field == name:
                return to_bin(value, size)
            if self._member_mask and name not in self._member_mask:
                continue
            binary += to_bin(value, size)
        if not header:
            if hasattr(self._body, "bin"):
                self._body.post_build()
                binary += self._body.bin()
            elif (
                isinstance(self._body, (six.binary_type, six.string_types))
                and self._body
            ):
                encoded_body = six.ensure_binary(self._body)
                hex_body = binascii.hexlify(encoded_body)
                binary += bin(int(hex_body, 16))[2:].zfill(4 * len(hex_body))
            elif isinstance(self._body, int):
                binary += bin(self._body)[2:]
        return binary

    def hex(self, field=None, whitespace=True):
        """
        To hex
        :param field:
        :param whitespace: "00 00" if whitespace else "0000"
        :return: string of hex
        """
        binary = self.bin(field)
        offset = 0
        hexa = ""
        while offset + 8 <= len(binary):
            bits = binary[offset : offset + 8]
            hexa += hex(int(bits, 2))[2:].rjust(2, "0") + " "
            offset += 8
        if whitespace:
            return hexa.rstrip()
        return "".join(hexa.rstrip().split())

    def pack(self):
        """Hex to bin"""
        hexa = self.hex().replace(" ", "")
        return binascii.unhexlify(hexa)

    def build(self):
        """alias for "pack" for compatibility with Scapy

        Does exactly the same as `bytes(pkt)`
        """
        return self.pack()

    @property
    def body(self):
        return self._body

    def copy(self):
        """ptf's packet.copy() compatibility"""
        return copy.deepcopy(self)

    @property
    def members(self):
        """Get members"""
        data = OrderedDict()
        _members = self._members()
        if _members:
            member, props = tuple(_members.items())[0]
            temp = OrderedDict()
            for each in props:
                if len(each) == 3:
                    key, value, _ = each
                    if self._member_mask and key not in self._member_mask:
                        continue
                    temp.update({key: value})
                    continue
                if isinstance(each, dict):
                    for group in tuple(each.items()):
                        if len(group) == 2:
                            key, value = group
                            if self._member_mask and key not in self._member_mask:
                                continue
                            temp.update({key: value})
            data[member] = tuple(temp.items())
        return data

    def load_hex(self, value):
        """
        Load hex into packet structure.

        pkt = Ether() / IP() / TCP()
        new_packet = pkt.load_bytes(bytes(pkt)
        :param value: bytes array
        :return: New Packet (Base) Object
        """
        return self.load_bytes(binascii.unhexlify(value.replace(" ", "")))

    def load_bytes(self, value):
        """
        Load bytes into packet structure.

        pkt = Ether() / IP() / TCP()
        new_packet = pkt.load_bytes(bytes(pkt)
        :param value: bytes array
        :return: New Packet (Base) Object
        """

        def create_structure():
            potential_packet_list = []
            current = self
            while current is not None:
                potential_packet_list.append(
                    (current.name, next(x for x in current._members().values()))
                )
                current = current._body
                if not hasattr(current, "name"):
                    break

            packets_list = []
            for key_member, value_member in potential_packet_list:
                temp_ordered_dict = OrderedDict()
                for element in value_member:
                    # element[0] packet argument, element[2] arg len in B
                    temp_ordered_dict[element[0]] = element[2]
                packets_list.append((key_member, temp_ordered_dict))
            return packets_list

        def bitstring_to_bytes(bit_string):
            return int(bit_string, 2).to_bytes(len(bit_string) // 8, byteorder="big")

        def combine(structure):
            from importlib import import_module

            last = 0
            packet = None

            for packet_class, members in structure:
                if last >= len(value):
                    break
                member_mask = set()
                packet_template = import_module("bf_pktpy.packets").__getattribute__(
                    packet_class
                )
                kwargs = {}
                for arg_name, arg_len in members.items():
                    bin_value = value[last : last + arg_len]
                    if len(bin_value) != arg_len and packet_class != "Raw":
                        last = len(value)
                        break
                    if packet_class == "Raw":
                        payload_bit_strs = [
                            bin_value[i : i + 8] for i in range(0, len(bin_value), 8)
                        ]
                        kwargs[arg_name] = b"".join(
                            bitstring_to_bytes(bit_str) for bit_str in payload_bit_strs
                        )
                    else:
                        kwargs[arg_name] = int(value[last : last + arg_len], 2)
                    member_mask.add(arg_name)
                    last += arg_len
                if not packet:
                    packet = packet_template(**kwargs)
                    packet._member_mask = member_mask
                    continue
                part = packet_template(**kwargs)
                part._member_mask = member_mask
                part.lock_all()
                packet = packet / part
            if last < len(value):
                remainder = value[last:]
                payload_bytes = binascii.unhexlify(
                    "".join(
                        "%02x" % int(remainder[i : i + 8], 2)
                        for i in range(0, len(remainder), 8)
                    )
                )
                packet = packet / payload_bytes
            packet.lock_all()
            return packet

        if not value:
            return self.copy()

        if six.PY2:
            value = "".join(format(ord(byte), "08b") for byte in value)
        else:
            value = "".join(format(byte, "08b") for byte in value)

        return combine(create_structure())

    @property
    def parameters(self):
        """Get parameters"""
        params = {}
        if self._members():
            _, props = tuple(self._members().items())[0]
            for each in props:
                if len(each) == 3:
                    key, value, _ = each
                    if self.name == "Ether":
                        if key in ("src", "dst"):
                            mac = hex(value)[2:].rjust(12, "0")
                            mac = [mac[i : i + 2] for i in range(0, 12, 2)]
                            value = ":".join(mac)
                    if self.name == "IP":
                        if key in ("src", "dst"):
                            addr = hex(value)[2:].rjust(8, "0")
                            addr = [
                                str(int(addr[x : x + 2], 16)) for x in range(0, 8, 2)
                            ]
                            value = ".".join(addr)
                    params.update({key: value})
        return params

    def post_build(self):
        self._post_build()
        if self.body is not None and isinstance(self.body, Base):
            self.body.post_build()

    def _post_build(self):
        """Dummy def for signaling a place for all actions
        which need to be done before sending a packet"""
        pass

    @classmethod
    def help(cls):
        """Helper method to provide additional help info"""
        docnote(cls.__doc__)
        instances, name, lookfor = {}, "", ""
        for line in cls.__doc__.split("\n"):
            if name in instances and not instances[name]:
                if lookfor in line:
                    for word in line.split():
                        if word.endswith(lookfor):
                            instances[name] = word
        footnote(instances)


# =============================================================================
