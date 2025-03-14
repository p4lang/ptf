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
""" Packet class """
import six
import warnings

from bf_pktpy.library.specs.base import Base


class Packet(Base):
    """Packet class which holds validation fields logic.

    In order to use it one needs to define headers like this:

    class MyPacket(Packet):
        name = "MyCustomPacket"\n
        fields_desc = [
            MyField("test", 0, size=24),\n
            StrField("foo", "bar")
        ]

    Then, Packet will take care of creating fields according to this definition, handle
    value transformations (external <-> internal) and validation (defined in the
    field class).
    """

    name = ""
    fields_desc = []

    # TODO(sborkows): raw_pkt is ATM experimental, only for a specific path in PTF
    def __init__(self, raw_pkt=None, **fields):
        super(Packet, self).__init__()
        # Dynamic creation of fields based on fields_desc definition
        for field_def in self.fields_desc:
            object.__setattr__(self, field_def.name, None)

        if raw_pkt is not None:
            warnings.warn(
                "raw_pkt is experimental, it is only needed for specific "
                "path in PTF, ATM we recommend not to use it"
            )
            pkt = self.load_bytes(raw_pkt)
            for field_def in self.fields_desc:
                setattr(self, field_def.name, pkt.internal_value(field_def.name))
            return

        Base._prepare_kwargs(fields)
        for field, value in six.iteritems(fields):
            setattr(self, field, value)

        # Perform post-build on fields:
        for field_def in self.fields_desc:
            field_def.post_build(self)

    def internal_value(self, field_name, default_if_none=False):
        # NOTE(sborkows): in order to get raw (internal) value of field, we need
        # to surpass __getattribute__ of the Packet class
        val = object.__getattribute__(self, field_name)
        if val is None and default_if_none:
            field_def = self._fields_desc_lookup(field_name)
            # noinspection PyProtectedMember
            val = (
                field_def._default_value(self)
                if callable(field_def._default_value)
                else field_def._default_value
            )
        return val

    def _cond_field_condition(self, field):
        return field.__class__.__name__ != "ConditionalField" or bool(
            field.condition(self)
        )

    def _members(self, default_if_none=True, **fields_to_override):
        members = {self.name: []}
        for field in self.fields_desc:
            value = None
            if field.name in fields_to_override:
                value = fields_to_override[field.name]
            elif self._cond_field_condition(field):
                value = self.internal_value(field.name, default_if_none=default_if_none)

            if value is None:
                continue

            # for IPOptions and TCPOptions
            if isinstance(value, list):
                value = b"".join(value)
                padding = len(value) % 4
                if padding != 0:
                    value += b"\x00" * (4 - padding)

            size = field.size(value) if callable(field.size) else field.size
            if size == 0:
                continue
            members[self.name].append((field.name, value, size))
        return members

    def _fields_desc_lookup(self, field_name):
        return next(
            field
            for field in object.__getattribute__(self, "fields_desc")
            if field.name == str(field_name)
        )

    @property
    def hdr_len(self):
        return (
            sum(
                (
                    field.size(getattr(self, field.name))
                    if callable(field.size)
                    else field.size
                )
                for field in self.fields_desc
                if self._cond_field_condition(field)
            )
            // 8
        )

    def __getattribute__(self, item):
        """Besides normal functionality, lookups `field_desc` in order to find a
        defined field. If found, returns transformed value (from the internal one).
        """
        value = object.__getattribute__(self, str(item))
        if callable(value):
            return value
        try:
            field_def = self._fields_desc_lookup(item)
            if value is None:
                return field_def.default_value
            return field_def.from_internal(value)
        except StopIteration:
            return value

    def __setattr__(self, key, value):
        """Besides normal functionality, lookups `field_desc` in order to find a
        defined field. If found, validates new value and if it's ok, transform it to
        an internal representation (usually int).
        """
        try:
            field_def = self._fields_desc_lookup(key)
        except StopIteration:
            object.__setattr__(self, key, value)
            return

        if value is None:
            object.__setattr__(self, field_def.name, value)
        elif field_def.validate(value):
            object.__setattr__(self, field_def.name, field_def.to_internal(value))
            return
        else:
            raise ValueError(
                "Value %s is not valid for field of type %s"
                % (repr(value), type(field_def).__name__)
            )

    def __repr__(self):
        members = [
            (field.name, getattr(self, field.name))
            for field in self.fields_desc
            if self._cond_field_condition(field)
        ]
        payload = []
        if self._body is not None:
            payload.append(repr(self._body))
        return "<{}  {} |{}>".format(
            self.name,
            " ".join(["{}={}".format(x[0], x[1]) for x in members if x[1] is not None]),
            " ".join(payload),
        )

    def show(self, indent_lvl=3):
        indent = " " * 2
        output_str = ""
        inner = self
        while inner:
            if not isinstance(inner, Base):
                output_str += "###[ Raw ]###\n"
                output_str += "{}payload= {}\n".format(indent, str(inner))
                break

            try:
                members = [
                    (field.name, getattr(inner, field.name))
                    for field in inner.fields_desc
                    if inner._cond_field_condition(field)
                ]
            except AttributeError:
                names = next(six.itervalues(inner._all_members()))
                members = [(name[0], getattr(inner, name[0])) for name in names]
            output_str += "###[ {} ]###\n{}".format(
                inner.name,
                "".join(["{}{:10s}= {}\n".format(indent, x[0], x[1]) for x in members]),
            )
            indent += " " * indent_lvl
            inner = inner.body
        print(output_str)

    def show2(self, indent_lvl=3):
        inner = self
        indent = " " * 2
        output_str = ""
        while inner:
            if not isinstance(inner, Base):
                output_str += "###[ Raw ]###\n"
                output_str += "{}payload= {}\n".format(indent, str(inner))
                break

            members = list(inner.members.values())[0]
            output_str += "###[ {} ]###\n".format(inner.name)
            for name in members:
                try:
                    field = inner._fields_desc_lookup(name[0])
                    field_value = getattr(inner, field.name)
                    if field_value is None and callable(field._default_value):
                        field_value = field._default_value(inner)
                    output_str += "{}{:10s}= {}\n".format(
                        indent, field.name, field_value
                    )
                except AttributeError:
                    output_str += "{}{:10s}= {}\n".format(indent, name[0], name[1])
            indent += " " * indent_lvl
            inner = inner.body
        print(output_str)
