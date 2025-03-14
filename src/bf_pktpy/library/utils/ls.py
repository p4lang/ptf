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
import six
import tabulate

from bf_pktpy.packets import Base, Packet


def ls(pkt=None):
    if pkt is None:
        _print_all_headers_info()
        return

    if not isinstance(pkt, Base):
        raise ValueError(
            "Given argument is not of neither Base nor Packet type: %s" % type(pkt)
        )

    lines_to_print = []
    current_layer = pkt
    while current_layer is not None:
        lines_to_print.append(
            "-- %s" % current_layer.name
            if hasattr(current_layer, "name")
            else "-- Payload"
        )
        if isinstance(current_layer, Packet):
            lines_to_print += _ls_packet(current_layer)
        elif isinstance(current_layer, Base):
            lines_to_print += _ls_base(current_layer)
        elif isinstance(
            current_layer, (six.string_types, six.text_type, six.binary_type)
        ):
            lines_to_print.append("load : %s" % current_layer)
        else:
            raise ValueError(
                "Given packet contains layer of invalid type: %s" % type(current_layer)
            )

        current_layer = current_layer.body if hasattr(current_layer, "body") else None

    for line in lines_to_print:
        print(line)


def _print_all_headers_info():
    all_modules = __recursive_subclass_lookup(Base)
    filtered_modules = [
        module for module in all_modules if not __module_in_blacklist(module)
    ]

    modules_for_print = [
        [module.__qualname__, module.name] for module in filtered_modules
    ]
    print(
        tabulate.tabulate(modules_for_print, headers=["class", "name"], tablefmt="psql")
    )


def __recursive_subclass_lookup(parent_module):
    my_headers = []
    for direct_subclass in parent_module.__subclasses__():
        my_headers.append(direct_subclass)
        my_headers.extend(__recursive_subclass_lookup(direct_subclass))

    return my_headers


def __module_in_blacklist(module_to_check):
    modules_blacklist = [
        "bf_pktpy.library.specs.packet",
        "bf_pktpy.library.specs.templates.ipoption",
        "bf_pktpy.library.specs.templates.raw",
        "bf_pktpy.library.specs.templates.tcpoption",
    ]
    return any(
        blacklisted_module in module_to_check.__module__
        for blacklisted_module in modules_blacklist
    )


def _ls_base(layer):
    # noinspection PyProtectedMember
    members = list(layer._members().values())[0]
    unzipped_members = list(zip(*members))
    name_offset, val_offset, size_offset = (
        max(len(str(item)) for item in field_type_tuple) + 1
        for field_type_tuple in unzipped_members
    )

    lines = []
    for name, value, size in members:
        lines.append(
            "%s%s: %d (bits)%s= %s"
            % (
                name,
                " " * (name_offset - len(name)),
                size,
                " " * (size_offset - len(str(size))),
                str(value),
            )
        )

    return lines


def _ls_packet(layer):
    members = [
        (
            field.name,
            type(field).__name__,
            field.size(layer) if callable(field.size) else field.size,
            getattr(layer, field.name),
            field.default_value(layer)
            if callable(field.default_value)
            else field.default_value,
        )
        for field in layer.fields_desc
    ]
    unzipped_members = list(zip(*members))
    name_offset, type_offset, size_offset, val_offset, _ = (
        max(len(str(item)) for item in field_type_tuple) + 1
        for field_type_tuple in unzipped_members
    )

    lines = []
    for name, type_name, size, value, default_value in members:
        lines.append(
            "%s%s: %s (%d bits)%s= %s%s (%s)"
            % (
                name,
                " " * (name_offset - len(name)),
                type_name,
                size,
                " " * (type_offset + size_offset - len(type_name) - len(str(size))),
                value,
                " " * (val_offset - len(str(value))),
                default_value,
            )
        )

    return lines
