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
""" Pretty module to transform code output """
import json
import re
import six
import types


# =============================================================================
def todict(data):
    """convert object structure to dictionary"""
    if isinstance(data, dict):
        new_dict = {}
        for key, value in data.items():
            new_dict[key] = todict(value)
        return new_dict
    if isinstance(data, tuple):
        new_dict = {}
        if len(data) == 2:
            if isinstance(
                data[0], (six.string_types, six.binary_type, six.integer_types)
            ):
                if (
                    isinstance(
                        data[1], (six.string_types, six.binary_type, six.integer_types)
                    )
                    or isinstance(data[1], (list, tuple))
                    and not data[1]
                ):
                    new_dict = {data[0]: data[1]}
                elif isinstance(data[1], (list, tuple)) and data[1]:
                    if isinstance(
                        data[1][0],
                        (six.string_types, six.binary_type, six.integer_types),
                    ):
                        new_dict = {data[0]: data[1]}
                    elif isinstance(data[1][0], (tuple)):
                        new_dict = {data[0]: todict(data[1])}
                if new_dict:
                    return new_dict
        for each in data:
            new_dict.update(todict(each))
        return new_dict
    if isinstance(data, list):
        new_list = []
        for each in data:
            new_list.append(todict(each))
        return new_list
    return data


def _print(ftype, indent=0, key="", data="", is_dash=False, constant=False):
    """Standard out"""

    def protect(data, strip=False):
        """Protect key from misread"""
        if not strip:
            data = list(data)
            data[1:1] = "__"
            return "".join(data)
        return re.sub("__", "", data)

    spaces = " " * indent
    if ftype == "yaml":
        spaces = spaces + "- " if is_dash else spaces
        if constant:
            print(spaces + str(key))
        else:
            line = spaces + str(key) + ": " + str(data)
            if isinstance(data, str) and data.isdigit():
                line = line.ljust(40) + "0x" + str(hex(int(data)))[2:].upper()
            print(line)
    if ftype == "json":
        for ikey in sorted(re.findall(r"\"(\S+)\":", data), key=len, reverse=True):
            pkey = protect(ikey)
            data = re.sub('"' + ikey + '"', '"' + pkey + '"', data)
        for ikey in sorted(re.findall(r":\s*\"(\S+)\"", data), key=len, reverse=True):
            if not re.findall(r"[*\/_]", ikey):
                data = re.sub('"' + ikey + '"', '"' + ikey + '"', data)
        data = protect(data, strip=True)
        print(data)


def pretty(obj, style="yaml"):
    """Pretty print obj structure"""

    def maxlength(obj):
        """Find max key length"""
        size = 0
        for each in obj:
            if isinstance(each, tuple) and size < len(each[0]):
                size = len(each[0])
        return size

    def printline(indent, key, value, is_dash=False):
        if isinstance(value, (six.string_types, six.binary_type, six.integer_types)):
            _print("yaml", indent, key, str(value), is_dash)
        else:
            _print("yaml", indent, key, is_dash=is_dash)
            align(value, indent + 4)

    def align(obj, indent=0):
        """Recursively align and print"""
        if isinstance(obj, dict):
            if len(obj) == 1:
                key, value = next(iter(obj.items()))
                printline(indent, key, value, False)
            else:
                for key, value in obj.items():
                    align({key: value}, indent)
        if isinstance(obj, list):
            key_length = maxlength(obj)
            in_loop = False
            for each in obj:
                if not in_loop:
                    is_first = True
                if indent == 0 and isinstance(each, tuple):
                    key, value = each[0].ljust(key_length), each[1]
                    _print("yaml", 0, key, value)
                elif isinstance(each, tuple):
                    if len(each) == 2:
                        if isinstance(
                            each[0], (six.binary_type, six.string_types)
                        ) and isinstance(each[1], (six.binary_type, six.string_types)):
                            if is_first:
                                printline(indent - 2, each[0], each[1], True)
                                is_first, in_loop = False, True
                            else:
                                printline(indent, each[0], each[1])
                    elif len(each) > 1:
                        for item in each:
                            key, value = item[0].ljust(key_length), item[1]
                            if is_first:
                                printline(indent - 2, key, value, True)
                                is_first = False
                            else:
                                printline(indent, key, value)
                    else:
                        key, value = each[0].ljust(key_length), each[1]
                        if is_first:
                            printline(indent - 2, key, value, True)
                            is_first = False
                        else:
                            printline(indent, key, value)
                elif isinstance(each, dict):
                    for key, value in each.items():
                        if is_first:
                            printline(indent - 2, key, value, True)
                            is_first = False
                        else:
                            align({key: value}, indent)
                elif isinstance(
                    each, (six.binary_type, six.string_types, six.integer_types)
                ):
                    _print("yaml", indent - 2, each, is_dash=True, constant=True)
                else:
                    align(each, indent)
        if isinstance(obj, tuple):
            if len(obj) == 2 and isinstance(
                obj[0], (six.binary_type, six.string_types)
            ):
                key, value = obj
                printline(indent, key, value, False)
            else:
                key_length = maxlength(obj)
                for each in obj:
                    if isinstance(each, tuple):
                        key, value = each[0].ljust(key_length), each[1]
                        printline(indent, key, value, False)
                    else:
                        align(each, indent)

    def transform(data, style="yaml"):
        """Prettify object"""
        if style == "yaml":
            align(data)
        else:
            _print("json", data=json.dumps(todict(data), indent=4))

    def callf(*args, **kwargs):
        """Transform obj into yaml or json output"""
        style = "yaml"
        if len(args) >= 2:
            if args[1] in "yaml json".split():
                style = args[1]
        data = obj(*args, **kwargs)
        transform(data, style, **kwargs)

    # Use as decorator
    if isinstance(obj, types.FunctionType):
        return callf

    # Use as function
    if style in "yaml json".split():
        return transform(obj, style)
    raise ValueError("Only supports json and yaml output format")


def _print_line(lline, wcount):
    for each in lline:
        print(each, "")
    print(" " * (81 - wcount))


def docnote(doc):
    """Pretty print class __doc__"""
    is_header = True

    print()
    for line in doc.split("\n"):
        line = line.rstrip()
        newline = []
        # if not len(line.split()):
        #     is_header = False
        if is_header:
            _print_line([line], len(line))
            is_header = False
            continue
        if len(line.split()) == 1:
            word = line.split()[0]
            if word.lower() in "usage: or definition: example: note:":
                _print_line([line], len(line))
                continue
        if "(optional)" in line:
            temp = re.sub("optional", "|", line)
            left, right = temp.split("|", 1)
            newline.extend([left, "optional", right])
        if "(required)" in line:
            temp = re.sub("required", "|", line)
            left, right = temp.split("|", 1)
            newline.extend([left, "required", right])

        if re.findall(r"=\s+[A-Za-z]", line) or re.findall(r"=\s+\W+[A-Za-z]", line):
            left, right = line.split("=", 1)
            newline.extend([left, "="])
            if "(" in right:
                cls, rest = right.split("(", 1)
                newline.extend([cls, "(" + rest])
            elif "{" in right:
                cls, rest = right.split("{", 1)
                newline.extend([cls, "{" + rest])
            else:
                newline.append(right)

        if not newline:
            newline.append(line)

        _print_line(newline, len(line))


def footnote(instances):
    """Pretty print additional help"""
    if instances:
        _print_line(["-" * 87], 81)
        line = (" This class contains one or more objects. To learn" " about:").ljust(
            87
        )
        _print_line([line], len(line))
        new_dict = {}
        # reverse key-value for sorting
        for name, parent in instances.items():
            if not parent:
                parent = name.title()
            new_dict[parent] = name
        # print helper
        for parent in sorted(new_dict):
            helper = parent + ".help()"
            newline = []
            newline.append("      _ ")
            newline.append(new_dict[parent])
            newline.append(", type ")
            newline.append(helper)
            _print_line(newline, len(new_dict[parent]) + len(helper) + 9)

    extra = []
    extra.append(["-" * 87])
    extra.append([" For quick helps, use".ljust(87)])
    extra.append(["      _ <object>.help()".ljust(87)])
    extra.append(
        [
            (
                "      _ <object>.info(), info() takes optional parameter "
                '"json" or "yaml"'
            ).ljust(87)
        ]
    )
    extra.append(["-" * 87])
    for each in extra:
        _print_line(each, 81)
    print()


# =============================================================================
