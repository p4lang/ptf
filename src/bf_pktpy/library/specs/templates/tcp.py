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
""" TCP template """
import math

from bf_pktpy.library.specs.base import Base
from bf_pktpy.library.specs.templates.tcpoption import TCPOptionPlaceholder

# =============================================================================
from bf_pktpy.library.specs.validate_sport_dport import ValidateSportDport


class TCP(Base, ValidateSportDport):
    """TCP class

    Definition:
        TCP
            sport                        (int)
            dport                        (int)
            seq                          (int)
            ack                          (int)
            dataofs                      (int)
            reserved                     (int)
            flags                        (int)
            window                       (int)
            chksum                       (int)
            urgptr                       (int)
            options                      (str)

        Examples:
            | + create
            |     tcp = TCP(sport=.., dport=.., )
            | + make change
            |     tcp.sport = <value>
            |     tcp.dport = <value>
            |     ...
            |
    """

    name = "TCP"

    _sport = 0
    _dport = 0
    _chksum = 0

    def __init__(self, **kwargs):
        Base._prepare_kwargs(kwargs)
        self.flags_field(kwargs)

        super(TCP, self).__init__()
        self.sport = kwargs.pop("sport", 20)
        self.dport = kwargs.pop("dport", 80)
        self.seq = kwargs.pop("seq", 0)
        self.ack = kwargs.pop("ack", 0)
        self.dataofs = kwargs.pop("dataofs", 0)
        self.reserved = kwargs.pop("reserved", 0)
        self.flags = kwargs.pop("flags", 2)
        self.window = kwargs.pop("window", 8192)
        self._chksum = 0
        if "chksum" in kwargs:
            self.chksum = kwargs.pop("chksum")
        self.urgptr = kwargs.pop("urgptr", 0)
        self.options = self._fix_options(kwargs.pop("options", ""))
        if kwargs:
            raise ValueError("Unsupported key(s) %s" % list(kwargs.keys()))

    def flags_field(self, kwargs):
        potential_f = kwargs.get("flags", None)
        if potential_f:
            flags = "FSRPAUECN"
            num = 0
            if isinstance(potential_f, int):
                kwargs["flags"] = potential_f
                return
            for f in potential_f:
                num += int(math.pow(2, flags.find(f))) if flags.index(f) >= 0 else 0
            kwargs["flags"] = num

    @property
    def hdr_len(self):
        """Get header length"""
        if not self.options:
            return 20
        return 20 + len(self.options.b)

    @property
    def total_len(self):
        """Get full length"""
        if self._body:
            return self.hdr_len + len(self._body)
        return self.hdr_len

    @property
    def chksum(self):
        return self._chksum

    @chksum.setter
    def chksum(self, custom_chksum):
        self.lock("chksum")
        self._chksum = custom_chksum

    def reset_chksum(self):
        self.lock("chksum", False)
        self._chksum = 0

    @staticmethod
    def from_hex(hex_str):
        """Create object from hex value"""
        sport = int(hex_str[0:4], 16)
        dport = int(hex_str[4:8], 16)
        seq = int(hex_str[8:16], 16)
        ack = int(hex_str[16:24], 16)
        dataofs = int(hex_str[24:25], 16)
        reserved = int(hex_str[25:26], 16) >> 1
        flags = int(hex_str[25:26], 16) % 2 * 512 + int(hex_str[26:28], 16)
        window = int(hex_str[28:32], 16)
        chksum = int(hex_str[32:36], 16)
        urgptr = int(hex_str[36:40], 16)
        opt_ = hex_str[40:]
        options = ""
        if opt_:
            options = ""
            for idx in range(len(opt_)):
                temp = bin(int(opt_[idx], 16))
                options += temp[2:]
            if options:
                pad = (32 - len(options) % 32) * "0"
                options += pad
        kwargs = {
            "sport": sport,
            "dport": dport,
            "seq": seq,
            "ack": ack,
            "dataofs": dataofs,
            "reserved": reserved,
            "flags": flags,
            "window": window,
            "chksum": chksum,
            "urgptr": urgptr,
            "options": options,
        }
        return TCP(**kwargs)

    def _members(self):
        """Member information"""
        dataofs = self.hdr_len // 4

        if self.options:
            opt = self.options.b
            members = (
                ("sport", self.sport, 16),
                ("dport", self.dport, 16),
                ("seq", self.seq, 32),
                ("ack", self.ack, 32),
                ("dataofs", dataofs, 4),
                ("reserved", self.reserved, 3),
                ("flags", self.flags, 9),
                ("window", self.window, 16),
                ("chksum", self.chksum, 16),
                ("urgptr", self.urgptr, 16),
                ("options", int(opt.encode("hex"), 16), len(opt) * 8),
            )
        else:
            members = (
                ("sport", self.sport, 16),
                ("dport", self.dport, 16),
                ("seq", self.seq, 32),
                ("ack", self.ack, 32),
                ("dataofs", dataofs, 4),
                ("reserved", self.reserved, 3),
                ("flags", self.flags, 9),
                ("window", self.window, 16),
                ("chksum", self.chksum, 16),
                ("urgptr", self.urgptr, 16),
            )
        return {"tcp": members}

    def _fix_options(self, options):
        if not options:
            return ""
        if isinstance(options, TCPOptionPlaceholder):
            return options
        if isinstance(options, list):
            op_bytes = b""
            for opt in options:
                op_bytes += opt.b if isinstance(opt, TCPOptionPlaceholder) else opt
            return TCPOptionPlaceholder(op_bytes)
        return TCPOptionPlaceholder(options)


# =============================================================================
