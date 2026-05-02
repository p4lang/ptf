#!/usr/bin/env python


# Copyright (c) 2021 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

###############################################################################
"""ICMP template"""

from bf_pktpy.library.specs.base import Base


# =============================================================================
class ICMP(Base):
    """ICMP class

    ICMP
        type                    (int)
        code                    (int)
        chksum                  (int)
        id                      (int)
        seq                     (int)

    Examples:
        | + create
        |     icmp = ICMP(type=.., code=.., ..)
        | + make change
        |     icmp.type = <value>
        |     icmp.code = <value>
        |     icmp.chksum = <value>
        |     icmp.id = <value>
        |     icmp.seq = <value>
    """

    name = "ICMP"

    def __init__(self, **kwargs):
        Base._prepare_kwargs(kwargs)

        super(ICMP, self).__init__()
        self.type = kwargs.pop("type", 8)
        self.code = kwargs.pop("code", 0)
        self.chksum = kwargs.pop("chksum", 0)
        self.id = kwargs.pop("id", 0)
        self.seq = kwargs.pop("seq", 0)
        if kwargs:
            raise ValueError("Unsupported key(s) %s" % list(kwargs.keys()))

    @property
    def hdr_len(self):
        """Get header length"""
        return 8

    @property
    def total_len(self):
        """Get full length"""
        if self._body:
            return self.hdr_len + len(self._body)
        return self.hdr_len

    @staticmethod
    def from_hex(hex_str):
        """Create object from hex value"""
        type_ = int(hex_str[:2], 16)
        code = int(hex_str[2:4], 16)
        chksum = int(hex_str[4:8], 16)
        id_ = int(hex_str[8:12], 16)
        seq = int(hex_str[12:16], 16)
        kwargs = {"type": type_, "code": code, "chksum": chksum, "id": id_, "seq": seq}
        return ICMP(**kwargs)

    def _members(self):
        """Member information"""

        members = (
            ("type", self.type, 8),
            ("code", self.code, 8),
            ("chksum", self.chksum, 16),
            ("id", self.id, 16),
            ("seq", self.seq, 16),
        )
        return {"icmp": members}


# =============================================================================
