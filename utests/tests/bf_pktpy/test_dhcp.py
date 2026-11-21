# Copyright 2026 Keshav Kumar
# SPDX-License-Identifier: Apache-2.0

import pytest

from bf_pktpy.library.specs.templates.dhcp import DHCP


def test_unknown_option_name_is_rejected():
    with pytest.raises(ValueError, match="Unsupported option"):
        DHCP(options=[("not_a_real_option", "x")])


def test_unknown_bare_option_name_is_rejected():
    with pytest.raises(ValueError, match="Unsupported option"):
        DHCP(options=["not_a_real_option"])


def test_unknown_message_type_is_rejected():
    with pytest.raises(ValueError, match="Unsupported message type"):
        DHCP(options=[("message-type", "bogus_type")])


@pytest.mark.parametrize(
    "options, expected",
    [
        ([("message-type", "discover")], "350101"),
        ([("message-type", "ack")], "350105"),
        (["end"], "ff"),
        (
            [("message-type", "request"), ("requested_addr", "10.0.0.5"), "end"],
            "35010332040a000005ff",
        ),
    ],
)
def test_known_options_are_unchanged(options, expected):
    assert DHCP(options=options).options == expected
