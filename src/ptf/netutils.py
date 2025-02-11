# Copyright 2025 Andy Fingerhut
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

# Note: Earlier versions of this file were licensed with a copyleft
# license.
#
# This version has been rewritten from scratch, with no reference to
# the implementations in file netutils.py earlier in the commit log of
# the repository https://github.com/p4lang/ptf

######################################################################
# get_mac:
#
# The new get_mac is copied from the Apache-2.0 implementation
# in source file ptf_nn_agent.py of this repo.

######################################################################
# set_promisc:
#
# StackOverflow answer explaining one way to do it at [2].
# [2] https://stackoverflow.com/questions/6067405/python-sockets-enabling-promiscuous-mode-in-linux

######################################################################
#
# Promiscuous mode enable/disable

import ctypes
import fcntl
import socket

# Constant from Linux /usr/include/linux/if.h or net/if.h
IFF_PROMISC = 0x100

# Constants from Linux bits/ioctls.h or linux/sockios.h
SIOCGIFHWADDR = 0x8927  # Get hardware address
SIOCGIFFLAGS = 0x8913
SIOCSIFFLAGS = 0x8914


class ifreq(ctypes.Structure):
    _fields_ = [("ifr_ifrn", ctypes.c_char * 16), ("ifr_flags", ctypes.c_short)]


def get_if(iff: str, cmd: int) -> bytes:
    s = socket.socket()
    ifreq = fcntl.ioctl(s, cmd, struct.pack("16s16x", iff.encode("utf-8")))
    s.close()
    return ifreq


# Given iff, the name of a network interface (e.g. 'veth0') as a
# string, return a string of the form 'xx:yy:zz:aa:bb:cc' containing
# the MAC address of that interface, where all digits are hexadecimal.
def get_mac(iff: str) -> str:
    return ":".join(
        ["%02x" % char for char in bytearray(get_if(iff, SIOCGIFHWADDR)[18:24])]
    )


# Given iff, the name of a network interface (e.g. 'veth0') as a
# string, and s, a SOCK_RAW socket bound to that interface, set the
# interface in promiscuous mode if parameter val != 0, or into
# non-promiscuous mode if val == 0.
def set_promisc(s, iff, val=1):
    ifr = ifreq()
    ifr.ifr_ifrn = bytes(iff, "utf-8")
    # Get current interface flags
    s_fileno = s.fileno()
    fcntl.ioctl(s_fileno, SIOCGIFFLAGS, ifr)
    orig_flags = ifr.ifr_flags
    if val != 0:
        ifr.ifr_flags |= IFF_PROMISC
    else:
        ifr.ifr_flags &= ~IFF_PROMISC
    # Set flags, if they have changed
    if ifr.ifr_flags != orig_flags:
        fcntl.ioctl(s_fileno, SIOCSIFFLAGS, ifr)
