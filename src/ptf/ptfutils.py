# Copyright 2010 The Board of Trustees of The Leland Stanford Junior University
# SPDX-License-Identifier: Apache-2.0

# This file was derived from code in the Floodlight OFTest repository
# https://github.com/floodlight/oftest released under the OpenFlow
# Software License:
# https://github.com/floodlight/oftest/blob/master/LICENSE
# See file README-oftest.md in the ptf repository for more details.

"""
Utilities for the OpenFlow test framework
"""

import random
import time
import os
import fcntl
import logging
import signal

default_timeout = None  # set by ptf
default_negative_timeout = None  # set by ptf


def gen_xid():
    return random.randrange(1, 0xFFFFFFFF)


def chown_to_invoking_user(path, recursive=False):
    """
    Give a file or directory created by ptf back to the user who ran sudo.

    ptf needs root to open raw sockets, so it is normally started with sudo.
    Everything it writes (logs, pcaps, xUnit results) would then be owned by
    root, leaving the invoking user with artifacts they can neither read nor
    remove. This is a no-op when ptf is not running under sudo.
    """

    # Only root can hand a file to somebody else. Without sudo there is
    # nothing to undo either: the files already belong to whoever ran ptf.
    if os.geteuid() != 0:
        return

    sudo_uid = os.environ.get("SUDO_UID")
    sudo_gid = os.environ.get("SUDO_GID")
    if sudo_uid is None or sudo_gid is None:
        return

    try:
        uid, gid = int(sudo_uid), int(sudo_gid)
    except ValueError:
        logging.warning(
            "Ignoring malformed SUDO_UID/SUDO_GID: %s/%s", sudo_uid, sudo_gid
        )
        return

    paths = [path]
    if recursive:
        for dirpath, dirnames, filenames in os.walk(path):
            paths.extend(os.path.join(dirpath, name) for name in dirnames + filenames)

    for target in paths:
        try:
            # lchown, not chown: the output directories are owned by an
            # unprivileged user by the time we walk them, so following a
            # symlink placed there would let that user have any file on the
            # system chowned to themselves.
            os.lchown(target, uid, gid)
        except OSError as e:
            logging.warning("Could not change ownership of %s: %s", target, e)


"""
Wait on a condition variable until the given function returns non-None or a timeout expires.
The condition variable must already be acquired.
The timeout value None means use the default timeout.
There is deliberately no support for an infinite timeout.
"""


def timed_wait(cv, fn, timeout=None):
    if timeout == None:
        timeout = default_timeout

    end_time = time.time() + timeout
    while True:
        val = fn()
        if val != None:
            return val

        remaining_time = end_time - time.time()
        cv.wait(remaining_time)

        if time.time() > end_time:
            return None


class EventDescriptor:
    """
    Similar to a condition variable, but can be passed to select().
    Only supports one waiter.
    """

    def __init__(self):
        self.pipe_rd, self.pipe_wr = os.pipe()
        fcntl.fcntl(self.pipe_wr, fcntl.F_SETFL, os.O_NONBLOCK)

    def close(self):
        os.close(self.pipe_rd)
        os.close(self.pipe_wr)

    def notify(self):
        try:
            os.write(self.pipe_wr, "x".encode("utf-8"))
        except OSError as e:
            logging.warn("Failed to notify EventDescriptor: %s", e)

    def wait(self):
        os.read(self.pipe_rd, 1)

    def fileno(self):
        return self.pipe_rd


# inspired from http://stackoverflow.com/questions/8464391/what-should-i-do-if-socket-setdefaulttimeout-is-not-working
class Timeout:
    """Timeout class using ALARM signal"""

    class TimeoutError(Exception):
        pass

    def __init__(self, sec):
        try:
            from signal import alarm

            self.supported = True
        except ImportError:
            logging.warn(
                "Your platform does not support alarm signals, "
                "the Timeout feature is therefore not supported"
            )
            self.supported = False
            return
        self.sec = sec
        if sec > 0:
            self.valid = True
        else:
            self.valid = False
            logging.warn("Invalid timeout requested")

    def __enter__(self):
        if not self.supported or not self.valid:
            return
        signal.signal(signal.SIGALRM, self.raise_timeout)
        signal.alarm(self.sec)

    def __exit__(self, *args):
        if not self.supported or not self.valid:
            return
        signal.alarm(0)  # disable alarm

    def raise_timeout(self, *args):
        raise Timeout.TimeoutError()
