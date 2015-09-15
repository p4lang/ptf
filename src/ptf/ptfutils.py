
"""
Utilities for the OpenFlow test framework
"""

import random
import time
import os
import fcntl
import logging

default_timeout = None # set by ptf
default_negative_timeout = None # set by ptf

def gen_xid():
    return random.randrange(1,0xffffffff)

"""
Wait on a condition variable until the given function returns non-None or a timeout expires.
The condition variable must already be acquired.
The timeout value -1 means use the default timeout.
There is deliberately no support for an infinite timeout.
"""
def timed_wait(cv, fn, timeout=-1):
    if timeout == -1:
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

class EventDescriptor():
    """
    Similar to a condition variable, but can be passed to select().
    Only supports one waiter.
    """

    def __init__(self):
        self.pipe_rd, self.pipe_wr = os.pipe()
        fcntl.fcntl(self.pipe_wr, fcntl.F_SETFL, os.O_NONBLOCK)

    def __del__(self):
        os.close(self.pipe_rd)
        os.close(self.pipe_wr)

    def notify(self):
        try:
            os.write(self.pipe_wr, "x")
        except OSError as e:
            logging.warn("Failed to notify EventDescriptor: %s", e)

    def wait(self):
        os.read(self.pipe_rd, 1)

    def fileno(self):
        return self.pipe_rd
