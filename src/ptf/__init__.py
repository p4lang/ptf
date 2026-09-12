# Copyright 2010 The Board of Trustees of The Leland Stanford Junior University
# SPDX-License-Identifier: Apache-2.0

# This file was derived from code in the Floodlight OFTest repository
# https://github.com/floodlight/oftest released under the OpenFlow
# Software License:
# https://github.com/floodlight/oftest/blob/master/LICENSE
# See file README-oftest.md in the ptf repository for more details.

"""Docstring to silence pylint; ignores --ignore option for __init__.py"""

import sys
import os
import logging

from . import ptfutils

try:
    from ._version import __version__
except ImportError:
    # the generated _version.py file should not be checked-in
    # if it is missing, we set the version string to "unknown"
    __version__ = "unknown"

# Global config dictionary
# Populated by oft.
config = {}

# Global DataPlane instance used by all tests.
# Populated by oft.
dataplane_instance = None

# A runner installs a scoped logfile opener while it is active. Keeping this
# hook here preserves the long-standing ptf.open_logfile() API used by tests
# without making those tests aware of runner internals.
_logfile_opener = None
_logging_disable_stack = []


def _close_owned_handlers(logger):
    """Remove and close handlers created by PTF, leaving caller handlers alone."""
    for handler in list(logger.handlers):
        if getattr(handler, "_ptf_owned", False):
            logger.removeHandler(handler)
            handler.close()


def open_logfile(name):
    """
    (Re)open logfile

    When using a log directory a new logfile is created for each test. The same
    code is used to implement a single logfile in the absence of --log-dir.
    """

    if _logfile_opener is not None:
        return _logfile_opener(name)

    _format = "%(asctime)s.%(msecs)03d  %(name)-10s: %(levelname)-8s: %(message)s"
    _datefmt = "%H:%M:%S"

    if config["log_dir"] != None:
        filename = os.path.join(config["log_dir"], name) + ".log"
    else:
        filename = config["log_file"]

    logger = logging.getLogger()

    _close_owned_handlers(logger)

    formatter = logging.Formatter(_format, _datefmt)

    # Add a new handler
    handler = logging.FileHandler(filename, mode="a")
    handler._ptf_owned = True
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    ptfutils.chown_to_invoking_user(filename)

    # We log all ERROR and CRITICAL messages to stdout as well as to the
    # logfile.
    stream_handler = logging.StreamHandler()
    stream_handler._ptf_owned = True
    stream_handler.setLevel(logging.ERROR)
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)


def disable_logging():
    """
    Temporarily disable all logging by setting the global log level to
    CRITICAL, which is the highest log level in use.
    """
    _logging_disable_stack.append(logging.root.manager.disable)
    logging.disable(logging.CRITICAL)


def enable_logging():
    """
    Turn logging back on after a call to disable_logging().
    """
    if _logging_disable_stack:
        logging.disable(_logging_disable_stack.pop())
