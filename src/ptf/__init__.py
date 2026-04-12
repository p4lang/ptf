# Copyright 2010 The Board of Trustees of The Leland Stanford Junior University
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

# This file was derived from code in the Floodlight OFTest repository
# https://github.com/floodlight/oftest released under the OpenFlow
# Software License:
# https://github.com/floodlight/oftest/blob/master/LICENSE
# See file README-oftest.md in the ptf repository for more details.

"""Docstring to silence pylint; ignores --ignore option for __init__.py"""

import sys
import os
import logging

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


def open_logfile(name):
    """
    (Re)open logfile

    When using a log directory a new logfile is created for each test. The same
    code is used to implement a single logfile in the absence of --log-dir.
    """

    _format = "%(asctime)s.%(msecs)03d  %(name)-10s: %(levelname)-8s: %(message)s"
    _datefmt = "%H:%M:%S"

    if config["log_dir"] != None:
        filename = os.path.join(config["log_dir"], name) + ".log"
    else:
        filename = config["log_file"]

    logger = logging.getLogger()

    # Remove any existing handlers
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()

    formatter = logging.Formatter(_format, _datefmt)

    # Add a new handler
    handler = logging.FileHandler(filename, mode="a")
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    # We log all ERROR and CRITICAL messages to stdout as well as to the
    # logfile.
    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(logging.ERROR)
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)


def disable_logging():
    """
    Temporarily disable all logging by setting the global log level to
    CRITICAL, which is the highest log level in use.
    """
    logging.disable(logging.CRITICAL)


def enable_logging():
    """
    Turn logging back on after a call to disable_logging().
    """
    logging.disable(logging.NOTSET)
