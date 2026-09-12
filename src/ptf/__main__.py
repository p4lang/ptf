# Copyright 2010 The Board of Trustees of The Leland Stanford Junior University
# SPDX-License-Identifier: Apache-2.0

# This file was derived from code in the Floodlight OFTest repository
# https://github.com/floodlight/oftest released under the OpenFlow
# Software License:
# https://github.com/floodlight/oftest/blob/master/LICENSE
# See file README-oftest.md in the ptf repository for more details.
"""
Entry point for ``python -m ptf``. This module behaves like the ``ptf``
binary.
"""

import sys

from ptf.cli import main

if __name__ == "__main__":
    sys.exit(main())
