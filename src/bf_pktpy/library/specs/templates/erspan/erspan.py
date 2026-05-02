#!/usr/bin/env python


# Copyright (c) 2021 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

###############################################################################
"""ERSPAN template"""

from bf_pktpy.library.specs.templates.erspan.erspan_ii import ERSPAN_II


# =============================================================================
class ERSPAN(ERSPAN_II):
    """
    This is a dummy class to set a ERSPAN II as a default
    """

    name = "ERSPAN"


# =============================================================================
