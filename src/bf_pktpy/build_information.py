# Copyright (c) 2021 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

from bf_pktpy.library.helpers import constants


class BuildInformation:
    def __init__(self):
        self._version = "0.2"

    def show_details(self, logo=False):
        if logo:
            print(constants.logo)
        print("\tBarefoot PKTPY (Packet Generator)\n\tVersion: %s" % self._version)
