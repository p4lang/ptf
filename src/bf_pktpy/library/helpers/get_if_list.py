# Copyright 2021 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

import psutil


def get_if_list():
    return sorted(psutil.net_if_addrs().keys())
