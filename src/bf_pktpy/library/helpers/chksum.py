# Copyright (c) 2021 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0


def checksum(binary):
    """Calculate checksum"""
    prev, total = "", 0
    for i in range(len(binary)):
        k = i * 16
        if k >= len(binary):
            break
        if not prev:
            prev = binary[k : k + 16]
            continue
        now = binary[k : k + 16]
        total = int(prev, 2) + int(now, 2)
        if total >> 16:
            total = (total >> 16) + (total & 0xFFFF)
        prev = bin(total)
    return total ^ 0xFFFF
