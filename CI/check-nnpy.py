#!/usr/bin/env python

import nnpy
import sys

print("----------------------------------------")
print("sys.path:")
for path in sys.path:
    print("    %s" % (path))
print("----------------------------------------")

pub = nnpy.Socket(nnpy.AF_SP, nnpy.PUB)
pub.bind("inproc://foo")

sub = nnpy.Socket(nnpy.AF_SP, nnpy.SUB)
sub.connect("inproc://foo")
sub.setsockopt(nnpy.SUB, nnpy.SUB_SUBSCRIBE, "")

pub.send("hello, world")
recv = sub.recv()

if recv != b"hello, world":
    sys.exit(1)
