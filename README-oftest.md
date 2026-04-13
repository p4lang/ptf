# Files in `ptf` repository derived from `oftest` repository code

Some source files in the `ptf` repository were derived from code in the
the Floodlight OFTest repository:

https://github.com/floodlight/oftest

The code in that repository has this copyright and license information:

```
Copyright 2010 The Board of Trustees of The Leland Stanford Junior University
Releaesd under the OpenFlow Software License
https://github.com/floodlight/oftest/blob/master/LICENSE
```

A copy of the OpenFlow Software License is also included in the file
[`LICENSE.OFTest`](LICENSE.OFTest) in the `ptf` repository.

Most files in this repository that were derived from `oftest` files
have the same file name in both repositories, and are listed below
with a mark of "S" for "same name".

A few files in this repository were copied from `oftest` files and
then renamed, and also then modified.  Those files are listed below
with a mark of "R" for "renamed", along with the name of the `oftest`
file from which it was derived.

Most files in the `src/ptf` directory of this repository were derived
from `oftest` code.  A few files in the `src/ptf` directory appear to
have been developed independently of the `oftest` code.  Files marked
with "I" below were developed independently of `oftest` code, but
placed in the `src/ptf` directory.

In particular, the `oftest` repository contains no mention of the
`nanomsg` library.  Thus all files in the `ptf_nn` directory of this
repository appear to be independently developed by Antonin Bas,
without deriving it from `oftest` code.

Similarly, all files in the `src/bf_pktpy` directory and its
subdirectories were developed by engineers working for Intel
Corporation, released under the Apache 2.0 license as part of the
`open-p4studio` repository at https://github.com/p4lang/open-p4studio.
Those files were copied into this repository for the convenience of
`ptf` users that wish to use it as a non-copylefted alternative to
Scapy.

Summary of abbrevation meanings:

+ S - file has same name in `ptf` repository as the file from `oftest`
  repository that it was copied from.
+ R - file was copied from `oftest` repository, then renamed, then
  modified.
+ I - file was independently developed, not derived from any code in
  the `oftest` repository.

List of all files in directory `src/ptf` and its subdirectories, and
whether they were derived from `oftest` code:

+ R `ptf` - renamed from file oft in the `oftest` repo
+ S `src/ptf/afpacket.py`
+ S `src/ptf/base_tests.py`
+ S `src/ptf/dataplane.py`
+ S `src/ptf/__init__.py`
+ I `src/ptf/mask.py` - I could find no evidence of any code in
  `oftest` from which this could have been derived.  It appears to
  have been independently developed by Antonin Bas.
+ I `src/ptf/netutils.py` - Originally copied from `oftest` code, then
  later in 2025 reimplemented from scratch so that it could be
  released under the Apache 2.0 license.
+ S `src/ptf/packet.py`
+ I `src/ptf/packet_scapy.py` - Appears to be independently developed
  from `oftest` code, but the author explicitly chose to use the
  OpenFlow Software License and copyright it by the same entity as
  other `oftest` files.
+ S `src/ptf/parse.py`
+ S `src/ptf/pcap_writer.py`
+ I `src/ptf/platforms/dummy.py`
+ S `src/ptf/platforms/eth.py`
+ I `src/ptf/platforms/__init__.py`
+ S `src/ptf/platforms/local.py`
+ I `src/ptf/platforms/nn.py`
+ S `src/ptf/platforms/remote.py`
+ R `src/ptf/ptfutils.py` - renamed from file ofutils.py in the
  `oftest` repo
+ S `src/ptf/testutils.py`
+ I `src/ptf/thriftutils.py` - Even though this file mentions `oftest`
  in a commit comment, I can find no occurrences of terms like
  "to_hex", "hex_to", "i16", or "i32" anywhere in the `oftest` code.
  This appears to be original work by Antonin Bas, not derived from
  `oftest`.
