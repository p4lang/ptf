"""
Pcap file writer
"""

import os
import struct
import time
from typing import Optional, Union

PcapHeader = struct.Struct("<LHHLLLL")
PcapPktHeader = struct.Struct("<LLLL")

# PCAP-PPI is a "legacy format", only recommended for legacy packet
# processors that cannot be updated to use PCAP-NG.
# https://wiki.wireshark.org/PPI
PPIPktHeader = struct.Struct("<BBHL")
PPIAggregateField = struct.Struct("<HHL")

PCAP_MAGIC_NUMBER = 0xA1B2C3D4
PCAP_MAJOR_VERSION = 2
PCAP_MINOR_VERSION = 4

# https://www.tcpdump.org/linktypes.html
LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_PPI = 192


class PcapWriter(object):
    def __init__(self, path: Union[str, os.PathLike], linktype: int = LINKTYPE_PPI):
        """Open a pcap file for writing at 'path'.

        The default link type is LINKTYPE_PPI, for backwards
        compatibility with callers that have used PcapWriter before it
        implemented other linktype values.

        """
        self.stream = open(path, "wb")
        if linktype == LINKTYPE_ETHERNET or linktype == LINKTYPE_NULL:
            self.ppi_len = 0
        elif linktype == LINKTYPE_PPI:
            self.ppi_len = PPIPktHeader.size + 2 * PPIAggregateField.size
        else:
            raise ValueError("Unsupported linktype %s" % (linktype))
        self.linktype = linktype
        self.stream.write(
            PcapHeader.pack(
                PCAP_MAGIC_NUMBER,
                PCAP_MAJOR_VERSION,
                PCAP_MINOR_VERSION,
                0,  # timezone offset
                0,  # timezone accuracy
                65535,  # snapshot length
                self.linktype,
            )
        )

    def write(
        self,
        data: bytes,
        timestamp: Optional[float] = None,
        device: Optional[int] = None,
        port: Optional[int] = None,
    ):
        """Write a packet to a pcap file.

        'data' contains the packet data.
        'timestamp' is optional, defaulting to the current time.

        'device' should be an integer device number, required if the
        PcapWriter was created with LINKTYPE_PPI, otherwise ignored.

        'port' should be an integer port number, required if the
        PcapWriter was created with LINKTYPE_PPI, otherwise ignored.
        """
        if timestamp is None:
            timestamp = time.time()
        self.stream.write(
            PcapPktHeader.pack(
                int(timestamp),  # timestamp seconds
                int((timestamp - int(timestamp)) * 10**6),  # timestamp microseconds
                len(data) + self.ppi_len,  # truncated length
                len(data) + self.ppi_len,  # un-truncated length
            )
        )
        if self.linktype == LINKTYPE_PPI:
            if device is None:
                raise ValueError(
                    "argument 'device' was None.  Must be integer"
                    " for PcapWriter with linktype=%d"
                    "" % (self.linktype)
                )
            if port is None:
                raise ValueError(
                    "argument 'port' was None.  Must be integer"
                    " for PcapWriter with linktype=%d"
                    "" % (self.linktype)
                )
            self.stream.write(
                PPIPktHeader.pack(
                    0,  # version
                    0,  # flags
                    self.ppi_len,  # length
                    1,  # ethernet dlt
                )
            )
            self.stream.write(
                PPIAggregateField.pack(8, PPIAggregateField.size - 4, port)
            )
            self.stream.write(
                PPIAggregateField.pack(8, PPIAggregateField.size - 4, device)
            )
        self.stream.write(data)

    def flush(self):
        self.stream.flush()

    def close(self):
        self.stream.close()


def rdpcap_one_packet(f, path: Union[str, os.PathLike], return_packet_metadata: bool):
    pkt_header_bytes = f.read(PcapPktHeader.size)
    if len(pkt_header_bytes) == 0:
        if return_packet_metadata:
            return None, None, None, None, None
        return None
    if len(pkt_header_bytes) != PcapPktHeader.size:
        raise ValueError(
            "Expected a packet header with length %d bytes"
            " in file %s but file ended after only %d bytes"
            "" % (PcapPktHeader.size, path, len(pkt_header_bytes))
        )
    pkt_header = PcapPktHeader.unpack(pkt_header_bytes)
    (timestamp_sec, timestamp_microsec, caplength, length) = pkt_header
    # Consider supporting linktype LINKTYPE_PPI for reading.
    pkt_data = f.read(caplength)
    if len(pkt_data) != caplength:
        raise ValueError(
            "Expected a packet body with length %d bytes"
            " in file %s but file ended after only %d bytes"
            "" % (caplength, path, len(pkt_data))
        )
    if return_packet_metadata:
        return pkt_data, timestamp_sec, timestamp_micro, length
    return pkt_data


def rdpcap(path: Union[str, os.PathLike], return_packet_metadata: bool = False):
    """Attempts to open 'path' for reading and interpret its contents
    as a pcap file.  Raises an exception if any unexpected file
    contents are found, or the path cannot be opened for reading.

    With the default behavior when 'return_packet_metadata' is False,
    returns a list of elements that are all type bytes, containing
    only the contents of the packets.

    If 'return_packet_metadata' is True, returns a list of dicts, each
    dict containing these keys:

    "pkt_data" - bytes.  The content of the packet.  The capture
    length is len(pkt_data).

    "timestamp" - float.  The timestamp of the packet in units of
    seconds.

    "length" - int.  The original length of the packet, which can be
    longer than len(pkt_data) if the packet was truncated before
    recording its contents in the pcap file.

    """
    pkts = []
    with open(path, "rb") as f:
        file_header_bytes = f.read(PcapHeader.size)
        file_header = PcapHeader.unpack(file_header_bytes)
        (
            magic_number,
            major_version,
            minor_version,
            timezone_offset,
            timezone_accuracy,
            snapshot_length,
            linktype,
        ) = file_header
        if magic_number != PCAP_MAGIC_NUMBER:
            raise ValueError(
                "Expecting first 4 bytes of supposed pcap file"
                " '%s' to be magic number 0x%08x"
                " but found instead 0x%08x"
                "" % (path, PCAP_MAGIC_NUMBER, magic_number)
            )
        if major_version != PCAP_MAJOR_VERSION:
            raise ValueError(
                "Expecting major version of pcap file"
                " '%s' to be 0x%08x"
                " but found instead 0x%08x"
                "" % (path, PCAP_MAJOR_VERSION, major_version)
            )
        if minor_version != PCAP_MINOR_VERSION:
            raise ValueError(
                "Expecting minor version of pcap file"
                " '%s' to be 0x%08x"
                " but found instead 0x%08x"
                "" % (path, PCAP_MINOR_VERSION, minor_version)
            )
        # Ignoring value of timezone offset.
        # Ignoring value of timezone accuracy.
        if not (linktype == LINKTYPE_ETHERNET or linktype == LINKTYPE_NULL):
            raise ValueError(
                "Found unsupported linktype value %d"
                " in pcap file '%s'"
                "" % (linktype, path)
            )
        while True:
            if return_packet_metadata:
                (pkt_data, timestamp_sec, timestamp_usec, length) = rdpcap_one_packet(
                    f, path, return_packet_metadata
                )
                if pkt_data is None:
                    pkt = None
                else:
                    timestamp = timestamp_sec + (timestamp_usec / 1000000.0)
                    pkt = {
                        "timestamp": timestamp,
                        "length": length,
                        "pkt_data": pkt_data,
                    }
            else:
                pkt = rdpcap_one_packet(f, path, return_packet_metadata)
            if pkt is None:
                break
            pkts.append(pkt)
    return pkts


if __name__ == "__main__":
    import time

    print("Writing test pcap to test.pcap")
    pcap_writer = PcapWriter("test.pcap")
    pcap_writer.write(
        "\x00\x01\x02\x03\x04\x05\x00\x0a\x0b\x0c\x0d\x0e\x08\x00", time.time(), 42
    )
    pcap_writer.close()
