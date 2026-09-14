# Copyright 2026 The P4 Language Consortium
# SPDX-License-Identifier: Apache-2.0

import pytest

from bf_pktpy.ptf import packet_pktpy
from ptf import dataplane


class FakePort:
    instances = []

    def __init__(self, interface, device, port, config):
        self.interface = interface
        self.closed = 0
        self.instances.append(self)

    def close(self):
        self.closed += 1


def make_dataplane(monkeypatch):
    monkeypatch.setattr(dataplane.DataPlane, "start", lambda self: None)
    return dataplane.DataPlane(
        {"platform": "fake", "dataplane": {"portclass": FakePort}, "qlen": 1}
    )


def test_port_replacement_and_removal_close_resources(monkeypatch):
    FakePort.instances = []
    plane = make_dataplane(monkeypatch)
    plane.port_add("first", 0, 1)
    first = FakePort.instances[-1]
    plane.port_add("second", 0, 1)
    second = FakePort.instances[-1]
    assert first.closed == 1
    assert plane.port_remove(0, 1)
    assert second.closed == 1
    plane.kill()
    plane.kill()


def test_kill_is_idempotent_and_closes_every_port(monkeypatch):
    FakePort.instances = []
    plane = make_dataplane(monkeypatch)
    plane.port_add("one", 0, 1)
    plane.port_add("two", 0, 2)
    plane.kill()
    assert [port.closed for port in FakePort.instances] == [1, 1]
    assert plane.ports == {}
    plane.kill()
    assert [port.closed for port in FakePort.instances] == [1, 1]


def test_kill_closes_remaining_resources_after_port_error(monkeypatch):
    class BrokenPort(FakePort):
        def close(self):
            super().close()
            if self.interface == "broken":
                raise RuntimeError("close failed")

    monkeypatch.setattr(dataplane.DataPlane, "start", lambda self: None)
    plane = dataplane.DataPlane(
        {"platform": "fake", "dataplane": {"portclass": BrokenPort}, "qlen": 1}
    )
    plane.port_add("broken", 0, 1)
    plane.port_add("healthy", 0, 2)

    with pytest.raises(RuntimeError, match="cleanup failed"):
        plane.kill()
    assert [port.closed for port in BrokenPort.instances[-2:]] == [1, 1]
    assert plane.ports == {}
    assert plane.waker.pipe_rd is None


def test_nn_source_closes_after_its_final_port(monkeypatch):
    class FakeSource:
        instances = []

        def __init__(self, *args):
            self.ports = set()
            self.removed = []
            self.closed = 0
            self.instances.append(self)

        def port_add(self, port):
            self.ports.add(port)

        def port_remove(self, port):
            if port in self.ports:
                self.ports.remove(port)
                self.removed.append(port)

        def close(self):
            self.closed += 1

    monkeypatch.setattr(dataplane, "DataPlanePacketSourceNN", FakeSource)
    dataplane.DataPlanePortNN.packet_injecters.clear()
    first = dataplane.DataPlanePortNN("ipc:///tmp/test", 0, 1)
    second = dataplane.DataPlanePortNN("ipc:///tmp/test", 0, 2)
    source = FakeSource.instances[0]
    first.close()
    assert source.closed == 0
    second.close()
    assert source.removed == [1, 2]
    assert source.closed == 1
    assert dataplane.DataPlanePortNN.packet_injecters == {}


def test_bf_pktpy_hexdump_formatter_returns_text():
    result = packet_pktpy.format_hexdump(packet_pktpy.Ether())
    assert isinstance(result, str)
