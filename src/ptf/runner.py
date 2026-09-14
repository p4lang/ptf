# Copyright 2010 The Board of Trustees of The Leland Stanford Junior University
# SPDX-License-Identifier: Apache-2.0

# This file was derived from code in the Floodlight OFTest repository
# https://github.com/floodlight/oftest released under the OpenFlow
# Software License:
# https://github.com/floodlight/oftest/blob/master/LICENSE
# See file README-oftest.md in the ptf repository for more details.

"""
PTF runner library.

This module contains the test-run logic of the Packet Test Framework (PTF).
The logic was part of the top-level ``ptf`` script before. Use this module
to run PTF tests inside any Python program, without a separate ``ptf``
process:

    from ptf import runner

    config = runner.PtfConfig(
        test_selection=runner.TestSelectionOptions(test_dir="tests"),
        platform=runner.PlatformOptions(
            platform="nn",
            device_sockets=[
                runner.DeviceSocket(0, {0, 1}, "ipc:///tmp/ptf_packets.ipc")
            ],
        ),
        test_behavior=runner.TestBehaviorOptions(
            test_params={"key1": 17, "key2": True}
        ),
    )
    exit_code = runner.run(config)

``run()`` performs the same steps as the ``ptf`` binary: logging setup, test
discovery and selection, sharding, platform loading, dataplane setup, test
execution, and teardown. It returns the exit code that the binary produces
for the same configuration. ``run()`` also accepts a dictionary in the flat
``ptf.config`` format; see :meth:`PtfConfig.from_dict`.

The tests read their settings from global state: the ``ptf.config``
dictionary, ``ptf.dataplane_instance``, and the module globals of
``ptf.testutils`` and ``ptf.ptfutils``. ``run()`` fills this state from the
given :class:`PtfConfig`. Set a non-default packet manipulation module in
the configuration before ``ptf.packet`` or ``ptf.testutils`` is imported for
the first time. ``run()`` keeps this order when it imports the test modules.
"""

import dataclasses
import fnmatch
import importlib
import importlib.machinery
import importlib.util
import json
import logging
import os
import random
import shutil
import signal
import sys
import threading
import time
import types
import unittest
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, TextIO, Union

import ptf
from . import ptfutils

LOGGER = logging.getLogger(__name__)

##@var DEBUG_LEVELS
# Map from strings to debugging levels
DEBUG_LEVELS = {
    "debug": logging.DEBUG,
    "verbose": logging.DEBUG,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "warn": logging.WARNING,
    "error": logging.ERROR,
    "critical": logging.CRITICAL,
}

TEST_ORDERS = ("default", "lexico", "rand")

# Default packet manipulation module, used when neither the configuration
# nor the PTF_PACKET_MANIPULATION_MODULE environment variable specify one.
DEFAULT_PACKET_MANIPULATION_MODULE = "ptf.packet_scapy"


class PtfError(Exception):
    """A fatal error that stops a test run before it starts.

    ``run()`` raises this error when the configuration or the environment
    is invalid. The ``ptf`` binary reports the error as a critical log
    message and exits with code 1.
    """


@dataclass
class Interface:
    """The mapping between a (device, port) pair and a dataplane interface.

    This class represents one entry in ``port@interface`` or
    ``device-port@interface`` syntax of the ``--interface`` command line
    option.
    """

    device: int = 0
    port: int = 0
    interface: str = ""


@dataclass
class DeviceSocket:
    """The nanomsg socket for packet input and output on a set of ports.

    This class represents one entry in the
    ``device-{port,port,...}@socketaddr`` syntax of the ``--device-socket``
    command line option.
    """

    device: int = 0
    ports: Set[int] = field(default_factory=set)
    address: str = ""


@dataclass
class TestSelectionOptions:
    """The tests to run, and their order.

    ``test_specs`` holds test names (``module.Test``), group names, or names
    negated with ``^``. An empty list selects the ``standard`` group. This is
    the same as the positional arguments of the binary.
    """

    test_dir: Optional[str] = None
    test_specs: List[str] = field(default_factory=list)
    test_file: Optional[str] = None
    test_order: str = "default"
    test_order_seed: int = 0xABA
    num_shards: int = 1
    shard_id: int = 0


@dataclass
class PlatformOptions:
    """The connection to the device under test (the PTF platform).

    ``port_info`` holds optional parameters for each port. The
    ``device-port@interface;key=value;...`` syntax of ``--interface``
    carries these parameters on the command line.
    """

    platform: str = "eth"
    platform_args: Optional[str] = None
    platform_dir: Optional[str] = None
    interfaces: List[Interface] = field(default_factory=list)
    device_sockets: List[DeviceSocket] = field(default_factory=list)
    port_info: Dict[int, Dict[str, str]] = field(default_factory=dict)


@dataclass
class LoggingOptions:
    """Log file, xUnit and profiling outputs."""

    log_file: Optional[str] = "ptf.log"
    log_dir: Optional[str] = None
    debug: str = "verbose"
    profile: bool = False
    profile_file: str = "profile.out"
    xunit: bool = False
    xunit_dir: str = "xunit"


@dataclass
class TestBehaviorOptions:
    """Options that control the behavior of the selected tests.

    ``test_params`` accepts two forms. The first form is a string in the
    ``key=value;key=value`` syntax of ``--test-params``. The binary and
    ``run()`` evaluate each value as a Python expression. The second form is
    a dictionary; the tests receive each entry as given.
    """

    relax: bool = False
    failfast: bool = False
    fail_skipped: bool = False
    test_params: Optional[Union[str, Dict[str, Any]]] = None
    default_timeout: float = 2.0
    default_negative_timeout: float = 0.1
    minsize: int = 0
    random_seed: Optional[int] = None
    test_case_timeout: Optional[int] = None
    qlen: int = 100
    disable_ipv6: bool = False
    disable_vxlan: bool = False
    disable_erspan: bool = False
    disable_geneve: bool = False
    disable_mpls: bool = False
    disable_nvgre: bool = False
    disable_igmp: bool = False
    disable_rocev2: bool = False


@dataclass
class SocketOptions:
    """Options for the sockets used by the dataplane."""

    socket_recv_size: int = 4096


@dataclass(frozen=True)
class RunOutput:
    """Runtime-only output and logging integration for :func:`run`.

    These values are deliberately separate from :class:`PtfConfig` so that
    the configuration remains serializable.
    """

    stdout: Optional[TextIO] = None
    stderr: Optional[TextIO] = None
    logger: Optional[logging.Logger] = None
    capture_root_logging: bool = False


@dataclass
class PtfConfig:
    """The complete configuration of one PTF test run.

    The nested option groups match the option groups of the ``ptf``
    binary. Use :meth:`to_dict` and :meth:`from_dict` to convert between
    this class and the flat ``ptf.config`` dictionary format. Use
    :meth:`to_json` and :meth:`from_json` to serialize the configuration,
    for example for a worker process.
    """

    # Print the list of available tests instead of running the tests.
    list_tests: bool = False
    # Print the names of the tests that match the test spec, instead of
    # running the tests.
    list_test_names: bool = False
    # Proceed when ptf does not run as root.
    allow_user: bool = False
    # The packet manipulation module. None selects the
    # PTF_PACKET_MANIPULATION_MODULE environment variable, or the default
    # module.
    packet_manipulation_module: Optional[str] = None
    # Additional directories appended to sys.path before the tests and the
    # platforms load (same as --pypath).
    pypath: List[str] = field(default_factory=list)
    test_selection: TestSelectionOptions = field(default_factory=TestSelectionOptions)
    platform: PlatformOptions = field(default_factory=PlatformOptions)
    logging: LoggingOptions = field(default_factory=LoggingOptions)
    test_behavior: TestBehaviorOptions = field(default_factory=TestBehaviorOptions)
    socket: SocketOptions = field(default_factory=SocketOptions)
    # Preserve platform-specific entries accepted by the legacy flat
    # ptf.config dictionary.
    extra_config: Dict[str, Any] = field(default_factory=dict)

    ########################################################################
    # (De)serialization helpers
    ########################################################################

    @staticmethod
    def _test_params_to_str(test_params):
        # Render dictionary test params in the string syntax of the binary.
        # The flat dictionary then stays compatible with the value that the
        # binary writes.
        if test_params is None or isinstance(test_params, str):
            return test_params
        return ";".join("{}={!r}".format(k, v) for k, v in test_params.items())

    def to_dict(self):
        # type: () -> Dict[str, Any]
        """Return the equivalent flat dictionary in the ``ptf.config``
        format. The PTF library and the platforms consume this format.
        ``port_map`` stays None; the platform fills this key in when
        ``run()`` executes."""
        tb = self.test_behavior
        result = dict(self.extra_config)
        result.update(
            {
                # Miscellaneous options
                "list": self.list_tests,
                "list_test_names": self.list_test_names,
                "allow_user": self.allow_user,
                "pypath": list(self.pypath),
                # Test selection options
                "test_spec": "",  # legacy key, unused
                "test_specs": list(self.test_selection.test_specs),
                "test_file": self.test_selection.test_file,
                "test_dir": self.test_selection.test_dir,
                "test_order": self.test_selection.test_order,
                "test_order_seed": self.test_selection.test_order_seed,
                "num_shards": self.test_selection.num_shards,
                "shard_id": self.test_selection.shard_id,
                # Switch connection options
                "platform": self.platform.platform,
                "platform_args": self.platform.platform_args,
                "platform_dir": self.platform.platform_dir,
                "interfaces": [
                    (i.device, i.port, i.interface) for i in self.platform.interfaces
                ],
                "port_info": {
                    port: dict(info) for port, info in self.platform.port_info.items()
                },
                "device_sockets": [
                    (s.device, set(s.ports), s.address)
                    for s in self.platform.device_sockets
                ],
                # Logging options
                "log_file": self.logging.log_file,
                "log_dir": self.logging.log_dir,
                "debug": self.logging.debug,
                "profile": self.logging.profile,
                "profile_file": self.logging.profile_file,
                "xunit": self.logging.xunit,
                "xunit_dir": self.logging.xunit_dir,
                # Test behavior options
                "relax": tb.relax,
                "test_params": self._test_params_to_str(tb.test_params),
                "failfast": tb.failfast,
                "fail_skipped": tb.fail_skipped,
                "default_timeout": tb.default_timeout,
                "default_negative_timeout": tb.default_negative_timeout,
                "minsize": tb.minsize,
                "random_seed": tb.random_seed,
                "disable_ipv6": tb.disable_ipv6,
                "disable_vxlan": tb.disable_vxlan,
                "disable_erspan": tb.disable_erspan,
                "disable_geneve": tb.disable_geneve,
                "disable_mpls": tb.disable_mpls,
                "disable_nvgre": tb.disable_nvgre,
                "disable_igmp": tb.disable_igmp,
                "disable_rocev2": tb.disable_rocev2,
                "qlen": tb.qlen,
                "test_case_timeout": tb.test_case_timeout,
                # Socket options
                "socket_recv_size": self.socket.socket_recv_size,
                # Other configuration; "port_map" is set by the platform.
                "port_map": None,
                # Left as None here on purpose: run() applies the
                # CLI > environment variable > default precedence.
                "packet_manipulation_module": self.packet_manipulation_module,
            }
        )
        return result

    @classmethod
    def from_dict(cls, d):
        # type: (Dict[str, Any]) -> PtfConfig
        """Build a PtfConfig from a dictionary in the flat ``ptf.config``
        format. The dictionary may be partial; missing keys get their
        default values. Each entry of ``interfaces`` and
        ``device_sockets`` may be a legacy tuple or a structured dataclass
        instance."""

        def interfaces(value):
            return [
                i if isinstance(i, Interface) else Interface(*i) for i in value or []
            ]

        def device_sockets(value):
            return [
                (
                    s
                    if isinstance(s, DeviceSocket)
                    else DeviceSocket(device=s[0], ports=set(s[1]), address=s[2])
                )
                for s in value or []
            ]

        defaults = cls()
        known_keys = set(defaults.to_dict())
        return cls(
            list_tests=d.get("list", defaults.list_tests),
            list_test_names=d.get("list_test_names", defaults.list_test_names),
            allow_user=d.get("allow_user", defaults.allow_user),
            packet_manipulation_module=d.get(
                "packet_manipulation_module", defaults.packet_manipulation_module
            ),
            pypath=list(d.get("pypath", [])),
            test_selection=TestSelectionOptions(
                test_dir=d.get("test_dir"),
                test_specs=list(d.get("test_specs", [])),
                test_file=d.get("test_file"),
                test_order=d.get("test_order", "default"),
                test_order_seed=d.get("test_order_seed", 0xABA),
                num_shards=d.get("num_shards", 1),
                shard_id=d.get("shard_id", 0),
            ),
            platform=PlatformOptions(
                platform=d.get("platform", "eth"),
                platform_args=d.get("platform_args"),
                platform_dir=d.get("platform_dir"),
                interfaces=interfaces(d.get("interfaces")),
                device_sockets=device_sockets(d.get("device_sockets")),
                port_info={
                    int(port): dict(info)
                    for port, info in (d.get("port_info") or {}).items()
                },
            ),
            logging=LoggingOptions(
                log_file=d.get("log_file", "ptf.log"),
                log_dir=d.get("log_dir"),
                debug=d.get("debug", "verbose"),
                profile=d.get("profile", False),
                profile_file=d.get("profile_file", "profile.out"),
                xunit=d.get("xunit", False),
                xunit_dir=d.get("xunit_dir", "xunit"),
            ),
            test_behavior=TestBehaviorOptions(
                relax=d.get("relax", False),
                failfast=d.get("failfast", False),
                fail_skipped=d.get("fail_skipped", False),
                test_params=d.get("test_params"),
                default_timeout=d.get("default_timeout", 2.0),
                default_negative_timeout=d.get("default_negative_timeout", 0.1),
                minsize=d.get("minsize", 0),
                random_seed=d.get("random_seed"),
                test_case_timeout=d.get("test_case_timeout"),
                qlen=d.get("qlen", 100),
                disable_ipv6=d.get("disable_ipv6", False),
                disable_vxlan=d.get("disable_vxlan", False),
                disable_erspan=d.get("disable_erspan", False),
                disable_geneve=d.get("disable_geneve", False),
                disable_mpls=d.get("disable_mpls", False),
                disable_nvgre=d.get("disable_nvgre", False),
                disable_igmp=d.get("disable_igmp", False),
                disable_rocev2=d.get("disable_rocev2", False),
            ),
            socket=SocketOptions(
                socket_recv_size=d.get("socket_recv_size", 4096),
            ),
            extra_config={k: v for k, v in d.items() if k not in known_keys},
        )

    def to_json(self):
        # type: () -> str
        """Serialize the configuration to JSON text. Sets become sorted
        lists. Use this method to pass a configuration to a worker
        process; see :meth:`from_json`."""

        data = dataclasses.asdict(self)
        for device_socket in data["platform"]["device_sockets"]:
            device_socket["ports"] = sorted(device_socket["ports"])
        return json.dumps(data, indent=2)

    @classmethod
    def from_json(cls, text):
        # type: (str) -> PtfConfig
        """Build a PtfConfig from the JSON text that :meth:`to_json`
        writes."""
        data = json.loads(text)

        def group(name):
            return data.get(name) or {}

        sel = group("test_selection")
        plat = group("platform")
        log = group("logging")
        beh = group("test_behavior")
        sock = group("socket")
        return cls(
            list_tests=data.get("list_tests", False),
            list_test_names=data.get("list_test_names", False),
            allow_user=data.get("allow_user", False),
            packet_manipulation_module=data.get("packet_manipulation_module"),
            pypath=data.get("pypath", []),
            test_selection=TestSelectionOptions(
                test_dir=sel.get("test_dir"),
                test_specs=sel.get("test_specs", []),
                test_file=sel.get("test_file"),
                test_order=sel.get("test_order", "default"),
                test_order_seed=sel.get("test_order_seed", 0xABA),
                num_shards=sel.get("num_shards", 1),
                shard_id=sel.get("shard_id", 0),
            ),
            platform=PlatformOptions(
                platform=plat.get("platform", "eth"),
                platform_args=plat.get("platform_args"),
                platform_dir=plat.get("platform_dir"),
                interfaces=[Interface(**i) for i in plat.get("interfaces", [])],
                device_sockets=[
                    DeviceSocket(
                        device=s["device"],
                        ports=set(s["ports"]),
                        address=s["address"],
                    )
                    for s in plat.get("device_sockets", [])
                ],
                port_info={
                    int(port): dict(info)
                    for port, info in plat.get("port_info", {}).items()
                },
            ),
            logging=LoggingOptions(
                log_file=log.get("log_file", "ptf.log"),
                log_dir=log.get("log_dir"),
                debug=log.get("debug", "verbose"),
                profile=log.get("profile", False),
                profile_file=log.get("profile_file", "profile.out"),
                xunit=log.get("xunit", False),
                xunit_dir=log.get("xunit_dir", "xunit"),
            ),
            test_behavior=TestBehaviorOptions(
                relax=beh.get("relax", False),
                failfast=beh.get("failfast", False),
                fail_skipped=beh.get("fail_skipped", False),
                test_params=beh.get("test_params"),
                default_timeout=beh.get("default_timeout", 2.0),
                default_negative_timeout=beh.get("default_negative_timeout", 0.1),
                minsize=beh.get("minsize", 0),
                random_seed=beh.get("random_seed"),
                test_case_timeout=beh.get("test_case_timeout"),
                qlen=beh.get("qlen", 100),
                disable_ipv6=beh.get("disable_ipv6", False),
                disable_vxlan=beh.get("disable_vxlan", False),
                disable_erspan=beh.get("disable_erspan", False),
                disable_geneve=beh.get("disable_geneve", False),
                disable_mpls=beh.get("disable_mpls", False),
                disable_nvgre=beh.get("disable_nvgre", False),
                disable_igmp=beh.get("disable_igmp", False),
                disable_rocev2=beh.get("disable_rocev2", False),
            ),
            socket=SocketOptions(
                socket_recv_size=sock.get("socket_recv_size", 4096),
            ),
            extra_config=data.get("extra_config", {}),
        )


########################################################################
# Helpers (ported from the former top-level ptf script)
########################################################################


_RUN_LOCK = threading.Lock()
_active_run_state = None
_MISSING = object()


class _ForwardingHandler(logging.Handler):
    """Forward PTF records to a caller-owned logger without owning it."""

    def __init__(self, target):
        super().__init__()
        self.target = target

    def emit(self, record):
        if (
            not self.target.disabled
            and record.levelno >= self.target.getEffectiveLevel()
        ):
            self.target.handle(record)


def _logger_propagates_to(logger, ancestor):
    while logger is not None:
        if logger is ancestor:
            return True
        if not logger.propagate:
            return False
        logger = logger.parent
    return False


def _caller_uses_log_path(path, directory=False):
    expected = os.path.realpath(os.path.abspath(path))
    loggers = [logging.getLogger()]
    loggers.extend(
        logger
        for logger in logging.root.manager.loggerDict.values()
        if isinstance(logger, logging.Logger)
    )
    for logger in loggers:
        for handler in logger.handlers:
            if not isinstance(handler, logging.FileHandler) or getattr(
                handler, "_ptf_owned", False
            ):
                continue
            actual = os.path.realpath(handler.baseFilename)
            if directory:
                try:
                    if os.path.commonpath((expected, actual)) == expected:
                        return True
                except ValueError:
                    continue
            elif actual == expected:
                return True
    return False


class _LoggingSession:
    """Own the handlers installed for one run and restore logger state."""

    def __init__(self, config, output):
        self.config = config
        self.output = output
        self.logger = (
            logging.getLogger()
            if output.capture_root_logging
            else logging.getLogger("ptf")
        )
        self.saved_level = self.logger.level
        self.saved_disabled = self.logger.disabled
        self.saved_propagate = self.logger.propagate
        self.saved_opener = ptf._logfile_opener
        self.handlers = []

    def start(self):
        if (
            self.output.logger is not None
            and self.output.logger is not self.logger
            and _logger_propagates_to(self.output.logger, self.logger)
        ):
            raise ValueError("output logger must not propagate back to the PTF logger")
        self.logger.setLevel(DEBUG_LEVELS[self.config.logging.debug])
        self.logger.disabled = False
        if not self.output.capture_root_logging:
            self.logger.propagate = False
        ptf._logfile_opener = self.open_logfile
        self.open_logfile("main")

    def open_logfile(self, name):
        for handler in self.handlers:
            self.logger.removeHandler(handler)
            handler.close()
        self.handlers = []

        if self.config.logging.log_dir is not None:
            filename = os.path.join(self.config.logging.log_dir, name) + ".log"
        else:
            filename = self.config.logging.log_file

        formatter = logging.Formatter(
            "%(asctime)s.%(msecs)03d  %(name)-10s: %(levelname)-8s: %(message)s",
            "%H:%M:%S",
        )
        if filename is not None:
            file_handler = logging.FileHandler(filename, mode="a")
            file_handler._ptf_owned = True
            file_handler.setFormatter(formatter)
            self._add_handler(file_handler)
            ptfutils.chown_to_invoking_user(filename)

        error_handler = logging.StreamHandler(self.output.stderr)
        error_handler._ptf_owned = True
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(formatter)
        self._add_handler(error_handler)

        if self.output.logger is not None and self.output.logger is not self.logger:
            observer = _ForwardingHandler(self.output.logger)
            observer._ptf_owned = True
            self._add_handler(observer)

    def _add_handler(self, handler):
        self.logger.addHandler(handler)
        self.handlers.append(handler)

    def close(self):
        ptf._logfile_opener = self.saved_opener
        for handler in self.handlers:
            self.logger.removeHandler(handler)
            handler.close()
        self.handlers = []
        self.logger.setLevel(self.saved_level)
        self.logger.disabled = self.saved_disabled
        self.logger.propagate = self.saved_propagate


class _RunState:
    """Snapshot and restore process state owned by an in-process PTF run."""

    def __init__(self, config):
        self.config = config
        self.config_object = ptf.config
        self.config_contents = dict(self.config_object)
        self.dataplane = None
        self.saved_dataplane = ptf.dataplane_instance
        self.added_paths = []
        self.modules = dict(sys.modules)
        self.touched_modules = set()
        self.module_roots = set()
        self.random_state = random.getstate()
        self.profile = sys.getprofile()
        self.logging_disable = logging.root.manager.disable
        self.logging_disable_stack = list(ptf._logging_disable_stack)
        self.ptfutils_timeouts = (
            ptfutils.default_timeout,
            ptfutils.default_negative_timeout,
        )
        self.testutils_state = None
        self.platform_module = None
        self.track_root(config.test_selection.test_dir)
        for path in config.pypath:
            self.track_root(path)

    def activate(self, config_dict):
        ptf.config = self.config_object
        self.config_object.clear()
        self.config_object.update(config_dict)
        for path in self.config.pypath:
            self.add_path(path)

    def add_path(self, path):
        self.added_paths.append((len(sys.path), path))
        sys.path.append(path)

    def track_root(self, path):
        if path:
            self.module_roots.add(os.path.realpath(os.path.abspath(path)))

    def mark_module(self, name):
        self.touched_modules.add(name)

    def module_was_loaded(self, name, source_path):
        module = sys.modules.get(name)
        if module is None:
            return False
        module_path = getattr(module, "__file__", None)
        if module_path is None:
            return False
        return module is not self.modules.get(name) and os.path.realpath(
            module_path
        ) == os.path.realpath(source_path)

    def capture_testutils(self, testutils):
        filters = testutils.FILTERS
        self.testutils_state = (
            testutils,
            testutils.TEST_PARAMS,
            testutils.PORT_INFO,
            testutils.MINSIZE,
            testutils.skipped_test_count,
            filters,
            list(filters),
        )

    def close_resources(self):
        errors = []
        if self.dataplane is not None:
            try:
                self.dataplane.stop_pcap()
            except Exception as error:
                LOGGER.exception("Failed to stop PTF packet capture")
                errors.append(error)
            try:
                self.dataplane.kill()
            except Exception as error:
                LOGGER.exception("Failed to shut down the PTF dataplane")
                errors.append(error)
            self.dataplane = None
        if self.platform_module is not None:
            teardown = getattr(self.platform_module, "platform_config_teardown", None)
            if callable(teardown):
                try:
                    teardown(ptf.config)
                except Exception as error:
                    LOGGER.exception("Failed to tear down the PTF platform")
                    errors.append(error)
        return errors

    def _track_modules_from_roots(self):
        for name, module in list(sys.modules.items()):
            if module is self.modules.get(name):
                continue
            module_path = getattr(module, "__file__", None)
            if module_path is None:
                continue
            path = os.path.realpath(module_path)
            if any(
                path == root or path.startswith(root + os.sep)
                for root in self.module_roots
            ):
                self.touched_modules.add(name)

    def restore(self):
        self._track_modules_from_roots()
        for name in self.touched_modules:
            previous = self.modules.get(name, _MISSING)
            if previous is _MISSING:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = previous

        if self.testutils_state is not None:
            (
                testutils,
                testutils.TEST_PARAMS,
                testutils.PORT_INFO,
                testutils.MINSIZE,
                testutils.skipped_test_count,
                filters,
                filter_contents,
            ) = self.testutils_state
            testutils.FILTERS = filters
            filters[:] = filter_contents

        ptfutils.default_timeout, ptfutils.default_negative_timeout = (
            self.ptfutils_timeouts
        )
        ptf.dataplane_instance = self.saved_dataplane
        ptf.config = self.config_object
        self.config_object.clear()
        self.config_object.update(self.config_contents)
        for index, path in reversed(self.added_paths):
            if index < len(sys.path) and sys.path[index] == path:
                sys.path.pop(index)
            else:
                for current in range(len(sys.path) - 1, index - 1, -1):
                    if sys.path[current] == path:
                        sys.path.pop(current)
                        break
        importlib.invalidate_caches()
        random.setstate(self.random_state)
        sys.setprofile(self.profile)
        logging.disable(self.logging_disable)
        ptf._logging_disable_stack[:] = self.logging_disable_stack


def import_module(root_path, module_name):
    """Import a module from the given directory, instead of the standard
    Python search path. The function registers the module in sys.modules
    under its name. This registration lets test modules import each
    other."""
    finder = importlib.machinery.PathFinder()
    module_spec = finder.find_spec(module_name, [root_path])
    if module_spec is None or module_spec.loader is None:
        raise ImportError("No module named %r in %r" % (module_name, root_path))
    module = importlib.util.module_from_spec(module_spec)
    if _active_run_state is not None:
        _active_run_state.mark_module(module_name)
    # Register the module so that subsequent imports of the same name
    # resolve to it (this also lets test modules import each other).
    sys.modules[module_name] = module
    module_spec.loader.exec_module(module)
    return module


def logging_setup(session):
    """
    Set up logging based on the global ptf.config
    """

    if ptf.config["log_dir"] != None:
        if os.path.exists(ptf.config["log_dir"]):
            if _caller_uses_log_path(ptf.config["log_dir"], directory=True):
                raise PtfError("PTF log directory contains a caller-owned log file")
            shutil.rmtree(ptf.config["log_dir"])
        os.makedirs(ptf.config["log_dir"])
        ptfutils.chown_to_invoking_user(ptf.config["log_dir"])
    else:
        if (
            ptf.config["log_file"] is not None
            and os.path.exists(ptf.config["log_file"])
            and not _caller_uses_log_path(ptf.config["log_file"])
        ):
            os.remove(ptf.config["log_file"])

    session.start()


def xunit_setup():
    """
    Set up xUnit output based on the global ptf.config
    """

    if not ptf.config["xunit"]:
        return

    if os.path.exists(ptf.config["xunit_dir"]):
        shutil.rmtree(ptf.config["xunit_dir"])
    os.makedirs(ptf.config["xunit_dir"])
    ptfutils.chown_to_invoking_user(ptf.config["xunit_dir"])


def pcap_setup():
    """
    Set up dataplane packet capturing based on the global ptf.config
    """

    if ptf.config["log_dir"] is None and ptf.config["log_file"] is not None:
        filename = os.path.splitext(ptf.config["log_file"])[0] + ".pcap"
        ptf.dataplane_instance.start_pcap(filename)


def profiler_setup():
    """
    Set up profiler based on the global ptf.config; returns the profiler
    object (or None when profiling is disabled).
    """

    if not ptf.config["profile"]:
        return None

    import cProfile

    profiler = cProfile.Profile()
    profiler.enable()

    return profiler


def profiler_teardown(profiler):
    """
    Tear down profiler based on the global ptf.config
    """

    if profiler is None:
        return

    profiler.disable()
    profiler.dump_stats(ptf.config["profile_file"])
    ptfutils.chown_to_invoking_user(ptf.config["profile_file"])


def load_test_modules():
    """
    Load tests from the test_dir directory.

    Test cases are subclasses of unittest.TestCase

    Also updates the _groups member to include "standard" and
    module test groups if appropriate.

    @returns A dictionary from test module names to tuples of
    (module, dictionary from test names to test classes).
    """

    result = OrderedDict()
    loaded_paths = {}

    for root, dirs, filenames in os.walk(ptf.config["test_dir"]):
        pyfiles = fnmatch.filter(filenames, "[!.]*.py")

        # guarantee that files will be visited in the same order every time tests are loaded
        pyfiles.sort()
        dirs.sort()

        if len(pyfiles) == 0:
            continue

        # Allow tests to import each other
        if _active_run_state is not None:
            _active_run_state.add_path(root)
        else:
            sys.path.append(root)

        # Iterate over each python file
        for filename in pyfiles:
            modname = os.path.splitext(os.path.basename(filename))[0]
            source_path = os.path.realpath(os.path.join(root, filename))
            if modname == "ptf":
                raise PtfError("a test module cannot be named 'ptf': %r" % source_path)

            try:
                previous_path = loaded_paths.get(modname)
                if previous_path is not None and previous_path != source_path:
                    raise PtfError(
                        "duplicate test module name %r in %r and %r"
                        % (modname, previous_path, source_path)
                    )
                if previous_path is not None or (
                    _active_run_state is not None
                    and _active_run_state.module_was_loaded(modname, source_path)
                ):
                    mod = sys.modules[modname]
                else:
                    mod = import_module(root, modname)
                loaded_paths[modname] = source_path
            except:
                LOGGER.warning("Could not import file " + filename)
                raise

            # Find all testcases defined in the module
            tests = dict(
                (k, v)
                for (k, v) in mod.__dict__.items()
                if type(v) == type
                and issubclass(v, unittest.TestCase)
                and hasattr(v, "runTest")
            )
            if tests:
                for testname, test in tests.items():
                    # Set default annotation values
                    if "_groups" not in test.__dict__:
                        test._groups = list(getattr(test, "_groups", ()))
                    if not hasattr(test, "_nonstandard"):
                        test._nonstandard = False
                    if not hasattr(test, "_disabled"):
                        test._disabled = False
                    if not hasattr(test, "_testtimeout"):
                        test._testtimeout = None

                    # Put test in its module's test group
                    if not test._disabled:
                        if modname not in test._groups:
                            test._groups.append(modname)
                    else:
                        # If the test is disabled, create a group named
                        # disabled and add it too. This is so that
                        # users can conveniently exclude disabled tests
                        # too when including only groups. Eg.
                        # -s "group1 ^disabled"
                        if "disabled" not in test._groups:
                            test._groups.append("disabled")

                    # Put test in the standard test group
                    if not test._disabled and not test._nonstandard:
                        if "standard" not in test._groups:
                            test._groups.append("standard")
                        if "all" not in test._groups:
                            test._groups.append("all")  # backwards compatibility

                result[modname] = (mod, tests)

    return result


def prune_tests(test_specs, test_modules):
    """
    Return tests matching the given test-specs.
    @param test_specs A list of group names or test names.
    @param test_modules Same format as the output of load_test_modules.
    @returns Same format as the output of load_test_modules.
    """
    result = OrderedDict()
    for e in test_specs:
        matched = False

        if e.startswith("^"):
            negated = True
            e = e[1:]
        else:
            negated = False

        for modname, (mod, tests) in test_modules.items():
            for testname, test in tests.items():
                if e in test._groups or e == "%s.%s" % (modname, testname):
                    result.setdefault(modname, (mod, OrderedDict()))
                    if not negated:
                        # if not hasattr(test, "_versions") or version in test._versions:
                        result[modname][1][testname] = test
                    else:
                        if modname in result and testname in result[modname][1]:
                            del result[modname][1][testname]
                            if not result[modname][1]:
                                del result[modname]
                    matched = True

        if not matched and not negated:
            raise PtfError("test-spec element %s did not match any tests" % e)

    return result


def apply_test_timeout(test, default_test_case_timeout=None):
    original_run = test.run

    def run_with_timeout(self, result=None):
        test_case_timeout = getattr(self, "_testtimeout", None)
        if test_case_timeout is None:
            test_case_timeout = default_test_case_timeout

        if test_case_timeout:
            with ptfutils.Timeout(test_case_timeout):
                return original_run(result)
        return original_run(result)

    test.run = types.MethodType(run_with_timeout, test)
    return test


def parse_test_params(test_params):
    """
    Parse the test parameters. The input accepts three forms: None (no
    parameters), a dictionary (used as given), or a string in the
    'key=value;key=value' syntax of the --test-params command line option.
    The binary and this function evaluate each string value as a Python
    expression.
    @returns A dictionary of parameters, or None.
    """
    if test_params is None:
        LOGGER.debug("No test params were provided with '--test-params' / '-t'")
        return None
    if isinstance(test_params, dict):
        params = dict(test_params)
        LOGGER.debug("Parsed test parameters:")
        for k, v in params.items():
            LOGGER.debug("\t*{}={}".format(k, v))
        return params
    params_str = "class _TestParams:\n    " + test_params
    namespace = {}
    try:
        exec(params_str, namespace)
    except:
        LOGGER.error(
            "Error when parsing test params "
            "(provided with '--test-params' / '-t'). "
            "Make sure you used the correct syntax: "
            '--test-params="[k=v;]*k=v"'
        )
        return None
    params = {}
    LOGGER.debug("Parsed test parameters:")
    for k, v in list(vars(namespace["_TestParams"]).items()):
        if k[:2] != "__":
            params[k] = v
            LOGGER.debug("\t*{}={}".format(k, v))
    LOGGER.debug(
        "If something is missing, make sure you used the correct syntax: "
        '--test-params="[k=v;]*k=v"'
    )
    return params


def _space_to(n, str):
    """
    Generate a string of spaces to achieve width n given string str
    If length of str >= n, return one space
    """
    spaces = n - len(str)
    if spaces > 0:
        return " " * spaces
    return " "


def _print_test_list(test_modules, stream):
    print(
        """\
Tests are shown grouped by module. If a test is in any groups beyond "standard"
and its module's group then they are shown in parentheses.""",
        file=stream,
    )
    print(file=stream)
    print(
        """\
Tests marked with '!' are disabled because they are experimental, special-purpose,
or are too long to be run normally. These are not part of the "standard" test
group or their module's test group.""",
        file=stream,
    )
    print(file=stream)
    print("Test List:", file=stream)
    mod_count = 0
    test_count = 0
    all_groups = set()
    for modname, (mod, tests) in test_modules.items():
        mod_count += 1
        desc = (mod.__doc__ or "No description").strip().split("\n")[0]
        start_str = "  Module " + mod.__name__ + ": "
        print(start_str + _space_to(22, start_str) + desc, file=stream)
        for testname, test in list(tests.items()):
            try:
                desc = (test.__doc__ or "").strip()
                desc = desc.split("\n")[0]
            except:
                desc = "No description"
            groups = set(test._groups) - set(["all", "standard", modname])
            all_groups.update(test._groups)
            if groups:
                desc = "(%s) %s" % (",".join(groups), desc)
            if hasattr(test, "_versions"):
                desc = "(%s) %s" % (",".join(sorted(test._versions)), desc)
            start_str = " %s%s %s:" % (
                test._nonstandard and "*" or " ",
                test._disabled and "!" or " ",
                testname,
            )
            if len(start_str) > 22:
                desc = "\n" + _space_to(22, "") + desc
            print(start_str + _space_to(22, start_str) + desc, file=stream)
            test_count += 1
        print(file=stream)
    print(
        "%d modules shown with a total of %d tests" % (mod_count, test_count),
        file=stream,
    )
    print(file=stream)
    print("Test groups: %s" % (", ".join(sorted(all_groups))), file=stream)


########################################################################
# Test run entry point
########################################################################


def _validate_config(config):
    ts = config.test_selection
    if ts.test_dir is None or not os.path.isdir(ts.test_dir):
        raise PtfError("invalid test directory: %r" % (ts.test_dir,))
    if ts.test_order not in TEST_ORDERS:
        raise PtfError(
            "invalid test order %r, expected one of %s" % (ts.test_order, TEST_ORDERS)
        )
    if config.logging.debug not in DEBUG_LEVELS:
        raise PtfError(
            "invalid debug level %r, expected one of %s"
            % (config.logging.debug, sorted(DEBUG_LEVELS, key=DEBUG_LEVELS.get))
        )


def _coerce_config(config):
    if config is None:
        return PtfConfig()
    if isinstance(config, dict):
        return PtfConfig.from_dict(config)
    if not isinstance(config, PtfConfig):
        raise TypeError("expected a PtfConfig or dict, got %r" % (config,))
    return config


def run(config=None, *, output=None, _manage_signals=False):
    # type: (Union[PtfConfig, Dict[str, Any], None], Optional[RunOutput], bool) -> int
    """Run PTF tests as described by the given configuration.

    @param config A PtfConfig instance, or a dictionary in the flat
    'ptf.config' format. run() converts a dictionary with
    PtfConfig.from_dict. None is the same as a default PtfConfig.
    @return The exit code that the ptf binary produces for the same
    configuration: 0 on success, 0 for the list modes, 1 when a test
    failed, errored, or was skipped while fail_skipped is set.

    A fatal configuration or environment problem raises PtfError. Exactly
    one in-process run may be active. Independent PTF processes can run in
    parallel.

    ``run()`` restores PTF configuration, imports, random state, logging,
    profiling, and test utility globals.
    It does not change SIGINT. Signal-based per-test timeouts require the main
    thread. ``output`` controls framework streams and optional logging
    forwarding without becoming part of the serializable configuration.
    """
    config = _coerce_config(config)
    _validate_config(config)
    output = output or RunOutput()
    if not isinstance(output, RunOutput):
        raise TypeError("output must be a RunOutput, got %r" % (output,))
    output = RunOutput(
        stdout=sys.stdout if output.stdout is None else output.stdout,
        stderr=sys.stderr if output.stderr is None else output.stderr,
        logger=output.logger,
        capture_root_logging=output.capture_root_logging,
    )
    if _manage_signals and threading.current_thread() is not threading.main_thread():
        raise PtfError("process signal management requires the main Python thread")
    if not _RUN_LOCK.acquire(blocking=False):
        raise PtfError(
            "another in-process PTF run is active; parallel PTF runs require "
            "separate processes"
        )

    global _active_run_state
    state = None
    session = None
    saved_sigint_handler = _MISSING
    try:
        state = _RunState(config)
        _active_run_state = state
        config_dict = config.to_dict()
        if config_dict["packet_manipulation_module"] is None:
            config_dict["packet_manipulation_module"] = (
                os.environ.get("PTF_PACKET_MANIPULATION_MODULE")
                or DEFAULT_PACKET_MANIPULATION_MODULE
            )
        state.activate(config_dict)
        if _manage_signals:
            saved_sigint_handler = signal.getsignal(signal.SIGINT)
            signal.signal(signal.SIGINT, signal.SIG_DFL)

        session = _LoggingSession(config, output)
        logging_setup(session)
        xunit_setup()
        LOGGER.info("++++++++ " + time.asctime() + " ++++++++")
        try:
            return _execute(config, output, state)
        except PtfError as error:
            LOGGER.critical(str(error))
            error._ptf_logged = True
            raise
    finally:
        had_exception = sys.exc_info()[0] is not None
        cleanup_errors = []
        try:
            if state is not None:
                cleanup_errors.extend(state.close_resources())
            if saved_sigint_handler is not _MISSING:
                try:
                    signal.signal(signal.SIGINT, saved_sigint_handler)
                except Exception as error:
                    LOGGER.exception("Failed to restore the SIGINT handler")
                    cleanup_errors.append(error)
            if session is not None:
                try:
                    session.close()
                except Exception as error:
                    cleanup_errors.append(error)
        finally:
            _active_run_state = None
            try:
                if state is not None:
                    try:
                        state.restore()
                    except Exception as error:
                        cleanup_errors.append(error)
            finally:
                _RUN_LOCK.release()
        if cleanup_errors and not had_exception:
            error = PtfError(
                "PTF cleanup failed: %s"
                % "; ".join(str(error) for error in cleanup_errors)
            )
            raise error


def _execute(config, output, state):
    # type: (PtfConfig) -> int
    # The actual test run. This function assumes that the global ptf.config
    # is populated and that logging is set up. It returns the exit code.

    # Import after logging is configured. This silences the scapy error
    # logs from the import of packet.py, and logs the warnings of ptf
    # correctly.
    packet_module = sys.modules.get("ptf.packet")
    requested_packet_config = {
        name: ptf.config[name]
        for name in (
            "disable_ipv6",
            "disable_vxlan",
            "disable_erspan",
            "disable_geneve",
            "disable_mpls",
            "disable_nvgre",
            "disable_igmp",
            "disable_rocev2",
        )
    }
    if packet_module is not None:
        loaded_packet_module = getattr(
            packet_module, "_packet_manipulation_module", None
        )
        loaded_packet_config = getattr(packet_module, "_packet_config", None)
        if (
            loaded_packet_module != ptf.config["packet_manipulation_module"]
            or loaded_packet_config != requested_packet_config
        ):
            raise PtfError(
                "the requested packet configuration differs from the one already "
                "loaded in this process; start a new PTF process"
            )
    else:
        backend_module = sys.modules.get(ptf.config["packet_manipulation_module"])
        backend_config = getattr(backend_module, "_ptf_packet_config", None)
        if backend_config is not None and backend_config != requested_packet_config:
            raise PtfError(
                "the requested packet configuration differs from the packet backend "
                "already loaded in this process; start a new PTF process"
            )

    testutils = importlib.import_module("ptf.testutils")

    state.capture_testutils(testutils)

    # Parse the test parameters and log them. Do this before the test
    # modules are imported: a test may read its parameters at import
    # time.
    testutils.TEST_PARAMS = parse_test_params(config.test_behavior.test_params)
    testutils.PORT_INFO = dict(ptf.config["port_info"])
    testutils.MINSIZE = ptf.config["minsize"]
    testutils.skipped_test_count = 0
    testutils.FILTERS.clear()
    ptfutils.default_timeout = ptf.config["default_timeout"]
    ptfutils.default_negative_timeout = ptf.config["default_negative_timeout"]

    test_specs = list(config.test_selection.test_specs)
    if ptf.config["test_file"] != None:
        with open(ptf.config["test_file"], "r") as f:
            for line in f:
                line, _, _ = line.partition("#")  # remove comments
                line = line.strip()
                if line:
                    test_specs.append(line)
    if test_specs == []:
        test_specs = ["standard"]

    test_modules = load_test_modules()

    # Check if test list is requested; display and return if so
    if ptf.config["list"]:
        _print_test_list(test_modules, output.stdout)
        return 0

    test_modules = prune_tests(test_specs, test_modules)

    # Check if test list is requested; display and return if so
    if ptf.config["list_test_names"]:
        for modname, (mod, tests) in test_modules.items():
            for testname, test in tests.items():
                print("%s.%s" % (modname, testname), file=output.stdout)
        return 0

    # Generate the test suite
    test_suite = []
    for modname, (mod, tests) in test_modules.items():
        for testname, test in tests.items():
            test_suite.append(test())

    if ptf.config["shard_id"] < 0 or ptf.config["shard_id"] >= ptf.config["num_shards"]:
        raise PtfError(
            "shard id should be equal or greater than 0 and lower than number of shards"
        )
    test_suite = test_suite[ptf.config["shard_id"] :: ptf.config["num_shards"]]

    if ptf.config["test_order"] == "lexico":
        test_suite.sort()
    elif ptf.config["test_order"] == "rand":
        seed = ptf.config["test_order_seed"]
        random.seed(seed)
        random.shuffle(test_suite)

    if threading.current_thread() is not threading.main_thread():
        for test in test_suite:
            timeout = getattr(test, "_testtimeout", None)
            if timeout is None:
                timeout = ptf.config["test_case_timeout"]
            if timeout and timeout > 0:
                raise PtfError("test-case timeouts require the main Python thread")

    test_suite = [
        apply_test_timeout(test, ptf.config["test_case_timeout"]) for test in test_suite
    ]
    test_suite = unittest.TestSuite(test_suite)

    if ptf.config["platform_dir"] is None:
        from ptf import platforms

        ptf.config["platform_dir"] = os.path.dirname(
            os.path.abspath(platforms.__file__)
        )

    # Allow platforms to import each other
    state.add_path(ptf.config["platform_dir"])
    state.track_root(ptf.config["platform_dir"])

    # Load the platform module
    platform_name = ptf.config["platform"]
    LOGGER.info("Importing platform: " + platform_name)

    # TODO(antonin): put this check in platforms/nn.py ?
    if platform_name == "nn":
        try:
            import pynng  # noqa: F401 pylint: disable=unused-import
        except ImportError:
            raise PtfError("Cannot use 'nn' platform if pynng package is not installed")

    platform_mod = None
    try:
        platform_mod = import_module(ptf.config["platform_dir"], platform_name)
    except:
        LOGGER.warning("Failed to import " + platform_name + " platform module")
        raise
    state.platform_module = platform_mod

    try:
        platform_mod.platform_config_update(ptf.config)
    except:
        LOGGER.warning("Could not run platform host configuration")
        raise

    if ptf.config["port_map"] is None:
        raise PtfError("Interface port map was not defined by the platform. Exiting.")

    LOGGER.debug("Configuration: " + str(ptf.config))
    LOGGER.info("port map: " + str(ptf.config["port_map"]))

    if os.getuid() != 0 and not ptf.config["allow_user"] and platform_name != "nn":
        raise PtfError(
            "Super-user privileges required. Please re-run with sudo or as root."
        )

    if ptf.config["random_seed"] is not None:
        LOGGER.info("Random seed: %d" % ptf.config["random_seed"])
        random.seed(ptf.config["random_seed"])
    else:
        # Generate random seed and report to log file
        seed = random.randrange(100000000)
        LOGGER.info("Autogen random seed: %d" % seed)
        random.seed(seed)

    profiler = profiler_setup()
    try:
        if ptf.config["port_map"]:
            dataplane = importlib.import_module("ptf.dataplane")

            # Set up the dataplane only when the selected platform exposes ports.
            state.dataplane = dataplane.DataPlane(ptf.config)
            ptf.dataplane_instance = state.dataplane
            pcap_setup()
            for port_id, ifname in ptf.config["port_map"].items():
                device, port = port_id
                ptf.dataplane_instance.port_add(ifname, device, port)
        else:
            ptf.dataplane_instance = None

        LOGGER.info("*** TEST RUN START: " + time.asctime())
        if ptf.config["xunit"]:
            try:
                import xmlrunner  # fail-fast if module missing
            except ImportError:
                raise
            test_runner = xmlrunner.XMLTestRunner(
                output=ptf.config["xunit_dir"],
                outsuffix="",
                verbosity=2,
                failfast=ptf.config["failfast"],
                stream=output.stderr,
            )
        else:
            test_runner = unittest.TextTestRunner(
                verbosity=2,
                failfast=ptf.config["failfast"],
                stream=output.stderr,
            )
        result = test_runner.run(test_suite)
        if ptf.config["xunit"]:
            # The XML result files are only written once the run completes.
            ptfutils.chown_to_invoking_user(ptf.config["xunit_dir"], recursive=True)
        run_failures = result.failures
        run_errors = result.errors
        run_timeouts = []
        for case in result.errors:
            traceback_str = case[1]
            # TODO: hacky? could not think of a better way
            if "raise Timeout.TimeoutError()" in traceback_str:
                LOGGER.info("Test case failed because of timeout")
                run_timeouts.append(case)

        ptf.open_logfile("main")
        testutils.skipped_test_count = len(getattr(result, "skipped", ()))
        if testutils.skipped_test_count > 0:
            ts = " tests"
            if testutils.skipped_test_count == 1:
                ts = " test"
            LOGGER.info("Skipped " + str(testutils.skipped_test_count) + ts)
            print(
                "Skipped " + str(testutils.skipped_test_count) + ts,
                file=output.stdout,
            )
        LOGGER.info("*** TEST RUN END  : " + time.asctime())

        if run_failures or run_errors:
            print(file=output.stdout)
            print("******************************************", file=output.stdout)
            print("ATTENTION: SOME TESTS DID NOT PASS!!!", file=output.stdout)
            if (not ptf.config["xunit"]) and run_failures:
                print(file=output.stdout)
                print("The following tests failed:", file=output.stdout)
                print(
                    ", ".join([f[0].__class__.__name__ for f in run_failures]),
                    file=output.stdout,
                )
            if (not ptf.config["xunit"]) and run_errors:
                print(file=output.stdout)
                print("The following tests errored:", file=output.stdout)
                print(
                    ", ".join([f[0].__class__.__name__ for f in run_errors]),
                    file=output.stdout,
                )
            if (not ptf.config["xunit"]) and run_timeouts:
                print(file=output.stdout)
                print(
                    "The following tests errored because of a timeout:",
                    file=output.stdout,
                )
                print(
                    ", ".join([f[0].__class__.__name__ for f in run_timeouts]),
                    file=output.stdout,
                )
            print(file=output.stdout)
            print("******************************************", file=output.stdout)
            return 1
        if testutils.skipped_test_count > 0 and ptf.config["fail_skipped"]:
            print(file=output.stdout)
            print("******************************************", file=output.stdout)
            print(
                "ATTENTION: %d TESTS WERE SKIPPED!!!" % testutils.skipped_test_count,
                file=output.stdout,
            )
            print("******************************************", file=output.stdout)
            print(file=output.stdout)
            return 1
        return 0
    finally:
        profiler_teardown(profiler)


if __name__ == "__main__":
    # Run PTF tests from a serialized PtfConfig, without the command line
    # parser of the ptf binary:
    #     python -m ptf.runner <config-file>
    # Use this entry point to start PTF as a Python process, for example
    # inside a network namespace, and to keep the configuration structured.
    import argparse

    parser = argparse.ArgumentParser(
        prog="python -m ptf.runner",
        description="Run PTF tests described by a PtfConfig JSON file "
        "(see ptf.runner.PtfConfig.to_json).",
    )
    parser.add_argument(
        "config_file", help="Path to the PtfConfig JSON file, or - to read stdin"
    )
    args = parser.parse_args()
    if args.config_file == "-":
        _config = PtfConfig.from_json(sys.stdin.read())
    else:
        with open(args.config_file, "r") as f:
            _config = PtfConfig.from_json(f.read())
    try:
        _rc = run(
            _config,
            output=RunOutput(capture_root_logging=True),
            _manage_signals=True,
        )
    except PtfError as error:
        if not getattr(error, "_ptf_logged", False):
            print("PTF error: %s" % error, file=sys.stderr)
        _rc = 1
    # A normal exit can hang when non-daemon threads are still active;
    # see ptf.cli.main.
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(_rc)
