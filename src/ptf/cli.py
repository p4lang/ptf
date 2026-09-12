# Copyright 2010 The Board of Trustees of The Leland Stanford Junior University
# SPDX-License-Identifier: Apache-2.0

# This file was derived from code in the Floodlight OFTest repository
# https://github.com/floodlight/oftest released under the OpenFlow
# Software License:
# https://github.com/floodlight/oftest/blob/master/LICENSE
# See file README-oftest.md in the ptf repository for more details.

"""
PTF command line interface.

This module contains the command line parser of the ``ptf`` binary. It
converts the parsed arguments to a :class:`ptf.runner.PtfConfig` object.
The test-run logic is in :mod:`ptf.runner`. The ``ptf`` binary and
``python -m ptf`` call :func:`main` in this module.
"""

import argparse
import logging
import os
import sys

import ptf
from ptf import __version__, runner


def build_parser():
    # type: () -> argparse.ArgumentParser
    """Build the command line parser of the ptf binary.

    To add a new command line option, add an argument in this function.
    Then add the matching field to ptf.runner.PtfConfig, or to one of its
    option groups. The value of the option ends up in the global
    ptf.config dictionary."""

    usage = "usage: ptf [options] --test-dir TEST_DIR [tests]"

    description = """PTF (Packet Test Framework) is a framework and set of tests
to test a software switch. It is strongly inspired by the OFTest framework, but
it is not tied to OpenFlow. It does not provide any control plane features, but
it is targetted at helping you test a dataplane.

The default configuration assumes that interfaces veth1, veth3, veth5, and veth7
should be connected to the switch's dataplane.

If no positional arguments are given then OFTest will run all tests found in the
--test-dir directory. Otherwise each positional argument is interpreted as
either a test name or a test group name. The union of these will be executed. To
see what groups each test belongs to use the --list option. Tests and groups can
be subtracted from the result by prefixing them with the '^' character.  """

    class ActionInterface(argparse.Action):
        def __call__(self, parser, namespace, values, option_string=None):
            # Parse --interface
            def check_interface(value):
                port_cfg = {}
                sp = ";"
                try:
                    if sp in value:
                        value, p_info = value.split(sp, 1)
                        params = p_info.split(sp)
                        for elem in params:
                            key, val = elem.split("=")
                            port_cfg[key.lower()] = val
                    dev_and_port, interface = value.split("@", 1)
                    dev_and_port = dev_and_port.split("-")
                    if len(dev_and_port) == 1:
                        dev, port = 0, int(dev_and_port[0])
                    elif len(dev_and_port) == 2:
                        dev, port = int(dev_and_port[0]), int(dev_and_port[1])
                    else:
                        raise ValueError("")
                    if port_cfg:
                        getattr(namespace, "port_info")[port] = port_cfg
                except ValueError:
                    parser.error(
                        "incorrect interface syntax (got %s, expected 'port@interface' or 'device-port@interface' \
                                  or providing port configuration using 'device-port@interface;arg=val;arg2=val...' )"
                        % repr(value)
                    )
                return (dev, port, interface)

            assert type(values) is str
            getattr(namespace, self.dest).append(check_interface(values))

    class ActionDeviceSocket(argparse.Action):
        def __call__(self, parser, namespace, values, option_string=None):
            # Parse --device-socket
            def check_device_socket(value):
                def parse_ports(ports):
                    port_set = set()
                    try:
                        ports = ports.strip("{}")
                        ports = ports.split(",")
                    except:
                        raise ValueError("")
                    for port in ports:
                        try:
                            p = int(port)
                            port_set.add(p)
                            continue
                        except:
                            pass
                        try:
                            p1, p2 = port.split("-", 1)
                            p1, p2 = int(p1), int(p2)
                            for p in range(p1, p2 + 1):  # p2 included
                                port_set.add(p)
                        except:
                            raise ValueError("")
                    return port_set

                try:
                    dev_and_port, addr = value.split("@", 1)
                    if dev_and_port[0] == "{":
                        dev, ports = (0, parse_ports(dev_and_port))
                    else:
                        dev_and_port = dev_and_port.split("-", 1)
                        if len(dev_and_port) != 2:
                            raise ValueError("")
                        dev, ports = (
                            int(dev_and_port[0]),
                            parse_ports(dev_and_port[1]),
                        )
                except ValueError:
                    parser.error(
                        "incorrect device-socket syntax (got %s, expected something of the form 0-{1,2,5-8}@<socket addr>)"
                        % repr(value)
                    )
                return (dev, ports, addr)

            assert type(values) is str
            getattr(namespace, self.dest).append(check_device_socket(values))

    class ActionTestDir(argparse.Action):
        def __call__(self, parser, namespace, values, option_string=None):
            assert type(values) is str
            if not os.path.isdir(values):
                parser.error(
                    "invalid value for --test-dir: directory %s does not exist" % values
                )
            setattr(namespace, self.dest, values)

    parser = argparse.ArgumentParser(usage=usage, description=description)

    # The default values come from PtfConfig. PtfConfig is the single
    # source of truth for the defaults; this file duplicated the defaults
    # before. to_dict() always creates new containers. Parsers therefore
    # do not share state.
    defaults = runner.PtfConfig().to_dict()
    defaults.pop("test_spec")  # legacy key, not a command line option
    defaults.pop("port_map")  # the platform fills this key at run time
    parser.set_defaults(**defaults)

    parser.add_argument("--version", action="version", version=__version__)

    parser.add_argument("test_specs", nargs="*", help="Tests / Groups to run")

    parser.add_argument("--list", action="store_true", help="List all tests and exit")
    parser.add_argument(
        "--list-test-names",
        action="store_true",
        help="List test names matching the test spec and exit",
    )
    parser.add_argument(
        "--allow-user",
        action="store_true",
        help="Proceed even if ptf is not run as root",
    )

    parser.add_argument("--pypath", dest="pypath", action="append")

    parser.add_argument(
        "-pmm",
        "--packet-manipulation-module",
        type=str,
        help="Provide packet manipulation module which should be used "
        "as a 'packet' one for other PTF modules",
    )

    group = parser.add_argument_group("Test selection options")
    group.add_argument("-f", "--test-file", help="File of tests to run, one per line")
    group.add_argument(
        "--test-dir",
        type=str,
        action=ActionTestDir,
        required=True,
        help="Directory containing tests",
    )
    test_order_help = """Choose the order in which the tests will be run:
    default (tests are run in the order in which they appear on command line),
    lexico (use default string ordering on test names),
    rand (random order, use --test-order-seed to specify a seed)
    """
    group.add_argument(
        "--test-order", choices=list(runner.TEST_ORDERS), help=test_order_help
    )
    group.add_argument(
        "--test-order-seed", type=int, help="Specify seed to randomize test order"
    )
    group.add_argument(
        "--num-shards",
        type=int,
        help="Number of shards that can be used to parallelize test execution",
    )
    group.add_argument(
        "--shard-id", type=int, help="Index of shard (>= 0 and < number of shards)"
    )

    group = parser.add_argument_group("Switch connection options")
    group.add_argument("-P", "--platform", help="Platform module name")
    group.add_argument(
        "-a", "--platform-args", help="Custom arguments for the platform"
    )
    group.add_argument(
        "--platform-dir", type=str, help="Directory containing platform modules"
    )
    group.add_argument(
        "--interface",
        "-i",
        type=str,
        dest="interfaces",
        metavar="INTERFACE",
        action=ActionInterface,
        help="Specify a port number and the dataplane interface to use. May be given multiple times. Example: 1@eth1 or 0-1@eth2 (use eth2 as port 1 of device 0)",
    )
    group.add_argument(
        "--device-socket",
        type=str,
        dest="device_sockets",
        metavar="DEVICE-SOCKET",
        action=ActionDeviceSocket,
        help="Specify the nanomsg socket to use to send / receive packets for a given device, as well as the ports to enable on the device. May be given multiple times. Example: 0-{1,2,5-8}@<socket addr>",
    )

    group = parser.add_argument_group("Logging options")
    group.add_argument("--log-file", help="Name of log file")
    group.add_argument("--log-dir", help="Name of log directory")
    dbg_lvl_names = sorted(
        list(runner.DEBUG_LEVELS.keys()), key=lambda x: runner.DEBUG_LEVELS[x]
    )
    group.add_argument(
        "--debug",
        choices=dbg_lvl_names,
        help="Debug lvl: debug, info, warning, error, critical",
    )
    group.add_argument(
        "--verbose",
        action="store_const",
        dest="debug",
        const="verbose",
        help="Shortcut for --debug=verbose",
    )
    group.add_argument(
        "-q",
        "--quiet",
        action="store_const",
        dest="debug",
        const="warning",
        help="Shortcut for --debug=warning",
    )
    group.add_argument("--profile", action="store_true", help="Enable Python profiling")
    group.add_argument("--profile-file", help="Output file for Python profiler")
    group.add_argument(
        "--xunit", action="store_true", help="Enable xUnit-formatted results"
    )
    group.add_argument(
        "--xunit-dir", help="Output directory for xUnit-formatted results"
    )

    group = parser.add_argument_group("Test behavior options")
    group.add_argument(
        "--relax",
        action="store_true",
        help="Relax packet match checks allowing other packets",
    )
    group.add_argument(
        "--failfast",
        action="store_true",
        help="Stop running tests as soon as one fails",
    )
    test_params_help = """Set test parameters: [key=val]*;key=val
    """
    group.add_argument("-t", "--test-params", help=test_params_help)
    group.add_argument(
        "--fail-skipped",
        action="store_true",
        help="Return failure if any test was skipped",
    )
    group.add_argument(
        "--default-timeout", type=float, help="Timeout in seconds for most operations"
    )
    group.add_argument(
        "--default-negative-timeout",
        type=float,
        help="Timeout in seconds for negative checks",
    )
    group.add_argument(
        "--minsize", type=int, help="Minimum allowable packet size on the dataplane."
    )
    group.add_argument("--random-seed", type=int, help="Random number generator seed")
    group.add_argument("--disable-ipv6", action="store_true", help="Disable IPv6 tests")
    group.add_argument("--qlen", type=int, help="Default queue length ")
    group.add_argument(
        "--test-case-timeout",
        type=int,
        help="Timeout for each test case, 0 means no timeout",
    )

    group.add_argument(
        "--disable-vxlan",
        action="store_true",
        help="Disable VXLAN (do not import from scapy even if supported)",
    )
    group.add_argument(
        "--disable-geneve",
        action="store_true",
        help="Disable GENEVE (do not import from scapy even if supported)",
    )
    group.add_argument(
        "--disable-erspan",
        action="store_true",
        help="Disable ERSPAN (do not import from scapy even if supported)",
    )
    group.add_argument(
        "--disable-mpls",
        action="store_true",
        help="Disable MPLS (do not import from scapy even if supported)",
    )
    group.add_argument(
        "--disable-nvgre",
        action="store_true",
        help="Disable NVGRE (do not import from scapy even if supported)",
    )
    group.add_argument(
        "--disable-igmp",
        action="store_true",
        help="Disable IGMP (do not import from scapy even if supported)",
    )

    group = parser.add_argument_group("Socket options")
    group.add_argument(
        "--socket-recv-size",
        type=int,
        help="When using raw sockets, specify the size of the buffer used to receive packets with socket.recv.",
    )

    return parser


def config_from_args(args):
    # type: (argparse.Namespace) -> runner.PtfConfig
    """Convert parsed command line arguments to a PtfConfig."""
    return runner.PtfConfig(
        list_tests=args.list,
        list_test_names=args.list_test_names,
        allow_user=args.allow_user,
        packet_manipulation_module=args.packet_manipulation_module,
        pypath=list(args.pypath or []),
        test_selection=runner.TestSelectionOptions(
            test_dir=args.test_dir,
            test_specs=list(args.test_specs),
            test_file=args.test_file,
            test_order=args.test_order,
            test_order_seed=args.test_order_seed,
            num_shards=args.num_shards,
            shard_id=args.shard_id,
        ),
        platform=runner.PlatformOptions(
            platform=args.platform,
            platform_args=args.platform_args,
            platform_dir=args.platform_dir,
            interfaces=[runner.Interface(*i) for i in args.interfaces],
            device_sockets=[
                runner.DeviceSocket(device=s[0], ports=set(s[1]), address=s[2])
                for s in args.device_sockets
            ],
            port_info={int(port): dict(info) for port, info in args.port_info.items()},
        ),
        logging=runner.LoggingOptions(
            log_file=args.log_file,
            log_dir=args.log_dir,
            debug=args.debug,
            profile=args.profile,
            profile_file=args.profile_file,
            xunit=args.xunit,
            xunit_dir=args.xunit_dir,
        ),
        test_behavior=runner.TestBehaviorOptions(
            relax=args.relax,
            failfast=args.failfast,
            fail_skipped=args.fail_skipped,
            test_params=args.test_params,
            default_timeout=args.default_timeout,
            default_negative_timeout=args.default_negative_timeout,
            minsize=args.minsize,
            random_seed=args.random_seed,
            test_case_timeout=args.test_case_timeout,
            qlen=args.qlen,
            disable_ipv6=args.disable_ipv6,
            disable_vxlan=args.disable_vxlan,
            disable_erspan=args.disable_erspan,
            disable_geneve=args.disable_geneve,
            disable_mpls=args.disable_mpls,
            disable_nvgre=args.disable_nvgre,
            disable_igmp=args.disable_igmp,
            disable_rocev2=args.disable_rocev2,
        ),
        socket=runner.SocketOptions(socket_recv_size=args.socket_recv_size),
    )


def main(argv=None):
    # type: (list) -> int
    """Parse the command line, build a PtfConfig, and run the tests.

    When the run fails, this function does not return: it calls
    os._exit(rc), as the ptf script did before. A normal exit can hang
    when non-daemon threads are active. Call this function only from a
    process entry point: the ptf binary or python -m ptf."""
    parser = build_parser()
    args = parser.parse_args(argv)
    config = config_from_args(args)
    try:
        rc = runner.run(
            config,
            output=runner.RunOutput(capture_root_logging=True),
            _manage_signals=True,
        )
    except runner.PtfError as e:
        if not getattr(e, "_ptf_logged", False):
            logging.critical(str(e))
        rc = 1
    if rc != 0:
        # A normal exit can hang when non-daemon threads are active.
        sys.stdout.flush()
        sys.stderr.flush()
        os._exit(rc)
    return rc
