PTF Packet Testing Framework

---

# Introduction

PTF is a Python based dataplane test framework. It is based on unittest, which
is included in the standard Python distribution.

This document is meant to provide an introduction to the framework, discuss the
basics of running tests and to provide examples of how to add tests.

Most of the code was taken from the [OFTest
framework](https://github.com/floodlight/oftest). However, PTF focuses on the
dataplane and is independent of OpenFlow. We also added several
[new features](#New-features).

---

# Longer Start

## Dependencies

The following software is required to run PTF:

 * Python 2.7 or 3.x
 * Scapy 2.4.4
 * pypcap (optional - VLAN tests will fail without this)
 * tcpdump (optional - Scapy will complain if it's missing)

Root/sudo privilege is required on the host, in order to run `ptf`.

## Run PTF

Once you have written tests and your switch is running, you can run 'ptf'. Use
`--help` to see command line switches.

For example:

    sudo ./ptf --test-dir mytests/ --pypath $PWD \
    	 --interface 0@veth1 --interface 1@veth3 --interface 2@veth5 \
    	 --interface 3@veth7 --interface 4@veth9 --interface 5@veth11 \
    	 --interface 6@veth13 --interface 7@veth15 --interface 8@veth17

This will run all the tests included in the `mytests` directory. The `--pypath`
option can be used to easily add directories to the Python PATH. This is useful
if you use a Python interface to configure your data plane (as part of your
tests). The `--interface` option (or `-i`) can be used to specify the interfaces
on which to inject packets (along with the corresponding port number).

## Install PTF

PTF can be installed by running `sudo python setup.py install`. For more
information on the different options accepted by `setup.py` (e.g. installing in
a custom location), please refer to the [setuptools documentation]
(https://pythonhosted.org/setuptools/setuptools.html).

---

# Writing tests for your switch

Take a look at the `example` directory. This is not a working example as it is
(the switch is not included), but it will show you how to write tests. This
directory contains the following:

* `run_client.sh`: a wrapper around `ptf`
* `switch_sai_thrift`: empty directory, this is where the Python bindings to
  program the switch's control plane would be copied
* `mytests/sai_base_test.py`: a wrapper Python class around PTF's BaseTest
  class. It is the base class for all the tests we added to `mytests/switch.py`
* `mytests/switch.py`: some example tests

## Running the example

If you want to run the example, you will need to obtain
[p4factory](https://github.com/p4lang/p4factory). For the following, I will
assume that you cloned the repository and installed the dependencies. I will
assume that environment variable `P4FACTORY` contains the path to the cloned
repository.

First, you need to create the required veths:

    cd $P4FACTORY/tools/
    sudo ./veth_setup.sh

The next step is to compile the target switch and to run it:

    cd $P4FACTORY/targets/switch/
    make bm-switchsai
    sudo ./behavioral-model

Finally, you can run the example tests:

    cd <ptf-dir>/example/
    sudo ../ptf --test-dir mytests/ \
    	 --pypath $P4FACTORY/targets/switch/tests/pd_thrift/
    	 --interface 0@veth1 --interface 1@veth3 --interface 2@veth5 \
    	 --interface 3@veth7 --interface 4@veth9 --interface 5@veth11 \
    	 --interface 6@veth13 --interface 7@veth15 --interface 8@veth17

---

# New features

We added the following features to the base OFTest framework:

## Filters

They can be used to discard some of the packets received from the switch. Take a
look at [sai_base_test.py](example/mytests/sai_base_test.py) for an example. You
will see the following code `testutils.add_filter(testutils.not_ipv6_filter)`
which tells PTF to discard received IPv6 packets. You can add your own filters
(they have to be callable Python objects which take a Scapy packet as input).

## Ternary matching

A PTF test -just like an OFTest test- matches the received packets against
expected packets. This is an exact match. However, sometimes one does not care
about all the fields in the packets. PTF introduces the Mask class which lets
you specified some field you do not care about when performing the match. For
example:

    import mask
    m = mask.Mask(expected_pkt)
    m.set_do_not_care_scapy(IP, 'ttl')
    verify_packets(<test>, m, <port list>)

## Test timeout

A timeout for test cases can be specified using the `--test-case-timeout`
command line option. This timeout must be expressed in seconds. A timeout of 0
is the same as no timeout (the default). If the timeout expires before the test
is done executing, an exception will be raised and the test counts as an
error. A timeout can also be specified for each individual test case, using the
`@testtimeout` decorator, which needs to be imported from `ptf.testutils`. This
timeout takes precedence over the global timeout passed on the command line.

---

# Configuring PTF

## Platforms

The "platform" is a configuration file (written in Python) that tells PTF how to
send packets to and receive packets from the dataplane of the switch.

### `eth`

The default platform, `eth`, uses Linux Ethernet interfaces and is configured
with the `-i` option (or `--interface`). Pass the option as `-i
ofport@interface`, for example `-i 1@eth1`. If no `-i` options are given the the
default configuration uses vEths.

### `remote`

Another common platform, `remote`, provides support for testing of switches on a
different host. This can be useful for cases where interfaces are not available
on one host (i.e. they're not bound to a Linux interface driver) or where PTF
cannot run on the same host (unsupported OS, missing software, etc.).

This can be enable by modifying the `platforms/remote.py` file to point to 4
NICs on the host running PTF, like so:

    remote_port_map = {
        (0, 23) : "eth2", # port 23 of device 0 is connected to physical port on the server eth2
        (0, 24) : "eth3", # port 24 of device 0 is connected to physical port on the server eth3
        (0, 25) : "eth4",
        (0, 26) : "eth5"
    }

### `nn`

We introduce a new platform, `nn`, which uses [nanomsg] (http://nanomsg.org/) to
send and receive packet to the switch. We support IPC and TCP nanomsg
sockets. When using this platform, you need to make sure that the Python package
[nnpy] (https://github.com/nanomsg/nnpy) is installed. With `nn`, do not use
`--interface`, instead use `--device-socket`. For each device, you need to
provide a list of enabled ports and a nanomsg socket address. For example:

    --device-socket 0-{1,2,5-8}@ipc:///tmp/bmv2_packets_1.ipc

This command will enable ports 1, 2, 5, 6, 7, 8 on device 0. Packets for device
0 will be captured and send on IPC socket `ipc:///tmp/bmv2_packets_1.ipc`.

## Passing Parameters to Tests

There is a facility for passing test-specific parameters into tests that works as follows. On the command line, give the parameter

    --test-params="key1=17;key2=True"

You can then access these parameters in your tests' Pyhton code using the
following code:

    import ptf.testutils as testutils
    # Returns a dictionary which includes all your parameters
    test_params = testutils.test_params_get()
    # Returns the value of the parameter "param", or None if not found
    param_value = testutils.test_param_get("param")

Take a look at [sai_base_test.py](example/mytests/sai_base_test.py) for an
example.

## Grouping Tests together

It is very easy to create groups of tests, using the provided `group` Python
decorator. Simply decorate your test with `@group(<name of group>)`.

Take a look at [switch.py](example/mytests/switch.py) for an example.

One given test can belong to several groups. You can choose to run only the
tests belonging to a given group using a command like this one:

    sudo ./ptf --test-dir mytests/ --pypath $PWD <name of group>

We also provide a convenient `disabled` decorator for tests.

## Support for multidevice tests

The original OFTest was meant to unit test a single OF-compliant switch. With
PTF, we tried to add support for testing a network of several devices. If you do
not intend to use this multi-device feature, you do not need to worry about it,
it should not impact you. If you want to leverage this feature, here is what you
need to do:

* when adding interfaces, instead of writing `<port_number>@<interface_name>`,
  you need to write `<device_number>-<port_number>@<interface_name>`
* when sending a packet, the port number becomes a tuple (device, port):
  `send_packet(self, (<device_number>, <port_number>), pkt)`
* the `verify_*` functions where also updated to include device information. For
  example: `verify_packets(self, pkt, device_number=<device_number>,
  ports=<port_list>)`. For more information, you can take a look at these
  functions in [src/ptf/dataplane.py](src/ptf/dataplane.py).

---
