# Copyright (c) 2021 Intel Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

###############################################################################
""" IP helpers """
import platform
import re
import six
import subprocess

IP_REGEX = (
    r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.)"
    r"{3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
)


def _get_src_ip_addr_system_independent(cmd, output_regex):
    try:
        process = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE)
        output, error = process.communicate()
        ret_code = process.returncode
    except (OSError, ValueError, subprocess.CalledProcessError) as ex:
        raise OSError(ex)
    if error:
        raise OSError(ret_code, error)

    try:
        return next(match for match in re.findall(output_regex, six.ensure_str(output)))
    except StopIteration:
        raise RuntimeError("Could not get egress IP from OS")


def get_src_ip_addr(dst_ip):
    """Retrieves egress IP for given destination IP address

    Supported OS: Windows, Linux

    :param dst_ip: destination IP address
    :type dst_ip: basestring
    :return: egress IP address
    :rtype: str
    :raise TypeError: when provided destination IP is not of string type
    :raise ValueError: when provided destination IP is invalid
    :raise OSError: when running subprocess command exits with non-zero status
    :raise RuntimeError: when function could not get egress IP for other reason than in other defined exceptions; or when run on not supported OS
    """
    if not isinstance(dst_ip, six.string_types):
        raise TypeError("Provided dst IP %s is not of string type" % dst_ip)
    if not re.match(IP_REGEX, dst_ip):
        raise ValueError("Provided dst IP %s is invalid" % dst_ip)

    system = platform.system()
    if not system:
        import os

        system = os.name

    if system in ("Windows", "nt"):
        cmd = "pathping -n -w 1 -h 1 -q 1 %s" % dst_ip
        output_regex = r"0\s*(?P<ipaddr>" + IP_REGEX + ")"
        return _get_src_ip_addr_system_independent(cmd, output_regex)

    if system in ("Linux", "posix"):
        cmd = "ip r g %s" % dst_ip
        output_regex = r"dev\s+\w+\s+src\s+(?P<ipaddr>" + IP_REGEX + ")"
        return _get_src_ip_addr_system_independent(cmd, output_regex)

    raise RuntimeError(
        "Could not determine system or system is not supported "
        "(currently supported systems: Linux, Windows)"
    )
