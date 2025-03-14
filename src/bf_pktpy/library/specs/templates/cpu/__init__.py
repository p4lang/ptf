# Copyright (c) 2022 Intel Corporation.
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

from bf_pktpy.library.specs.templates.cpu.dtel_report_hdr import DtelReportHdr
from bf_pktpy.library.specs.templates.cpu.dtel_report_v2_hdr import DtelReportV2Hdr
from bf_pktpy.library.specs.templates.cpu.fabric_cpu_bfd_event_header import (
    FabricCpuBfdEventHeader,
)
from bf_pktpy.library.specs.templates.cpu.fabric_cpu_header import FabricCpuHeader
from bf_pktpy.library.specs.templates.cpu.fabric_cpu_sflow_header import (
    FabricCpuSflowHeader,
)
from bf_pktpy.library.specs.templates.cpu.fabric_cpu_timestamp_header import (
    FabricCpuTimestampHeader,
)
from bf_pktpy.library.specs.templates.cpu.fabric_header import FabricHeader
from bf_pktpy.library.specs.templates.cpu.fabric_multicast_header import (
    FabricMulticastHeader,
)
from bf_pktpy.library.specs.templates.cpu.fabric_payload_header import (
    FabricPayloadHeader,
)
from bf_pktpy.library.specs.templates.cpu.fabric_unicast_header import (
    FabricUnicastHeader,
)
from bf_pktpy.library.specs.templates.cpu.mod_header import ModHeader
from bf_pktpy.library.specs.templates.cpu.postcard_header import PostcardHeader
from bf_pktpy.library.specs.templates.cpu.simple_l3_mirror_cpu_header import (
    SimpleL3SwitchCpuHeader,
)

from bf_pktpy.library.specs.templates.cpu.mirror_pre_deparser import MirrorPreDeparser
