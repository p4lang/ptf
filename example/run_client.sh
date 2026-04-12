#!/bin/bash
# Copyright 2015 Antonin Bas
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

sudo ../ptf --test-dir mytests/ --pypath $PWD \
    --interface 0@veth1 --interface 1@veth3 --interface 2@veth5 \
    --interface 3@veth7 --interface 4@veth9 --interface 5@veth11 \
    --interface 6@veth13 --interface 7@veth15 --interface 8@veth17
