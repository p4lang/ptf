#!/usr/bin/env bash
# Copyright 2023 Antonin Bas
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


set -x

sudo -E PATH=${PATH} python3 ptf_nn/ptf_nn_agent.py \
    --device-socket 0@tcp://127.0.0.1:10001 -i 0-1@veth0 \
    &

sleep 5

sudo -E PATH=${PATH} python3 ptf_nn/ptf_nn_agent.py \
    --device-socket 1@tcp://127.0.0.1:10002 -i 1-1@veth3 \
    &

sleep 5

sudo -E PATH=${PATH} python3 ptf_nn/ptf_nn_test_bridge.py -ifrom veth1 -ito veth2 \
    &

sleep 5

sudo -E PATH=${PATH} `which ptf` --test-dir ptf_nn/ptf_nn_test \
    --device-socket 0-{0-64}@tcp://127.0.0.1:10001 \
    --device-socket 1-{0-64}@tcp://127.0.0.1:10002 \
    --platform nn

sudo -E PATH=${PATH} python3 `which nose2` utests.tests.test
