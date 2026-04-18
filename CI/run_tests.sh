#!/usr/bin/env bash
# Copyright 2023 Antonin Bas
# SPDX-License-Identifier: Apache-2.0


set -x

. CI/uv-setup-env.bash

sudo "${UV_VENV_BIN_DIR}/uv" run ptf_nn/ptf_nn_agent.py \
    --device-socket 0@tcp://127.0.0.1:10001 -i 0-1@veth0 \
    &

sleep 5

sudo "${UV_VENV_BIN_DIR}/uv" run ptf_nn/ptf_nn_agent.py \
    --device-socket 1@tcp://127.0.0.1:10002 -i 1-1@veth3 \
    &

sleep 5

sudo "${UV_VENV_BIN_DIR}/uv" run ptf_nn/ptf_nn_test_bridge.py -ifrom veth1 -ito veth2 \
    &

sleep 5

sudo "${UV_VENV_BIN_DIR}/uv" run ptf --test-dir ptf_nn/ptf_nn_test \
    --device-socket 0-{0-64}@tcp://127.0.0.1:10001 \
    --device-socket 1-{0-64}@tcp://127.0.0.1:10002 \
    --platform nn

sudo "${UV_VENV_BIN_DIR}/uv" run nose2 utests.tests.test
