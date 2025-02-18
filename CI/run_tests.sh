#!/usr/bin/env bash

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
