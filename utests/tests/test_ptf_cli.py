# Copyright 2019 Antonin Bas
# SPDX-License-Identifier: Apache-2.0

import pytest
import subprocess
import sys

TESTDIR = "utests/specs"


def run_ptf(args=None, input=None):
    # redirect stderr to stdout so we can get error messages
    r = subprocess.run(
        [sys.executable, "./ptf"] + (args or []),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        input=input,
        universal_newlines=True,
    )
    return r.returncode, r.stdout


def parse_params(out):
    params = {}
    for line in out.splitlines():
        if not line.startswith(">>>"):
            continue
        line = line[3:]
        if line == "None":
            return None
        k, v = line.split("=")
        params[k] = int(v)
    return params


def do_test_params(testspec, test_params_str):
    rc, out = run_ptf(
        args=[
            "--test-dir",
            TESTDIR,
            f"--test-params={test_params_str}",
            "--platform",
            "dummy",
            "--allow-user",
            testspec,
        ]
    )
    assert rc == 0
    return out


@pytest.mark.parametrize(
    ("test_params_str", "expected_params"),
    [("k1=9;k2=18", {"k1": 9, "k2": 18}), ("k1=9;k2=18;", {"k1": 9, "k2": 18})],
)
def test_test_params_get(test_params_str, expected_params):
    out = do_test_params("test.TestParamsGet", test_params_str)
    assert parse_params(out) == expected_params


@pytest.mark.parametrize("test_params_str", ["bad"])
def test_test_params_get_error(test_params_str):
    out = do_test_params("test.TestParamsGet", test_params_str)
    assert "Error when parsing test params" in out


@pytest.mark.parametrize(
    ("test_params_str", "expected_value"),
    [("k1=9;k2=18", 9), ("k1=9;k2=18;", 9), ("k2=18", -1)],
)
def test_test_param_get(test_params_str, expected_value):
    out = do_test_params("test.TestParamGet", test_params_str)
    params = parse_params(out)
    assert params["k1"] == expected_value


@pytest.mark.parametrize("test_params_str", ["bad"])
def test_test_param_get_error(test_params_str):
    out = do_test_params("test.TestParamGet", test_params_str)
    assert "Error when parsing test params" in out


def test_module_and_class_fixtures_run():
    rc, out = run_ptf(
        args=[
            "--test-dir",
            TESTDIR,
            "--platform",
            "dummy",
            "--allow-user",
            "fixtures.ModuleFixtureProbeOne",
            "fixtures.ModuleFixtureProbeTwo",
        ]
    )
    assert rc == 0
    assert out.count(">>>setUpModule") == 1
    assert out.count(">>>tearDownModule") == 1
    assert out.count(">>>ModuleFixtureProbeOne.setUpClass") == 1
    assert out.count(">>>ModuleFixtureProbeOne.tearDownClass") == 1
    assert out.count(">>>ModuleFixtureProbeTwo.setUpClass") == 1
    assert out.count(">>>ModuleFixtureProbeTwo.tearDownClass") == 1
    assert ">>>ModuleFixtureProbeOne.runTest" in out
    assert ">>>ModuleFixtureProbeTwo.runTest" in out
