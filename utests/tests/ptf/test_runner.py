# Copyright 2026 The P4 Language Consortium
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the ptf.runner library API. The API runs PTF tests inside
the current process, without the ptf binary."""

import subprocess
import sys
import io
import logging
import random
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from ptf import runner

TESTDIR = "utests/specs"


def make_config(**kwargs):
    log_file = kwargs.pop("log_file", "test_runner_ptf.log")
    return runner.PtfConfig(
        allow_user=True,
        logging=runner.LoggingOptions(log_file=log_file),
        platform=runner.PlatformOptions(platform="dummy"),
        **kwargs,
    )


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


def test_run_in_process_with_string_test_params(capsys):
    config = make_config(
        test_selection=runner.TestSelectionOptions(
            test_dir=TESTDIR,
            test_specs=["test.TestParamsGet"],
        ),
        test_behavior=runner.TestBehaviorOptions(test_params="k1=9;k2=18"),
    )
    assert runner.run(config) == 0
    assert parse_params(capsys.readouterr().out) == {"k1": 9, "k2": 18}


def test_run_in_process_with_dict_test_params(capsys):
    config = make_config(
        test_selection=runner.TestSelectionOptions(
            test_dir=TESTDIR,
            test_specs=["test.TestParamGet"],
        ),
        test_behavior=runner.TestBehaviorOptions(test_params={"k1": 42}),
    )
    assert runner.run(config) == 0
    assert parse_params(capsys.readouterr().out) == {"k1": 42}


def test_run_in_process_with_no_test_params(capsys):
    config = make_config(
        test_selection=runner.TestSelectionOptions(
            test_dir=TESTDIR,
            test_specs=["test.TestParamsGet"],
        ),
    )
    assert runner.run(config) == 0
    assert parse_params(capsys.readouterr().out) is None


def test_run_in_process_with_flat_dict_config(capsys):
    # run() also accepts a dictionary in the flat ptf.config format.
    config = {
        "test_dir": TESTDIR,
        "test_specs": ["test.TestParamGet"],
        "platform": "dummy",
        "allow_user": True,
        "log_file": "test_runner_ptf.log",
        "test_params": "k1=7",
    }
    assert runner.run(config) == 0
    assert parse_params(capsys.readouterr().out) == {"k1": 7}


def test_run_in_process_list_tests(capsys):
    config = make_config(
        list_tests=True,
        test_selection=runner.TestSelectionOptions(test_dir=TESTDIR),
    )
    assert runner.run(config) == 0
    out = capsys.readouterr().out
    assert "Module test:" in out
    assert "TestParamsGet" in out
    assert "modules shown with a total of" in out


def test_run_in_process_list_test_names(capsys):
    config = make_config(
        list_test_names=True,
        test_selection=runner.TestSelectionOptions(test_dir=TESTDIR),
    )
    assert runner.run(config) == 0
    out = capsys.readouterr().out
    assert "test.TestParamGet" in out
    assert "fixtures.ModuleFixtureProbeOne" in out


def test_run_in_process_unknown_test_spec(capsys):
    config = make_config(
        test_selection=runner.TestSelectionOptions(
            test_dir=TESTDIR,
            test_specs=["does-not-exist"],
        ),
    )
    with pytest.raises(runner.PtfError, match="did not match any tests"):
        runner.run(config)


def test_run_in_process_invalid_test_dir():
    config = make_config(
        test_selection=runner.TestSelectionOptions(test_dir="not-a-dir"),
    )
    with pytest.raises(runner.PtfError, match="invalid test directory"):
        runner.run(config)


def test_run_in_process_restores_logging_handlers():
    root = logging.getLogger()
    saved_handlers = list(root.handlers)
    saved_level = root.level
    saved_disable = logging.root.manager.disable
    config = make_config(
        test_selection=runner.TestSelectionOptions(
            test_dir=TESTDIR,
            test_specs=["test.TestParamGet"],
        ),
    )
    assert runner.run(config) == 0
    assert list(root.handlers) == saved_handlers
    assert root.level == saved_level
    assert logging.root.manager.disable == saved_disable


def test_run_keeps_caller_file_handler_usable(tmp_path):
    root = logging.getLogger()
    logfile = tmp_path / "caller.log"
    handler = logging.FileHandler(logfile, mode="w")
    root.addHandler(handler)
    try:
        root.warning("before")
        config = make_config(
            log_file=str(tmp_path / "ptf.log"),
            list_tests=True,
            test_selection=runner.TestSelectionOptions(test_dir=TESTDIR),
        )
        assert runner.run(config) == 0
        assert handler.stream is not None
        root.warning("after")
        handler.flush()
        assert logfile.read_text().splitlines() == ["before", "after"]
    finally:
        root.removeHandler(handler)
        handler.close()


def test_run_preserves_caller_handler_using_ptf_log_path(tmp_path):
    root = logging.getLogger()
    logfile = tmp_path / "shared.log"
    handler = logging.FileHandler(logfile, mode="w")
    root.addHandler(handler)
    try:
        root.warning("before")
        config = make_config(
            log_file=str(logfile),
            list_tests=True,
            test_selection=runner.TestSelectionOptions(test_dir=TESTDIR),
        )
        assert runner.run(config) == 0
        root.warning("after")
        handler.flush()
        contents = logfile.read_text()
        assert "before" in contents
        assert "after" in contents
    finally:
        root.removeHandler(handler)
        handler.close()


def test_run_forwards_logs_and_uses_supplied_streams(tmp_path):
    stdout = io.StringIO()
    stderr = io.StringIO()
    records = []

    class RecordHandler(logging.Handler):
        def emit(self, record):
            records.append(record)

    observer = logging.getLogger("ptf-test-observer")
    saved_level = observer.level
    saved_propagate = observer.propagate
    observer.propagate = False
    observer.setLevel(logging.DEBUG)
    observer_handler = RecordHandler()
    observer.addHandler(observer_handler)
    try:
        config = make_config(
            log_file=str(tmp_path / "ptf.log"),
            test_selection=runner.TestSelectionOptions(
                test_dir=TESTDIR,
                test_specs=["test.TestParamGet"],
            ),
        )
        assert (
            runner.run(
                config,
                output=runner.RunOutput(stdout=stdout, stderr=stderr, logger=observer),
            )
            == 0
        )
    finally:
        observer.removeHandler(observer_handler)
        observer.setLevel(saved_level)
        observer.propagate = saved_propagate
    assert ">>>k1=-1" not in stdout.getvalue()  # Test-owned stdout is not redirected.
    assert "test.TestParamGet" in stderr.getvalue()
    assert any("TEST RUN START" in record.getMessage() for record in records)


def test_run_rejects_recursive_output_logger(tmp_path):
    config = make_config(
        log_file=str(tmp_path / "ptf.log"),
        list_tests=True,
        test_selection=runner.TestSelectionOptions(test_dir=TESTDIR),
    )
    with pytest.raises(ValueError, match="must not propagate"):
        runner.run(
            config,
            output=runner.RunOutput(logger=logging.getLogger("ptf.consumer")),
        )


def test_run_can_disable_ptf_log_artifacts(tmp_path, monkeypatch):
    test_dir = str(Path(TESTDIR).resolve())
    monkeypatch.chdir(tmp_path)
    config = make_config(
        log_file=None,
        list_tests=True,
        test_selection=runner.TestSelectionOptions(test_dir=test_dir),
    )

    assert runner.run(config) == 0
    assert not list(tmp_path.glob("*.log"))
    assert not list(tmp_path.glob("*.pcap"))


def test_run_restores_process_state(tmp_path, monkeypatch):
    import ptf

    original_config = ptf.config
    original_config.clear()
    original_config["sentinel"] = {"value": 1}
    original_path = sys.path
    original_path_contents = list(sys.path)
    random.seed(12345)
    original_random_state = random.getstate()

    config = make_config(
        log_file=str(tmp_path / "ptf.log"),
        list_tests=True,
        test_selection=runner.TestSelectionOptions(test_dir=TESTDIR),
        pypath=[str(tmp_path)],
    )
    assert runner.run(config) == 0

    assert ptf.config is original_config
    assert ptf.config == {"sentinel": {"value": 1}}
    assert sys.path is original_path
    assert sys.path == original_path_contents
    assert random.getstate() == original_random_state


def test_test_modules_are_fresh_for_each_run(tmp_path, capsys):
    def run_with(value):
        config = make_config(
            log_file=str(tmp_path / "ptf-{}.log".format(value)),
            test_selection=runner.TestSelectionOptions(
                test_dir=TESTDIR,
                test_specs=["import_state.ImportStateProbe"],
            ),
            test_behavior=runner.TestBehaviorOptions(
                test_params={"import_value": value}
            ),
        )
        assert runner.run(config) == 0
        return capsys.readouterr().out

    assert ">>>import_value=1" in run_with(1)
    assert ">>>import_value=2" in run_with(2)


def test_run_can_execute_on_a_worker_thread(tmp_path):
    config = make_config(
        log_file=str(tmp_path / "ptf.log"),
        list_tests=True,
        test_selection=runner.TestSelectionOptions(test_dir=TESTDIR),
    )
    with ThreadPoolExecutor(max_workers=1) as pool:
        assert pool.submit(runner.run, config).result() == 0


def test_zero_timeout_can_execute_on_a_worker_thread(tmp_path):
    config = make_config(
        log_file=str(tmp_path / "ptf.log"),
        list_tests=True,
        test_selection=runner.TestSelectionOptions(test_dir=TESTDIR),
        test_behavior=runner.TestBehaviorOptions(test_case_timeout=0),
    )
    with ThreadPoolExecutor(max_workers=1) as pool:
        assert pool.submit(runner.run, config).result() == 0


def test_decorated_timeout_is_rejected_on_a_worker_thread(tmp_path):
    config = make_config(
        log_file=str(tmp_path / "ptf.log"),
        test_selection=runner.TestSelectionOptions(
            test_dir=TESTDIR,
            test_specs=["isolation.Timed"],
        ),
    )
    with ThreadPoolExecutor(max_workers=1) as pool:
        with pytest.raises(runner.PtfError, match="main Python thread"):
            pool.submit(runner.run, config).result()


def test_overlapping_in_process_runs_are_rejected(tmp_path, monkeypatch):
    entered = threading.Event()
    release = threading.Event()

    def blocking_execute(config, output, state):
        entered.set()
        release.wait(5)
        return 0

    monkeypatch.setattr(runner, "_execute", blocking_execute)
    config = make_config(
        log_file=str(tmp_path / "ptf.log"),
        test_selection=runner.TestSelectionOptions(test_dir=TESTDIR),
    )
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(runner.run, config)
        assert entered.wait(5)
        with pytest.raises(runner.PtfError, match="another in-process PTF run"):
            runner.run(config)
        release.set()
        assert future.result() == 0


def test_cleanup_failure_changes_success_to_error(tmp_path, monkeypatch):
    class BrokenDataplane:
        def stop_pcap(self):
            pass

        def kill(self):
            raise RuntimeError("close failed")

    def execute(config, output, state):
        state.dataplane = BrokenDataplane()
        return 0

    monkeypatch.setattr(runner, "_execute", execute)
    config = make_config(
        log_file=str(tmp_path / "ptf.log"),
        test_selection=runner.TestSelectionOptions(test_dir=TESTDIR),
    )
    with pytest.raises(runner.PtfError, match="cleanup failed"):
        runner.run(config)


@pytest.mark.parametrize("fail_skipped, expected", [(False, 0), (True, 1)])
def test_skips_use_unittest_result(tmp_path, fail_skipped, expected):
    config = make_config(
        log_file=str(tmp_path / "ptf.log"),
        test_selection=runner.TestSelectionOptions(
            test_dir=TESTDIR,
            test_specs=["isolation.Skipped"],
        ),
        test_behavior=runner.TestBehaviorOptions(fail_skipped=fail_skipped),
    )
    assert runner.run(config) == expected


def test_ptf_config_json_roundtrip():
    config = runner.PtfConfig(
        allow_user=True,
        pypath=["/some/path"],
        test_selection=runner.TestSelectionOptions(
            test_dir="tests",
            test_specs=["test.Foo", "^group"],
            test_order="rand",
            test_order_seed=1234,
        ),
        platform=runner.PlatformOptions(
            platform="nn",
            device_sockets=[
                runner.DeviceSocket(0, {1, 2, 5, 6, 7, 8}, "ipc:///tmp/p.ipc")
            ],
            interfaces=[runner.Interface(0, 1, "eth1"), runner.Interface(1, 2, "eth2")],
            port_info={1: {"mac": "aa:bb:cc:dd:ee:ff"}},
        ),
        test_behavior=runner.TestBehaviorOptions(
            test_params={"k1": "abc", "k2": 21},
            random_seed=42,
        ),
    )
    rebuilt = runner.PtfConfig.from_json(config.to_json())
    assert rebuilt == config


def test_ptf_config_from_dict_defaults():
    # A partial flat dictionary must produce the default configuration,
    # plus the given keys.
    rebuilt = runner.PtfConfig.from_dict({"test_dir": "tests"})
    assert rebuilt == runner.PtfConfig(
        test_selection=runner.TestSelectionOptions(test_dir="tests")
    )


def test_ptf_config_to_dict_legacy_shape():
    config = runner.PtfConfig(
        pypath=["/some/path"],
        platform=runner.PlatformOptions(
            interfaces=[runner.Interface(0, 1, "eth1")],
            device_sockets=[runner.DeviceSocket(0, {1, 2}, "tcp://1.2.3.4:1")],
        ),
        test_behavior=runner.TestBehaviorOptions(
            test_params={"k1": "abc"},
        ),
    )
    d = config.to_dict()
    # interfaces and device_sockets keep their legacy tuple/set shapes
    assert d["interfaces"] == [(0, 1, "eth1")]
    assert d["device_sockets"] == [(0, {1, 2}, "tcp://1.2.3.4:1")]
    assert d["pypath"] == ["/some/path"]
    # dict test params are rendered in the legacy string syntax
    assert d["test_params"] == "k1='abc'"
    assert d["port_map"] is None
    assert d["packet_manipulation_module"] is None


def test_flat_config_preserves_platform_extensions():
    portclass = object()
    config = runner.PtfConfig.from_dict(
        {"test_dir": "tests", "dataplane": {"portclass": portclass}}
    )
    assert config.extra_config == {"dataplane": {"portclass": portclass}}
    assert config.to_dict()["dataplane"]["portclass"] is portclass


def test_json_rejects_non_json_platform_extensions():
    config = runner.PtfConfig(extra_config={"extension": {1, 2}})
    with pytest.raises(TypeError):
        config.to_json()


def test_preimported_packet_backend_config_is_rejected(tmp_path):
    script = """
import ptf
import ptf.packet_scapy
from ptf import runner

config = runner.PtfConfig(
    allow_user=True,
    list_tests=True,
    logging=runner.LoggingOptions(log_file=None),
    platform=runner.PlatformOptions(platform="dummy"),
    test_selection=runner.TestSelectionOptions(test_dir="utests/specs"),
    test_behavior=runner.TestBehaviorOptions(disable_ipv6=True),
)
try:
    runner.run(config)
except runner.PtfError as error:
    print(error)
else:
    raise SystemExit("configuration was not rejected")
"""
    result = subprocess.run(
        [sys.executable, "-c", script],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    assert result.returncode == 0, result.stdout
    assert "packet backend already loaded" in result.stdout


def test_python_dash_m_entry_point(tmp_path):
    # python -m ptf must behave like the ptf binary.
    r = subprocess.run(
        [
            sys.executable,
            "-m",
            "ptf",
            "--test-dir",
            TESTDIR,
            "--platform",
            "dummy",
            "--allow-user",
            "--log-file",
            str(tmp_path / "ptf.log"),
            "test.TestParamGet",
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        input=None,
        universal_newlines=True,
    )
    assert r.returncode == 0
    # No --test-params: test_param_get falls back to its default (-1).
    assert ">>>k1=-1" in r.stdout


def test_serialized_config_stdin_entry_point(tmp_path):
    config = make_config(
        log_file=str(tmp_path / "ptf.log"),
        test_selection=runner.TestSelectionOptions(
            test_dir=TESTDIR,
            test_specs=["test.TestParamGet"],
        ),
    )
    result = subprocess.run(
        [sys.executable, "-m", "ptf.runner", "-"],
        input=config.to_json(),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )

    assert result.returncode == 0, result.stdout
    assert ">>>k1=-1" in result.stdout
