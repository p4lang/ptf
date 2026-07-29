# Copyright 2026 Xsight Labs
# SPDX-License-Identifier: Apache-2.0

import logging
import os

import pytest

import ptf
from ptf.ptfutils import chown_to_invoking_user

INVOKING_UID = 1234
INVOKING_GID = 5678


def _reject_chown(*args, **kwargs):
    raise AssertionError("ownership must be changed with lchown, not chown")


@pytest.fixture
def chown_calls(monkeypatch):
    """
    Record ownership changes instead of performing them.

    Fails the test if plain chown is used. Following a symlink placed in an
    output directory would let an unprivileged user have any file on the
    system chowned to themselves.
    """

    calls = []
    monkeypatch.setattr(
        os, "lchown", lambda path, uid, gid: calls.append((path, uid, gid))
    )
    monkeypatch.setattr(os, "chown", _reject_chown)
    return calls


@pytest.fixture
def sudo_env(monkeypatch):
    """
    Pretend to be root under sudo, whoever is really running the tests.
    """

    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_UID", str(INVOKING_UID))
    monkeypatch.setenv("SUDO_GID", str(INVOKING_GID))


@pytest.fixture
def restore_root_logger():
    """
    open_logfile() replaces the handlers on the root logger. Put back the ones
    pytest installed, so log capturing keeps working for later tests.
    """

    logger = logging.getLogger()
    original_handlers = list(logger.handlers)
    original_level = logger.level

    yield

    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        if handler not in original_handlers:
            handler.close()
    for handler in original_handlers:
        logger.addHandler(handler)
    logger.setLevel(original_level)


class TestChownToInvokingUser:
    def test_chowns_to_the_user_who_ran_sudo(self, tmp_path, chown_calls, sudo_env):
        logfile = tmp_path / "ptf.log"
        logfile.touch()

        chown_to_invoking_user(str(logfile))

        assert chown_calls == [(str(logfile), INVOKING_UID, INVOKING_GID)]

    def test_does_nothing_when_not_running_as_root(
        self, tmp_path, chown_calls, sudo_env, monkeypatch
    ):
        # sudo -u someuser ptf: SUDO_UID is set, but we cannot give a file away.
        monkeypatch.setattr(os, "geteuid", lambda: 1000)

        chown_to_invoking_user(str(tmp_path))

        assert chown_calls == []

    def test_does_nothing_when_root_without_sudo(
        self, tmp_path, chown_calls, monkeypatch
    ):
        # Running as root directly, for instance in a container. The files
        # are meant to belong to root.
        monkeypatch.setattr(os, "geteuid", lambda: 0)
        monkeypatch.delenv("SUDO_UID", raising=False)
        monkeypatch.delenv("SUDO_GID", raising=False)

        chown_to_invoking_user(str(tmp_path))

        assert chown_calls == []

    def test_does_nothing_when_only_the_uid_is_known(
        self, tmp_path, chown_calls, sudo_env, monkeypatch
    ):
        monkeypatch.delenv("SUDO_GID")

        chown_to_invoking_user(str(tmp_path))

        assert chown_calls == []

    def test_warns_and_gives_up_on_a_malformed_sudo_uid(
        self, tmp_path, chown_calls, sudo_env, monkeypatch, caplog
    ):
        monkeypatch.setenv("SUDO_UID", "not-a-number")

        with caplog.at_level(logging.WARNING):
            chown_to_invoking_user(str(tmp_path))

        assert chown_calls == []
        assert "not-a-number" in caplog.text

    def test_recursive_covers_the_whole_tree(self, tmp_path, chown_calls, sudo_env):
        (tmp_path / "TEST-results.xml").touch()
        (tmp_path / "nested").mkdir()
        (tmp_path / "nested" / "TEST-more.xml").touch()

        chown_to_invoking_user(str(tmp_path), recursive=True)

        assert sorted(path for path, _, _ in chown_calls) == [
            str(tmp_path),
            str(tmp_path / "TEST-results.xml"),
            str(tmp_path / "nested"),
            str(tmp_path / "nested" / "TEST-more.xml"),
        ]
        assert all(
            (uid, gid) == (INVOKING_UID, INVOKING_GID) for _, uid, gid in chown_calls
        )

    def test_a_failed_chown_is_reported_but_does_not_stop_the_run(
        self, tmp_path, sudo_env, monkeypatch, caplog
    ):
        def refuse(path, uid, gid):
            raise OSError(1, "Operation not permitted")

        monkeypatch.setattr(os, "lchown", refuse)

        with caplog.at_level(logging.WARNING):
            chown_to_invoking_user(str(tmp_path))

        assert "Could not change ownership" in caplog.text


class TestLogFileOwnership:
    def test_open_logfile_hands_the_log_to_the_invoking_user(
        self, tmp_path, chown_calls, sudo_env, monkeypatch, restore_root_logger
    ):
        logfile = tmp_path / "ptf.log"
        monkeypatch.setitem(ptf.config, "log_dir", None)
        monkeypatch.setitem(ptf.config, "log_file", str(logfile))

        ptf.open_logfile("main")

        assert logfile.exists()
        assert chown_calls == [(str(logfile), INVOKING_UID, INVOKING_GID)]
