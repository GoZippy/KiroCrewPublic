"""Tests for the Windows Task Scheduler service backend.

Everything here runs on any platform: the XML document and the command
resolution are pure, and every ``schtasks`` call goes through one seam that
these tests replace. What they deliberately do NOT cover is what a real Task
Scheduler DOES with the document once it accepts it — that the trigger's
repetition is what restarts a terminated gateway, and that ``RestartOnFailure``
is not, was established against a live scheduler and is recorded in the module
docstring. These tests pin the document that behaviour depends on.
"""

from __future__ import annotations

import subprocess
import xml.etree.ElementTree as ET

import pytest

from kiro_crew.service import windows

_NS = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}


def _render(**kw) -> str:
    kw.setdefault("user_id", "CORP\\alice")
    kw.setdefault("command", r"C:\Python\Scripts\kirocrew.exe")
    kw.setdefault("arguments", "gateway")
    kw.setdefault("working_dir", r"C:\Users\alice\.kiro\crew")
    return windows.render_task_xml(**kw)


def _tree(xml: str) -> ET.Element:
    # Parsed as bytes: the document declares encoding="UTF-16", and ElementTree
    # refuses a str carrying an encoding declaration.
    return ET.fromstring(xml.encode("utf-16"))


class TestTaskDocument:
    def test_the_document_is_well_formed(self):
        assert _tree(_render()).tag.endswith("}Task")

    def test_no_execution_time_limit(self):
        """The default is three days, which would kill a healthy gateway."""
        root = _tree(_render())
        assert root.find(".//t:ExecutionTimeLimit", _NS).text == "PT0S"

    def test_restart_on_failure_is_bounded(self):
        """It only reaches a launch failure, which does not heal by retrying."""
        root = _tree(_render())
        assert root.find(".//t:RestartOnFailure/t:Count", _NS).text == str(windows.RESTART_COUNT)
        assert root.find(".//t:RestartOnFailure/t:Interval", _NS).text == "PT1M"

    def test_the_trigger_repeats_so_a_terminated_gateway_comes_back(self):
        """RestartOnFailure does not fire on a non-zero exit; this is what does.

        The watchdog terminates the gateway with status 1, which a real Task
        Scheduler records as a completed run rather than a failure. Without a
        repetition on the trigger the task holds a green tick and the gateway
        stays down, which is the bug this backend exists to fix.
        """
        root = _tree(_render())
        rep = root.find(".//t:LogonTrigger/t:Repetition", _NS)
        assert rep is not None, "the trigger must repeat, or nothing supervises"
        assert rep.find("t:Interval", _NS).text == windows.RESTART_INTERVAL

    def test_the_repetition_never_expires(self):
        """A Duration would silently end supervision while the task looks fine.

        An omitted Duration is Task Scheduler's "indefinitely". Any value here
        would mean the gateway stops being recovered once it elapses, and
        nothing in the task's own state would say so.
        """
        rep = _tree(_render()).find(".//t:LogonTrigger/t:Repetition", _NS)
        assert rep.find("t:Duration", _NS) is None
        assert rep.find("t:StopAtDurationEnd", _NS).text == "false"

    @pytest.mark.parametrize("tag", ["DisallowStartIfOnBatteries", "StopIfGoingOnBatteries"])
    def test_battery_settings_are_off(self, tag):
        """Both default to true; a laptop gateway would silently never start."""
        root = _tree(_render())
        assert root.find(f".//t:{tag}", _NS).text == "false"

    def test_a_second_logon_does_not_start_a_second_gateway(self):
        root = _tree(_render())
        assert root.find(".//t:MultipleInstancesPolicy", _NS).text == "IgnoreNew"

    def test_the_trigger_and_principal_name_the_invoking_user(self):
        """An all-users trigger needs admin and fails with 'Access is denied'."""
        root = _tree(_render())
        assert root.find(".//t:LogonTrigger/t:UserId", _NS).text == "CORP\\alice"
        assert root.find(".//t:Principal/t:UserId", _NS).text == "CORP\\alice"

    def test_it_asks_for_no_elevation(self):
        root = _tree(_render())
        assert root.find(".//t:Principal/t:RunLevel", _NS).text == "LeastPrivilege"

    def test_the_action_carries_the_resolved_command(self):
        root = _tree(_render())
        exec_el = root.find(".//t:Actions/t:Exec", _NS)
        assert exec_el.find("t:Command", _NS).text.endswith("kirocrew.exe")
        assert exec_el.find("t:Arguments", _NS).text == "gateway"

    def test_a_hostile_username_cannot_break_the_document(self):
        """A domain or path is attacker-adjacent data; it must be escaped."""
        root = _tree(_render(user_id='A&B<"x">'))
        assert root.find(".//t:Principal/t:UserId", _NS).text == 'A&B<"x">'


class TestGatewayCommand:
    def test_it_falls_back_to_the_module_when_no_script_is_installed(self, tmp_path, monkeypatch):
        """A task pointing at a missing exe fails at logon with only a code."""
        monkeypatch.setattr(windows.sys, "executable", str(tmp_path / "python.exe"))
        cmd, args = windows.gateway_command()
        assert cmd.endswith("python.exe")
        assert args == "-m kiro_crew gateway"

    def test_it_prefers_the_installed_console_script(self, tmp_path, monkeypatch):
        (tmp_path / "kirocrew.exe").write_text("")
        monkeypatch.setattr(windows.sys, "executable", str(tmp_path / "python.exe"))
        cmd, args = windows.gateway_command()
        assert cmd.endswith("kirocrew.exe")
        assert args == "gateway"


class TestWriteTaskXml:
    def test_it_writes_utf16_with_a_bom(self, tmp_path):
        """Task Scheduler's own exports are UTF-16; UTF-8 is refused by some builds."""
        p = windows.write_task_xml(_render(), tmp_path / "task.xml")
        assert p.read_bytes()[:2] in (b"\xff\xfe", b"\xfe\xff")
        assert "RestartOnFailure" in p.read_text(encoding="utf-16")

    def test_it_leaves_no_temporary_file_behind(self, tmp_path):
        windows.write_task_xml(_render(), tmp_path / "task.xml")
        assert [f.name for f in tmp_path.iterdir()] == ["task.xml"]


def _fake_schtasks(rc: int, stdout: str = "", stderr: str = ""):
    def run(*args: str) -> subprocess.CompletedProcess:
        run.calls.append(args)
        return subprocess.CompletedProcess(list(args), rc, stdout, stderr)

    run.calls = []
    return run


class TestSchtasksVerbs:
    def test_install_refuses_when_schtasks_is_not_trusted(self, monkeypatch):
        """PATH must not be able to supply the binary that registers a logon task."""
        monkeypatch.setattr(windows, "schtasks_bin", lambda: None)
        monkeypatch.setattr(windows, "write_task_xml", lambda *a, **k: None)
        with pytest.raises(windows.ServiceInstallError, match="trusted system"):
            windows.install()

    def test_install_surfaces_a_refusal_rather_than_claiming_success(self, monkeypatch, tmp_path):
        monkeypatch.setattr(windows, "write_task_xml", lambda *a, **k: tmp_path / "t.xml")
        monkeypatch.setattr(windows, "LOG_DIR", tmp_path / "logs")
        monkeypatch.setattr(windows, "_schtasks", _fake_schtasks(1, stderr="ERROR: denied"))
        with pytest.raises(windows.ServiceInstallError, match="denied"):
            windows.install()

    def test_install_replaces_an_existing_task(self, monkeypatch, tmp_path):
        """Reinstall after an upgrade must not need an uninstall first."""
        fake = _fake_schtasks(0)
        monkeypatch.setattr(windows, "write_task_xml", lambda *a, **k: tmp_path / "t.xml")
        monkeypatch.setattr(windows, "LOG_DIR", tmp_path / "logs")
        monkeypatch.setattr(windows, "_schtasks", fake)
        windows.install()
        assert "/F" in fake.calls[0]

    def test_uninstalling_an_absent_task_is_not_an_error(self, monkeypatch):
        monkeypatch.setattr(windows, "_schtasks", _fake_schtasks(1))
        monkeypatch.setattr(windows, "is_installed", lambda: False)
        windows.uninstall()

    def test_stopping_a_stopped_task_is_not_an_error(self, monkeypatch):
        monkeypatch.setattr(windows, "_schtasks", _fake_schtasks(1))
        windows.stop()

    def test_stop_disables_the_task_so_the_stop_holds(self, monkeypatch):
        """Ending the instance alone leaves the trigger to undo it in a minute."""
        fake = _fake_schtasks(0)
        monkeypatch.setattr(windows, "_schtasks", fake)
        windows.stop()
        assert [c[0] for c in fake.calls] == ["/End", "/Change"]
        assert "/DISABLE" in fake.calls[1]

    def test_start_re_enables_before_running(self, monkeypatch):
        """Otherwise a start after a stop is accepted and supervises nothing."""
        fake = _fake_schtasks(0)
        monkeypatch.setattr(windows, "_schtasks", fake)
        windows.start()
        assert [c[0] for c in fake.calls] == ["/Change", "/Run"]
        assert "/ENABLE" in fake.calls[0]

    def test_start_surfaces_a_refused_enable(self, monkeypatch):
        """A start that could not re-arm the trigger has not started anything."""
        monkeypatch.setattr(windows, "_schtasks", _fake_schtasks(1, stderr="ERROR: denied"))
        with pytest.raises(windows.ServiceInstallError, match="ENABLE"):
            windows.start()

    def test_restart_re_enables_a_stopped_task(self, monkeypatch):
        """Restart after a stop must not inherit the disabled state."""
        fake = _fake_schtasks(0)
        monkeypatch.setattr(windows, "_schtasks", fake)
        assert windows.restart() is True
        assert [c[0] for c in fake.calls] == ["/End", "/Change", "/Run"]
        assert "/ENABLE" in fake.calls[1]

    def test_is_installed_reads_the_exit_code_only(self, monkeypatch):
        """Localized output must never decide this."""
        monkeypatch.setattr(
            windows,
            "_schtasks",
            _fake_schtasks(0, stdout="Bereit\nFolder: KiroCrew"),  # brand-ok: task folder
        )
        assert windows.is_installed() is True
        monkeypatch.setattr(windows, "_schtasks", _fake_schtasks(1, stdout="Bereit"))
        assert windows.is_installed() is False


class TestIsActive:
    def test_a_localized_scheduler_status_never_decides_it(self, monkeypatch):
        """The whole point: a German host must answer the same as an English one."""
        called = []
        monkeypatch.setattr(
            windows, "_schtasks", lambda *a: called.append(a) or pytest.fail("parsed")
        )
        monkeypatch.setattr(windows, "_dashboard_port", lambda: 9)

        def refuse(*a, **k):
            raise OSError("closed")

        monkeypatch.setattr(windows.socket, "create_connection", refuse)
        assert windows.is_active() is False
        assert called == []

    def test_a_serving_gateway_reads_as_active(self, monkeypatch):
        class _Sock:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        monkeypatch.setattr(windows, "_dashboard_port", lambda: 5476)
        monkeypatch.setattr(windows.socket, "create_connection", lambda *a, **k: _Sock())
        assert windows.is_active() is True

    def test_an_unreadable_config_still_has_a_port(self, monkeypatch):
        monkeypatch.setattr(windows, "DEFAULT_PORT", 1234)
        import kiro_crew.config as cfgmod

        monkeypatch.setattr(
            cfgmod.KiroCrewConfig, "load", staticmethod(lambda: (_ for _ in ()).throw(OSError()))
        )
        assert windows._dashboard_port() == 1234
