"""Windows service management through Task Scheduler.

The third backend beside :mod:`kiro_crew.service.linux` (systemd) and
:mod:`kiro_crew.service.macos` (launchd). It exists because the loop-stall
watchdog is designed to TERMINATE the gateway — ``faulthandler`` exits with
status 1 after writing its dump — and on Windows nothing brought it back, so a
designed-to-exit process was paired with no supervised lifetime. Reported
upstream as kirodotdev/KiroCrew#6590.

It follows launchd rather than systemd: the task is registered in the INVOKING
USER's scope and needs no elevation. A bare all-users logon trigger requires
administrator rights and fails with "Access is denied", which is easy to hit
and hard to read.

Four decisions are load-bearing, and each closes a way Task Scheduler's
defaults would have made a supervisor that silently does not supervise:

**The definition is XML, not ``/Create`` flags.** ``schtasks /Create`` exposes
no flag for ``RestartOnFailure`` or the battery settings below, and those are
the whole point of the task. ``/XML`` is the only route to them.
:mod:`kiro_crew.pod.windows` uses the flag form deliberately — its tasks are
one-shot pods that must NOT be restarted — so the two are not merged.

**``ExecutionTimeLimit`` is ``PT0S``.** The Task Scheduler default is three
days, after which it would terminate a perfectly healthy gateway. ``PT0S``
means no limit.

**Both battery settings are ``false``.** ``DisallowStartIfOnBatteries``
defaults to TRUE, so on a laptop the default task would simply not start, and
Task Scheduler reports that as a task that ran and did nothing — the exact
failure this module exists to prevent, wearing a green tick.

**``MultipleInstancesPolicy`` is ``IgnoreNew``.** A logon trigger can fire
while a gateway from a previous session is still up (fast user switching, a
remote session reconnect). Two gateways on one data home is a worse outcome
than a missed start, and the running one is the one to keep.

**The TRIGGER repeats, and that is what supervises the gateway.**
``RestartOnFailure`` does not, and the difference is the whole point of this
module. Measured against a live Task Scheduler: a task whose action exits 1 is
NOT restarted by it. The scheduler counts a non-zero exit as a run that
completed and records the code; only an action it could not LAUNCH is the
failure it restarts. A watchdog termination is precisely the former —
``faulthandler.dump_traceback_later(..., exit=True)`` calls ``_exit(1)`` — so
relying on ``RestartOnFailure`` alone leaves the gateway down, which is
kirodotdev/KiroCrew#6590 with a supervisor bolted on rather than fixed.

The logon trigger therefore carries a ``Repetition`` with an interval and NO
``Duration``, which repeats indefinitely: every minute the scheduler tries to
start the gateway. ``MultipleInstancesPolicy`` above is what makes that safe
rather than a fork bomb — while a healthy gateway holds the slot every tick is
dropped, and the first tick after it dies brings it back. ``RestartOnFailure``
is kept for the launch failure it does cover, and its count stays bounded
because that failure does not heal by retrying.

A repeating trigger costs one thing, and :func:`stop` pays it: a gateway an
operator stopped would otherwise be back within the minute. See there.

**This backend never parses ``schtasks`` output**, the same invariant
:mod:`kiro_crew.pod.windows` documents at length: both the CSV headers and the
``Status`` values are LOCALIZED, so a German or Japanese host would read as a
different state entirely. Only exit codes are consulted.

**Task Scheduler, not the SCM — and that is a scope decision, not a
preference.** kirodotdev/KiroCrew#7305 asks for headless Windows support and
proposes ``sc.exe``/SCM or an NSSM-style wrapper. The two are not
interchangeable:

* A real SCM service starts at BOOT and survives logout, but installing one
  needs ADMINISTRATOR rights, and Python is not a native service binary, so it
  also needs a wrapper (pywin32 or NSSM) to be one.
* A logon-triggered task needs no elevation at all, which is what makes it
  installable by the operator who hit kirodotdev/KiroCrew#6590 — but it starts at LOGON and does
  not survive logout.

This backend answers kirodotdev/KiroCrew#6590 (a workstation whose gateway
must come back after the watchdog kills it) and does NOT yet answer
kirodotdev/KiroCrew#7305 (a headless VM or server
that must come up before anyone signs in). Task Scheduler can reach that case
— a ``BootTrigger`` plus ``LogonType=S4U``, which avoids storing a password —
but S4U needs the "Log on as a batch job" right, so it is elevation by another
name and belongs in the same conversation as the SCM proposal rather than
being chosen here unilaterally.

One thing is deliberately NOT wired.
:func:`kiro_crew.service.controller.installed_unit_path` still answers ``None``
on this platform, so a host running this task does not claim the wider
managed-service watchdog budget. Claiming it would loosen a stall threshold on
the strength of an unvalidated backend, and the failure mode of that error is
the one this module exists to fix. It is a decision to revisit once the verbs
below have been proven against a real Task Scheduler, not an oversight.

.. warning::

   The document, the verbs and the supervision contract were exercised
   against a live Task Scheduler on Windows 10 Pro 19045 — the UTF-16
   definition is accepted, ``DOMAIN\\user`` resolves to the invoking
   principal, and the repeating trigger restarts a terminated action on the
   next minute while ``IgnoreNew`` drops the ticks a live one covers. Two
   things are still unproven and neither is reachable from a desktop:
   ``DisallowStartIfOnBatteries`` on a host that HAS a battery, and the
   document on a build whose Task Scheduler rejects UTF-16 rather than
   accepting it. The definition is kept at ``<data home>/service`` so an
   operator hitting either can read back exactly what was registered.
"""

from __future__ import annotations

import getpass
import logging
import os
import socket
import subprocess
import sys
from pathlib import Path
from xml.sax.saxutils import escape as _xml_escape

from kiro_crew import platform_compat
from kiro_crew.config.paths import config_dir

logger = logging.getLogger(__name__)

#: Task Scheduler path. The leading folder keeps the task out of the crowded
#: root and matches how the pod backend namespaces its own.
TASK_FOLDER = r"\KiroCrew"
TASK_NAME = rf"{TASK_FOLDER}\gateway"

#: Where the generated definition is kept. Under the data home rather than a
#: temp dir so an operator can read back exactly what was registered, and so
#: the file survives for ``kirocrew doctor`` to diff against the live task.
TASK_XML_PATH = config_dir() / "service" / "kirocrew-gateway.xml"

LOG_DIR = config_dir() / "logs"

#: Fallback when the config cannot be read. ``KIROCREW_PORT`` is honoured for
#: the same reason :mod:`kiro_crew.snapshot` honours it: an operator who moved
#: the port must not be told their running gateway is down.
DEFAULT_PORT = int(os.environ.get("KIROCREW_PORT", 5476))

#: Supervision cadence, shared by the repeating trigger and the restart
#: budget. One minute is Task Scheduler's floor for a repetition interval, so
#: it is also the longest a gateway stays down after the watchdog kills it.
RESTART_INTERVAL = "PT1M"

#: Bounded budget for ``RestartOnFailure`` ONLY, which reaches an action that
#: could not be launched. Three attempts distinguishes "this host hiccuped"
#: from "this gateway cannot start", and stops rather than spinning on the
#: latter. It is not what recovers a terminated gateway — the trigger is.
RESTART_COUNT = 3


class ServiceInstallError(RuntimeError):
    """Raised when the task could not be registered or removed."""


def _current_user_id() -> str:
    """The principal to run as, as ``DOMAIN\\user`` where a domain is known.

    Task Scheduler accepts a bare username, but a bare name on a
    domain-joined host can resolve to a different principal than the one
    invoking this. ``USERDOMAIN`` is present on every interactive Windows
    session; where it is absent (a service context, a stripped environment)
    the bare name is the honest answer rather than a guessed domain.
    """
    user = os.environ.get("USERNAME") or getpass.getuser()
    domain = os.environ.get("USERDOMAIN")
    return f"{domain}\\{user}" if domain else user


def gateway_command() -> tuple[str, str]:
    """``(command, arguments)`` Task Scheduler should execute.

    Prefers the installed ``kirocrew`` console script next to this
    interpreter, which is what the operator themselves runs. Falls back to
    ``<python> -m kiro_crew`` when the script is absent — an editable or
    unusual install — because a task pointing at a missing exe fails at logon
    with nothing but an exit code to explain it.
    """
    scripts = Path(sys.executable).parent
    for candidate in (scripts / "kirocrew.exe", scripts / "Scripts" / "kirocrew.exe"):
        if candidate.is_file():
            return str(candidate), "gateway"
    return sys.executable, "-m kiro_crew gateway"


def render_task_xml(
    *,
    user_id: str | None = None,
    command: str | None = None,
    arguments: str | None = None,
    working_dir: str | None = None,
) -> str:
    """Render the Task Scheduler definition.

    Pure and fully injectable so the whole document is testable off Windows.
    """
    if user_id is None:
        user_id = _current_user_id()
    if command is None or arguments is None:
        resolved_cmd, resolved_args = gateway_command()
        command = resolved_cmd if command is None else command
        arguments = resolved_args if arguments is None else arguments
    if working_dir is None:
        working_dir = str(config_dir())

    e = _xml_escape
    return f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>{e(user_id)}</Author>
    <Description>Kiro Crew gateway. Restarts the gateway after the loop-stall watchdog terminates it.</Description>
    <URI>{e(TASK_NAME)}</URI>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>{e(user_id)}</UserId>
      <Repetition>
        <Interval>{RESTART_INTERVAL}</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{e(user_id)}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartOnFailure>
      <Interval>{RESTART_INTERVAL}</Interval>
      <Count>{RESTART_COUNT}</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{e(command)}</Command>
      <Arguments>{e(arguments)}</Arguments>
      <WorkingDirectory>{e(working_dir)}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"""


def write_task_xml(contents: str, path: Path | None = None) -> Path:
    """Write the definition where ``schtasks /XML`` will read it.

    UTF-16 with a BOM, matching Task Scheduler's own exports and the
    ``encoding="UTF-16"`` the document declares. Written to a sibling
    temporary file and moved into place so a concurrent reader never sees a
    half-written definition.
    """
    target = path or TASK_XML_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_name(f"{target.name}.{os.getpid()}.tmp")
    tmp.write_text(contents, encoding="utf-16")
    os.replace(tmp, target)
    return target


def schtasks_bin() -> str | None:
    """Absolute path of ``schtasks.exe``, or ``None`` when unavailable.

    Resolved through the trusted-system-path table rather than ``PATH``: a
    writable directory earlier on ``PATH`` must not be able to supply the
    binary that registers a task running as this user at every logon.
    """
    return platform_compat.trusted_system_bin("schtasks")


def _schtasks(*args: str) -> subprocess.CompletedProcess[str]:
    """The single chokepoint for talking to Task Scheduler."""
    exe = schtasks_bin()
    if exe is None:
        raise ServiceInstallError(
            "schtasks.exe was not found in a trusted system directory, so the "
            "gateway cannot be supervised on this host."
        )
    return subprocess.run(
        [exe, *args],
        capture_output=True,
        timeout=30,
        check=False,
        encoding="utf-8",
        errors="replace",
    )


def install() -> Path:
    """Register (or replace) the gateway task. Returns the definition's path.

    ``/F`` replaces an existing task rather than failing, so a reinstall after
    an upgrade picks up a changed command without an uninstall first.
    """
    path = write_task_xml(render_task_xml())
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    created = _schtasks("/Create", "/TN", TASK_NAME, "/XML", str(path), "/F")
    if created.returncode != 0:
        # The message is NOT parsed, only surfaced: it is localized, and the
        # operator reading it is the one who can act on it.
        raise ServiceInstallError(
            f"schtasks /Create rc={created.returncode}: "
            f"{(created.stderr or created.stdout or '').strip()}"
        )
    return path


def uninstall() -> None:
    """Remove the task. A task that is already absent is not an error."""
    deleted = _schtasks("/Delete", "/TN", TASK_NAME, "/F")
    if deleted.returncode != 0 and not is_installed():
        return
    if deleted.returncode != 0:
        raise ServiceInstallError(
            f"schtasks /Delete rc={deleted.returncode}: "
            f"{(deleted.stderr or deleted.stdout or '').strip()}"
        )


def is_installed() -> bool:
    """Whether Task Scheduler holds our task.

    The EXIT CODE answers this; the output is localized and never read.
    """
    try:
        return _schtasks("/Query", "/TN", TASK_NAME).returncode == 0
    except ServiceInstallError:
        return False


def start() -> None:
    """Start the task now, without waiting for a logon.

    Re-enables first, because :func:`stop` disables the task to make an
    operator's stop hold against the repeating trigger. Enabling a task that
    is already enabled is accepted, so this costs one call and no branch.
    """
    enabled = _schtasks("/Change", "/TN", TASK_NAME, "/ENABLE")
    if enabled.returncode != 0:
        raise ServiceInstallError(
            f"schtasks /Change /ENABLE rc={enabled.returncode}: "
            f"{(enabled.stderr or enabled.stdout or '').strip()}"
        )
    run = _schtasks("/Run", "/TN", TASK_NAME)
    if run.returncode != 0:
        raise ServiceInstallError(
            f"schtasks /Run rc={run.returncode}: " f"{(run.stderr or run.stdout or '').strip()}"
        )


def stop() -> None:
    """Stop the gateway and stand the supervisor down until :func:`start`.

    ``/End`` alone would not hold. The trigger repeats every minute, so a
    gateway the operator stopped would be back inside one — the supervisor
    cannot tell an operator's stop from the watchdog's, and it must not, or it
    would not recover the watchdog's. Disabling the task is how the operator
    says which one it was, and it is this backend's ``systemctl stop``.

    Neither verb's failure is an error: a task that is not running and a task
    that is already disabled are both the state the caller asked for.
    """
    _schtasks("/End", "/TN", TASK_NAME)
    _schtasks("/Change", "/TN", TASK_NAME, "/DISABLE")


def is_active() -> bool:
    """Whether a gateway is actually serving.

    Deliberately NOT ``schtasks /Query``'s ``Status`` column. That column is
    LOCALIZED, so matching it would answer correctly on an English host and
    wrongly everywhere else — and the failure would be silent, which is the
    class of defect this module exists to remove.

    It also answers a different question than the caller asks. The scheduler
    knows whether it launched something; the caller wants to know whether a
    gateway is up. Those diverge exactly when it matters: a task that started
    and whose gateway then wedged reads as running. A connect to the dashboard
    port is the same evidence :func:`kiro_crew.snapshot._is_gateway_running`
    uses, it is locale-independent, and it is answered by the gateway itself.
    """
    port = _dashboard_port()
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1):
            return True
    except OSError:
        return False


def restart() -> bool:
    """Stop the running instance and start it again. True iff accepted.

    Task Scheduler has no atomic restart verb, so this is ``/End`` then
    ``/Run``. Only ``/Run``'s exit code decides the answer: ``/End`` on an
    instance that already exited is a refusal that says nothing about whether
    the restart will work, and treating it as failure would report a
    successful restart as a failed one.
    """
    _schtasks("/End", "/TN", TASK_NAME)
    _schtasks("/Change", "/TN", TASK_NAME, "/ENABLE")
    return _schtasks("/Run", "/TN", TASK_NAME).returncode == 0


def status() -> str:
    """A human-readable status line.

    Composed from facts this module can establish without reading localized
    output: whether Task Scheduler holds the task, and whether a gateway is
    answering. ``schtasks``'s own status prose is never echoed, because an
    operator comparing two hosts should not see two different vocabularies for
    the same state.
    """
    installed = is_installed()
    active = is_active()
    if not installed:
        return f"not installed (no task at {TASK_NAME})"
    return f"installed at {TASK_NAME}; gateway is {'running' if active else 'not running'}"


def _dashboard_port() -> int:
    """The port a local gateway would be serving on."""
    try:
        from kiro_crew.config import KiroCrewConfig

        cfg = KiroCrewConfig.load()
        return int(getattr(getattr(cfg, "dashboard", None), "port", 0)) or DEFAULT_PORT
    except Exception:  # noqa: BLE001 - an unreadable config still has a default
        return DEFAULT_PORT
