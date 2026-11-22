"""Start with Windows.
The app needs admin, and Windows skips admin apps in the normal Run/Startup list,
so we register a sign-in Task Scheduler task with 'highest privileges' instead:
no UAC prompt, delayed 30 s so it doesn't slow boot, starts in the system tray."""
import os
import sys

from . import install
from .util import ps, ps_out, ps_quote

TASK = "PC Shield"


def _command():
    return install.task_target("--startup")


def status():
    out = ps_out(f"$t=Get-ScheduledTask -TaskName {ps_quote(TASK)} -ErrorAction SilentlyContinue; "
                 f"if ($t) {{ $t.Actions[0].Execute }}")
    exe, _ = _command()
    return {"enabled": bool(out), "path": out,
            "moved": bool(out) and os.path.normcase(out) != os.path.normcase(exe)}


def set_enabled(enabled):
    if not enabled:
        ps(f"Unregister-ScheduledTask -TaskName {ps_quote(TASK)} -Confirm:$false -ErrorAction SilentlyContinue")
        return {"ok": True, "enabled": False}
    install.ensure_installed()  # the task runs the Program Files copy, which only admins can replace
    exe, args = _command()
    script = (
        f"$u=[Security.Principal.WindowsIdentity]::GetCurrent().Name; "
        f"$a=New-ScheduledTaskAction -Execute {ps_quote(exe)} -Argument {ps_quote(args)}; "
        f"$t=New-ScheduledTaskTrigger -AtLogOn -User $u; $t.Delay='PT30S'; "
        f"$p=New-ScheduledTaskPrincipal -UserId $u -LogonType Interactive -RunLevel Highest; "
        f"$s=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries "
        f"-ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew -Priority 4; "  # tasks default to below-normal priority
        f"Register-ScheduledTask -TaskName {ps_quote(TASK)} -Action $a -Trigger $t -Principal $p -Settings $s -Force | Out-Null; 'ok'"
    )
    out, err, code = ps(script)
    ok = out.strip().endswith("ok")
    return {"ok": ok, "enabled": ok, "message": "" if ok else (err.strip() or "Couldn't create the startup task - run as administrator.")}
