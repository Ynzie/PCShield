"""Real-Windows checks for the security pieces (run by the GitHub build on windows-latest, as admin).

    python tests/test_windows.py
"""
import os
import shutil
import subprocess
import sys
import tempfile
import time
import traceback

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
RESULTS = []


def test(fn):
    try:
        fn()
        RESULTS.append(("PASS", fn.__name__, ""))
    except Exception:  # noqa
        RESULTS.append(("FAIL", fn.__name__, traceback.format_exc()))
    return fn


def ps(cmd):
    r = subprocess.run(["powershell", "-NoProfile", "-Command", cmd], capture_output=True, text=True)
    return r.stdout.strip()


@test
def known_folders_ignore_environment_overrides():
    env = dict(os.environ, ProgramFiles=r"C:\evil", ProgramData=r"C:\evil", SystemRoot=r"C:\evil")
    out = subprocess.run([sys.executable, "-c", "from core import util; print(util.PROGRAM_FILES); print(util.PROGRAM_DATA); print(util.POWERSHELL)"],
                         capture_output=True, text=True, cwd=ROOT, env=env).stdout.splitlines()
    assert out[0].lower() == r"c:\program files" and out[1].lower() == r"c:\programdata", out
    assert os.path.isfile(out[2]), out


from core import install, scanner, system, util, vpn  # noqa: E402


@test
def tools_exist_at_full_paths():
    for t in ("icacls", "cmd", "schtasks", "cipher", "rasdial"):
        assert os.path.isfile(util.sys_exe(t)), t
    assert os.path.isfile(scanner._mpcmdrun()), scanner._mpcmdrun()


@test
def data_folder_gets_locked_and_planted_files_dropped():
    if os.path.lexists(util.DATA_DIR):
        shutil.rmtree(util.DATA_DIR, ignore_errors=True)
    os.makedirs(util.REPORT_DIR)
    open(util.SETTINGS_FILE, "w").write('{"theme": "kaleb"}')
    open(os.path.join(util.DATA_DIR, "evil.dll"), "w").write("x")
    t = time.time()
    assert not install.acl_locked(util.DATA_DIR)
    print(f"      acl check took {time.time() - t:.2f}s")
    assert install.secure_data_dir()
    assert install.acl_locked(util.DATA_DIR)
    assert util.load_settings().get("theme") == "kaleb", "settings weren't carried over"
    assert not os.path.exists(os.path.join(util.DATA_DIR, "evil.dll"))
    assert not [n for n in os.listdir(util.PROGRAM_DATA) if n.startswith("PCShield.untrusted")], "aside folder left behind"
    vpn_acl = ps(f"(Get-Acl -LiteralPath '{util.VPN_DIR}').Access | ForEach-Object {{ $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value }}")
    assert "S-1-5-32-545" not in vpn_acl, f"Users can read VPN keys: {vpn_acl}"
    users = ps(f"(Get-Acl -LiteralPath '{util.DATA_DIR}').Access | Where-Object {{ $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -eq 'S-1-5-32-545' }} | ForEach-Object {{ $_.FileSystemRights }}")
    assert "Write" not in users and "Modify" not in users and "FullControl" not in users, users
    assert install.secure_data_dir() and util.load_settings().get("theme") == "kaleb"  # already locked: nothing moves


@test
def planted_junction_is_moved_aside_not_followed():
    shutil.rmtree(util.DATA_DIR, ignore_errors=True)
    target = tempfile.mkdtemp()
    open(os.path.join(target, "victim.txt"), "w").write("keep")
    subprocess.run(["cmd", "/c", "mklink", "/J", util.DATA_DIR, target], capture_output=True, check=True)
    assert install._is_link(util.DATA_DIR)
    assert install.secure_data_dir()
    assert not install._is_link(util.DATA_DIR) and install.acl_locked(util.DATA_DIR)
    assert open(os.path.join(target, "victim.txt")).read() == "keep"
    acl_before = ps(f"(Get-Acl -LiteralPath '{target}').AreAccessRulesProtected")
    assert acl_before == "False", "the junction target's permissions were changed"
    shutil.rmtree(target, ignore_errors=True)


@test
def old_tasks_retargeted_keep_highest_privileges():
    d = tempfile.mkdtemp()
    fake = os.path.join(d, "PCShield.exe")
    shutil.copyfile(util.sys_exe("cmd"), fake)
    real = (getattr(sys, "frozen", None), sys.executable, install.INSTALL_DIR, install.INSTALL_EXE, install.TASKS)
    sys.frozen, sys.executable = True, fake
    install.INSTALL_DIR = os.path.join(d, "pf"); install.INSTALL_EXE = os.path.join(install.INSTALL_DIR, "PCShield.exe")
    install.TASKS = ["PC Shield Test Task"]
    try:
        ps("$u=[Security.Principal.WindowsIdentity]::GetCurrent().Name; "
           f"$a=New-ScheduledTaskAction -Execute '{fake}'; "
           "$p=New-ScheduledTaskPrincipal -UserId $u -LogonType Interactive -RunLevel Highest; "
           "Register-ScheduledTask -TaskName 'PC Shield Test Task' -Action $a -Principal $p -Force | Out-Null")
        assert install.retarget_tasks() == ["PC Shield Test Task"]
        got = ps("$t=Get-ScheduledTask -TaskName 'PC Shield Test Task'; $t.Actions[0].Execute; $t.Principal.RunLevel")
        assert got.splitlines() == [install.INSTALL_EXE, "Highest"], got
        assert os.path.isfile(install.INSTALL_EXE)
    finally:
        ps("Unregister-ScheduledTask -TaskName 'PC Shield Test Task' -Confirm:$false -ErrorAction SilentlyContinue")
        if real[0] is None:
            del sys.frozen
        else:
            sys.frozen = real[0]
        sys.executable, install.INSTALL_DIR, install.INSTALL_EXE, install.TASKS = real[1:]
        shutil.rmtree(d, ignore_errors=True)


@test
def per_user_uninstall_task_is_limited_and_cleaned_up():
    seen = []
    real = system.ps

    def spy(cmd, timeout=600):
        seen.append(cmd)
        return real(cmd.replace("Start-ScheduledTask", "Get-ScheduledTask"), timeout)  # register, don't run
    system.ps = spy
    try:
        assert system.run_as_user('echo hi', wait_minutes=1)
    finally:
        system.ps = real
    assert "-RunLevel Limited" in seen[0]
    assert not ps("Get-ScheduledTask -TaskName 'PC Shield Uninstall *' -ErrorAction SilentlyContinue")


@test
def vpn_config_acl_by_sid():
    p = os.path.join(util.VPN_DIR, "t.conf")
    open(p, "w").write("[Interface]\n[Peer]\n")
    code, out = util.run(["icacls", p, "/inheritance:r", "/grant:r", "*S-1-5-18:F", "/grant:r", "*S-1-5-32-544:F"])
    assert code == 0, out
    os.remove(p)


for status, name, tb in RESULTS:
    print(f"{status}  {name}")
    if tb:
        print("      " + tb.strip().replace("\n", "\n      "))
print(f"\n{sum(1 for r in RESULTS if r[0] == 'PASS')}/{len(RESULTS)} passed")
sys.exit(0 if all(r[0] == "PASS" for r in RESULTS) else 1)
