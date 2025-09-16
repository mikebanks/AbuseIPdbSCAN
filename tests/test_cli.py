import os
import sys
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "AbuseIPDB.py"


def run(args, env=None):
    cmd = [sys.executable, str(SCRIPT), *args]
    return subprocess.run(
        cmd,
        cwd=str(REPO_ROOT),
        env=env or os.environ.copy(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def test_version_runs():
    r = run(["-v"])
    assert r.returncode == 0
    assert "Version:" in r.stdout


def test_help_runs():
    r = run(["-h"])
    assert r.returncode == 0
    assert "usage:" in r.stdout


def test_private_ip_skipped(monkeypatch):
    env = os.environ.copy()
    env["API_KEY"] = "dummy"
    r = run(["-i", "127.0.0.1"], env=env)
    # No network call needed; should skip and print "No results."
    assert r.returncode == 0
    assert "Skipping private IP" in r.stderr
    assert "No results." in r.stderr


def test_private_block_skipped(monkeypatch):
    env = os.environ.copy()
    env["API_KEY"] = "dummy"
    r = run(["-b", "10.0.0.0/24"], env=env)
    assert r.returncode == 0
    assert "Skipping private block" in r.stderr
    assert "No results." in r.stderr


def test_invalid_block_exits_nonzero():
    env = os.environ.copy()
    env["API_KEY"] = "dummy"
    r = run(["-b", "1.1.1.0/23"], env=env)
    assert r.returncode != 0
    assert "AbuseIPDB only accepts /24 to /32" in r.stderr


def test_block_with_invalid_octet():
    env = os.environ.copy()
    env["API_KEY"] = "dummy"
    r = run(["-b", "999.1.1.0/24"], env=env)
    assert r.returncode != 0
    assert "Not a valid CIDR" in r.stderr
