#!/usr/bin/env python3
"""scripts/verify_wheel.py — Phase 38.9: installed-wheel test in a clean environment.

CI installs the project with `pip install -e .`, so modules and packages are
always read from the source tree and the packaging configuration is never
exercised. This script closes that gap. It:

  1. builds the wheel and inspects it (all six root shims, every app/ and core/
     package present, nothing from tests/docs/scripts, one console script:
     `peerc = app.main:main`);
  2. installs it into a brand-new virtualenv (never editable);
  3. from an empty working directory with no PYTHONPATH — so nothing can be
     found in the source tree — checks that `peerc --help` runs, that every
     module in the wheel imports, and that the six legacy shims resolve inside
     site-packages;
  4. copies a curated slice of the test suite (shims, handshake, relay tunnel,
     connection FSM, discovery, Textual pilot flows) next to that clean
     directory and runs it against the INSTALLED package.

Needs network access for pip (dependencies and pytest). Exits non-zero on any
failure. Run by hand before a release; deliberately not part of per-push CI.

    python scripts/verify_wheel.py [--keep]
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SHIMS = ("peer", "discovery", "chat", "file_transfer", "protocol", "ui")

# Slice of tests/ that is independent of the source-tree layout and covers the
# paths the refactor touched: shims, direct connect, relay tunnel, discovery,
# and headless Textual flows.
TEST_SLICE = (
    "test_shims.py",
    "test_handshake.py",
    "test_connection_fsm_integration.py",
    "test_relay_pipe.py",
    "test_discovery.py",
    "test_link_ui.py",
    "test_relay_ui.py",
    "test_transfer_fsm_integration.py",
)

_failures = []


def step(msg):
    print(f"\n== {msg}")


def check(ok, msg):
    print(f"  [{'ok' if ok else 'FAIL'}] {msg}")
    if not ok:
        _failures.append(msg)


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def expected_packages():
    pkgs = set()
    for top in ("app", "core"):
        for init in (REPO / top).rglob("__init__.py"):
            if "__pycache__" not in init.parts:
                pkgs.add(init.parent.relative_to(REPO).as_posix())
    return pkgs


def inspect_wheel(wheel: Path):
    step("Inspect wheel contents")
    with zipfile.ZipFile(wheel) as z:
        names = z.namelist()
        entry = next((n for n in names if n.endswith(".dist-info/entry_points.txt")), None)
        entry_text = z.read(entry).decode() if entry else ""
    for shim in SHIMS:
        check(f"{shim}.py" in names, f"root shim {shim}.py present")
    have = {n.rsplit("/", 1)[0] for n in names if n.endswith("/__init__.py")}
    missing = sorted(expected_packages() - have)
    check(not missing, f"every app/ and core/ package is in the wheel (missing: {missing or 'none'})")
    stray = [n for n in names if n.split("/")[0] in ("tests", "docs", "scripts", "build")]
    check(not stray, f"nothing from tests/docs/scripts/build (found: {stray[:3] or 'none'})")
    scripts = [l.strip() for l in entry_text.splitlines() if "=" in l]
    check(scripts == ["peerc = app.main:main"], f"console scripts are exactly ['peerc = app.main:main'] (got {scripts})")
    return sorted(
        n[:-3].replace("/", ".").removesuffix(".__init__")
        for n in names if n.endswith(".py") and n.split("/")[0] not in ("tests", "docs", "scripts")
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--keep", action="store_true", help="keep the temp directory for inspection")
    args = ap.parse_args()

    tmp = Path(tempfile.mkdtemp(prefix="peerc-wheel-"))
    try:
        step(f"Build wheel (temp dir: {tmp})")
        r = run([sys.executable, "-m", "pip", "wheel", str(REPO), "--no-deps", "-q", "-w", str(tmp / "dist")])
        check(r.returncode == 0, "pip wheel succeeded" + ("" if r.returncode == 0 else f": {r.stderr[-300:]}"))
        wheels = list((tmp / "dist").glob("peerc-*.whl"))
        if not wheels:
            return 1
        for junk in (REPO / "build", *REPO.glob("*.egg-info")):
            shutil.rmtree(junk, ignore_errors=True)
        modules = inspect_wheel(wheels[0])

        step("Create clean virtualenv and install the wheel (not editable)")
        venv = tmp / "venv"
        check(run([sys.executable, "-m", "venv", str(venv)]).returncode == 0, "venv created")
        py = str(venv / ("Scripts" if os.name == "nt" else "bin") / "python")
        r = run([py, "-m", "pip", "install", "-q", str(wheels[0]), "pytest", "pytest-asyncio"])
        check(r.returncode == 0, "wheel + test tools installed" + ("" if r.returncode == 0 else f": {r.stderr[-300:]}"))
        if r.returncode:
            return 1

        work = tmp / "run"
        (work / "tests").mkdir(parents=True)
        env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
        env["HOME"] = str(tmp / "home")
        env["USERPROFILE"] = env["HOME"]

        step("Console script and imports, from an empty directory")
        peerc = str(venv / ("Scripts" if os.name == "nt" else "bin") / "peerc")
        r = run([peerc, "--help"], cwd=work, env=env, timeout=120)
        check(r.returncode == 0 and r.stdout.startswith("usage: peerc"), "`peerc --help` runs")
        probe = (
            "import importlib, json, sys\n"
            f"mods = {modules!r}\n"
            "bad = {}\n"
            "for m in mods:\n"
            "    try: importlib.import_module(m)\n"
            "    except Exception as e: bad[m] = f'{type(e).__name__}: {e}'\n"
            f"shims = {list(SHIMS)!r}\n"
            "where = {s: importlib.import_module(s).__file__ for s in shims}\n"
            "print(json.dumps({'bad': bad, 'where': where, 'n': len(mods)}))\n"
        )
        r = run([py, "-c", probe], cwd=work, env=env, timeout=300)
        try:
            import json
            info = json.loads(r.stdout.strip().splitlines()[-1])
        except Exception:
            info = {"bad": {"<probe>": (r.stderr or r.stdout)[-300:]}, "where": {}, "n": 0}
        check(not info["bad"], f"all {info['n']} modules in the wheel import (failures: {info['bad'] or 'none'})")
        outside = [s for s, f in info["where"].items() if "site-packages" not in f]
        check(not outside, f"legacy shims resolve inside site-packages (outside: {outside or 'none'})")

        step("Run a test slice against the INSTALLED package")
        for name in TEST_SLICE:
            shutil.copy(REPO / "tests" / name, work / "tests" / name)
        r = run(
            [py, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-o", "asyncio_mode=auto",
             "--rootdir", str(work), *(f"tests/{n}" for n in TEST_SLICE)],
            cwd=work, env=env, timeout=900,
        )
        tail = "\n".join(r.stdout.strip().splitlines()[-4:])
        print("  " + tail.replace("\n", "\n  "))
        check(r.returncode == 0, "test slice passed against the installed wheel")
    finally:
        if args.keep:
            print(f"\n(kept {tmp})")
        else:
            shutil.rmtree(tmp, ignore_errors=True)

    print("\n" + ("PASSED" if not _failures else f"FAILED ({len(_failures)} check(s))"))
    return 1 if _failures else 0


if __name__ == "__main__":
    sys.exit(main())
