"""tests/test_benchmarking_portability.py — the importability note in the security audit.

core/benchmarking.py imported the POSIX-only `resource` module at module level,
so on Windows the whole test suite died during collection (any test module that
imports it fails). Without `resource` the module must still import, and the
memory reading must say "not measured" rather than raise.

The "no resource module" case is checked on a private copy of the file loaded
under another name. Reloading the shared module instead would redefine classes
such as `Direction` and break every other test that already imported them.
"""

import importlib.util
import sys

import pytest

import core.benchmarking as benchmarking

pytestmark = pytest.mark.unit


def _isolated_copy():
    spec = importlib.util.spec_from_file_location("benchmarking_isolated_copy", benchmarking.__file__)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_module_imports_and_reports_zero_when_resource_is_unavailable(monkeypatch):
    monkeypatch.setitem(sys.modules, "resource", None)          # `import resource` now raises ImportError
    copy = _isolated_copy()
    assert copy.resource is None
    assert copy.peak_rss_mb() == 0.0


def test_a_real_reading_is_still_taken_where_resource_exists():
    pytest.importorskip("resource")
    assert benchmarking.peak_rss_mb() > 0.0


def test_checking_the_no_resource_case_does_not_disturb_the_shared_module(monkeypatch):
    direction_before, resource_before = benchmarking.Direction, benchmarking.resource
    monkeypatch.setitem(sys.modules, "resource", None)
    _isolated_copy()
    assert benchmarking.Direction is direction_before
    assert benchmarking.resource is resource_before
