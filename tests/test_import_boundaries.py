"""tests/test_import_boundaries.py — Phase 38.8: dependency-rule guard.

Static (AST) enforcement of docs/PROJECT_STRUCTURE_DESIGN.md section 3, so the
layering cannot silently erode after the Phase 38 migration:

    app --------> core
    root shims -> app or core
    core -------X-> app
    core -------X-> root shims
    app --------X-> root shims

The six root modules (peer, discovery, chat, file_transfer, protocol, ui) are
backward-compatibility shims. Production code must import the canonical
`app.*` / `core.*` paths; only tests may still reach the shims (the dedicated
shim suite).

Nothing here imports the code under test at runtime — files are parsed, never
executed — so a violation is reported even if the offending import would fail
or be lazy (inside a function).
"""

import ast
import pathlib
import re

import pytest

pytestmark = pytest.mark.unit

REPO = pathlib.Path(__file__).resolve().parent.parent
SHIMS = ("peer", "discovery", "chat", "file_transfer", "protocol", "ui")
SKIP_TOP_DIRS = {"tests", "docs", "build", "dist"}


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

def find_forbidden_imports(source: str, forbidden) -> list:
    """Return [(lineno, text)] for absolute imports of any top-level module in
    `forbidden`, including imports nested in functions and dynamic
    import_module()/__import__() calls with a literal name.

    `from core import protocol` is NOT a hit: its module is `core`. Relative
    imports never leave their own package, so they are ignored.
    """
    hits = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in forbidden:
                    hits.append((node.lineno, f"import {alias.name}"))
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module and node.module.split(".")[0] in forbidden:
                hits.append((node.lineno, f"from {node.module} import ..."))
        elif isinstance(node, ast.Call):
            fn = node.func
            name = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
            if (
                name in ("import_module", "__import__")
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
                and node.args[0].value.split(".")[0] in forbidden
            ):
                hits.append((node.lineno, f"{name}({node.args[0].value!r})"))
    return hits


def _is_skipped(rel: pathlib.PurePath) -> bool:
    parts = rel.parts
    return (
        parts[0] in SKIP_TOP_DIRS
        or any(p.startswith(".") or p.endswith(".egg-info") or p == "__pycache__" for p in parts)
    )


def production_files() -> list:
    """Every .py outside tests/docs/build output, excluding the six shims."""
    shim_names = {f"{s}.py" for s in SHIMS}
    out = []
    for path in sorted(REPO.rglob("*.py")):
        rel = path.relative_to(REPO)
        if _is_skipped(rel):
            continue
        if len(rel.parts) == 1 and rel.name in shim_names:
            continue
        out.append(path)
    return out


def _format(violations: dict) -> str:
    return "\n".join(
        f"  {path}:{line}  {text}" for path, items in violations.items() for line, text in items
    )


# ---------------------------------------------------------------------------
# Negative controls: prove the scanner actually detects what it claims to
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "source, expected",
    [
        ("import peer\n", ["import peer"]),
        ("from discovery import Discovery\n", ["from discovery import ..."]),
        ("import ui as u\n", ["import ui"]),
        ("def f():\n    from chat import ChatSession\n", ["from chat import ..."]),
        ("import importlib\nimportlib.import_module('file_transfer')\n", ["import_module('file_transfer')"]),
        ("__import__('protocol')\n", ["__import__('protocol')"]),
        ("from protocol import make_error\n", ["from protocol import ..."]),
    ],
)
def test_scanner_flags_root_shim_imports(source, expected):
    hits = find_forbidden_imports(source, SHIMS)
    assert [text for _, text in hits] == expected


@pytest.mark.parametrize(
    "source",
    [
        "from core import protocol\n",
        "import core.protocol as protocol\n",
        "from core.discovery.broadcast import Discovery\n",
        "from app.ui.app import ChatApp\n",
        "from . import protocol\n",
        "from .peer import X\n",
        "import importlib\nimportlib.import_module('core.protocol')\n",
        "import importlib\nimportlib.import_module(name)\n",
    ],
)
def test_scanner_allows_canonical_imports(source):
    assert find_forbidden_imports(source, SHIMS) == []


def test_scanner_flags_core_importing_app():
    assert find_forbidden_imports("from app.ui.app import ChatApp\n", {"app"})
    assert find_forbidden_imports("import app.config\n", {"app"})
    assert not find_forbidden_imports("from core.events import Event\n", {"app"})


# ---------------------------------------------------------------------------
# The real rules, applied to the repository
# ---------------------------------------------------------------------------

def test_production_code_never_imports_root_shims():
    files = production_files()
    assert len(files) > 50, "scan found suspiciously few files; skip rules changed?"
    violations = {}
    for path in files:
        hits = find_forbidden_imports(path.read_text(encoding="utf-8"), SHIMS)
        if hits:
            violations[path.relative_to(REPO).as_posix()] = hits
    assert not violations, "production code must import app.* / core.*, not root shims:\n" + _format(violations)


def test_core_never_imports_app():
    core_files = sorted((REPO / "core").rglob("*.py"))
    assert core_files
    violations = {}
    for path in core_files:
        hits = find_forbidden_imports(path.read_text(encoding="utf-8"), {"app"})
        if hits:
            violations[path.relative_to(REPO).as_posix()] = hits
    assert not violations, "core must not depend on app:\n" + _format(violations)


def test_only_the_six_shims_live_at_the_repo_root():
    root_modules = {p.stem for p in REPO.glob("*.py")}
    assert root_modules == set(SHIMS), (
        "root-level .py files must be exactly the compatibility shims; "
        f"unexpected: {sorted(root_modules - set(SHIMS))}, missing: {sorted(set(SHIMS) - root_modules)}"
    )


def _pyproject() -> str:
    return (REPO / "pyproject.toml").read_text(encoding="utf-8")


def test_pyproject_py_modules_matches_the_shims():
    m = re.search(r"^py-modules\s*=\s*\[(.*?)\]", _pyproject(), re.S | re.M)
    assert m, "py-modules not found in pyproject.toml"
    declared = set(re.findall(r'"([^"]+)"', m.group(1)))
    assert declared == set(SHIMS)


def test_console_scripts_do_not_target_a_root_shim():
    m = re.search(r"^\[project\.scripts\]\n(.*?)(?:\n\[|\Z)", _pyproject(), re.S | re.M)
    assert m, "[project.scripts] not found"
    targets = re.findall(r'^\s*[\w.-]+\s*=\s*"([\w.]+):[\w.]+"', m.group(1), re.M)
    assert targets, "no console scripts parsed"
    for target in targets:
        assert target.split(".")[0] not in SHIMS, f"console script targets a root shim: {target}"


@pytest.mark.parametrize("shim", SHIMS)
def test_shims_only_reexport_and_carry_no_logic(shim):
    """A shim is: docstring, imports from app/core, __all__, and (ui only) the
    documented `python3 ui.py` launch guard. No other statements."""
    tree = ast.parse((REPO / f"{shim}.py").read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            continue  # module docstring
        if isinstance(node, ast.ImportFrom):
            assert node.level == 0 and node.module.split(".")[0] in ("app", "core"), (
                f"{shim}.py may only import from app/core, found: from {node.module} import ..."
            )
            continue
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == "__all__"
        ):
            continue
        if shim == "ui" and _is_main_guard(node):
            continue
        pytest.fail(f"{shim}.py must only re-export; found {type(node).__name__} at line {node.lineno}")


def _is_main_guard(node) -> bool:
    """`if __name__ == "__main__": main()` and nothing else."""
    if not (isinstance(node, ast.If) and not node.orelse and len(node.body) == 1):
        return False
    t = node.test
    is_guard = (
        isinstance(t, ast.Compare)
        and isinstance(t.left, ast.Name) and t.left.id == "__name__"
        and len(t.ops) == 1 and isinstance(t.ops[0], ast.Eq)
        and isinstance(t.comparators[0], ast.Constant) and t.comparators[0].value == "__main__"
    )
    stmt = node.body[0]
    calls_main = (
        isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call)
        and isinstance(stmt.value.func, ast.Name) and stmt.value.func.id == "main"
        and not stmt.value.args and not stmt.value.keywords
    )
    return is_guard and calls_main
