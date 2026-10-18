import ast
import pathlib
import sys

PACKAGE = pathlib.Path(__file__).parent.parent / "stationchief"
ALLOWED_THIRD_PARTY = {
    "stationchief/adapters/otel.py": {"opentelemetry"},
}
# The service runs on a server, never in a hook, so it may use its extra.
ALLOWED_THIRD_PARTY_PREFIXES = {
    "stationchief/server/": {"starlette", "uvicorn", "anyio", "boto3", "botocore", "google"},
}


def _allowed_for(rel):
    allowed = set(ALLOWED_THIRD_PARTY.get(rel, set()))
    for prefix, roots in ALLOWED_THIRD_PARTY_PREFIXES.items():
        if rel.startswith(prefix):
            allowed |= roots
    return allowed


def _imported_roots(path):
    tree = ast.parse(path.read_text())
    roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.add(node.module.split(".")[0])
    return roots


def test_only_stdlib_and_declared_extras_are_imported():
    stdlib = sys.stdlib_module_names
    offenders = {}
    for path in sorted(PACKAGE.rglob("*.py")):
        rel = path.relative_to(PACKAGE.parent).as_posix()
        allowed = stdlib | {"stationchief"} | _allowed_for(rel)
        extra = _imported_roots(path) - allowed
        if extra:
            offenders[rel] = sorted(extra)
    assert offenders == {}, f"third-party imports outside declared extras: {offenders}"


def test_the_client_never_imports_the_server():
    """Hooks must not pull in starlette/boto3 through stationchief.server."""
    offenders = []
    for path in sorted(PACKAGE.rglob("*.py")):
        rel = path.relative_to(PACKAGE.parent).as_posix()
        if rel.startswith("stationchief/server/"):
            continue
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("stationchief.server"):
                offenders.append(rel)
            elif isinstance(node, ast.Import) and any(a.name.startswith("stationchief.server") for a in node.names):
                offenders.append(rel)
    assert offenders == [], f"client modules import the server: {offenders}"
