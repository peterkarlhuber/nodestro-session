"""The package: standard library only, typed, brand-neutral, and its public names."""

from __future__ import annotations

import ast
from pathlib import Path
import sys

import nodestro_session

SRC = Path(nodestro_session.__file__).resolve().parent


def test_the_package_imports_only_the_standard_library() -> None:
    allowed = set(sys.stdlib_module_names) | {"nodestro_session"}
    for path in SRC.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names = [node.module]
            else:
                continue
            for name in names:
                assert name.split(".")[0] in allowed, f"{path.name} imports {name}"


def test_the_api_is_brand_neutral() -> None:
    # Beyond the package name, nothing names a product: the products keep their texts, codes and cookie names.
    for path in SRC.glob("*.py"):
        text = path.read_text(encoding="utf-8").lower().replace("nodestro_session", "")
        for brand in ("nodestro", "locria", "tabrion", "axentra", "levuvo"):
            assert brand not in text, f"{path.name} names {brand}"


def test_the_package_is_typed_and_exports_its_names() -> None:
    assert (SRC / "py.typed").is_file()
    for name in nodestro_session.__all__:
        assert hasattr(nodestro_session, name), name
    assert nodestro_session.__version__.startswith("0.1.")
