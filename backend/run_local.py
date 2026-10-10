"""Run the local API with SQLAlchemy's Python fallbacks when native modules are blocked."""
import importlib.abc
import importlib.util
import os
import sys
from importlib.machinery import ModuleSpec
from pathlib import Path
from types import ModuleType
from typing import Sequence

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))


class _PythonFallbackFinder(importlib.abc.MetaPathFinder):
    def find_spec(
        self,
        fullname: str,
        path: Sequence[str] | None = None,
        target: ModuleType | None = None,
    ) -> ModuleSpec | None:
        if not fullname.startswith("sqlalchemy.") or path is None:
            return None

        module_name = fullname.rsplit(".", 1)[-1]
        for package_path in path:
            fallback = Path(package_path) / f"{module_name}.py"
            if fallback.is_file():
                return importlib.util.spec_from_file_location(fullname, fallback)
        return None


def main() -> None:
    sys.meta_path.insert(0, _PythonFallbackFinder())
    from app.config import settings
    import uvicorn

    uvicorn.run(
        "app.main:app",
        app_dir=str(ROOT / "backend"),
        host="127.0.0.1",
        port=settings.port,
    )


if __name__ == "__main__":
    main()