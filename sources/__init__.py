"""Dynamic source registry.

Scans *sources/passive/* and *sources/active/* at import time and builds
``{name: class}`` dicts consumed by the engine and the CLI.

To add a new source, drop a .py file in the appropriate sub-package -
no other changes are needed anywhere else.
"""
import importlib
import pkgutil

import sources.passive
import sources.active


def _load_package(package) -> dict:
    """Return {NAME: class} for every source found in package."""
    result: dict = {}
    for _, module_name, _ in pkgutil.iter_modules(package.__path__):
        if module_name.startswith('_'):
            continue
        try:
            mod = importlib.import_module(f'{package.__name__}.{module_name}')
            for attr in dir(mod):
                obj = getattr(mod, attr)
                if isinstance(obj, type) and getattr(obj, 'NAME', None) == module_name:
                    result[module_name] = obj
                    break
        except Exception:
            pass
    return result


PASSIVE_SOURCES: dict = _load_package(sources.passive)
ACTIVE_SOURCES: dict  = _load_package(sources.active)
