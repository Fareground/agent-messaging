"""Protocol and package versions.

``PROTOCOL_VERSION`` is the wire version and is hand-pinned — it changes only
when the on-the-wire format does, independently of package releases.
``PACKAGE_VERSION`` is derived from installed package metadata so it never
drifts from ``pyproject.toml``; the fallback covers running from a source tree
that was never installed.
"""

from importlib.metadata import PackageNotFoundError, version

# Wire protocol version — tracked separately from the package version and
# frozen at 0.1 until the v1.0 wire freeze.
PROTOCOL_VERSION = "0.1"

try:
    PACKAGE_VERSION = version("fg-amp")
except PackageNotFoundError:  # pragma: no cover — source tree without install
    PACKAGE_VERSION = "0.0.0+unknown"
