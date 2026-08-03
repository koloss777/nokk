"""nokk-cf — harvest Cloudflare `cf_clearance` with a real browser, for reuse by nokk.

See :func:`harvest` and docs/RESEARCH.md.
"""

from __future__ import annotations

from .harvester import ClearanceResult, harvest

__all__ = ["harvest", "ClearanceResult", "__version__"]
__version__ = "0.0.1"
