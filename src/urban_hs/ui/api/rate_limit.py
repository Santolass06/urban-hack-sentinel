"""Shared slowapi Limiter instance.

Lives in its own module so both ``main`` (which registers it on
``app.state``) and the routers (which decorate routes with it) can
import the same instance without a circular import.
"""

from __future__ import annotations

from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
