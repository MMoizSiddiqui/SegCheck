"""SegCheck web application package."""

from . import models
from .app import create_app

__all__ = ["create_app"]
