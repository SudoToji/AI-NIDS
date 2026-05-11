"""
AI-NIDS API Package
===================
REST API server for Network Intrusion Detection System.

Usage:
    python -m src.api.server
"""

from .server import app

__all__ = ["app"]
