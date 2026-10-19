"""Collector plugins. Importing this package registers the built-in collectors."""

from amwe.collectors import git_identity, username

__all__ = ["git_identity", "username"]
