"""Collector plugins. Importing this package registers the built-in collectors."""

from amwe.collectors import exif, git_identity, username

__all__ = ["exif", "git_identity", "username"]
