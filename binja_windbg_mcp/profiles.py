"""Local secrets, never exposed through MCP or stored in a database."""

import json
import os
import secrets
import stat
from pathlib import Path
from urllib.parse import urlsplit


def validate_url(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.username or parsed.password or parsed.fragment or parsed.query:
        raise ValueError("profile URL must not contain credentials, query, or fragment")
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("profile requires HTTP or HTTPS")
    if parsed.scheme == "http" and parsed.hostname not in ("localhost", "127.0.0.1", "::1"):
        raise ValueError("remote profiles require HTTPS; tunnel HTTP to loopback")
    return url


class Profiles:
    def __init__(self, directory: Path):
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.path = directory / "profiles.json"
        try:
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            pass
        else:
            with os.fdopen(fd, "w") as stream:
                json.dump({"token": secrets.token_hex(32), "groups": "all", "windbg": {}}, stream)
        fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd) as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise ValueError("profiles.json must be owned by this user with mode 0600")
            self._data = json.load(stream)
        token = self._data["token"]
        if not isinstance(token, str) or len(token) != 64:
            raise ValueError("listener token must encode 32 random bytes")
        bytes.fromhex(token)

    @property
    def token(self):
        return self._data["token"]

    @property
    def groups(self):
        return self._data.get("groups", "all")

    def profile(self, name: str) -> tuple[str, str]:
        value = self._data.get("windbg", {}).get(name)
        if not value:
            raise ValueError("unknown WinDbg profile")
        if not isinstance(value.get("token"), str) or not value["token"]:
            raise ValueError("WinDbg profile requires a bearer credential")
        return validate_url(value["url"]), value["token"]
