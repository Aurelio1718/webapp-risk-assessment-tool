"""Configuration loading and validation (config.ini, standard library only)."""
from __future__ import annotations

import configparser
import os
import shlex
import stat
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit


class ConfigError(Exception):
    """Raised when the configuration is missing or invalid."""


def _bool(value: str, name: str) -> bool:
    v = (value or "").strip().lower()
    if v in ("yes", "true", "1", "on"):
        return True
    if v in ("no", "false", "0", "off", ""):
        return False
    raise ConfigError(f"{name}: expected yes/no, got {value!r}")


def _int(value: str, name: str, default: int) -> int:
    if value is None or str(value).strip() == "":
        return default
    try:
        return int(value)
    except ValueError as exc:
        raise ConfigError(f"{name}: expected an integer, got {value!r}") from exc


def _path(value: str) -> str:
    value = (value or "").strip()
    return str(Path(value).expanduser()) if value else ""


@dataclass
class ScopeCfg:
    authorized: bool
    hosts: list[str]


@dataclass
class TargetCfg:
    url: str
    insecure_tls: bool
    timeout: int

    @property
    def host(self) -> str:
        return urlsplit(self.url).hostname or ""

    @property
    def scheme(self) -> str:
        return urlsplit(self.url).scheme

    @property
    def port(self) -> int:
        parts = urlsplit(self.url)
        return parts.port or (443 if parts.scheme == "https" else 80)


@dataclass
class SSHCfg:
    host: str
    port: int
    user: str
    key_path: str
    known_hosts: str
    connect_timeout: int

    @property
    def enabled(self) -> bool:
        return bool(self.host)


@dataclass
class AppCfg:
    source_path: str
    compose_path: str


@dataclass
class DBCfg:
    engine: str
    access: str
    host: str
    port: int
    user: str
    database: str
    container: str
    password_file: str

    def password(self) -> str | None:
        """Return the DB password from WRA_DB_PASSWORD or a mode-600 file, else None."""
        env = os.environ.get("WRA_DB_PASSWORD")
        if env:
            return env
        if self.password_file:
            return read_secret_file(self.password_file)
        return None


@dataclass
class RuntimeCfg:
    engine: str
    mode: str
    extra_args: list[str]
    volume_opts: str
    allow_unpinned: bool


@dataclass
class ScoringCfg:
    low_max: int
    medium_max: int


@dataclass
class Config:
    path: str
    scope: ScopeCfg
    target: TargetCfg
    ssh: SSHCfg
    app: AppCfg
    db: DBCfg
    runtime: RuntimeCfg
    tool_args: dict[str, list[str]] = field(default_factory=dict)
    images: dict[str, str] = field(default_factory=dict)
    scoring: ScoringCfg = field(default_factory=lambda: ScoringCfg(6, 12))


def read_secret_file(path: str) -> str:
    """Read a secret from a file that must not be readable by group/others."""
    p = Path(path).expanduser()
    try:
        st = p.stat()
    except OSError as exc:
        raise ConfigError(f"secret file {p}: {exc.strerror}") from exc
    if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise ConfigError(f"secret file {p} must be mode 600 (found {stat.filemode(st.st_mode)})")
    return p.read_text(encoding="utf-8").strip()


def load_config(path: str) -> Config:
    p = Path(path).expanduser()
    if not p.is_file():
        raise ConfigError(f"config file not found: {p} (copy config.example.ini to config.ini)")
    cp = configparser.ConfigParser(interpolation=None)
    try:
        cp.read(p, encoding="utf-8")
    except configparser.Error as exc:
        raise ConfigError(f"cannot parse {p}: {exc}") from exc

    def get(section: str, key: str, default: str = "") -> str:
        return cp.get(section, key, fallback=default).strip()

    hosts = [h.strip() for h in get("scope", "hosts").replace("\n", ",").split(",") if h.strip()]
    scope = ScopeCfg(authorized=_bool(get("scope", "authorized", "no"), "scope.authorized"), hosts=hosts)

    url = get("target", "url")
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ConfigError(f"target.url must be an http(s) URL with a host, got {url!r}")
    target = TargetCfg(
        url=url,
        insecure_tls=_bool(get("target", "insecure_tls", "yes"), "target.insecure_tls"),
        timeout=_int(get("target", "timeout"), "target.timeout", 15),
    )

    ssh = SSHCfg(
        host=get("ssh", "host"),
        port=_int(get("ssh", "port"), "ssh.port", 22),
        user=get("ssh", "user"),
        key_path=_path(get("ssh", "key_path")),
        known_hosts=_path(get("ssh", "known_hosts")),
        connect_timeout=_int(get("ssh", "connect_timeout"), "ssh.connect_timeout", 10),
    )
    if ssh.enabled and (not ssh.user or not ssh.key_path or not ssh.known_hosts):
        raise ConfigError("ssh.user, ssh.key_path and ssh.known_hosts are required when ssh.host is set")

    app = AppCfg(source_path=get("app", "source_path"), compose_path=get("app", "compose_path"))

    db = DBCfg(
        engine=get("db", "engine", "auto").lower(),
        access=get("db", "access", "none").lower(),
        host=get("db", "host", "127.0.0.1"),
        port=_int(get("db", "port"), "db.port", 5432),
        user=get("db", "user"),
        database=get("db", "database"),
        container=get("db", "container"),
        password_file=_path(get("db", "password_file")),
    )
    if db.engine not in ("auto", "postgresql", "mysql"):
        raise ConfigError(f"db.engine must be auto|postgresql|mysql, got {db.engine!r}")
    if db.access not in ("docker_exec", "tcp", "none"):
        raise ConfigError(f"db.access must be docker_exec|tcp|none, got {db.access!r}")
    if cp.has_option("db", "password"):
        raise ConfigError("db.password is not allowed in the config: use WRA_DB_PASSWORD or db.password_file")

    runtime = RuntimeCfg(
        engine=get("runtime", "engine", "podman"),
        mode=get("runtime", "mode", "container").lower(),
        extra_args=shlex.split(get("runtime", "extra_args")),
        volume_opts=get("runtime", "volume_opts", "auto").lower(),
        allow_unpinned=_bool(get("runtime", "allow_unpinned", "no"), "runtime.allow_unpinned"),
    )
    if runtime.engine not in ("podman", "docker"):
        raise ConfigError(f"runtime.engine must be podman|docker, got {runtime.engine!r}")
    if runtime.mode not in ("container", "local"):
        raise ConfigError(f"runtime.mode must be container|local, got {runtime.mode!r}")

    tool_args = {k: shlex.split(v) for k, v in cp.items("tool_args")} if cp.has_section("tool_args") else {}
    images = {k: v.strip() for k, v in cp.items("images")} if cp.has_section("images") else {}

    scoring = ScoringCfg(
        low_max=_int(get("scoring", "low_max"), "scoring.low_max", 6),
        medium_max=_int(get("scoring", "medium_max"), "scoring.medium_max", 12),
    )
    if not 1 <= scoring.low_max < scoring.medium_max < 25:
        raise ConfigError("scoring: require 1 <= low_max < medium_max < 25")

    return Config(str(p), scope, target, ssh, app, db, runtime, tool_args, images, scoring)
