"""Internal probe: PostgreSQL configuration and permissions via `docker exec` + psql (read-only queries).

Runs as the container's POSTGRES_USER over the local socket inside the DB container: no password
leaves the target and none is needed. The container is the configured [db] container, or the first
running container whose image contains 'postgres'.
"""
from __future__ import annotations

import re
import shlex

from ..finding import not_assessed
from ..internal import host_el, ifinding, remote, sections
from .base import Probe

SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
QUERIES = {
    "roles": "SELECT rolname, rolsuper, rolcreaterole, rolcreatedb, rolcanlogin, rolbypassrls FROM pg_roles "
             "WHERE rolname !~ '^pg_' ORDER BY 1",
    "settings": "SELECT name, setting FROM pg_settings WHERE name IN ('ssl','password_encryption',"
                "'listen_addresses','log_connections','log_disconnections') ORDER BY 1",
    "hba": "SELECT type, array_to_string(database,','), array_to_string(user_name,','), coalesce(address,''), "
           "auth_method FROM pg_hba_file_rules WHERE error IS NULL",
    "owners": "SELECT tableowner, count(*) FROM pg_tables WHERE schemaname NOT IN ('pg_catalog',"
              "'information_schema') GROUP BY 1",
    "version": "SELECT version()",
}


def build_script(container: str = "", user: str = "") -> str:
    """user set -> authenticate as that role with the password read from stdin (never on a command line);
    user empty -> container's POSTGRES_USER over the local socket (works only with local 'trust')."""
    if user and not SAFE_NAME.match(user):
        raise ValueError(f"unsafe [db] user {user!r}")
    if container:
        if not SAFE_NAME.match(container):
            raise ValueError(f"unsafe [db] container {container!r}")
        pick = f"c={shlex.quote(container)}"
    else:
        pick = "c=$(docker ps --format '{{.Names}} {{.Image}}' | awk '$2 ~ /postgres/ {print $1; exit}')"
    lines = ([r"IFS= read -r WRA_PW"] if user else []) + [pick, 'echo "##container $c"', '[ -n "$c" ] || exit 0']
    for name, sql in QUERIES.items():
        if user:
            inner = (f'IFS= read -r PGPASSWORD; export PGPASSWORD; psql -X -A -t -F "|" -U {shlex.quote(user)} '
                     f'-d "${{POSTGRES_DB:-postgres}}" -c {shlex.quote(sql)}')
            lines.append(f'echo "##{name}"; printf \'%s\\n\' "$WRA_PW" | docker exec -i "$c" sh -c {shlex.quote(inner)} 2>&1')
        else:
            inner = f'psql -X -A -t -F "|" -U "$POSTGRES_USER" -d "${{POSTGRES_DB:-postgres}}" -c {shlex.quote(sql)}'
            lines.append(f'echo "##{name}"; docker exec "$c" sh -c {shlex.quote(inner)} 2>&1')
    return "\n".join(lines)


AUTH_ERRORS = ("no password supplied", "password authentication failed")


def parse(stdout: str, host: str, app_user: str, database: str, evidence: list[str]) -> list:
    sec = sections(stdout)
    cont = next((k.split(" ", 1)[1] for k in sec if k.startswith("container ")), "")
    if not cont:
        return []
    el = f"postgresql://{host}/{database or 'postgres'}"
    out = []

    def add(check, title, cwe, desc, fix, chain=False, element=el):
        out.append(ifinding("wra-db", title=title, element=element, category=cwe, owasp="A05", check_id=check,
                            evidence=evidence, description=desc, remediation=fix, chain=chain))

    roles = [l.split("|") for l in sec.get("roles", []) if l.count("|") == 5]
    supers = [r[0] for r in roles if r[1] == "t" and r[4] == "t"]
    for r in roles:
        name, sup, crole, cdb = r[0], r[1] == "t", r[2] == "t", r[3] == "t"
        if name == app_user and (sup or crole or cdb):
            add("db-app-role-privileged", "Application DB role has administrative privileges", "CWE-250",
                f"role {name}: superuser={sup} createrole={crole} createdb={cdb}",
                "Use a least-privilege role for the app (no SUPERUSER/CREATEROLE/CREATEDB).",
                element=f"{el}?role={name}")
    if len(supers) > 1:
        add("db-multiple-superusers", "More than one login superuser", "CWE-250", f"superusers: {', '.join(supers)}",
            "Keep a single administrative role; remove superuser from the others.", chain=True)
    st = dict(l.split("|", 1) for l in sec.get("settings", []) if "|" in l)
    if st.get("password_encryption", "").lower() == "md5":
        add("db-md5-passwords", "Passwords hashed with MD5", "CWE-916", "password_encryption = md5",
            "Set password_encryption = scram-sha-256 and reset passwords.")
    if st.get("ssl") == "off":
        add("db-no-tls", "Database connections not encrypted", "CWE-319", "ssl = off",
            "Enable TLS (ssl=on) or keep the DB reachable only on an isolated network (verify).", chain=True)
    for l in sec.get("hba", []):
        p = l.split("|")
        if len(p) == 5 and p[0].startswith("host") and p[4] in ("trust", "password"):
            add("db-weak-hba", f"pg_hba allows '{p[4]}' authentication over the network", "CWE-287",
                f"{p[0]} db={p[1]} user={p[2]} addr={p[3]} method={p[4]}",
                "Use scram-sha-256 for all host lines; restrict addresses.")
            break
    owners = dict(l.split("|", 1) for l in sec.get("owners", []) if "|" in l)
    if app_user and app_user in owners:
        add("db-app-owns-schema", "Application role owns the tables (DDL rights)", "CWE-250",
            f"{app_user} owns {owners[app_user]} table(s): it can ALTER/DROP them",
            "Let an admin/migration role own the schema; grant the app only DML.", chain=True,
            element=f"{el}?role={app_user}")
    return out


class DatabaseProbe(Probe):
    name = "int-database"
    phase = "internal"
    source = "wra-db"
    requires_access = "privileged"
    order = 40

    def element(self, ctx):
        return host_el(ctx) if ctx.config.ssh.host else super().element(ctx)

    def applicable(self, ctx):
        db = ctx.config.db
        if db.access != "docker_exec":
            return False, f"db.access={db.access}: only docker_exec is implemented"
        if db.engine not in ("auto", "postgresql"):
            return False, f"db.engine={db.engine}: only PostgreSQL is implemented"
        if not ctx.access()["facts"].get("docker"):
            return False, "Docker API not available to the audit user"
        return True, "applicable"

    def run(self, ctx):
        db = ctx.config.db
        pw = db.password()
        script = build_script(db.container, db.user if pw else "")
        stdout = remote(ctx, self, script, secret_stdin=(pw + "\n") if pw else None)
        ev = ctx.store.write_evidence("int-database.txt", stdout)
        el = f"postgresql://{ctx.config.ssh.host}/{db.database or 'postgres'}"
        if "##container " not in stdout or stdout.split("##container", 1)[1].splitlines()[0].strip() == "":
            return [not_assessed(el, self.name, self.phase, self.source, "no PostgreSQL container found")]
        if any(e in stdout for e in AUTH_ERRORS):
            reason = ("DB authentication failed for the configured role" if pw else
                      "local socket requires a password (good: no 'trust'); set WRA_DB_PASSWORD for [db] user")
            return [not_assessed(el, self.name, self.phase, self.source, reason)]
        notes = [f"{k}: {v[0][:120]}" for k, v in sections(stdout).items()
                 if v and ("permission denied" in v[0].lower() or v[0].startswith("ERROR"))]
        if notes:
            ctx.store.write_raw(self.phase, "int-database-notes.txt",
                                "Queries not permitted for this role (not assessed):\n" + "\n".join(notes) + "\n")
        return parse(stdout, ctx.config.ssh.host, db.user, db.database, [ev])
