"""A small Sigma-to-SQL backend for DuckDB.

Supports what the rules in sigma/ use, which covers most Linux auth-log rules:
  * selections as maps (AND across fields) or lists of maps (OR)
  * value lists (OR), and the modifiers contains, startswith, endswith, re, all
  * conditions with and / or / not / parentheses, `1 of sel*`, `all of sel*`, `1 of them`
  * Sigma correlation rules of type event_count (group-by, timespan, gte/gt)

Values are escaped as SQL string literals and field names are checked against the
table schema, so a rule file cannot inject SQL.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path

import yaml

SIGMA_DIR = Path(__file__).resolve().parent.parent / "sigma"
TIMESPAN = re.compile(r"^(\d+)([smhd])$")
UNITS = {"s": "SECOND", "m": "MINUTE", "h": "HOUR", "d": "DAY"}


class SigmaError(ValueError):
    pass


def lit(v) -> str:
    if isinstance(v, bool):
        return "TRUE" if v else "FALSE"
    if isinstance(v, (int, float)):
        return repr(v)
    return "'" + str(v).replace("'", "''") + "'"


def _like_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _field_expr(key: str, value, columns: set) -> str:
    field, *mods = key.split("|")
    if field not in columns:
        raise SigmaError(f"unknown field {field!r}")
    col = f'"{field}"'
    values = value if isinstance(value, list) else [value]
    join = " AND " if "all" in mods else " OR "
    parts = []
    for v in values:
        if v is None:
            parts.append(f"{col} IS NULL")
        elif "re" in mods:
            parts.append(f"regexp_matches(CAST({col} AS VARCHAR), {lit(v)})")
        elif "contains" in mods:
            parts.append(f"CAST({col} AS VARCHAR) ILIKE {lit('%' + _like_escape(str(v)) + '%')} ESCAPE '\\'")
        elif "startswith" in mods:
            parts.append(f"CAST({col} AS VARCHAR) ILIKE {lit(_like_escape(str(v)) + '%')} ESCAPE '\\'")
        elif "endswith" in mods:
            parts.append(f"CAST({col} AS VARCHAR) ILIKE {lit('%' + _like_escape(str(v)))} ESCAPE '\\'")
        else:
            parts.append(f"{col} = {lit(v)}")
    return "(" + join.join(parts) + ")"


def _selection(sel, columns) -> str:
    if isinstance(sel, list):
        return "(" + " OR ".join(_selection(s, columns) for s in sel) + ")"
    if isinstance(sel, dict):
        return "(" + " AND ".join(_field_expr(k, v, columns) for k, v in sel.items()) + ")"
    raise SigmaError("selections must be maps or lists of maps")


def _tokens(cond: str) -> list[str]:
    return re.findall(r"\(|\)|[A-Za-z0-9_*]+", cond)


def compile_condition(cond: str, selections: dict, columns: set) -> str:
    toks, pos = _tokens(cond), 0

    def peek():
        return toks[pos] if pos < len(toks) else None

    def take(expected=None):
        nonlocal pos
        t = toks[pos] if pos < len(toks) else None
        if expected and t != expected:
            raise SigmaError(f"expected {expected!r} in condition, got {t!r}")
        pos += 1
        return t

    def name_group(pattern):
        names = [n for n in selections if fnmatch(n, pattern)] if pattern != "them" else list(selections)
        if not names:
            raise SigmaError(f"condition refers to no selection: {pattern!r}")
        return [_selection(selections[n], columns) for n in names]

    def atom():
        t = peek()
        if t == "(":
            take("(")
            e = expr()
            take(")")
            return e
        if t == "not":
            take()
            return f"(NOT {atom()})"
        if t in ("1", "all"):
            q = take()
            take("of")
            parts = name_group(take())
            return "(" + (" OR " if q == "1" else " AND ").join(parts) + ")"
        if t in selections:
            take()
            return _selection(selections[t], columns)
        raise SigmaError(f"unexpected token {t!r} in condition")

    def conj():
        e = atom()
        while peek() == "and":
            take()
            e = f"({e} AND {atom()})"
        return e

    def expr():
        e = conj()
        while peek() == "or":
            take()
            e = f"({e} OR {conj()})"
        return e

    out = expr()
    if pos != len(toks):
        raise SigmaError(f"trailing tokens in condition: {toks[pos:]}")
    return out


@dataclass
class Rule:
    id: str
    name: str
    title: str
    level: str
    tags: list
    description: str
    falsepositives: list
    sql: str
    kind: str  # "event" or "correlation"
    path: str


def _base_sql(spec, table, columns):
    det = dict(spec["detection"])
    cond = det.pop("condition")
    if isinstance(cond, list):
        cond = " or ".join(f"({c})" for c in cond)
    where = compile_condition(cond, det, columns)
    return f"SELECT * FROM {table} WHERE {where}"


def load_rules(con, table: str = "auth", directory: Path = SIGMA_DIR) -> list[Rule]:
    columns = {r[0] for r in con.execute(f"DESCRIBE {table}").fetchall()}
    docs = []
    for f in sorted(directory.glob("*.yml")):
        for spec in yaml.safe_load_all(f.read_text()):
            docs.append((f, spec))
    base = {}
    rules = []
    for f, spec in docs:
        if "detection" in spec:
            name = spec.get("name") or f.stem
            sql = _base_sql(spec, table, columns)
            base[name] = sql
            rules.append(Rule(spec["id"], name, spec["title"], spec.get("level", "medium"), spec.get("tags", []),
                              spec.get("description", ""), spec.get("falsepositives", []), sql, "event", f.name))
    for f, spec in docs:
        if "correlation" in spec:
            c = spec["correlation"]
            if c["type"] != "event_count":
                raise SigmaError(f"{f.name}: only event_count correlations are supported")
            src = c["rules"][0]
            if src not in base:
                raise SigmaError(f"{f.name}: unknown base rule {src}")
            gb = c["group-by"]
            bad = set(gb) - columns
            if bad:
                raise SigmaError(f"{f.name}: unknown group-by {bad}")
            m = TIMESPAN.match(c["timespan"])
            if not m:
                raise SigmaError(f"{f.name}: bad timespan {c['timespan']}")
            n, unit = int(m[1]), UNITS[m[2]]
            op, thr = next(iter(c["condition"].items()))
            sym = {"gte": ">=", "gt": ">", "lte": "<=", "lt": "<", "eq": "="}[op]
            g = ", ".join(f'"{x}"' for x in gb)
            sql = (f"SELECT {g}, time_bucket(INTERVAL {n} {unit}, ts) AS window_start, count(*) AS event_count, "
                   f"min(ts) AS first_ts, max(ts) AS last_ts, list(line_no) AS lines FROM ({base[src]}) "
                   f"GROUP BY {g}, time_bucket(INTERVAL {n} {unit}, ts) HAVING count(*) {sym} {int(thr)}")
            rules.append(Rule(spec["id"], spec.get("name", f.stem), spec["title"], spec.get("level", "medium"),
                              spec.get("tags", []), spec.get("description", ""), spec.get("falsepositives", []), sql, "correlation", f.name))
    return rules


def run(con, rules: list[Rule]) -> dict:
    return {r.name: con.execute(r.sql).df() for r in rules}
