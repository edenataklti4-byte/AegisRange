import shutil
from datetime import datetime, timezone

from sqlalchemy import DateTime, Boolean, Integer, inspect, text

# If an old column was renamed, list its old name(s) here:
# (table, new_column) -> [old_column, ...]
COLUMN_ALIASES = {
    ("incidents", "created_at"): ["timestamp"],
}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _value_for(table, col, old_row: dict, new_row: dict):
    """Pick the value for `col` when rebuilding a row of `table`."""
    if col.name in old_row and old_row[col.name] is not None:
        return old_row[col.name]
    for alias in COLUMN_ALIASES.get((table.name, col.name), []):
        if old_row.get(alias) is not None:
            return old_row[alias]
    if isinstance(col.type, DateTime):
        if col.name == "updated_at" and new_row.get("created_at"):
            return new_row["created_at"]
        return _now()
    if col.default is not None and col.default.is_scalar:
        return col.default.arg
    if col.nullable:
        return None
    if isinstance(col.type, (Integer, Boolean)):
        return 0
    return "unknown"


def _rebuild_table(engine, table, actual_cols, expected_cols):
    added = sorted(expected_cols - actual_cols)
    dropped = sorted(actual_cols - expected_cols)
    print(f"[schema_sync] Rebuilding '{table.name}': adding {added or '-'}, removing {dropped or '-'}")

    names = [c.name for c in table.columns]
    quoted = ", ".join(f'"{n}"' for n in names)
    params = ", ".join(f":{n}" for n in names)
    insert_sql = text(f'INSERT INTO "{table.name}" ({quoted}) VALUES ({params})')

    with engine.begin() as conn:
        old_rows = [dict(r) for r in conn.execute(text(f'SELECT * FROM "{table.name}"')).mappings()]
        conn.execute(text(f'DROP TABLE "{table.name}"'))  # also drops its indexes
        table.create(conn)                                # new schema + indexes

        new_rows = []
        for old in old_rows:
            new = {}
            for col in table.columns:
                new[col.name] = _value_for(table, col, old, new)
            new_rows.append(new)
        if new_rows:
            conn.execute(insert_sql, new_rows)  # raw SQL: values copied as-is (no JSON re-encoding)

    print(f"[schema_sync] '{table.name}': migrated {len(old_rows)} row(s)")


def sync_schema(engine, metadata) -> None:
    if engine.dialect.name != "sqlite":
        metadata.create_all(bind=engine)
        print("[schema_sync] Non-SQLite database: only create_all() ran. Use Alembic for migrations.")
        return

    metadata.create_all(bind=engine)  # step 1: missing tables

    insp = inspect(engine)
    stale = []
    for table in metadata.sorted_tables:
        actual = {c["name"] for c in insp.get_columns(table.name)}
        expected = {c.name for c in table.columns}
        if actual != expected:
            stale.append((table, actual, expected))

    if not stale:
        return

    db_path = engine.url.database
    if db_path and db_path != ":memory:":
        backup = f"{db_path}.bak-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        shutil.copy2(db_path, backup)
        print(f"[schema_sync] Backup written to {backup}")

    for table, actual, expected in stale:
        _rebuild_table(engine, table, actual, expected)