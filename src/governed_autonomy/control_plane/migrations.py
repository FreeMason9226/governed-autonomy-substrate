from __future__ import annotations

from pathlib import Path
from typing import Any

MIGRATIONS_DIR = Path(__file__).resolve().parents[3] / "deploy" / "postgres" / "migrations"


def run_postgres_migrations(connection: Any, migrations_dir: Path | None = None) -> list[str]:
    directory = migrations_dir or MIGRATIONS_DIR
    cursor = connection.cursor()
    try:
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS gas_schema_migrations (
                version TEXT PRIMARY KEY,
                applied_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        cursor.execute("SELECT version FROM gas_schema_migrations")
        applied = {row[0] for row in cursor.fetchall()}
        executed: list[str] = []
        for path in sorted(directory.glob("*.sql")):
            if path.name in applied:
                continue
            runner = getattr(connection, "execute", None)
            if callable(runner):
                runner(path.read_text(encoding="utf-8"))
            else:
                cursor.execute(path.read_text(encoding="utf-8"))
            cursor.execute(
                "INSERT INTO gas_schema_migrations(version) VALUES (%s)",
                (path.name,),
            )
            executed.append(path.name)
        connection.commit()
        return executed
    except Exception:
        connection.rollback()
        raise
    finally:
        cursor.close()
