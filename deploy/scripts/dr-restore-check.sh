#!/usr/bin/env bash
set -euo pipefail

: "${BACKUP_FILE:?BACKUP_FILE must point to a gzip-compressed pg_dump file}"
: "${PGHOST:?PGHOST is required}"
: "${PGUSER:?PGUSER is required}"
: "${PGDATABASE:?PGDATABASE is required}"

[[ -r "$BACKUP_FILE" ]] || { echo "Backup is not readable: $BACKUP_FILE" >&2; exit 2; }
createdb --if-not-exists "$PGDATABASE"
gunzip -c "$BACKUP_FILE" | psql --set ON_ERROR_STOP=1
psql --set ON_ERROR_STOP=1 -c 'SELECT count(*) AS replay_frames FROM replay_frames;'
psql --set ON_ERROR_STOP=1 -c 'SELECT count(*) AS consumed_nonces FROM consumed_nonces;'
echo 'Restore validation completed. Promote only after application conformance tests pass.'
