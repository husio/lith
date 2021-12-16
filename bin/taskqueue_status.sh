#!/bin/sh

db="${1:-/tmp/lith_taskqueue.sqlite3.db}"

echo
echo "=== FAILURES ==="
echo "select * from failures order by created_at desc limit 5" | sqlite3 "$db"
echo
echo "=== TASK TO PROCESS ==="
echo "select * from tasks order by execute_at desc limit 5" | sqlite3 "$db"
echo
echo "=== DEADQUEUE ==="
echo "select * from deadqueue order by created_at desc limit 2" | sqlite3 "$db"
echo
