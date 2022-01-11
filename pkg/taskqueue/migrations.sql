CREATE TABLE IF NOT EXISTS tasks (
	task_id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	payload BLOB NOT NULL,
	retry INTEGER NOT NULL,
	timeout INTEGER NOT NULL,
	execute_at INTEGER NOT NULL,
	created_at INTEGER NOT NULL
);

---

CREATE INDEX IF NOT EXISTS tasks_execute_at_idx ON tasks(execute_at);

---

-- Cleanup acquired tasks by recreating the table;
DROP TABLE IF EXISTS acquired;

---

CREATE TABLE acquired (
	task_id TEXT UNIQUE,
	created_at INTEGER NOT NULL
);

---

CREATE TABLE IF NOT EXISTS failures (
	task_id TEXT NOT NULL,
	created_at INTEGER NOT NULL,
	description TEXT NOT NULL
);

---

CREATE TABLE IF NOT EXISTS deadqueue (
	task_id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	payload BLOB NOT NULL,
	created_at INTEGER NOT NULL
);

---

-- Optimize the space used by the database file.
VACUUM;
