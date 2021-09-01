CREATE TABLE accounts (
	account_id TEXT PRIMARY KEY,
	email TEXT UNIQUE NOT NULL,
	password BLOB NOT NULL,
	totp_secret BLOB NULLABLE,

	-- unix time
	created_at INTEGER NOT NULL,
	modified_at INTEGER NOT NULL
);

---

CREATE TABLE sessions (
	session_id TEXT PRIMARY KEY,
	account_id TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,

	-- unix time
	created_at INTEGER NOT NULL,
	expires_at INTEGER NOT NULL
);

---


CREATE TABLE permissiongroups (
	permissiongroup_id INTEGER PRIMARY KEY,
	permissions_array TEXT NOT NULL,
	description TEXT NOT NULL,

	-- unix time
	created_at INTEGER NOT NULL,
	modified_at INTEGER NOT NULL
);

---

CREATE TABLE account_permissiongroups (
	account_id TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
	permissiongroup_id INTEGER NOT NULL REFERENCES permissiongroups(permissiongroup_id) ON DELETE CASCADE,
	UNIQUE (account_id, permissiongroup_id)
);

---

CREATE TABLE changelogs (
	changelog_id INTEGER PRIMARY KEY,
	account_id TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,

	-- A generic way to reference any entity
	--
	-- Operation is either created, modified or deleted.
	operation TEXT NOT NULL,
	-- Entity is the name of the entitie changed, for example Account or
	-- PermissionGroup
	entity_kind TEXT NOT NULL,
	-- Entity primary key, that is used by the corresponding entity type.
	-- All values are stored as strings. Composite primary keys are not
	-- supported.
	entity_pk TEXT NOT NULL,

	-- unix time
	created_at INTEGER NOT NULL
);

---

CREATE TABLE ephemeraltokens (
	token_id TEXT PRIMARY KEY,
	action TEXT NOT NULL,
	payload BLOB NOT NULL,

	-- unix time
	created_at INTEGER NOT NULL,
	expires_at INTEGER NOT NULL
);


---

-- Bootstrap database.

INSERT INTO permissiongroups (permissiongroup_id, permissions_array, description, created_at, modified_at)
VALUES  (1, 'lith-admin',      'System Admin',   strftime('%s', 'now'), strftime('%s', 'now')),
	(2, 'login',           'Active Account', strftime('%s', 'now'), strftime('%s', 'now'));
