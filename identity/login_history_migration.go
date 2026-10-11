package identity

const accountLoginHistoryMigration = `
ALTER TABLE sessions ADD COLUMN client_ip TEXT NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN user_agent TEXT NOT NULL DEFAULT '';
CREATE TABLE account_login_records (
	id TEXT PRIMARY KEY,
	user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	auth_method TEXT NOT NULL,
	kind TEXT NOT NULL CHECK (kind IN ('login', 'rotation', 'legacy')),
	created_at INTEGER NOT NULL,
	expires_at INTEGER NOT NULL,
	last_seen_at INTEGER,
	revoked_at INTEGER,
	revoked_reason TEXT NOT NULL DEFAULT '',
	client_ip TEXT NOT NULL DEFAULT '',
	user_agent TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_account_login_records_user_page ON account_login_records(user_id, created_at DESC, id DESC);
INSERT INTO account_login_records
	(id, user_id, auth_method, kind, created_at, expires_at, last_seen_at, revoked_at, revoked_reason)
SELECT id, user_id, auth_method, 'legacy', created_at, expires_at, last_seen_at, revoked_at, revoked_reason
FROM sessions WHERE EXISTS (SELECT 1 FROM users WHERE users.id = sessions.user_id);

CREATE TRIGGER account_login_record_created AFTER INSERT ON sessions BEGIN
	INSERT INTO account_login_records
		(id, user_id, auth_method, kind, created_at, expires_at, last_seen_at,
		 revoked_at, revoked_reason, client_ip, user_agent)
	VALUES (NEW.id, NEW.user_id, NEW.auth_method,
		CASE WHEN NEW.rotated_from = '' THEN 'login' ELSE 'rotation' END,
		NEW.created_at, NEW.expires_at, NEW.last_seen_at, NEW.revoked_at,
		NEW.revoked_reason, NEW.client_ip, NEW.user_agent);
	SELECT CASE WHEN changes() != 1 THEN RAISE(ABORT, 'identity: login record creation failed') END;
END;
CREATE TRIGGER account_login_record_updated AFTER UPDATE OF last_seen_at, expires_at, revoked_at, revoked_reason ON sessions BEGIN
	UPDATE account_login_records SET last_seen_at = NEW.last_seen_at, expires_at = NEW.expires_at,
		revoked_at = NEW.revoked_at, revoked_reason = NEW.revoked_reason
	WHERE id = NEW.id AND user_id = NEW.user_id;
	SELECT CASE WHEN changes() != 1 THEN RAISE(ABORT, 'identity: login record update failed') END;
END;
`
