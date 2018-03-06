ALTER TABLE users ADD COLUMN deprovisioned BOOLEAN;
UPDATE users SET deprovisioned = FALSE WHERE deprovisioned IS NULL;
ALTER TABLE users ALTER COLUMN deprovisioned SET NOT NULL;
ALTER TABLE users ALTER COLUMN deprovisioned SET default FALSE;