ALTER TABLE identities ADD COLUMN deprovisioned BOOLEAN;
UPDATE identities SET deprovisioned = FALSE WHERE deprovisioned IS NULL;